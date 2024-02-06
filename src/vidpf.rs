use blake3::Hasher;
use prio::{codec::Encode, field::Field128};
use serde::{Deserialize, Serialize};

use crate::{prg, vec_add, vec_neg, vec_sub, xor_three_vecs, xor_vec, HASH_SIZE};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CorWord {
    seed: prg::PrgSeed,
    bits: (bool, bool),
    word: Vec<Field128>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VidpfKey {
    /// Server ID used for conditional negations.
    pub key_idx: bool,

    /// The initial seeds.
    root_seed: prg::PrgSeed,

    /// List of correction words.
    cor_words: Vec<CorWord>,

    /// List of correction seeds (hashes).
    pub cs: Vec<[u8; HASH_SIZE]>,
}

#[derive(Clone, Debug)]
pub struct EvalState {
    /// Current level of the evaluation.
    level: usize,

    /// Current seed of VIDPF.
    pub seed: prg::PrgSeed,

    /// The last bit from the seed used for conditional decisions.
    pub bit: bool,

    /// The VIDPF proof.
    pub proof: [u8; HASH_SIZE],
}

pub(crate) struct VidpfEvalNode {
    /// String representation of the path to this node.
    bit_str: String,

    /// The word for this node. Set for every node except the root.
    word_share: Option<Vec<Field128>>,

    /// The patch check component for this node. Set for every node except the root and the leaves.
    path_check: Option<Vec<Field128>>,

    /// The node state.
    state: EvalState,

    /// Left child.
    l: Option<Box<VidpfEvalNode>>,

    /// Right child.
    r: Option<Box<VidpfEvalNode>>,
}

impl VidpfEvalNode {
    pub(crate) fn new_root_from_key(key: &VidpfKey) -> Self {
        Self {
            bit_str: "".into(),
            word_share: None,
            path_check: None,
            state: key.eval_init(),
            l: None,
            r: None,
        }
    }

    fn next(&mut self, bit: bool, key: &VidpfKey, input_len: usize) -> Self {
        let bit_str = self.bit_str.clone() + if bit { "1" } else { "0" };
        let (state, word_share) = key.eval_bit(&self.state, bit, &bit_str, input_len);
        Self {
            bit_str,
            word_share: Some(word_share),
            path_check: None,
            state,
            l: None,
            r: None,
        }
    }

    pub(crate) fn traverse(
        &mut self,
        path: &[bool],
        key: &VidpfKey,
        input_len: usize,
        eval_proof: &mut blake3::Hasher,
    ) -> &mut VidpfEvalNode {
        if path.is_empty() {
            return self;
        }

        // If this is not the root node, then ensure the node check is initialized.
        let mut p = if self.word_share.is_some() && self.path_check.is_none() {
            Some(self.word_share.as_ref().unwrap().clone())
        } else {
            None
        };

        // Compute the left child node and update the node check.
        if self.l.is_none() {
            let l = self.next(false, key, input_len);
            if let (Some(ref mut path_check), Some(ref word_share_l)) = (&mut p, &l.word_share) {
                vec_sub(path_check, word_share_l);
            }
            self.l = Some(Box::new(l));
        }

        // Compute the right child node and update the node check.
        if self.r.is_none() {
            let r = self.next(true, key, input_len);
            if let (Some(ref mut path_check), Some(ref word_share_r)) = (&mut p, &r.word_share) {
                vec_sub(path_check, word_share_r);
            }
            self.r = Some(Box::new(r));
        }

        // Finish path check.
        if let Some(mut path_check) = p {
            if key.key_idx {
                vec_neg(&mut path_check)
            }
            for x in &path_check {
                eval_proof.update(&x.get_encoded());
            }
            self.path_check = Some(path_check);
        }

        if !path[0] {
            self.l.as_deref_mut().unwrap()
        } else {
            self.r.as_deref_mut().unwrap()
        }
        .traverse(&path[1..], key, input_len, eval_proof)
    }
}

trait TupleMapToExt<T, U> {
    type Output;
    fn map<F: FnMut(&T) -> U>(&self, f: F) -> Self::Output;
}

type TupleMutIter<'a, T> =
    std::iter::Chain<std::iter::Once<(bool, &'a mut T)>, std::iter::Once<(bool, &'a mut T)>>;

trait TupleExt<T> {
    fn map_mut<F: Fn(&mut T)>(&mut self, f: F);
    fn get(&self, val: bool) -> &T;
    fn get_mut(&mut self, val: bool) -> &mut T;
    fn iter_mut(&mut self) -> TupleMutIter<T>;
}

impl<T, U> TupleMapToExt<T, U> for (T, T) {
    type Output = (U, U);

    #[inline(always)]
    fn map<F: FnMut(&T) -> U>(&self, mut f: F) -> Self::Output {
        (f(&self.0), f(&self.1))
    }
}

impl<T> TupleExt<T> for (T, T) {
    #[inline(always)]
    fn map_mut<F: Fn(&mut T)>(&mut self, f: F) {
        f(&mut self.0);
        f(&mut self.1);
    }

    #[inline(always)]
    fn get(&self, val: bool) -> &T {
        match val {
            false => &self.0,
            true => &self.1,
        }
    }

    #[inline(always)]
    fn get_mut(&mut self, val: bool) -> &mut T {
        match val {
            false => &mut self.0,
            true => &mut self.1,
        }
    }

    fn iter_mut(&mut self) -> TupleMutIter<T> {
        std::iter::once((false, &mut self.0)).chain(std::iter::once((true, &mut self.1)))
    }
}

fn gen_cor_word(
    bit: bool,
    beta: &Vec<Field128>,
    bits: &mut (bool, bool),
    seeds: &mut (prg::PrgSeed, prg::PrgSeed),
) -> CorWord {
    let data = seeds.map(|s| s.expand());

    // If alpha[i] = 0:
    //   Keep = L,  Lose = R
    // Else
    //   Keep = R,  Lose = L
    let keep = bit;
    let lose = !keep;

    let mut cw = CorWord {
        seed: data.0.seeds.get(lose) ^ data.1.seeds.get(lose),
        bits: (
            data.0.bits.0 ^ data.1.bits.0 ^ bit ^ true,
            data.0.bits.1 ^ data.1.bits.1 ^ bit,
        ),
        word: beta.clone(),
    };

    for (b, seed) in seeds.iter_mut() {
        *seed = data.get(b).seeds.get(keep).clone();

        if *bits.get(b) {
            *seed = &*seed ^ &cw.seed;
        }

        let mut newbit = *data.get(b).bits.get(keep);
        if *bits.get(b) {
            newbit ^= cw.bits.get(keep);
        }

        *bits.get_mut(b) = newbit;
    }

    let input_len = beta.len();
    let converted = seeds.map(|s| s.convert(input_len));

    // Counter is last
    cw.word.push(Field128::from(1));
    vec_sub(&mut cw.word, &converted.0.word);
    vec_add(&mut cw.word, &converted.1.word);
    if bits.1 {
        vec_neg(&mut cw.word);
    }
    seeds.0 = converted.0.seed;
    seeds.1 = converted.1.seed;

    cw
}

/// All-prefix DPF implementation.
impl VidpfKey {
    pub fn get_root_seed(&self) -> prg::PrgSeed {
        self.root_seed.clone()
    }

    pub fn gen(alpha_bits: &[bool], beta: &Vec<Field128>) -> (VidpfKey, VidpfKey) {
        let root_seeds = (prg::PrgSeed::random(), prg::PrgSeed::random());
        let root_bits = (false, true);

        let mut seeds = root_seeds.clone();
        let mut bits = root_bits;

        let mut hasher = Hasher::new();
        let mut cor_words: Vec<CorWord> = Vec::new();
        let mut cs: Vec<[u8; HASH_SIZE]> = Vec::new();
        let mut bit_str: String = "".to_string();
        for &bit in alpha_bits {
            bit_str.push_str(if bit { "1" } else { "0" });
            let cw = gen_cor_word(bit, beta, &mut bits, &mut seeds);
            cor_words.push(cw);

            let pi_0 = {
                hasher.reset();
                hasher.update_rayon(bit_str.as_bytes());
                hasher.update_rayon(&seeds.0.key);
                hasher.finalize()
            };
            let pi_1 = {
                hasher.reset();
                hasher.update_rayon(bit_str.as_bytes());
                hasher.update_rayon(&seeds.1.key);
                hasher.finalize()
            };
            cs.push(
                xor_vec(pi_0.as_bytes(), pi_1.as_bytes())[..HASH_SIZE]
                    .try_into()
                    .unwrap(),
            );
        }

        (
            VidpfKey {
                key_idx: false,
                root_seed: root_seeds.0,
                cor_words: cor_words.clone(),
                cs: cs.clone(),
            },
            VidpfKey {
                key_idx: true,
                root_seed: root_seeds.1,
                cor_words,
                cs,
            },
        )
    }

    pub fn eval_bit(
        &self,
        state: &EvalState,
        dir: bool,
        bit_str: &String,
        input_len: usize,
    ) -> (EvalState, Vec<Field128>) {
        let tau = state.seed.expand_dir(!dir, dir);
        let mut seed = tau.seeds.get(dir).clone();
        let mut new_bit = *tau.bits.get(dir);

        if state.bit {
            seed = &seed ^ &self.cor_words[state.level].seed;
            new_bit ^= self.cor_words[state.level].bits.get(dir);
        }

        let converted = seed.convert(input_len);
        let new_seed = converted.seed;

        let mut word = converted.word;
        if new_bit {
            vec_add(&mut word, &self.cor_words[state.level].word);
        }

        if self.key_idx {
            vec_neg(&mut word);
        }

        // Compute proofs
        let mut hasher = Hasher::new();

        hasher.update_rayon(bit_str.as_bytes());
        hasher.update_rayon(&new_seed.key);
        let binding = hasher.finalize();
        let pi_prime = binding.as_bytes()[0..HASH_SIZE].try_into().unwrap();

        let h2 = {
            let h: [u8; HASH_SIZE] = if !new_bit {
                // H(pi ^ pi_prime)
                xor_vec(&state.proof, pi_prime).try_into().unwrap()
            } else {
                //  H(pi ^ pi_prime ^ cs)
                xor_three_vecs(&state.proof, pi_prime, &self.cs[state.level])
                    .try_into()
                    .unwrap()
            };
            hasher.reset();
            hasher.update_rayon(&h);
            hasher.finalize()
        };
        let proof = xor_vec(
            h2.as_bytes()[0..HASH_SIZE].try_into().unwrap(),
            &state.proof,
        )
        .as_slice()
        .try_into()
        .unwrap();

        (
            EvalState {
                level: state.level + 1,
                seed: new_seed,
                bit: new_bit,
                proof,
            },
            word,
        )
    }

    pub fn eval_init(&self) -> EvalState {
        EvalState {
            level: 0,
            seed: self.root_seed.clone(),
            bit: self.key_idx,
            proof: [0u8; HASH_SIZE],
        }
    }

    pub fn eval(
        &self,
        idx: &[bool],
        pi: &mut [u8; HASH_SIZE],
        input_len: usize,
    ) -> (Vec<Vec<Field128>>, Vec<Field128>) {
        debug_assert!(idx.len() <= self.domain_size());
        debug_assert!(!idx.is_empty());
        let mut out = vec![];
        let mut state = self.eval_init();

        let mut bit_str: String = "".to_string();
        state.proof = *pi;

        for &bit in idx.iter().take(idx.len() - 1) {
            bit_str.push(if bit { '1' } else { '0' });

            let (state_new, word) = self.eval_bit(&state, bit, &bit_str, input_len);
            out.push(word);
            state = state_new;
        }

        let (_, last) = self.eval_bit(&state, *idx.last().unwrap(), &bit_str, input_len);
        *pi = state.proof;

        (out, last)
    }

    /// Evaluate the prefix tree, appending the path and onehot checks to `eval_proof`. Use `root`
    /// as the evaluation cache. Return the value share for each path traversed, as well as the
    /// share of `beta`.
    pub fn eval_tree<I: AsRef<[bool]>>(
        &self,
        paths: impl Iterator<Item = I>,
        input_len: usize,
        eval_proof: &mut blake3::Hasher,
    ) -> (Vec<Vec<Field128>>, Vec<Field128>) {
        let key_idx = Field128::from(if self.key_idx { 1 } else { 0 });
        let mut values_share = Vec::new();
        let mut root = VidpfEvalNode::new_root_from_key(self);

        // Traverse each indicated path of the subtree, appending the path checks and onehot checks
        // to the evaluation proof.
        //
        // NOTE The order in which we traverse the tree and the computation of the evaluation proof
        // differ from the draft. The onehot proofs in particular need careful consideration, as we
        // don't daisy-chain them directly to compute a unified onehot proof for the entire
        // traversal. Instead we interleave the components with the path checks.
        for path in paths {
            assert_ne!(path.as_ref().len(), 0);
            let node = root.traverse(path.as_ref(), self, input_len, eval_proof);
            eval_proof.update(&node.state.proof);
            values_share.push(node.word_share.as_ref().unwrap().clone());
        }

        // Compute the counter and our share of beta.
        let (counter, beta_share) = {
            let mut y = root
                .traverse(&[false], self, input_len, eval_proof)
                .word_share
                .as_ref()
                .unwrap()
                .clone();

            vec_add(
                &mut y,
                root.traverse(&[true], self, input_len, eval_proof)
                    .word_share
                    .as_ref()
                    .unwrap(),
            );

            let mut counter = y[input_len];
            if self.key_idx {
                counter = -counter;
            }
            counter += key_idx;

            y.truncate(input_len); // beta_share
            (counter, y)
        };
        eval_proof.update(&counter.get_encoded());

        (values_share, beta_share)
    }

    pub fn gen_from_str(s: &str, beta: &Vec<Field128>) -> (Self, Self) {
        let bits = crate::string_to_bits(s);
        VidpfKey::gen(&bits, beta)
    }

    pub fn domain_size(&self) -> usize {
        self.cor_words.len()
    }
}

#[cfg(test)]
mod tests {
    use prio::field::FieldElement;

    use super::*;
    use crate::string_to_bits;

    /// Test the VIDPF functionality required for the attribute-based metrics use case.
    #[test]
    fn mode_attribute_based_metrics() {
        let input_len = 1;
        let expected_beta = vec![Field128::from(1337); input_len];
        let (key_0, key_1) = VidpfKey::gen_from_str("h", &expected_beta);
        assert_eq!(key_0.key_idx, false);
        assert_eq!(key_1.key_idx, true);

        let attributes = ["h", "s", "b", "c"];

        let mut eval_proof_0 = blake3::Hasher::new();
        let mut eval_proof_1 = blake3::Hasher::new();

        let (values_0, beta_0) = key_0.eval_tree(
            attributes.iter().map(|attribute| string_to_bits(attribute)),
            1,
            &mut eval_proof_0,
        );
        let (values_1, beta_1) = key_1.eval_tree(
            attributes.iter().map(|attribute| string_to_bits(attribute)),
            1,
            &mut eval_proof_1,
        );
        println!("values_0 {values_0:?}");
        println!("values_1 {values_1:?}");
        println!("eval_proof_0 {}", eval_proof_0.finalize().to_hex());
        println!("eval_proof_1 {}", eval_proof_1.finalize().to_hex());
        assert_eq!(values_0.len(), attributes.len());
        assert_eq!(values_1.len(), attributes.len());
        assert_eq!(beta_0.len(), input_len);
        assert_eq!(beta_1.len(), input_len);

        let mut values = values_0.clone();
        for (v, s1) in values.iter_mut().zip(values_1.iter()) {
            vec_add(v, s1);
        }

        let mut beta = beta_0.clone();
        vec_add(&mut beta, &beta_1);
        assert_eq!(beta, expected_beta);

        for (value, expected_value) in values.iter().zip(
            [
                [Field128::from(1337), Field128::one()],
                [Field128::zero(), Field128::zero()],
                [Field128::zero(), Field128::zero()],
                [Field128::zero(), Field128::zero()],
            ]
            .iter(),
        ) {
            assert_eq!(value, expected_value);
        }
        assert_eq!(eval_proof_0.finalize(), eval_proof_1.finalize());
    }
}
