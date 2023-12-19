use blake3::Hasher;
use prio::field::Field64;
use serde::{Deserialize, Serialize};

use crate::{prg, vec_add, vec_neg, vec_sub, xor_three_vecs, xor_vec, HASH_SIZE};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CorWord {
    seed: prg::PrgSeed,
    bits: (bool, bool),
    word: Vec<Field64>,
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
    beta: &Vec<Field64>,
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
    cw.word.push(Field64::from(1));
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

    pub fn gen(alpha_bits: &[bool], beta: &Vec<Field64>) -> (VidpfKey, VidpfKey) {
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
    ) -> (EvalState, Vec<Field64>) {
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
    ) -> (Vec<Vec<Field64>>, Vec<Field64>) {
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

    pub fn gen_from_str(s: &str, beta: &Vec<Field64>) -> (Self, Self) {
        let bits = crate::string_to_bits(s);
        VidpfKey::gen(&bits, beta)
    }

    pub fn domain_size(&self) -> usize {
        self.cor_words.len()
    }
}
