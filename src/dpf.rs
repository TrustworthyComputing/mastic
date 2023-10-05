use crate::prg;
use crate::Group;
use crate::{xor_three_vecs, xor_vec};

use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CorWord<T> {
    seed: prg::PrgSeed,
    bits: (bool, bool),
    word: T,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DPFKey<T, U> {
    pub key_idx: bool,
    root_seed: prg::PrgSeed,
    cor_words: Vec<CorWord<T>>,
    cor_word_last: CorWord<U>,
    pub cs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct EvalState {
    level: usize,
    pub seed: prg::PrgSeed,
    pub bit: bool,
    pub proof: Vec<u8>,
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

fn gen_cor_word<W>(
    bit: bool,
    value: W,
    bits: &mut (bool, bool),
    seeds: &mut (prg::PrgSeed, prg::PrgSeed),
) -> CorWord<W>
where
    W: prg::FromRng + Clone + Group + std::fmt::Debug,
{
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
        word: W::zero(),
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

    let converted = seeds.map(|s| s.convert());
    cw.word = value;
    cw.word.sub(&converted.0.word);
    cw.word.add(&converted.1.word);

    if bits.1 {
        cw.word.negate();
    }

    seeds.0 = converted.0.seed;
    seeds.1 = converted.1.seed;

    cw
}

/// All-prefix DPF implementation.
impl<T, U> DPFKey<T, U>
where
    T: prg::FromRng + Clone + Group + std::fmt::Debug,
    U: prg::FromRng + Clone + Group + std::fmt::Debug,
{
    pub fn gen(alpha_bits: &[bool], values: &[T], value_last: &U) -> (DPFKey<T, U>, DPFKey<T, U>) {
        debug_assert!(alpha_bits.len() == values.len() + 1);

        let root_seeds = (prg::PrgSeed::random(), prg::PrgSeed::random());
        let root_bits = (false, true);

        let mut seeds = root_seeds.clone();
        let mut bits = root_bits;

        let mut hasher = Sha256::new();
        let mut cor_words: Vec<CorWord<T>> = Vec::new();
        let mut cs: Vec<Vec<u8>> = Vec::new();
        let mut bit_str: String = "".to_string();
        for i in 0..(alpha_bits.len() - 1) {
            let bit = alpha_bits[i];
            bit_str.push_str(if bit { "1" } else { "0" });
            let cw = gen_cor_word::<T>(bit, values[i].clone(), &mut bits, &mut seeds);
            cor_words.push(cw);

            let pi_0 = {
                hasher.update(&bit_str);
                hasher.update(seeds.0.key);
                hasher.finalize_reset().to_vec()
            };
            let pi_1 = {
                hasher.update(&bit_str);
                hasher.update(seeds.1.key);
                hasher.finalize_reset().to_vec()
            };
            cs.push(crate::xor_vec(&pi_0, &pi_1));
        }

        let bit = alpha_bits[values.len()];
        bit_str.push_str(if bit { "1" } else { "0" });
        let last_cw = gen_cor_word::<U>(bit, value_last.clone(), &mut bits, &mut seeds);

        let pi_0 = {
            hasher.update(&bit_str);
            hasher.update(seeds.0.key);
            hasher.finalize_reset().to_vec()
        };
        let pi_1 = {
            hasher.update(&bit_str);
            hasher.update(seeds.1.key);
            hasher.finalize_reset().to_vec()
        };
        cs.push(crate::xor_vec(&pi_0, &pi_1));

        (
            DPFKey::<T, U> {
                key_idx: false,
                root_seed: root_seeds.0,
                cor_words: cor_words.clone(),
                cor_word_last: last_cw.clone(),
                cs: cs.clone(),
            },
            DPFKey::<T, U> {
                key_idx: true,
                root_seed: root_seeds.1,
                cor_words,
                cor_word_last: last_cw,
                cs,
            },
        )
    }

    pub fn eval_bit(&self, state: &EvalState, dir: bool, bit_str: &String) -> (EvalState, T) {
        let tau = state.seed.expand_dir(!dir, dir);
        let mut seed = tau.seeds.get(dir).clone();
        let mut new_bit = *tau.bits.get(dir);

        if state.bit {
            seed = &seed ^ &self.cor_words[state.level].seed;
            new_bit ^= self.cor_words[state.level].bits.get(dir);
        }

        let converted = seed.convert::<T>();
        let new_seed = converted.seed;

        let mut word = converted.word;
        if new_bit {
            word.add(&self.cor_words[state.level].word);
        }

        if self.key_idx {
            word.negate()
        }

        // Compute proofs
        let mut hasher = Sha256::new();
        let pi_prime = {
            hasher.update(bit_str);
            hasher.update(new_seed.key);
            hasher.finalize_reset().to_vec()
        };
        let h2 = {
            let h: [u8; 32] = if !new_bit {
                // H(pi ^ pi_prime)
                xor_vec(&state.proof, &pi_prime).try_into().unwrap()
            } else {
                //  H(pi ^ pi_prime ^ cs)
                xor_three_vecs(&state.proof, &pi_prime, &self.cs[state.level])
                    .try_into()
                    .unwrap()
            };
            hasher.update(h);
            &hasher.finalize_reset()
        };

        (
            EvalState {
                level: state.level + 1,
                seed: new_seed,
                bit: new_bit,
                proof: xor_vec(h2, &state.proof),
            },
            word,
        )
    }

    pub fn eval_bit_last(&self, state: &EvalState, dir: bool, bit_str: &String) -> (EvalState, U) {
        let tau = state.seed.expand_dir(!dir, dir);
        let mut seed = tau.seeds.get(dir).clone();
        let mut new_bit = *tau.bits.get(dir);

        if state.bit {
            seed = &seed ^ &self.cor_word_last.seed;
            new_bit ^= self.cor_word_last.bits.get(dir);
        }

        let converted = seed.convert::<U>();
        let new_seed = converted.seed;

        let mut word = converted.word;
        if new_bit {
            word.add(&self.cor_word_last.word);
        }

        if self.key_idx {
            word.negate()
        }

        // Compute proofs
        let mut hasher = Sha256::new();
        let pi_prime = {
            hasher.update(bit_str);
            hasher.update(new_seed.key);
            hasher.finalize_reset().to_vec()
        };
        let h2 = {
            let h: [u8; 32] = if !new_bit {
                // H(pi ^ pi_prime)
                xor_vec(&state.proof, &pi_prime).try_into().unwrap()
            } else {
                //  H(pi ^ pi_prime ^ cs)
                xor_three_vecs(&state.proof, &pi_prime, &self.cs[state.level])
                    .try_into()
                    .unwrap()
            };
            hasher.update(h);
            &hasher.finalize_reset()
        };

        (
            EvalState {
                level: state.level + 1,
                seed,
                bit: new_bit,
                proof: xor_vec(h2, &state.proof),
            },
            word,
        )
    }

    pub fn eval_init(&self) -> EvalState {
        EvalState {
            level: 0,
            seed: self.root_seed.clone(),
            bit: self.key_idx,
            proof: vec![0u8; 32],
        }
    }

    pub fn eval(&self, idx: &[bool], pi: &mut Vec<u8>) -> (Vec<T>, U) {
        debug_assert!(idx.len() <= self.domain_size());
        debug_assert!(!idx.is_empty());
        let mut out = vec![];
        let mut state = self.eval_init();

        let mut bit_str: String = "".to_string();
        state.proof = pi.to_vec();

        for &bit in idx.iter().take(idx.len() - 1) {
            bit_str.push(if bit { '1' } else { '0' });

            let (state_new, word) = self.eval_bit(&state, bit, &bit_str);
            out.push(word);
            state = state_new;
        }

        let (_, last) = self.eval_bit_last(&state, *idx.last().unwrap(), &bit_str);
        *pi = state.proof;

        (out, last)
    }

    pub fn gen_from_str(s: &str) -> (Self, Self) {
        let bits = crate::string_to_bits(s);
        let values = vec![T::one(); bits.len() - 1];
        DPFKey::gen(&bits, &values, &U::one())
    }

    pub fn domain_size(&self) -> usize {
        self.cor_words.len()
    }
}
