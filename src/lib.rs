pub mod collect;
pub mod config;
pub mod prg;
pub mod rpc;
pub mod vidpf;

extern crate lazy_static;

use config::Mode;
use prio::{
    field::Field128,
    flp::{
        gadgets::{Mul, ParallelSum},
        types::{Histogram, Sum},
        FlpError,
    },
    vdaf::VdafError,
};

pub use crate::rpc::CollectorClient;

pub const HASH_SIZE: usize = 16;

pub fn histogram_chunk_length(num_buckets: usize, mode: Mode) -> usize {
    // The "asymptotically optimal" chunk length is `(num_buckets as f64).sqrt()
    // as usize`. However Mastic histograms are so small that a constant size seems
    // to perform better. For PlainMetrics, we use bigger histograms.
    match mode {
        Mode::WeightedHeavyHitters { .. } | Mode::AttributeBasedMetrics { .. } => 2,
        Mode::PlainMetrics => (num_buckets as f64).sqrt() as usize,
    }
}

#[derive(Clone, Debug)]
pub struct Mastic<T>
where
    T: prio::flp::Type,
{
    typ: T,
}

impl<T> Mastic<T>
where
    T: prio::flp::Type,
{
    /// Construct an instance of this MasticFlp VDAF with the given number of aggregators, number of
    /// proofs to generate and verify, the algorithm ID, and the underlying type.
    pub fn new(typ: T) -> Result<Self, VdafError> {
        Ok(Self { typ })
    }

    pub fn encode_measurement(
        &self,
        measurement: &T::Measurement,
    ) -> Result<Vec<T::Field>, VdafError> {
        Ok(self.typ.encode_measurement(measurement)?)
    }

    pub fn input_len(&self) -> usize {
        self.typ.input_len()
    }

    pub fn joint_rand_len(&self) -> usize {
        self.typ.joint_rand_len()
    }

    pub fn query_rand_len(&self) -> usize {
        self.typ.query_rand_len()
    }

    pub fn prove_rand_len(&self) -> usize {
        self.typ.prove_rand_len()
    }

    pub fn prove(
        &self,
        input: &[T::Field],
        prove_rand: &[T::Field],
        joint_rand: &[T::Field],
    ) -> Result<Vec<T::Field>, FlpError> {
        self.typ.prove(input, prove_rand, joint_rand)
    }

    pub fn query(
        &self,
        input: &[T::Field],
        proof: &[T::Field],
        query_rand: &[T::Field],
        joint_rand: &[T::Field],
        num_shares: usize,
    ) -> Result<Vec<T::Field>, FlpError> {
        self.typ
            .query(input, proof, query_rand, joint_rand, num_shares)
    }

    pub fn decide(&self, verifier: &[T::Field]) -> Result<bool, FlpError> {
        self.typ.decide(verifier)
    }
}

/// The histogram type. Each measurement is an integer in `[0, length)` and the result is a
/// histogram counting the number of occurrences of each measurement.
pub type MasticSum = Mastic<Sum<Field128>>;

impl MasticSum {
    /// Constructs an instance of MasticHistogram with the given number of aggregators,
    /// number of buckets, and parallel sum gadget chunk length.
    pub fn new_sum(bits: usize) -> Result<Self, VdafError> {
        Mastic::new(Sum::new(bits)?)
    }
}

/// The histogram type. Each measurement is an integer in `[0, length)` and the result is a
/// histogram counting the number of occurrences of each measurement.
pub type MasticHistogram = Mastic<Histogram<Field128, ParallelSum<Field128, Mul<Field128>>>>;

impl MasticHistogram {
    /// Constructs an instance of MasticHistogram with the given number of aggregators,
    /// number of buckets, and parallel sum gadget chunk length.
    pub fn new_histogram(length: usize) -> Result<Self, VdafError> {
        Mastic::new(Histogram::new(
            length,
            histogram_chunk_length(
                length,
                Mode::WeightedHeavyHitters {
                    threshold: 0.0, // Unused here.
                },
            ),
        )?)
    }
}

impl crate::prg::FromRng for Field128 {
    fn from_rng(&mut self, rng: &mut impl rand::Rng) {
        let low_bits = rng.next_u64();
        let high_bits = rng.next_u64();
        *self = Field128::from(((high_bits as u128) << 64) | low_bits as u128);
    }
}

pub fn u32_to_bits(nbits: u8, input: u32) -> Vec<bool> {
    assert!(nbits <= 32);

    let mut out: Vec<bool> = Vec::new();
    for i in 0..nbits {
        let bit = (input & (1 << i)) != 0;
        out.push(bit);
    }
    out
}

pub fn string_to_bits(s: &str) -> Vec<bool> {
    let mut bits = vec![];
    let byte_vec = s.to_string().into_bytes();
    for byte in &byte_vec {
        let mut b = crate::u32_to_bits(8, (*byte).into());
        bits.append(&mut b);
    }
    bits
}

fn bits_to_u8(bits: &[bool]) -> u8 {
    assert_eq!(bits.len(), 8);
    let mut out = 0u8;
    for i in 0..8 {
        let b8: u8 = bits[i].into();
        out |= b8 << i;
    }

    out
}

pub fn bits_to_string(bits: &[bool]) -> String {
    assert_eq!(bits.len() % 8, 0);

    let mut out: String = "".to_string();
    let byte_len = bits.len() / 8;
    for b in 0..byte_len {
        let byte = &bits[8 * b..8 * (b + 1)];
        let ubyte = bits_to_u8(byte);
        out.push_str(std::str::from_utf8(&[ubyte]).unwrap());
    }

    out
}

pub fn bits_to_bitstring(bits: &[bool]) -> String {
    let mut out: String = "".to_string();
    for b in bits {
        if *b {
            out.push('1');
        } else {
            out.push('0');
        }
    }

    out
}

pub fn xor_vec(v1: &[u8], v2: &[u8]) -> Vec<u8> {
    v1.iter().zip(v2.iter()).map(|(&x1, &x2)| x1 ^ x2).collect()
}

pub fn vec_add<T>(v1: &mut [T], v2: &[T])
where
    T: prg::FromRng + Clone + prio::field::FieldElement + std::fmt::Debug,
{
    v1.iter_mut()
        .zip(v2.iter())
        .for_each(|(x1, &x2)| x1.add_assign(x2));
}

pub fn vec_sub<T>(v1: &mut [T], v2: &[T])
where
    T: prg::FromRng + Clone + prio::field::FieldElement + std::fmt::Debug,
{
    v1.iter_mut()
        .zip(v2.iter())
        .for_each(|(x1, &x2)| x1.sub_assign(x2));
}

pub fn vec_neg<T>(v1: &mut [T])
where
    T: prg::FromRng + Clone + prio::field::FieldElement + std::fmt::Debug,
{
    v1.iter_mut().for_each(|x| *x = x.neg());
}

pub fn xor_in_place(v1: &mut [u8], v2: &[u8]) {
    for (x1, &x2) in v1.iter_mut().zip(v2.iter()) {
        *x1 ^= x2;
    }
}

pub fn xor_three_vecs(v1: &[u8], v2: &[u8], v3: &[u8]) -> Vec<u8> {
    v1.iter()
        .zip(v2.iter())
        .zip(v3.iter())
        .map(|((&x1, &x2), &x3)| x1 ^ x2 ^ x3)
        .collect()
}

pub fn take<T>(vec: &mut Vec<T>, index: usize) -> Option<T> {
    if vec.get(index).is_none() {
        None
    } else {
        Some(vec.swap_remove(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_bits() {
        let empty: Vec<bool> = vec![];
        assert_eq!(u32_to_bits(0, 7), empty);
        assert_eq!(u32_to_bits(1, 0), vec![false]);
        assert_eq!(u32_to_bits(2, 0), vec![false, false]);
        assert_eq!(u32_to_bits(2, 3), vec![true, true]);
        assert_eq!(u32_to_bits(2, 1), vec![true, false]);
        assert_eq!(u32_to_bits(12, 65535), vec![true; 12]);
    }

    #[test]
    fn to_string() {
        let empty: Vec<bool> = vec![];
        assert_eq!(string_to_bits(""), empty);
        let avec = vec![true, false, false, false, false, true, true, false];
        assert_eq!(string_to_bits("a"), avec);

        let mut aaavec = vec![];
        for _i in 0..3 {
            aaavec.append(&mut avec.clone());
        }
        assert_eq!(string_to_bits("aaa"), aaavec);
    }

    #[test]
    fn to_from_string() {
        let s = "basfsdfwefwf";
        let bitvec = string_to_bits(s);
        let s2 = bits_to_string(&bitvec);

        assert_eq!(bitvec.len(), s.len() * 8);
        assert_eq!(s, s2);
    }
}
