pub mod collect;
pub mod config;
pub mod prg;
pub mod rpc;
pub mod vidpf;

extern crate lazy_static;

use prio::field::Field64;

pub use crate::rpc::CollectorClient;

pub const HASH_SIZE: usize = 16;

impl crate::prg::FromRng for Field64 {
    fn from_rng(&mut self, rng: &mut impl rand::Rng) {
        *self = Field64::from(rng.next_u64());
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
