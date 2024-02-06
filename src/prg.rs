#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_add_epi64, _mm_loadu_si128, _mm_set_epi64x, _mm_storeu_si128,
};

use aes::{
    cipher::{
        generic_array::{typenum::U8, GenericArray},
        Block, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher,
    },
    Aes128,
};
use cfg_if::cfg_if;
use rand::Rng;

type Aes128Ctr128LE = ctr::Ctr128LE<aes::Aes128>;

use std::{cell::RefCell, ops};

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone)]
struct Counter(__m128i);

#[cfg(not(target_arch = "x86_64"))]
#[derive(Copy, Clone)]
struct Counter(Block<Aes128>);

// AES key size in bytes. We always use AES-128,
// which has 16-byte keys.
const AES_KEY_SIZE: usize = 16;

// AES block size in bytes. Always 16 bytes.
pub const AES_BLOCK_SIZE: usize = 16;

pub struct FixedKeyPrgStream {
    aes: Aes128,
    ctr: Counter,
    buf: [u8; AES_BLOCK_SIZE * 8],
    have: usize,
    buf_ptr: usize,
    count: usize,
}

thread_local!(static FIXED_KEY_STREAM: RefCell<FixedKeyPrgStream> = RefCell::new(FixedKeyPrgStream::new()));

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrgSeed {
    pub key: [u8; AES_KEY_SIZE],
}

impl PrgSeed {
    pub fn to_rng(&self) -> PrgStream {
        let iv: [u8; AES_BLOCK_SIZE] = [0; AES_BLOCK_SIZE];

        let key = GenericArray::from_slice(&self.key);
        let nonce = GenericArray::from_slice(&iv);
        PrgStream {
            // stream: Aes128::new(key),
            stream: Aes128Ctr128LE::new(key, nonce),
        }
    }

    pub fn expand_dir(self: &PrgSeed, left: bool, right: bool) -> PrgOutput {
        FIXED_KEY_STREAM.with(|s_in| {
            let mut key_short = self.key;

            // Zero out first two bits and use for output
            key_short[0] &= 0xFC;

            let mut s = s_in.borrow_mut();
            s.set_key(&key_short);

            let mut out = PrgOutput {
                bits: ((key_short[0] & 0x1) == 0, (key_short[0] & 0x2) == 0),
                seeds: (PrgSeed::zero(), PrgSeed::zero()),
            };

            if left {
                s.fill_bytes(&mut out.seeds.0.key);
            } else {
                s.skip_block();
            }

            if right {
                s.fill_bytes(&mut out.seeds.1.key);
            } else {
                s.skip_block();
            }

            out
        })
    }

    pub fn expand(self: &PrgSeed) -> PrgOutput {
        self.expand_dir(true, true)
    }

    pub fn convert<T: FromRng + prio::field::FieldElement>(
        self: &PrgSeed,
        input_len: usize,
    ) -> ConvertOutput<T> {
        let mut out = ConvertOutput {
            seed: PrgSeed::zero(),
            word: vec![T::zero(); input_len + 1],
        };

        FIXED_KEY_STREAM.with(|s_in| {
            let mut s = s_in.borrow_mut();
            s.set_key(&self.key);
            s.fill_bytes(&mut out.seed.key);
            unsafe {
                let sp = s_in.as_ptr();
                for x in out.word.iter_mut() {
                    x.from_rng(&mut *sp);
                }
            }
        });

        out
    }

    pub fn zero() -> PrgSeed {
        PrgSeed {
            key: [0; AES_KEY_SIZE],
        }
    }

    pub fn random() -> PrgSeed {
        let mut key: [u8; AES_KEY_SIZE] = [0; AES_KEY_SIZE];
        rand::thread_rng().fill(&mut key);
        PrgSeed { key }
    }
}

impl ops::BitXor for &PrgSeed {
    type Output = PrgSeed;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut out = PrgSeed::zero();

        for ((out, left), right) in out.key.iter_mut().zip(&self.key).zip(&rhs.key) {
            *out = left ^ right;
        }

        out
    }
}

pub trait FromRng {
    fn from_rng(&mut self, stream: &mut (impl rand::Rng + rand_core::RngCore));

    fn randomize(&mut self) {
        self.from_rng(&mut rand::thread_rng());
    }
}

#[derive(Clone)]
pub struct PrgStream {
    stream: Aes128Ctr128LE,
}

impl rand::RngCore for PrgStream {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        println!("1) dest {:?}", dest);
        for v in dest.iter() {
            debug_assert_eq!(*v, 0u8);
        }
        // TODO: encrypt
        // let mut rng = thread_rng();

        println!("dest {}", dest.len());
        self.stream.apply_keystream(dest);
        // rng.fill(dest);                    // array fill

        // let mut block = GenericArray::from([0u8; AES_BLOCK_SIZE]);
        // self.stream.encrypt_block(&mut block);

        // let slb = block.as_slice();
        // for i in 0..AES_BLOCK_SIZE {
        //     dest[i] = slb[i];
        // }
        println!("2) dest {:?}", dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub struct PrgOutput {
    pub bits: (bool, bool),
    pub seeds: (PrgSeed, PrgSeed),
}

pub struct ConvertOutput<T: FromRng> {
    pub seed: PrgSeed,
    pub word: Vec<T>,
}

impl FixedKeyPrgStream {
    fn new() -> Self {
        let key = GenericArray::from([0u8; AES_KEY_SIZE]);

        let ctr_init = FixedKeyPrgStream::load(&[0; AES_BLOCK_SIZE]);
        FixedKeyPrgStream {
            aes: Aes128::new(&key),
            ctr: ctr_init,
            buf: [0; AES_BLOCK_SIZE * 8],
            buf_ptr: AES_BLOCK_SIZE,
            have: AES_BLOCK_SIZE,
            count: 0,
        }
    }

    fn set_key(&mut self, key: &[u8; 16]) {
        self.ctr = FixedKeyPrgStream::load(key);
        self.buf_ptr = AES_BLOCK_SIZE;
        self.have = AES_BLOCK_SIZE;
    }

    fn skip_block(&mut self) {
        // Only allow skipping a block on a block boundary.
        debug_assert_eq!(self.have % AES_BLOCK_SIZE, 0);
        debug_assert_eq!(self.buf_ptr, AES_BLOCK_SIZE);
        self.ctr = FixedKeyPrgStream::inc_be(self.ctr);
    }

    fn refill(&mut self) {
        //println!("Refill");
        debug_assert_eq!(self.buf_ptr, AES_BLOCK_SIZE);

        self.have = AES_BLOCK_SIZE;
        self.buf_ptr = 0;

        // Write counter into buffer.
        FixedKeyPrgStream::store(self.ctr, &mut self.buf[0..AES_BLOCK_SIZE]);

        let count_bytes = self.buf;
        let gen = GenericArray::from_mut_slice(&mut self.buf[0..AES_BLOCK_SIZE]);
        self.aes.encrypt_block(gen);

        // Compute:   AES_0000(ctr) XOR ctr
        self.buf
            .iter_mut()
            .zip(count_bytes.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);

        self.ctr = FixedKeyPrgStream::inc_be(self.ctr);
        self.count += AES_BLOCK_SIZE;
    }

    fn refill8(&mut self) {
        self.have = 8 * AES_BLOCK_SIZE;
        self.buf_ptr = 0;

        let block = GenericArray::from([0u8; 16]);
        let mut block8: GenericArray<_, U8> = GenericArray::clone_from_slice(&[block; 8]);

        let mut cnts = [[0u8; AES_BLOCK_SIZE]; 8];
        for i in 0..8 {
            // Write counter into buffer
            FixedKeyPrgStream::store(self.ctr, &mut block8[i]);
            FixedKeyPrgStream::store(self.ctr, &mut cnts[i]);
            self.ctr = FixedKeyPrgStream::inc_be(self.ctr);
        }

        self.aes.encrypt_blocks(&mut block8);

        for i in 0..8 {
            // Compute:   AES_0000(ctr) XOR ctr
            block8[i]
                .iter_mut()
                .zip(cnts[i].iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);
        }

        for i in 0..8 {
            self.buf[i * AES_BLOCK_SIZE..(i + 1) * AES_BLOCK_SIZE].copy_from_slice(&block8[i]);
        }

        self.count += 8 * AES_BLOCK_SIZE;

        //println!("Blocks: {:?}", self.buf[0]);
        //println!("Blocks: {:?}", self.buf[1]);
        //println!("Blocks: {:?}", self.buf[2]);
    }

    // From RustCrypto aesni crate
    #[inline(always)]
    fn inc_be(v: Counter) -> Counter {
        cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                #[allow(clippy::cast_ptr_alignment)]
                unsafe { Counter(_mm_add_epi64(v.0, _mm_set_epi64x(1, 0))) }
            } else {
                let Counter(mut block) = v;

                // NOTE This might produce a different counter than for x86_64. It depends on the
                // endianness of _mm_set_epi64x, which I haven't checked.
                let mut carry = true;
                for byte in block.as_mut_slice().iter_mut().take(8) {
                    (*byte, carry) = (*byte).overflowing_add(u8::from(carry));
                }
                Counter(block)
            }
        }
    }

    #[inline(always)]
    fn store(val: Counter, at: &mut [u8]) {
        debug_assert_eq!(at.len(), AES_BLOCK_SIZE);

        cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                #[allow(clippy::cast_ptr_alignment)]
                unsafe { _mm_storeu_si128(at.as_mut_ptr() as *mut __m128i, val.0); }
            } else {
                at.copy_from_slice(&val.0)
            }
        }
    }

    // Modified from RustCrypto aesni crate
    #[inline(always)]
    fn load(key: &[u8; 16]) -> Counter {
        let val = Block::<Aes128>::from_slice(key);
        cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                // Safety: `loadu` supports unaligned loads
                #[allow(clippy::cast_ptr_alignment)]
                unsafe { Counter(_mm_loadu_si128(val.as_ptr() as *const __m128i)) }
            } else {
                Counter(val.to_owned())
            }
        }
    }
}

impl rand::RngCore for FixedKeyPrgStream {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut dest_ptr = 0;
        while dest_ptr < dest.len() {
            if self.buf_ptr == self.have {
                if dest.len() > 4 * AES_BLOCK_SIZE {
                    self.refill8();
                //self.refill();
                } else {
                    self.refill();
                }
            }

            let to_copy = std::cmp::min(self.have - self.buf_ptr, dest.len() - dest_ptr);
            dest[dest_ptr..dest_ptr + to_copy]
                .copy_from_slice(&self.buf[self.buf_ptr..self.buf_ptr + to_copy]);

            self.buf_ptr += to_copy;
            dest_ptr += to_copy;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
