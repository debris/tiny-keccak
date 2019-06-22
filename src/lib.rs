//! An implementation of the FIPS-202-defined SHA-3 and SHAKE functions.
//!
//! The `Keccak-f[1600]` permutation is fully unrolled; it's nearly as fast
//! as the Keccak team's optimized permutation.
//!
//! ## Building
//!
//! ```bash
//! cargo build
//! ```
//!
//! ## Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! tiny-keccak = "1.0"
//! ```
//!
//! Original implementation in C:
//! https://github.com/coruus/keccak-tiny
//!
//! Implementor: David Leon Gil
//!
//! Port to rust:
//! Marek Kotewicz (marek.kotewicz@gmail.com)
//!
//! License: CC0, attribution kindly requested. Blame taken too,
//! but not liability.

#![no_std]

use crunchy::unroll;

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const RC: [u64; 24] = [
    1u64,
    0x8082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x808bu64,
    0x80000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x8au64,
    0x88u64,
    0x80008009u64,
    0x8000000au64,
    0x8000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x80000001u64,
    0x8000000080008008u64,
];

const RC_KANGAROO: [u64; 12] = [
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
];

/// keccak-f[1600]
#[inline]
pub fn keccakf(a: &mut [u64; PLEN]) {
    keccakf_with_rounds(a, &RC);
}

#[allow(unused_assignments)]
fn keccakf_with_rounds(a: &mut [u64; PLEN], rounds: &[u64]) {
    for round in rounds {
        let mut array: [u64; 5] = [0; 5];

        // Theta
        unroll! {
            for x in 0..5 {
                unroll! {
                    for y_count in 0..5 {
                        let y = y_count * 5;
                        array[x] ^= a[x + y];
                    }
                }
            }
        }

        unroll! {
            for x in 0..5 {
                unroll! {
                    for y_count in 0..5 {
                        let y = y_count * 5;
                        a[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                    }
                }
            }
        }

        // Rho and pi
        let mut last = a[1];
        unroll! {
            for x in 0..24 {
                array[0] = a[PI[x]];
                a[PI[x]] = last.rotate_left(RHO[x]);
                last = array[0];
            }
        }

        // Chi
        unroll! {
            for y_step in 0..5 {
                let y = y_step * 5;

                unroll! {
                    for x in 0..5 {
                        array[x] = a[y + x];
                    }
                }

                unroll! {
                    for x in 0..5 {
                        a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                    }
                }
            }
        };

        // Iota
        a[0] ^= round;
    }
}

/// Total number of lanes.
const PLEN: usize = 25;

#[derive(Default, Clone)]
struct Buffer([u64; PLEN]);

impl Buffer {
    fn inner(&mut self) -> &mut [u64; PLEN] {
        &mut self.0
    }

    #[cfg(target_endian = "little")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        let buffer: &mut [u8; PLEN * 8] = unsafe { ::core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
    }

    #[cfg(target_endian = "big")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        fn swap_endianess(buffer: &mut [u64]) {
            for item in buffer {
                *item = item.swap_bytes();
            }
        }

        let start = offset / 8;
        let end = (offset + len + 7) / 8;
        swap_endianess(&mut self.0[start..end]);
        let buffer: &mut [u8; PLEN * 8] = unsafe { ::core::mem::transmute(&mut self.0) };
        f(&mut buffer[offset..][..len]);
        swap_endianess(&mut self.0[start..end]);
    }

    fn setout(&mut self, dst: &mut [u8], offset: usize, len: usize) {
        self.execute(offset, len, |buffer| dst[..len].copy_from_slice(buffer));
    }

    fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            assert!(dst.len() <= src.len());
            let len = dst.len();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut src_ptr = src.as_ptr();
            for _ in 0..len {
                unsafe {
                    *dst_ptr ^= *src_ptr;
                    src_ptr = src_ptr.offset(1);
                    dst_ptr = dst_ptr.offset(1);
                }
            }
        });
    }

    fn pad(&mut self, offset: usize, delim: u8, rate: usize) {
        self.execute(offset, 1, |buff| buff[0] ^= delim);
        self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);
    }
}

/// This structure should be used to create keccak/sha3 hash.
///
/// ```rust
/// use tiny_keccak::Keccak;
///
/// fn main() {
///     let mut sha3 = Keccak::new_sha3_256();
///     let data: Vec<u8> = From::from("hello");
///     let data2: Vec<u8> = From::from("world");
///
///     sha3.update(&data);
///     sha3.update(&[b' ']);
///     sha3.update(&data2);
///
///     let mut res: [u8; 32] = [0; 32];
///     sha3.finalize(&mut res);
///
///     let expected = vec![
///         0x64, 0x4b, 0xcc, 0x7e, 0x56, 0x43, 0x73, 0x04,
///         0x09, 0x99, 0xaa, 0xc8, 0x9e, 0x76, 0x22, 0xf3,
///         0xca, 0x71, 0xfb, 0xa1, 0xd9, 0x72, 0xfd, 0x94,
///         0xa3, 0x1c, 0x3b, 0xfb, 0xf2, 0x4e, 0x39, 0x38
///     ];
///
///     let ref_ex: &[u8] = &expected;
///     assert_eq!(&res, ref_ex);
/// }
/// ```
pub struct Keccak {
    buffer: Buffer,
    offset: usize,
    rate: usize,
    delim: u8,
    rounds: &'static [u64],
}

impl Clone for Keccak {
    fn clone(&self) -> Self {
        let mut res = Keccak::new_with_rounds(self.rate, self.delim, self.rounds);
        res.buffer = self.buffer.clone();
        res.offset = self.offset;
        res
    }
}

macro_rules! impl_constructor {
    ($name: ident, $alias: ident, $bits: expr, $delim: expr) => {
        pub fn $name() -> Keccak {
            Keccak::new(200 - $bits / 4, $delim)
        }

        pub fn $alias(data: &[u8], result: &mut [u8]) {
            let mut keccak = Keccak::$name();
            keccak.update(data);
            keccak.finalize(result);
        }
    };
}

macro_rules! impl_global_alias {
    ($alias: ident, $size: expr) => {
        pub fn $alias(data: &[u8]) -> [u8; $size / 8] {
            let mut result = [0u8; $size / 8];
            Keccak::$alias(data, &mut result);
            result
        }
    };
}

impl_global_alias!(shake128, 128);
impl_global_alias!(shake256, 256);
impl_global_alias!(keccak224, 224);
impl_global_alias!(keccak256, 256);
impl_global_alias!(keccak384, 384);
impl_global_alias!(keccak512, 512);
impl_global_alias!(sha3_224, 224);
impl_global_alias!(sha3_256, 256);
impl_global_alias!(sha3_384, 384);
impl_global_alias!(sha3_512, 512);

impl Keccak {
    pub fn new(rate: usize, delim: u8) -> Keccak {
        Keccak::new_with_rounds(rate, delim, &RC)
    }

    pub fn new_with_rounds(rate: usize, delim: u8, rounds: &'static [u64]) -> Keccak {
        assert!(rate != 0, "rate cannot be equal 0");
        Keccak {
            buffer: Buffer::default(),
            offset: 0,
            rate,
            delim,
            rounds,
        }
    }

    impl_constructor!(new_shake128, shake128, 128, 0x1f);
    impl_constructor!(new_shake256, shake256, 256, 0x1f);
    impl_constructor!(new_keccak224, keccak224, 224, 0x01);
    impl_constructor!(new_keccak256, keccak256, 256, 0x01);
    impl_constructor!(new_keccak384, keccak384, 384, 0x01);
    impl_constructor!(new_keccak512, keccak512, 512, 0x01);
    impl_constructor!(new_sha3_224, sha3_224, 224, 0x06);
    impl_constructor!(new_sha3_256, sha3_256, 256, 0x06);
    impl_constructor!(new_sha3_384, sha3_384, 384, 0x06);
    impl_constructor!(new_sha3_512, sha3_512, 512, 0x06);

    pub fn update(&mut self, input: &[u8]) {
        self.absorb(input);
    }

    #[inline]
    pub fn keccakf(&mut self) {
        keccakf_with_rounds(self.buffer.inner(), self.rounds);
    }

    pub fn finalize(mut self, output: &mut [u8]) {
        self.pad();

        // apply keccakf
        self.keccakf();

        // squeeze output
        self.squeeze(output);
    }

    // Absorb input
    pub fn absorb(&mut self, input: &[u8]) {
        //first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.xorin(&input[ip..], offset, rate);
            self.keccakf();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        // Xor in the last block
        self.buffer.xorin(&input[ip..], offset, l);
        self.offset = offset + l;
    }

    pub fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    pub fn fill_block(&mut self) {
        self.keccakf();
        self.offset = 0;
    }

    // squeeze output
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        while l >= self.rate {
            self.buffer.setout(&mut output[op..], 0, self.rate);
            self.keccakf();
            op += self.rate;
            l -= self.rate;
        }

        self.buffer.setout(&mut output[op..], 0, l);
    }

    #[inline]
    pub fn xof(mut self) -> XofReader {
        self.pad();

        self.keccakf();

        XofReader {
            keccak: self,
            offset: 0,
        }
    }
}

pub struct XofReader {
    keccak: Keccak,
    offset: usize,
}

impl XofReader {
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.keccak.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.keccak.buffer.setout(&mut output[op..], offset, rate);
            self.keccak.keccakf();
            op += rate;
            l -= rate;
            rate = self.keccak.rate;
            offset = 0;
        }

        self.keccak.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }
}

/// KangarooTwelve's length encoding.
struct EncodedLen {
    offset: usize,
    buffer: [u8; 9],
}

impl EncodedLen {
    fn new(len: usize) -> Self {
        let len_view = len.to_be_bytes();
        let offset = len_view.iter().position(|i| *i != 0).unwrap_or(8);
        let mut buffer = [0u8; 9];
        buffer[..8].copy_from_slice(&len_view);
        buffer[8] = 8 - offset as u8;

        EncodedLen {
            offset,
            buffer,
        }
    }

    fn value(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }
}

pub struct KangarooTwelve<T> {
    state: Keccak,
    current_chunk: Keccak,
    custom_string: Option<T>,
    written: usize,
    chunks: usize,
}

impl<T: AsRef<[u8]>> KangarooTwelve<T> {
    const MAX_CHUNK_SIZE: usize = 8192;

    pub fn new(custom_string: T) -> Self {
        KangarooTwelve {
            state: Keccak::new_with_rounds(168, 0, &RC_KANGAROO),
            current_chunk: Keccak::new_with_rounds(168, 0x0b, &RC_KANGAROO),
            custom_string: Some(custom_string),
            written: 0,
            chunks: 0,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut to_absorb = input;
        while to_absorb.len() > 0 {
            if self.written == Self::MAX_CHUNK_SIZE {
                if self.chunks == 0 {
                    self.state.update(&[0x03, 0, 0, 0, 0, 0, 0, 0]);
                } else {
                    let mut tmp_chunk = [0u8; 32];
                    self.current_chunk.clone().finalize(&mut tmp_chunk);
                    self.state.update(&tmp_chunk);
                    self.current_chunk = Keccak::new_with_rounds(168, 0x0b, &RC_KANGAROO);
                }

                self.written = 0;
                self.chunks += 1;
            }

            let todo = ::core::cmp::min(Self::MAX_CHUNK_SIZE - self.written, to_absorb.len());
            if self.chunks == 0 {
                self.state.update(&to_absorb[..todo]);
            } else {
                self.current_chunk.update(&to_absorb[..todo]);
            }
            self.written += todo;
            to_absorb = &to_absorb[todo..];
        }
    }

    pub fn finalize(mut self, output: &mut [u8]) {
        let custom_string = self.custom_string.take()
            .expect("KangarooTwelve cannot be initialized without custom_string; qed");
        let encoded_len = EncodedLen::new(custom_string.as_ref().len());
        self.update(custom_string.as_ref());
        self.update(encoded_len.value());

        if self.chunks == 0 {
            self.state.delim = 0x07;
        } else {
            let encoded_chunks = EncodedLen::new(self.chunks);
            let mut tmp_chunk = [0u8; 32];
            self.current_chunk.finalize(&mut tmp_chunk);
            self.state.update(&tmp_chunk);
            self.state.update(encoded_chunks.value());
            self.state.update(&[0xff, 0xff]);
            self.state.delim = 0x06;
        }

        self.state.finalize(output);
    }
}
