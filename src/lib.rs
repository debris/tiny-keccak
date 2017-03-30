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
//! and this to your crate root:
//!
//! ```rust
//! extern crate tiny_keccak;
//! ```
//!
//! Original implemntation in C:
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

use typenum::uint::Unsigned;
use typenum::consts;

extern crate typenum;

const RHO: [u32; 24] = [
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
];

const PI: [usize; 24] = [
    10,  7, 11, 17, 18, 3,
     5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9,  6, 1
];

const RC: [u64; 24] = [
    1u64, 0x8082u64, 0x800000000000808au64, 0x8000000080008000u64,
    0x808bu64, 0x80000001u64, 0x8000000080008081u64, 0x8000000000008009u64,
    0x8au64, 0x88u64, 0x80008009u64, 0x8000000au64,
    0x8000808bu64, 0x800000000000008bu64, 0x8000000000008089u64, 0x8000000000008003u64,
    0x8000000000008002u64, 0x8000000000000080u64, 0x800au64, 0x800000008000000au64,
    0x8000000080008081u64, 0x8000000000008080u64, 0x80000001u64, 0x8000000080008008u64
];

macro_rules! REPEAT4 {
    ($e: expr) => ( $e; $e; $e; $e; )
}

macro_rules! REPEAT5 {
    ($e: expr) => ( $e; $e; $e; $e; $e; )
}

macro_rules! REPEAT6 {
    ($e: expr) => ( $e; $e; $e; $e; $e; $e; )
}

macro_rules! REPEAT24 {
    ($e: expr, $s: expr) => (
        REPEAT6!({ $e; $s; });
        REPEAT6!({ $e; $s; });
        REPEAT6!({ $e; $s; });
        REPEAT5!({ $e; $s; });
        $e;
    )
}

macro_rules! FOR5 {
    ($v: expr, $s: expr, $e: expr) => {
        $v = 0;
        REPEAT4!({
            $e;
            $v += $s;
        });
        $e;
    }
}

/// keccak-f[1600]
pub fn keccakf(a: &mut [u64; PLEN]) {
    let mut b: [u64; 5] = [0; 5];
    let mut t: u64;
    let mut x: usize;
    let mut y: usize;

    for i in 0..24 {
        // Theta
        FOR5!(x, 1, {
            b[x] = 0;
            FOR5!(y, 5, {
                b[x] ^= a[x + y];
            });
        });

        FOR5!(x, 1, {
            FOR5!(y, 5, {
                a[y + x] ^= b[(x + 4) % 5] ^ b[(x + 1) % 5].rotate_left(1);
            });
        });

        // Rho and pi
        t = a[1];
        x = 0;
        REPEAT24!({
            b[0] = a[PI[x]];
            a[PI[x]] = t.rotate_left(RHO[x]);
        }, {
            t = b[0];
            x += 1;
        });

        // Chi
        FOR5!(y, 5, {
            FOR5!(x, 1, {
                b[x] = a[y + x];
            });
            FOR5!(x, 1, {
                a[y + x] = b[x] ^ ((!b[(x + 1) % 5]) & (b[(x + 2) % 5]));
            });
        });

        // Iota
        a[0] ^= RC[i];
    }
}

/// Total number of lanes.
const PLEN: usize = 25;

/// This structure should be used to create keccak/sha3 hash.
///
/// ```rust
/// extern crate tiny_keccak;
///
/// fn main() {
///     let mut sha3 = tiny_keccak::new_sha3_256();
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
pub struct Keccak<Rate: Unsigned> {
    a: [u64; PLEN],
    offset: usize,
    delim: u8,
    _marker: ::core::marker::PhantomData<Rate>,
}

impl<Rate: Unsigned> Clone for Keccak<Rate> {
    fn clone(&self) -> Self {
        let mut res = Keccak::new(self.delim);
        res.a.copy_from_slice(&self.a);
        res.offset = self.offset;
        res
    }
}

macro_rules! impl_variant {
    ($name: ident, $alias: ident, $into: ident, $rate: ty, $delim: expr, $size: expr) => {
        /// Create a `$alias` digest.
        pub fn $name() -> Keccak<$rate> {
            Keccak::new($delim)
        }

        /// Apply the `$alias` function, writing the result into the `result` buffer.
        /// Truncates if necessary.
        pub fn $into(data: &[u8], result: &mut [u8]) {
            let mut keccak = $name();
            keccak.update(data);
            keccak.finalize(result);
        }

        /// Apply the `$alias` function, writing the result into
        /// the returned byte array.
        pub fn $alias(data: &[u8]) -> [u8; $size / 8] {
            let mut result = [0u8; $size / 8];
            $into(data, &mut result);
            result
        }
    };
}

// rate = 200 - bits/4;
impl_variant!(new_shake128,  shake128,  shake128_into,  consts::U168, 0x1f, 128);
impl_variant!(new_shake256,  shake256,  shake256_into,  consts::U136, 0x1f, 256);
impl_variant!(new_keccak224, keccak224, keccak224_into, consts::U144, 0x01, 224);
impl_variant!(new_keccak256, keccak256, keccak256_into, consts::U136, 0x01, 256);
impl_variant!(new_keccak384, keccak384, keccak384_into, consts::U104, 0x01, 384);
impl_variant!(new_keccak512, keccak512, keccak512_into, consts::U72,  0x01, 512);
impl_variant!(new_sha3_224,  sha3_224,  sha3_224_into,  consts::U144, 0x06, 224);
impl_variant!(new_sha3_256,  sha3_256,  sha3_256_into,  consts::U136, 0x06, 256);
impl_variant!(new_sha3_384,  sha3_384,  sha3_384_into,  consts::U104, 0x06, 384);
impl_variant!(new_sha3_512,  sha3_512,  sha3_512_into,  consts::U72,  0x06, 512);

impl<Rate: Unsigned> Keccak<Rate> {
    fn new(delim: u8) -> Self {
        if Rate::to_usize() > PLEN * 8 {
            panic!("Rate {} longer than sponge length of {}", Rate::to_usize(), PLEN * 8);
        }

        Keccak {
            a: [0u64; PLEN],
            offset: 0,
            delim: delim,
            _marker: ::core::marker::PhantomData,
        }
    }

    fn a_bytes(&self) -> &[u8; PLEN * 8] {
        unsafe { ::core::mem::transmute(&self.a) }
    }

    fn a_bytes_mut(&mut self) -> &mut [u8; PLEN * 8] {
        unsafe { ::core::mem::transmute(&mut self.a) }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.absorb(input);
    }

    #[inline]
    pub fn keccakf(&mut self) {
        keccakf(&mut self.a);
    }

    pub fn finalize(mut self, output: &mut [u8]) {
        self.pad();

        // apply keccakf
        keccakf(&mut self.a);

        // squeeze output
        self.squeeze(output);
    }

    // Absorb input
    pub fn absorb(&mut self, input: &[u8]) {
        fn xorin(dst: &mut [u8], src: &[u8]) {
            for (d, i) in dst.iter_mut().zip(src) {
                *d ^= *i;
            }
        }

        let inlen = input.len();
        let mut rate = Rate::to_usize() - self.offset;

        //first foldp
        let mut ip = 0;
        let mut l = inlen;
        while l >= rate {
            let offset = self.offset;
            xorin(&mut self.a_bytes_mut()[offset..][..rate], &input[ip..]);
            keccakf(&mut self.a);
            ip += rate;
            l -= rate;
            rate = Rate::to_usize();
            self.offset = 0;
        }

        // Xor in the last block
        let offset = self.offset;
        xorin(&mut self.a_bytes_mut()[offset..][..l], &input[ip..]);
        self.offset += l;
    }

    pub fn pad(&mut self) {
        let offset = self.offset;
        let rate = Rate::to_usize();

        let delim = self.delim;
        let a = self.a_bytes_mut();
        a[offset] ^= delim;
        a[rate - 1] ^= 0x80;
    }

    // squeeze output
    pub fn squeeze(&mut self, output: &mut [u8]) {
        fn setout(src: &[u8], dst: &mut [u8], len: usize) {
            dst[..len].copy_from_slice(&src[..len]);
        }

        let outlen = output.len();
        let rate = Rate::to_usize();

        // second foldp
        let mut op = 0;
        let mut l = outlen;
        while l >= rate {
            setout(self.a_bytes(), &mut output[op..], rate);
            keccakf(&mut self.a);
            op += rate;
            l -= rate;
        }

        setout(self.a_bytes(), &mut output[op..], l);
    }
}
