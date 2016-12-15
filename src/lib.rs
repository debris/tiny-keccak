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

const RHO: [u32; 24] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
                        39, 61, 20, 44];

const PI: [usize; 24] = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14,
                         22, 9, 6, 1];

const RC: [u64; 24] = [1u64,
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
                       0x8000000080008008u64];

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
                  },
                  {
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

fn xorin(dst: &mut [u8], src: &[u8], len: usize) {
    unsafe {
        for i in 0..len {
            *dst.get_unchecked_mut(i) ^= *src.get_unchecked(i);
        }
    }
}

fn setout(src: &[u8], dst: &mut [u8], len: usize) {
    dst[..len].copy_from_slice(&src[..len]);
}

/// Total number of lanes.
const PLEN: usize = 25;

/// Lets cheat borrow checker.
fn as_bytes_slice<'a, 'b>(ints: &'a [u64]) -> &'b [u8] {
    unsafe { ::core::slice::from_raw_parts(ints.as_ptr() as *mut u8, ints.len() * 8) }
}

/// Lets cheat borrow checker... again.
fn as_mut_bytes_slice<'a, 'b>(ints: &'a mut [u64]) -> &'b mut [u8] {
    unsafe { ::core::slice::from_raw_parts_mut(ints.as_mut_ptr() as *mut u8, ints.len() * 8) }
}

/// This structure should be used to create keccak/sha3 hash.
///
/// ```rust
/// extern crate tiny_keccak;
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
    a: [u64; PLEN],
    offset: usize,
    rate: usize,
    delim: u8,
}

impl Clone for Keccak {
    fn clone(&self) -> Self {
        let mut res = Keccak::new(self.rate, self.delim);
        res.a.copy_from_slice(&self.a);
        res.offset = self.offset;
        res
    }
}

macro_rules! impl_constructor {
    ($name: ident, $bits: expr, $delim: expr) => {
        pub fn $name() -> Keccak {
            Keccak::new(200 - $bits/4, $delim)
        }
    }
}

impl Keccak {
    fn new(rate: usize, delim: u8) -> Keccak {
        Keccak {
            a: [0; PLEN],
            offset: 0,
            rate: rate,
            delim: delim,
        }
    }

    impl_constructor!(new_shake128, 128, 0x1f);
    impl_constructor!(new_shake256, 256, 0x1f);
    impl_constructor!(new_keccak224, 224, 0x01);
    impl_constructor!(new_keccak256, 256, 0x01);
    impl_constructor!(new_keccak384, 384, 0x01);
    impl_constructor!(new_keccak512, 512, 0x01);
    impl_constructor!(new_sha3_224, 224, 0x06);
    impl_constructor!(new_sha3_256, 256, 0x06);
    impl_constructor!(new_sha3_384, 384, 0x06);
    impl_constructor!(new_sha3_512, 512, 0x06);

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
        let mut a = as_mut_bytes_slice(&mut self.a);

        let inlen = input.len();
        let mut rate = self.rate - self.offset;

        // first foldp
        let mut ip = 0;
        let mut l = inlen;
        while l >= rate {
            xorin(&mut a[self.offset..], &input[ip..], rate);
            keccakf(&mut self.a);
            ip += rate;
            l -= rate;
            rate = self.rate;
            self.offset = 0;
        }

        // Xor in the last block
        xorin(&mut a[self.offset..], &input[ip..], l);
        self.offset += l;
    }

    pub fn pad(&mut self) {
        let mut a = as_mut_bytes_slice(&mut self.a);

        let offset = self.offset;
        let rate = self.rate;

        unsafe {
            *a.get_unchecked_mut(offset) ^= self.delim;
            *a.get_unchecked_mut(rate - 1) ^= 0x80;
        }
    }

    // squeeze output
    pub fn squeeze(&mut self, output: &mut [u8]) {
        let a = as_bytes_slice(&mut self.a);

        let outlen = output.len();
        let rate = self.rate;

        // second foldp
        let mut op = 0;
        let mut l = outlen;
        while l >= rate {
            setout(&a, &mut output[op..], rate);
            keccakf(&mut self.a);
            op += rate;
            l -= rate;
        }

        setout(&a, &mut output[op..], l);
    }
}

/// Simple wrapper around tiny-keccak
pub fn sha3_224(data: &[u8]) -> [u8; 28] {
    let mut sha3 = Keccak::new_sha3_224();
    sha3.update(data);
    let mut res = [0u8; 28];
    sha3.finalize(&mut res);
    res
}
/// Simple wrapper around tiny-keccak
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sha3 = Keccak::new_sha3_256();
    sha3.update(data);
    let mut res = [0u8; 32];
    sha3.finalize(&mut res);
    res
}
/// Simple wrapper around tiny-keccak
pub fn sha3_384(data: &[u8]) -> [u8; 48] {
    let mut sha3 = Keccak::new_sha3_384();
    sha3.update(data);
    let mut res = [0u8; 48];
    sha3.finalize(&mut res);
    res
}

/// Simple wrapper around tiny-keccak
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut sha3 = Keccak::new_sha3_512();
    sha3.update(data);
    let mut res = [0u8; 64];
    sha3.finalize(&mut res);
    res
}
