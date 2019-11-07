//! Keccak derived functions specified in [`FIPS-202`] and [`SP800-185`]
//!
//! # Example
//!
//! ```
//! ```
//!
//! # Credits
//!
//! `tiny-keccak` was heavily inspsired by the following libraries:
//!
//! - [`keccak-tiny`]
//! - [`GoKangarooTwelve`]
//! - [`quininer/sp800-185`]
//!
//! License: [`CC0`], attribution kindly requested. Blame taken too,
//! but not liability.
//!
//! [`FIPS-202`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//! [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//! [`keccak-tiny`]: https://github.com/coruus/keccak-tiny
//! [`GoKangarooTwelve`]: https://github.com/mimoo/GoKangarooTwelve
//! [`quininer/sp800-185`]: https://github.com/quininer/sp800-185
//! [`CC0`]: https://github.com/debris/tiny-keccak/blob/master/LICENSE

#![no_std]

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const WORDS: usize = 25;

macro_rules! keccak_function {
    ($name: ident, $rounds: expr, $rc: expr) => {
        #[allow(unused_assignments)]
        #[allow(non_upper_case_globals)]
        pub fn $name(a: &mut [u64; $crate::WORDS]) {
            use crunchy::unroll;

            for i in 0..$rounds {
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
                        array[0] = a[$crate::PI[x]];
                        a[$crate::PI[x]] = last.rotate_left($crate::RHO[x]);
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
                a[0] ^= $rc[i];
            }
        }

    }
}

#[cfg(feature = "k12")]
mod k12;

#[cfg(feature = "k12")]
pub use k12::KangarooTwelve;

#[cfg(feature = "fips202")]
mod fips202;

#[cfg(feature = "fips202")]
pub use fips202::*;

#[cfg(feature = "sp800")]
mod sp800;

#[cfg(feature = "sp800")]
pub use sp800::*;

pub trait Hasher: Clone {
    /// Absorb additional input. Can be called multiple times.
    fn update(&mut self, input: &[u8]);

    /// Pad and squeeze the state to the output.
    fn finalize(self, output: &mut [u8]);
}

pub trait XofReader {
    fn squeeze(&mut self, output: &mut [u8]);
}

/// Extendable output function.
struct GenericXofReader<P> {
    state: KeccakFamily<P>,
    offset: usize,
}

impl<P: Permutation> XofReader for GenericXofReader<P> {
    fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.state.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.state.buffer.setout(&mut output[op..], offset, rate);
            self.state.keccakf();
            op += rate;
            l -= rate;
            rate = self.state.rate;
            offset = 0;
        }

        self.state.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }
}

struct EncodedLen {
    offset: usize,
    buffer: [u8; 9],
}

impl EncodedLen {
    fn value(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }
}

#[derive(Default, Clone)]
struct Buffer([u64; WORDS]);

impl Buffer {
    fn words(&mut self) -> &mut [u64; WORDS] {
        &mut self.0
    }

    #[cfg(target_endian = "little")]
    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
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
        let buffer: &mut [u8; WORDS * 8] = unsafe { core::mem::transmute(&mut self.0) };
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

struct KeccakFamily<P> {
    buffer: Buffer,
    offset: usize,
    rate: usize,
    delim: u8,
    permutation: core::marker::PhantomData<P>,
}

impl <P> Clone for KeccakFamily<P> {
    fn clone(&self) -> Self {
        KeccakFamily {
            buffer: self.buffer.clone(),
            offset: self.offset,
            rate: self.rate,
            delim: self.delim,
            permutation: core::marker::PhantomData,
        }
    }
}

impl <P: Permutation> KeccakFamily<P> {
    fn new(rate: usize, delim: u8) -> Self {
        assert!(rate != 0, "rate cannot be equal 0");
        KeccakFamily {
            buffer: Buffer::default(),
            offset: 0,
            rate,
            delim,
            permutation: core::marker::PhantomData,
        }
    }

    fn keccakf(&mut self) {
        P::execute(&mut self.buffer);
    }

    fn update(&mut self, input: &[u8]) {
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

    fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
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

    fn finalize(mut self, output: &mut [u8]) {
        self.pad();

        // apply keccakf
        self.keccakf();

        // squeeze output
        self.squeeze(output);
    }

    fn fill_block(&mut self) {
        self.keccakf();
        self.offset = 0;
    }
}

trait Permutation {
    fn execute(a: &mut Buffer);
}

mod permutation {
    #[cfg(any(
            feature = "keccak", feature = "shake", feature = "sha3",
            feature = "cshake", feature = "kmac", feature = "tuple_hash"
    ))]
    pub struct Standard;

    #[cfg(any(
            feature = "keccak", feature = "shake", feature = "sha3",
            feature = "cshake", feature = "kmac", feature = "tuple_hash"
    ))]
    impl crate::Permutation for Standard {
        fn execute(buffer: &mut crate::Buffer) {
            const ROUNDS: usize = 24;

            const RC: [u64; ROUNDS] = [
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

            // keccak-f[1600, 24]
            keccak_function!(keccakf, ROUNDS, RC);

            keccakf(buffer.words());
        }
    }
}
