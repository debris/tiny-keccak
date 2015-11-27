//! An implementation of the FIPS-202-defined SHA-3 
//! and SHAKE functions in 120 cloc (156 lines). 
//! 
//! The `Keccak-f[1600]` permutation is fully unrolled; 
//! it's nearly as fast as the Keccak team's optimized permutation.
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

trait TransmuteToU64 {
    fn transmute_to_u64<'a>(&'a mut self) -> &'a mut [u64];
}

impl TransmuteToU64 for [u8] {

    #[allow(mutable_transmutes)]
    fn transmute_to_u64<'a>(&'a mut self) -> &'a mut [u64] {
        unsafe {
            let p = self.as_mut_ptr();
            std::mem::transmute(std::slice::from_raw_parts(p, self.len() / 8))
        }
    }
}

const RHO: [usize; 24] = [
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

macro_rules! ROL {
    ($x: expr, $s: expr) => ((($x) << $s) | (($x) >> (64 - $s)))
}

macro_rules! REPEAT6 {
    ($e: expr) => ( for _ in 0..6 { $e } )
}

macro_rules! REPEAT5 {
    ($e: expr) => ( for _ in 0..5 { $e } )
}

macro_rules! REPEAT24 {
    ($e: expr) => ( for _ in 0..24 { $e } )
}

macro_rules! FOR5 {
    ($v: expr, $s: expr, $e: expr) => { 
        $v = 0; 
        REPEAT5!({
            $e;
            $v += $s;
        });
    }
}

/// helper function
fn keccakf_u8(a: &mut [u8]) {
    keccakf(a.transmute_to_u64());
}

/// keccak-f[1600]
fn keccakf(a: &mut [u64]) {
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
                a[y + x] ^= b[(x + 4) % 5] ^ ROL!(b[(x + 1) % 5], 1);
            });
        });

        // Rho and pi
        t = a[1]; 
        x = 0;
        REPEAT24!({
            b[0] = a[PI[x]];
            a[PI[x]] = ROL!(t, RHO[x]);
            t = b[0];
            x += 1;
        });

        // Chi
        FOR5!(y, 5, {
            FOR5!(x, 1, {
                b[x] = a[y + x];
            });
            FOR5!(x, 1, {
                a[y + x] = b[x] ^ ((!b[(x + 1) % 5]) & b[(x + 2) % 5]);
            });
        });

        // Iota
        a[0] ^= RC[i];
    }
}

fn xorin(dst: &mut [u8], src: &[u8], len: usize) {
    for i in 0..len {
        dst[i] ^= src[i];
    }
}

fn setout(src: &[u8], dst: &mut [u8], len: usize) {
    for i in 0..len {
        dst[i] = src[i];
    }
}

const PLEN: usize = 200;

fn hash(input: &[u8], rate: usize, delim: u8, outlen: usize) -> Vec<u8> {

    let inlen = input.len();
    let mut a: [u8; PLEN] = [0; PLEN];

    // Absorb input
    {
        //first foldp
        let mut ip = 0;
        let mut l = inlen;
        while l >= rate {
            xorin(&mut a, &input[ip..], rate);
            keccakf_u8(&mut a);
            ip += rate;
            l -= rate;
        }

        // Xor in DS and pad frame
        a[l] ^= delim;
        a[rate - 1] ^= 0x80;
        // Xor in the last block 
        xorin(&mut a, &input[ip..], l);
    }

    // apply keccakf
    keccakf_u8(&mut a);

    let mut out = vec![];
    out.reserve(outlen);
    unsafe { out.set_len(outlen); }
    
    // squeeze output
    {
        // second foldp
        let mut op = 0;
        let mut l = outlen;
        while l >= rate {
            setout(&a, &mut out[op..], rate);
            keccakf_u8(&mut a);
            op += rate;
            l -= rate;
        }

        setout(&a, &mut out[op..], l);
    }

    out
}

macro_rules! define_shake {
    ($name: ident, $bits: expr) => {
        pub fn $name (input: &[u8], outlen: usize) -> Vec<u8> {
            hash(input, 200 - ($bits/4), 0x1f, outlen)
        }
    }
}

macro_rules! define_sha3 {
    ($name: ident, $bits: expr) => {
        pub fn $name (input: &[u8], outlen: usize) -> Vec<u8> {
            if outlen > $bits / 8 {
                panic!();
            }
            hash(input, 200 - ($bits/4), 0x6, outlen)
        }
    }
}

define_shake!(shake_128, 128);
define_shake!(shake_256, 256);

define_sha3!(sha3_224, 224);
define_sha3!(sha3_256, 256);
define_sha3!(sha3_384, 384);
define_sha3!(sha3_512, 512);


#[cfg(test)]
mod tests {
    use sha3_256 as sha3;
    use sha3_512;

    #[test]
    fn empty_input() {
        let res = sha3(&[], 32);

        let expected = vec![
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
        ];

        assert_eq!(res, expected);
    }

    #[test]
    fn plain_string() {
        let v: Vec<u8> = From::from("hello");
        let res = sha3(&v, 32);

        let expected = vec![
            0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3,
            0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68, 0x64, 
            0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79,
            0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98, 0xf3, 0x92
        ];

        assert_eq!(res, expected);
    }

    #[test]
    fn long_input() {
        let v: Vec<u8> = From::from("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");

        let res = sha3_512(&v, 64);

        let expected = vec![
            0xf3, 0x2a, 0x94, 0x23, 0x55, 0x13, 0x51, 0xdf, 
            0x0a, 0x07, 0xc0, 0xb8, 0xc2, 0x0e, 0xb9, 0x72,
            0x36, 0x7c, 0x39, 0x8d, 0x61, 0x06, 0x60, 0x38,
            0xe1, 0x69, 0x86, 0x44, 0x8e, 0xbf, 0xbc, 0x3d,
            0x15, 0xed, 0xe0, 0xed, 0x36, 0x93, 0xe3, 0x90,
            0x5e, 0x9a, 0x8c, 0x60, 0x1d, 0x9d, 0x00, 0x2a,
            0x06, 0x85, 0x3b, 0x97, 0x97, 0xef, 0x9a, 0xb1,
            0x0c, 0xbd, 0xe1, 0x00, 0x9c, 0x7d, 0x0f, 0x09
        ];

        assert_eq!(res, expected);
    }
}



