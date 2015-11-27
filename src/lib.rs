//! tiny keccak

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
                // is "~" equal rust "!" ?
                a[y + x] = b[x] ^ ((!b[(x + 1) % 5]) & b[(x + 2) % 5]);
            });
        });

        // Iota
        a[0] ^= RC[i];
    }
}

macro_rules! FOR {
    ($st: expr, $l: expr, $s: expr) => {
        let i = 0;
        while i < $l {
            $s;
            i += $st;
        }
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

// TODO: fix absorption!
macro_rules! FOLDP {
    ($i: expr, $l: expr, $f: expr, $rate: expr, $a: expr) => {
        while $l >= $rate {
            $f($a, $i, $rate);
            keccakf_u8($a);
            //$i += $rate;
            //$l -= $rate;
        }
    }
}

const PLEN: usize = 200;

fn hash(input: &[u8], rate: usize, delim: u8, outlen: usize) -> Vec<u8> {

    let inlen = input.len();
    let mut a: [u8; PLEN] = [0; PLEN];
    // Absorb input
    FOLDP!(input, inlen, xorin, rate, &mut a);
    // Xor in DS and pad frame
    a[inlen] ^= delim;
    a[rate - 1] ^= 0x80;
    // Xor in the last block 
    xorin(&mut a, input, inlen);
    // apply keccakf
    keccakf_u8(&mut a);
    // squeeze output
    let mut res = vec![];
    res.reserve(outlen);
    unsafe { res.set_len(outlen); }
    
    {
        let mut res_ref: &mut [u8] = &mut res;
        FOLDP!(res_ref, outlen, setout, rate, &mut a);
    }

    setout(&a, &mut res, outlen);
    res
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

define_sha3!(sha3_224, 224);
define_sha3!(sha3_256, 256);
define_sha3!(sha3_384, 384);
define_sha3!(sha3_512, 512);

#[test]
fn it_works() {

    let v: Vec<u8> = From::from("hello");
    let res = sha3_256(&v, 32);

    let expected = vec![
        0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3,
        0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68, 0x64, 
        0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79,
        0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98, 0xf3, 0x92
    ];
    assert_eq!(res, expected);
}

