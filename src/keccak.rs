use crunchy::unroll;
use super::{KeccakFamily, Permutation, Buffer};

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

/// keccak-f[1600, 24]
keccak_function!(keccakf, ROUNDS, RC);

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

pub(crate) struct Normal;

impl Permutation for Normal {
    #[inline]
    fn execute(buffer: &mut Buffer) {
        keccakf(buffer.words());
    }
}

/// shake, keccak and sha3 implementation.
///
/// ```rust
/// use tiny_keccak::Keccak;
///
/// fn main() {
///     let mut sha3 = Keccak::new_sha3_256();
///
///     sha3.update("hello".as_ref());
///     sha3.update(&[b' ']);
///     sha3.update("world".as_ref());
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
#[derive(Clone)]
pub struct Keccak {
    state: KeccakFamily<Normal>
}

impl Keccak {
    pub fn new(rate: usize, delim: u8) -> Keccak {
        Keccak {
            state: KeccakFamily::new(rate, delim),
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
        self.state.update(input);
    }

    #[deprecated(
        since = "1.5.0",
        note = "Please use the update function instead"
    )]
    pub fn absorb(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    pub fn keccakf(&mut self) {
        self.state.keccakf()
    }

    pub fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }

    pub fn pad(&mut self) {
        self.state.pad();
    }

    pub fn fill_block(&mut self) {
        self.state.keccakf();
        self.state.offset = 0;
    }

    pub fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output);
    }

    #[inline]
    pub fn xof(mut self) -> XofReader {
        self.pad();

        self.keccakf();

        XofReader {
            keccak: self.state,
            offset: 0,
        }
    }
}

pub struct XofReader {
    keccak: KeccakFamily<Normal>,
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

