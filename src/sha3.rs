use crate::{KeccakFamily, Standard, Hasher};

const SHA3_DELIM: u8 = 0x06;

/// The `SHA3` hash functions defined in [`FIPS-202`].
///
/// [`FIPS-202`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
///
/// # Example
///
/// ```
/// # use tiny_keccak::{Hasher, Sha3};
/// #
/// # fn main() {
/// let mut sha3 = Sha3::v256();
/// let mut output = [0; 32];
/// sha3.update(b"hello world");
/// sha3.finalize(&mut output);
///
/// let expected = [
///     0x64, 0x4b, 0xcc, 0x7e, 0x56, 0x43, 0x73, 0x04,
///     0x09, 0x99, 0xaa, 0xc8, 0x9e, 0x76, 0x22, 0xf3,
///     0xca, 0x71, 0xfb, 0xa1, 0xd9, 0x72, 0xfd, 0x94,
///     0xa3, 0x1c, 0x3b, 0xfb, 0xf2, 0x4e, 0x39, 0x38
/// ];
///
/// assert_eq!(expected, output);
/// # }
/// ```
#[derive(Clone)]
pub struct Sha3 {
    state: KeccakFamily<Standard>,
}

impl Sha3 {
    pub fn v128() -> Sha3 {
        Sha3::new(128)
    }

    pub fn v224() -> Sha3 {
        Sha3::new(224)
    }

    pub fn v256() -> Sha3 {
        Sha3::new(256)
    }

    pub fn v512() -> Sha3 {
        Sha3::new(512)
    }

    fn new(bits: usize) -> Sha3 {
        Sha3 {
            state: KeccakFamily::new(200 - bits / 4, SHA3_DELIM),
        }
    }
}

impl Hasher for Sha3 {
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}
