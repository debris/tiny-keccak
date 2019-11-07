//! Keccak derived functions specified in [`FIPS-202`]
//!
//! [`FIPS-202`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

use super::{KeccakFamily, Hasher};
use crate::permutation::Standard;

const SHAKE_DELIM: u8 = 0x1f;
const SHA3_DELIM: u8 = 0x06;
const KECCAK_DELIM: u8 = 0x01;

/// `shake`, `keccak` and `sha3` implementation.
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
pub struct Keccak {
    state: KeccakFamily<Standard>,
}

impl Keccak  {
    pub fn v128() -> Keccak {
        Keccak::new(128)
    }

    pub fn v224() -> Keccak {
        Keccak::new(224)
    }

    pub fn v256() -> Keccak {
        Keccak::new(256)
    }

    pub fn v512() -> Keccak {
        Keccak::new(512)
    }

    fn new(bits: usize) -> Keccak {
        Keccak {
            state: KeccakFamily::new(200 - bits / 4, KECCAK_DELIM),
        }
    }
}

impl Hasher for Keccak {
    /// Absorb additional input. Can be called multiple times.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let mut keccak = Keccak::v256();
    /// keccak.update(b"hello");
    /// keccak.update(b" world");
    /// # }
    /// ```
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// Pad and squeeze the state to the output.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let keccak = Keccak::v256();
    /// # let mut output = [0u8; 32];
    /// keccak.finalize(&mut output);
    /// # }
    /// #
    /// ```
    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}

#[derive(Clone)]
pub struct Shake {
    state: KeccakFamily<Standard>,
}

impl Shake {
    pub fn v128() -> Shake {
        Shake::new(128)
    }

    pub fn v256() -> Shake {
        Shake::new(256)
    }

    fn new(bits: usize) -> Shake {
        Shake {
            state: KeccakFamily::new(200 - bits / 4, SHAKE_DELIM),
        }
    }
}

impl Hasher for Shake {
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}

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

