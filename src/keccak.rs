//! The `Keccak` hash functions.

use super::{bits_to_rate, Hasher, KeccakFamily, Standard};

const KECCAK_DELIM: u8 = 0x01;

/// The `Keccak` hash functions.
#[derive(Clone)]
pub struct Keccak {
    state: KeccakFamily<Standard>,
}

impl Keccak {
    /// Creates  new [`Keccak`] hasher with a security level of 128 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v128() -> Keccak {
        Keccak::new(128)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 224 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v224() -> Keccak {
        Keccak::new(224)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 256 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v256() -> Keccak {
        Keccak::new(256)
    }

    /// Creates  new [`Keccak`] hasher with a security level of 512 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v512() -> Keccak {
        Keccak::new(512)
    }

    fn new(bits: usize) -> Keccak {
        Keccak {
            state: KeccakFamily::new(bits_to_rate(bits), KECCAK_DELIM),
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
