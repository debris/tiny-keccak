//! The `cSHAKE` extendable-output functions defined in [`SP800-185`].
//!
//! [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

use crate::{bits_to_rate, keccakf::KeccakF, left_encode, Hasher, KeccakXof, Xof};

/// The `cSHAKE` extendable-output functions defined in [`SP800-185`].
///
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
#[derive(Clone)]
pub struct CShake {
    state: KeccakXof<KeccakF>,
}

impl CShake {
    const DELIM: u8 = 0x04;

    /// Creates  new [`CShake`] hasher with a security level of 128 bits.
    ///
    /// [`CShake`]: struct.CShake.html
    pub fn v128(name: &[u8], custom_string: &[u8]) -> CShake {
        CShake::new(name, custom_string, 128)
    }

    /// Creates  new [`CShake`] hasher with a security level of 256 bits.
    ///
    /// [`CShake`]: struct.CShake.html
    pub fn v256(name: &[u8], custom_string: &[u8]) -> CShake {
        CShake::new(name, custom_string, 256)
    }

    pub(crate) fn new(name: &[u8], custom_string: &[u8], bits: usize) -> CShake {
        let rate = bits_to_rate(bits);
        let mut state = KeccakXof::new(rate, Self::DELIM);
        state.update(left_encode(rate).value());
        state.update(left_encode(name.len() * 8).value());
        state.update(name);
        state.update(left_encode(custom_string.len() * 8).value());
        state.update(custom_string);
        state.fill_block();
        CShake { state }
    }

    pub(crate) fn fill_block(&mut self) {
        self.state.fill_block();
    }
}

impl Hasher for CShake {
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}

impl Xof for CShake {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output);
    }
}
