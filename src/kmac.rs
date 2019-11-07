use crate::{Hasher, CShake, left_encode, right_encode};

/// The `KMAC` pseudo-random functions defined in [`SP800-185`].
///
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
#[derive(Clone)]
pub struct Kmac {
    state: CShake,
}

impl Kmac {
    /// Creates  new [`Kmac`] hasher with a security level of 128 bits.
    ///
    /// [`Kmac`]: struct.Kmac.html
    pub fn v128(key: &[u8], custom_string: &[u8]) -> Kmac {
        Kmac::new(key, custom_string, 128)
    }

    /// Creates  new [`Kmac`] hasher with a security level of 256 bits.
    ///
    /// [`Kmac`]: struct.Kmac.html
    pub fn v256(key: &[u8], custom_string: &[u8]) -> Kmac {
        Kmac::new(key, custom_string, 256)
    }

    fn new(key: &[u8], custom_string: &[u8], bits: usize) -> Kmac {
        let rate = 200 - bits / 4;
        let mut state = CShake::new(b"KMAC", custom_string, bits);
        state.update(left_encode(rate).value());
        state.update(left_encode(key.len() * 8).value());
        state.update(key);
        state.fill_block();
        Kmac {
            state,
        }
    }
}

impl Hasher for Kmac {
    fn update(&mut self, input: &[u8]) {
        self.state.update(input)
    }

    fn finalize(mut self, output: &mut [u8]) {
	    self.state.update(right_encode(output.len() * 8).value());
        self.state.finalize(output)
    }
}
