use crate::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakXof, Xof};

const SHAKE_DELIM: u8 = 0x1f;

/// The `SHAKE` extendable-output functions defined in [`FIPS-202`].
///
/// [`FIPS-202`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
#[derive(Clone)]
pub struct Shake {
    state: KeccakXof<KeccakF>,
}

impl Shake {
    /// Creates  new [`Shake`] hasher with a security level of 128 bits.
    ///
    /// [`Shake`]: struct.Shake.html
    pub fn v128() -> Shake {
        Shake::new(128)
    }

    /// Creates  new [`Shake`] hasher with a security level of 256 bits.
    ///
    /// [`Shake`]: struct.Shake.html
    pub fn v256() -> Shake {
        Shake::new(256)
    }

    fn new(bits: usize) -> Shake {
        Shake {
            state: KeccakXof::new(bits_to_rate(bits), SHAKE_DELIM),
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

impl Xof for Shake {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output)
    }
}
