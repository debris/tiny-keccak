use crate::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakXof, Xof, IntoXof};

/// The `SHAKE` extendable-output functions defined in [`FIPS-202`].
///
/// [`FIPS-202`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
#[derive(Clone)]
pub struct Shake {
    state: KeccakXof<KeccakF>,
}

impl Shake {
    const DELIM: u8 = 0x1f;

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

    pub(crate) fn new(bits: usize) -> Shake {
        Shake {
            state: KeccakXof::new(bits_to_rate(bits), Self::DELIM),
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

impl IntoXof for Shake {
    type Xof = Shake;

    fn into_xof(self) -> Shake {
        self
    }
}

impl Xof for Shake {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output)
    }
}
