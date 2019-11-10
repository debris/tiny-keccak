use crate::{left_encode, right_encode, CShake, Hasher, IntoXof, Xof};

/// The `TupleHash` hash functions defined in [`SP800-185`].
///
/// `TupleHash` is designed to provide a generic, misuse-resistant way to combine a sequence of
/// strings for hashing such that, for example, a `TupleHash` computed on the tuple (`"abc"` ,`"d"`) will
/// produce a different hash value than a `TupleHash` computed on the tuple (`"ab"`,`"cd"`), even though
/// all the remaining input parameters are kept the same, and the two resulting concatenated
/// strings, without string encoding, are identical.
///
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
#[derive(Clone)]
pub struct TupleHash {
    state: CShake,
}

impl TupleHash {
    /// Creates  new [`TupleHash`] hasher with a security level of 128 bits.
    ///
    /// [`TupleHash`]: struct.TupleHash.html
    pub fn v128(custom_string: &[u8]) -> TupleHash {
        TupleHash::new(custom_string, 128)
    }

    /// Creates  new [`TupleHash`] hasher with a security level of 256 bits.
    ///
    /// [`TupleHash`]: struct.TupleHash.html
    pub fn v256(custom_string: &[u8]) -> TupleHash {
        TupleHash::new(custom_string, 256)
    }

    fn new(custom_string: &[u8], bits: usize) -> TupleHash {
        TupleHash {
            state: CShake::new(b"TupleHash", custom_string, bits),
        }
    }
}

impl Hasher for TupleHash {
    fn update(&mut self, input: &[u8]) {
        self.state.update(left_encode(input.len() * 8).value());
        self.state.update(input)
    }

    fn finalize(mut self, output: &mut [u8]) {
        self.state.update(right_encode(output.len() * 8).value());
        self.state.finalize(output)
    }
}

/// The `TupleHashXOF` extendable-output functions defined in [`SP800-185`].
///
/// It can be created only by using [`TupleHash::IntoXof`] interface.
///
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
/// [`TupleHash::IntoXof`]: struct.TupleHash.html#impl-IntoXof
#[derive(Clone)]
pub struct TupleHashXof {
    state: CShake,
}

impl IntoXof for TupleHash {
    type Xof = TupleHashXof;

    fn into_xof(mut self) -> TupleHashXof {
        self.state.update(right_encode(0).value());
        TupleHashXof { state: self.state }
    }
}

impl Xof for TupleHashXof {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output)
    }
}
