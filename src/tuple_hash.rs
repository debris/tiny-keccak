use crate::{Hasher, CShake, left_encode, right_encode};

/// The `TupleHash` extendable-output and hash functions defined in [`SP800-185`].
///
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
#[derive(Clone)]
pub struct TupleHash {
    state: CShake,
}

impl TupleHash {
    pub fn v128(custom_string: &[u8]) -> TupleHash {
        TupleHash::new(custom_string, 128)
    }

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
