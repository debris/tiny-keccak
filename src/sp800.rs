//! Keccak derived functions defined in [`SP800-185`].
//!
//! [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

use crate::{Hasher, KeccakFamily, EncodedLen};
use crate::permutation::Standard;

const CSHAKE_DELIM: u8 = 0x04;

fn left_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[1..].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(8);
    buffer[offset - 1] = 9 - offset as u8;

    EncodedLen {
        offset: offset - 1,
        buffer,
    }
}

fn right_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[..8].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(7);
    buffer[8] = 8 - offset as u8;

    EncodedLen {
        offset,
        buffer,
    }
}

#[derive(Clone)]
pub struct CShake {
    state: KeccakFamily<Standard>,
}

impl CShake {
    pub fn v128(name: &[u8], custom_string: &[u8]) -> CShake {
        CShake::new(name, custom_string, 128)
    }

    pub fn v256(name: &[u8], custom_string: &[u8]) -> CShake {
        CShake::new(name, custom_string, 256)
    }

    fn new(name: &[u8], custom_string: &[u8], bits: usize) -> CShake {
        let rate = 200 - bits / 4;
        let mut state = KeccakFamily::new(rate, CSHAKE_DELIM);
        state.update(left_encode(rate).value());
        state.update(left_encode(name.len() * 8).value());
        state.update(name);
        state.update(left_encode(custom_string.len() * 8).value());
        state.update(custom_string);
        state.fill_block();
        CShake {
            state,
        }
    }
}

impl Hasher for CShake {
    fn update(&mut self, input: &[u8]) {
        self.state.update(input)
    }

    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output)
    }
}

#[derive(Clone)]
pub struct KMac {
    state: CShake,
}

impl KMac {
    pub fn v128(key: &[u8], custom_string: &[u8]) -> KMac {
        KMac::new(key, custom_string, 128)
    }

    pub fn v256(key: &[u8], custom_string: &[u8]) -> KMac {
        KMac::new(key, custom_string, 256)
    }

    fn new(key: &[u8], custom_string: &[u8], bits: usize) -> KMac {
        let rate = 200 - bits / 4;
        let mut state = CShake::new(b"KMAC", custom_string, bits);
        state.update(left_encode(rate).value());
        state.update(left_encode(key.len() * 8).value());
        state.update(key);
        state.state.fill_block();
        KMac {
            state,
        }
    }
}

impl Hasher for KMac {
    fn update(&mut self, input: &[u8]) {
        self.state.update(input)
    }

    fn finalize(mut self, output: &mut [u8]) {
	    self.state.update(right_encode(output.len() * 8).value());
        self.state.finalize(output)
    }
}

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

#[cfg(test)]
mod tests {
    use super::{left_encode, right_encode};

    #[test]
    fn test_left_encode() {
        assert_eq!(left_encode(0).value(), &[1, 0]);
        assert_eq!(left_encode(128).value(), &[1, 128]);
        assert_eq!(left_encode(65536).value(), &[3, 1, 0, 0]);
        assert_eq!(left_encode(4096).value(), &[2, 16, 0]);
        assert_eq!(left_encode(18446744073709551615).value(), &[8, 255, 255, 255, 255, 255, 255, 255, 255]);
        assert_eq!(left_encode(54321).value(), &[2, 212, 49]);
    }

    #[test]
    fn test_right_encode() {
        assert_eq!(right_encode(0).value(), &[0, 1]);
        assert_eq!(right_encode(128).value(), &[128, 1]);
        assert_eq!(right_encode(65536).value(), &[1, 0, 0, 3]);
        assert_eq!(right_encode(4096).value(), &[16, 0, 2]);
        assert_eq!(right_encode(18446744073709551615).value(), &[255, 255, 255, 255, 255, 255, 255, 255, 8]);
        assert_eq!(right_encode(54321).value(), &[212, 49, 2]);
    }
}
