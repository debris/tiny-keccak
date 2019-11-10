use crate::{left_encode, right_encode, CShake, Hasher, IntoXof, Xof};

#[derive(Clone)]
struct UnfinishedState {
    state: CShake,
    absorbed: usize,
}

struct Suboutout {
    state: [u8; 64],
    size: usize,
}

impl Suboutout {
    fn security(bits: usize) -> Suboutout {
        Suboutout {
            state: [0u8; 64],
            // 128 => 32, 256 => 64
            size: bits / 4,
        }
    }

    #[inline]
    fn as_bytes(&self) -> &[u8] {
        &self.state[..self.size]
    }

    #[inline]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.state[..self.size]
    }
}

/// The `ParallelHash` hash functions defined in [`SP800-185`].
///
/// The purpose of `ParallelHash` is to support the efficient hashing of very long strings, by
/// taking advantage of the parallelism available in modern processors. `ParallelHash` supports the
/// [`128-bit`] and [`256-bit`] security strengths, and also provides variable-length output.
///
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
/// [`128-bit`]: struct.ParallelHash.html#method.v128
/// [`256-bit`]: struct.ParallelHash.html#method.v256
#[derive(Clone)]
pub struct ParallelHash {
    state: CShake,
    block_size: usize,
    bits: usize,
    blocks: usize,
    unfinished: Option<UnfinishedState>,
}

impl ParallelHash {
    pub fn v128(custom_string: &[u8], block_size: usize) -> ParallelHash {
        ParallelHash::new(custom_string, block_size, 128)
    }

    pub fn v256(custom_string: &[u8], block_size: usize) -> ParallelHash {
        ParallelHash::new(custom_string, block_size, 256)
    }

    fn new(custom_string: &[u8], block_size: usize, bits: usize) -> ParallelHash {
        let mut state = CShake::new(b"ParallelHash", custom_string, bits);
        state.update(left_encode(block_size).value());
        ParallelHash {
            state,
            block_size,
            bits,
            blocks: 0,
            unfinished: None,
        }
    }
}

impl Hasher for ParallelHash {
    fn update(&mut self, mut input: &[u8]) {
        if let Some(mut unfinished) = self.unfinished.take() {
            let to_absorb = self.block_size - unfinished.absorbed;
            if input.len() >= to_absorb {
                unfinished.state.update(&input[..to_absorb]);
                input = &input[to_absorb..];

                let mut suboutput = Suboutout::security(self.bits);
                unfinished.state.finalize(suboutput.as_bytes_mut());
                self.state.update(suboutput.as_bytes());
                self.blocks += 1;
            } else {
                unfinished.state.update(input);
                unfinished.absorbed += input.len();
                self.unfinished = Some(unfinished);
                return;
            }
        }

        let bits = self.bits;
        let input_blocks_end = input.len() / self.block_size * self.block_size;
        let input_blocks = &input[..input_blocks_end];
        let input_end = &input[input_blocks_end..];
        let parts = input_blocks.chunks(self.block_size).map(|chunk| {
            let mut state = CShake::new(b"", b"", bits);
            state.update(chunk);
            let mut suboutput = Suboutout::security(bits);
            state.finalize(suboutput.as_bytes_mut());
            suboutput
        });

        for part in parts {
            self.state.update(part.as_bytes());
            self.blocks += 1;
        }

        if !input_end.is_empty() {
            assert!(self.unfinished.is_none());
            let mut state = CShake::new(b"", b"", bits);
            state.update(input_end);
            self.unfinished = Some(UnfinishedState {
                state,
                absorbed: input_end.len(),
            });
        }
    }

    fn finalize(mut self, output: &mut [u8]) {
        if let Some(unfinished) = self.unfinished.take() {
            let mut suboutput = Suboutout::security(self.bits);
            unfinished.state.finalize(suboutput.as_bytes_mut());
            self.state.update(suboutput.as_bytes());
            self.blocks += 1;
        }

        self.state.update(right_encode(self.blocks).value());
        self.state.update(right_encode(output.len() * 8).value());
        self.state.finalize(output);
    }
}

/// The `ParallelHashXOF` extendable-output functions defined in [`SP800-185`].
///
/// It can be created only by using [`ParallelHash::IntoXof`] interface.
///
/// [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
/// [`ParallelHash::IntoXof`]: struct.ParallelHash.html#impl-IntoXof
#[derive(Clone)]
pub struct ParallelHashXof {
    state: CShake,
}

impl IntoXof for ParallelHash {
    type Xof = ParallelHashXof;

    fn into_xof(mut self) -> Self::Xof {
        if let Some(unfinished) = self.unfinished.take() {
            let mut suboutput = Suboutout::security(self.bits);
            unfinished.state.finalize(suboutput.as_bytes_mut());
            self.state.update(suboutput.as_bytes());
            self.blocks += 1;
        }

        self.state.update(right_encode(self.blocks).value());
        self.state.update(right_encode(0).value());

        ParallelHashXof { state: self.state }
    }
}

impl Xof for ParallelHashXof {
    fn squeeze(&mut self, output: &mut [u8]) {
        self.state.squeeze(output);
    }
}
