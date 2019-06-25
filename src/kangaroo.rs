use crunchy::unroll;
use super::{KeccakFamily, Permutation, Buffer};

const ROUNDS: usize = 12;
const K12_RATE: usize = 168;

const RC: [u64; ROUNDS] = [
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
];

/// keccak-f[1600, 12]
keccak_function!(keccakf, ROUNDS, RC);

struct Reduced;

impl Permutation for Reduced {
    #[inline]
    fn execute(buffer: &mut Buffer) {
        keccakf(buffer.words());
    }
}

/// KangarooTwelve's length encoding.
struct EncodedLen {
    offset: usize,
    buffer: [u8; 9],
}

impl EncodedLen {
    fn new(len: usize) -> Self {
        let len_view = (len as u64).to_be_bytes();
        let offset = len_view.iter().position(|i| *i != 0).unwrap_or(8);
        let mut buffer = [0u8; 9];
        buffer[..8].copy_from_slice(&len_view);
        buffer[8] = 8 - offset as u8;

        EncodedLen {
            offset,
            buffer,
        }
    }

    fn value(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }
}

/// Hashes the data with `KangarooTwelve` hash function using custom string.
pub fn k12(custom_string: &[u8], data: &[u8], result: &mut [u8]) {
    let mut k12 = KangarooTwelve::new(custom_string);
    k12.update(data);
    k12.finalize(result);
}

/// KangarooTwelve implementation.
#[derive(Clone)]
pub struct KangarooTwelve<T> {
    state: KeccakFamily<Reduced>,
    current_chunk: KeccakFamily<Reduced>,
    custom_string: Option<T>,
    written: usize,
    chunks: usize,
}

impl<T: AsRef<[u8]>> KangarooTwelve<T> {
    const MAX_CHUNK_SIZE: usize = 8192;

    pub fn new(custom_string: T) -> Self {
        KangarooTwelve {
            state: KeccakFamily::new(K12_RATE, 0),
            current_chunk: KeccakFamily::new(K12_RATE, 0x0b),
            custom_string: Some(custom_string),
            written: 0,
            chunks: 0,
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        let mut to_absorb = input;
        if self.chunks == 0 {
            let todo = core::cmp::min(Self::MAX_CHUNK_SIZE - self.written, to_absorb.len());
            self.state.update(&to_absorb[..todo]);
            self.written += todo;
            to_absorb = &to_absorb[todo..];

            if to_absorb.len() > 0 && self.written == Self::MAX_CHUNK_SIZE {
                self.state.update(&[0x03, 0, 0, 0, 0, 0, 0, 0]);
                self.written = 0;
                self.chunks += 1;
            }
        }

        while to_absorb.len() > 0 {
            if self.written == Self::MAX_CHUNK_SIZE {
                let mut chunk_hash = [0u8; 32];
                let current_chunk = core::mem::replace(&mut self.current_chunk, KeccakFamily::new(K12_RATE, 0x0b));
                current_chunk.finalize(&mut chunk_hash);
                self.state.update(&chunk_hash);
                self.written = 0;
                self.chunks += 1;
            }

            let todo = core::cmp::min(Self::MAX_CHUNK_SIZE - self.written, to_absorb.len());
            self.current_chunk.update(&to_absorb[..todo]);
            self.written += todo;
            to_absorb = &to_absorb[todo..];
        }
    }

    pub fn finalize(mut self, output: &mut [u8]) {
        let custom_string = self.custom_string.take()
            .expect("KangarooTwelve cannot be initialized without custom_string; qed");
        let encoded_len = EncodedLen::new(custom_string.as_ref().len());
        self.update(custom_string.as_ref());
        self.update(encoded_len.value());

        if self.chunks == 0 {
            self.state.delim = 0x07;
        } else {
            let encoded_chunks = EncodedLen::new(self.chunks);
            let mut tmp_chunk = [0u8; 32];
            self.current_chunk.finalize(&mut tmp_chunk);
            self.state.update(&tmp_chunk);
            self.state.update(encoded_chunks.value());
            self.state.update(&[0xff, 0xff]);
            self.state.delim = 0x06;
        }

        self.state.finalize(output);
    }
}
