//! should be started with:
//! ```bash
//! multirust run nightly cargo bench
//! ```

#![feature(test)]

extern crate test;

use tiny_keccak::*;

use test::Bencher;

#[bench]
fn bench_sha3_256_input_4096_bytes(b: &mut Bencher) {
    let data = vec![254u8; 4096];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut res: [u8; 32] = [0; 32];
        let mut keccak = Keccak::new_sha3_256();
        keccak.update(&data);
        keccak.finalize(&mut res);
    });
}

#[bench]
fn keccakf_u64(b: &mut Bencher) {
    const BYTES: usize = 25;
    b.bytes = BYTES as u64;

    b.iter(|| {
        let mut data = [0u64; BYTES];
        keccakf(&mut data);
    });
}
