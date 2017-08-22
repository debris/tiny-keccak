//! should be started with:
//! ```bash
//! multirust run nightly cargo bench
//! ```

#![feature(test)]

extern crate test;
extern crate tiny_keccak;

use tiny_keccak::*;

use test::{Bencher, black_box};

#[bench]
fn bench_sha3_256_input_4096_bytes(b: &mut Bencher) {
    let data = black_box(vec![254u8; 4096]);

    b.iter(|| {
        let mut res: [u8; 32] = [0; 32];
        let mut keccak = Keccak::new_sha3_256();
        keccak.update(&data);
        keccak.finalize(&mut res);
    });
}

#[bench]
fn bench_sha3_256_input_32_bytes(b: &mut Bencher) {
    let data = black_box(vec![254u8; 32]);

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
    let mut data = black_box([0u64; BYTES]);

    b.iter(|| {
        keccakf(&mut data);
    });
}
