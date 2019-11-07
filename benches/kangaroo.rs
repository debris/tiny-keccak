#![feature(test)]

extern crate test;

use test::Bencher;
use tiny_keccak::*;

#[bench]
fn bench_k12(b: &mut Bencher) {
    const BYTES: usize = 32;
    b.bytes = BYTES as u64;

    b.iter(|| {
        let data = [0u8; BYTES];
        let mut result = [0u8; BYTES];
        k12(&[], &data, &mut result);
    });
}
