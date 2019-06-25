#![feature(test)]

extern crate test;

use tiny_keccak::*;
use test::Bencher;

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
