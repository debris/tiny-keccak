//! should be started with:
//! ```bash
//! multirust run nightly cargo bench
//! ```

#![feature(test)]

extern crate test;
extern crate tiny_keccak;

use tiny_keccak::*;

use test::Bencher;

#[bench]
fn bench_sha3_256(b: &mut Bencher) {
    b.iter(|| {
        let v: Vec<u8> = From::from("hello");
        let _ = sha3_256(&v, 32);
    });
}
