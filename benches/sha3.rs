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
    let v: Vec<u8> = From::from("hello");
    b.iter(|| {
        let mut res: [u8; 32] = [0; 32];
        let _ = sha3_256(&v, &mut res);
    });
}
