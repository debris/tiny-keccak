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
	let data: Vec<u8> = From::from("hello");
	b.iter(|| {
		let mut res: [u8; 32] = [0; 32];
		let mut keccak = Keccak::new_sha3_256();
		keccak.update(&data);
		keccak.finalize(&mut res);
	});
}

#[bench]
fn keccakf_u64(b: &mut Bencher) {
	b.iter(|| {
		let mut data: [u64; 25] = [0; 25];
		keccakf(&mut data);
	});
}
