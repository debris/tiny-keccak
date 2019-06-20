#![feature(test)]

extern crate test;

use sha3::{Digest, Sha3_256};
use test::Bencher;

#[bench]
fn tiny_keccak_sha3_256_input_32_bytes(b: &mut Bencher) {
    let data = vec![254u8; 32];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut res: [u8; 32] = [0; 32];
        let mut keccak = tiny_keccak::Keccak::new_sha3_256();
        keccak.update(&data);
        keccak.finalize(&mut res);
    });
}

#[bench]
fn tiny_keccak_sha3_256_input_4096_bytes(b: &mut Bencher) {
    let data = vec![254u8; 4096];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut res: [u8; 32] = [0; 32];
        let mut keccak = tiny_keccak::Keccak::new_sha3_256();
        keccak.update(&data);
        keccak.finalize(&mut res);
    });
}

#[bench]
fn rust_crypto_sha3_256_input_32_bytes(b: &mut Bencher) {
    let data = vec![254u8; 32];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut keccak = Sha3_256::default();
        keccak.input(&data);
        keccak.result();
    });
}

#[bench]
fn rust_crypto_sha3_256_input_4096_bytes(b: &mut Bencher) {
    let data = vec![254u8; 4096];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut keccak = Sha3_256::default();
        keccak.input(&data);
        keccak.result();
    });
}
