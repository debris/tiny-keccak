#![feature(test)]

extern crate test;

use test::Bencher;

#[bench]
fn tiny_keccak_sha3_256_input_32_bytes(b: &mut Bencher) {
    use tiny_keccak::{Sha3, Hasher};
    let data = vec![254u8; 32];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut res: [u8; 32] = [0; 32];
        let mut sha3 = Sha3::v256();
        sha3.update(&data);
        sha3.finalize(&mut res);
    });
}

#[bench]
fn tiny_keccak_sha3_256_input_4096_bytes(b: &mut Bencher) {
    use tiny_keccak::{Sha3, Hasher};
    let data = vec![254u8; 4096];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut res: [u8; 32] = [0; 32];
        let mut sha3 = Sha3::v256();
        sha3.update(&data);
        sha3.finalize(&mut res);
    });
}

#[bench]
fn rust_crypto_sha3_256_input_32_bytes(b: &mut Bencher) {
    use sha3::{Digest, Sha3_256};
    let data = vec![254u8; 32];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut sha3 = Sha3_256::default();
        sha3.input(&data);
        sha3.result();
    });
}

#[bench]
fn rust_crypto_sha3_256_input_4096_bytes(b: &mut Bencher) {
    use sha3::{Digest, Sha3_256};
    let data = vec![254u8; 4096];
    b.bytes = data.len() as u64;

    b.iter(|| {
        let mut sha3 = Sha3_256::default();
        sha3.input(&data);
        sha3.result();
    });
}
