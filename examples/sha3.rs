use tiny_keccak::{Hasher, Sha3};

fn main() {
    let mut sha3 = Sha3::v256();
    let mut res: [u8; 32] = [0; 32];

    sha3.update(b"hello");
    sha3.update(b" ");
    sha3.update(b"world");
    sha3.finalize(&mut res);

    let expected = &[
        0x64, 0x4b, 0xcc, 0x7e, 0x56, 0x43, 0x73, 0x04, 0x09, 0x99, 0xaa, 0xc8, 0x9e, 0x76, 0x22,
        0xf3, 0xca, 0x71, 0xfb, 0xa1, 0xd9, 0x72, 0xfd, 0x94, 0xa3, 0x1c, 0x3b, 0xfb, 0xf2, 0x4e,
        0x39, 0x38,
    ];

    assert_eq!(expected, &res);
}