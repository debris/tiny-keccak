use tiny_keccak::*;

#[test]
fn empty_keccak() {
    let keccak = Keccak::new_keccak256();
    let mut res: [u8; 32] = [0; 32];
    keccak.finalize(&mut res);

    let expected = vec![
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    let ref_ex: &[u8] = &expected;
    assert_eq!(&res, ref_ex);
}

#[test]
fn string_keccak_256_overlapping_buffer() {
    let mut in_and_out: [u8; 32] = [0; 32];
    for i in 1..6 {
        in_and_out[i as usize - 1] = i
    }

    let ptr = in_and_out.as_mut_ptr();
    Keccak::keccak256(
        unsafe {
            core::slice::from_raw_parts(ptr, 5) // read a piece from start of in_and_out
        },
        &mut in_and_out, // write over the whole array
    );

    let expected = vec![
        125, 135, 197, 234, 117, 247, 55, 139, 183, 1, 228, 4, 197, 6, 57, 22, 26, 243, 239, 246,
        98, 147, 233, 243, 117, 181, 241, 126, 181, 4, 118, 244,
    ];
    assert_eq!(&in_and_out, &expected.as_ref());

    // Verify using overlapping in/out buffers yields same result as a "normal" hash
    let control_in: [u8; 5] = [1, 2, 3, 4, 5];
    let mut control_out: [u8; 32] = [0; 32];
    Keccak::keccak256(&control_in, &mut control_out);
    assert_eq!(&control_out, &in_and_out);
}

#[test]
fn empty_sha3_256() {
    let sha3 = Keccak::new_sha3_256();
    let mut res: [u8; 32] = [0; 32];
    sha3.finalize(&mut res);

    let expected = vec![
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6,
        0x62, 0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa, 0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8,
        0x43, 0x4a,
    ];

    let ref_ex: &[u8] = &expected;
    assert_eq!(&res, ref_ex);
}

#[test]
fn string_sha3_256() {
    let mut sha3 = Keccak::new_sha3_256();
    let data: Vec<u8> = From::from("hello");
    sha3.update(&data);

    let mut res: [u8; 32] = [0; 32];
    sha3.finalize(&mut res);

    let expected = vec![
        0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3, 0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68,
        0x64, 0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79, 0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98,
        0xf3, 0x92,
    ];

    let ref_ex: &[u8] = &expected;
    assert_eq!(&res, ref_ex);
}

#[test]
fn string_sha3_256_parts() {
    let mut sha3 = Keccak::new_sha3_256();
    let data: Vec<u8> = From::from("hell");
    sha3.update(&data);
    sha3.update(&[b'o']);

    let mut res: [u8; 32] = [0; 32];
    sha3.finalize(&mut res);

    let expected = vec![
        0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3, 0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68,
        0x64, 0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79, 0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98,
        0xf3, 0x92,
    ];

    let ref_ex: &[u8] = &expected;
    assert_eq!(&res, ref_ex);
}

#[test]
fn string_sha3_256_parts5() {
    let mut sha3 = Keccak::new_sha3_256();
    sha3.update(&[b'h']);
    sha3.update(&[b'e']);
    sha3.update(&[b'l']);
    sha3.update(&[b'l']);
    sha3.update(&[b'o']);

    let mut res: [u8; 32] = [0; 32];
    sha3.finalize(&mut res);

    let expected = vec![
        0x33, 0x38, 0xbe, 0x69, 0x4f, 0x50, 0xc5, 0xf3, 0x38, 0x81, 0x49, 0x86, 0xcd, 0xf0, 0x68,
        0x64, 0x53, 0xa8, 0x88, 0xb8, 0x4f, 0x42, 0x4d, 0x79, 0x2a, 0xf4, 0xb9, 0x20, 0x23, 0x98,
        0xf3, 0x92,
    ];

    let ref_ex: &[u8] = &expected;
    assert_eq!(&res, ref_ex);
}

#[test]
fn long_string_sha3_512() {
    let mut sha3 = Keccak::new_sha3_512();
    let data: Vec<u8> = From::from("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");

    sha3.update(&data);
    let mut res: [u8; 64] = [0; 64];
    sha3.finalize(&mut res);

    let expected = vec![
        0xf3, 0x2a, 0x94, 0x23, 0x55, 0x13, 0x51, 0xdf, 0x0a, 0x07, 0xc0, 0xb8, 0xc2, 0x0e, 0xb9,
        0x72, 0x36, 0x7c, 0x39, 0x8d, 0x61, 0x06, 0x60, 0x38, 0xe1, 0x69, 0x86, 0x44, 0x8e, 0xbf,
        0xbc, 0x3d, 0x15, 0xed, 0xe0, 0xed, 0x36, 0x93, 0xe3, 0x90, 0x5e, 0x9a, 0x8c, 0x60, 0x1d,
        0x9d, 0x00, 0x2a, 0x06, 0x85, 0x3b, 0x97, 0x97, 0xef, 0x9a, 0xb1, 0x0c, 0xbd, 0xe1, 0x00,
        0x9c, 0x7d, 0x0f, 0x09,
    ];

    let ref_res: &[u8] = &res;
    let ref_ex: &[u8] = &expected;
    assert_eq!(ref_res, ref_ex);
}

#[test]
fn long_string_sha3_512_parts() {
    let mut sha3 = Keccak::new_sha3_512();
    let data: Vec<u8> = From::from("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ");
    let data2: Vec<u8> = From::from("ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.");

    sha3.update(&data);
    sha3.update(&data2);

    let mut res: [u8; 64] = [0; 64];
    sha3.finalize(&mut res);

    let expected = vec![
        0xf3, 0x2a, 0x94, 0x23, 0x55, 0x13, 0x51, 0xdf, 0x0a, 0x07, 0xc0, 0xb8, 0xc2, 0x0e, 0xb9,
        0x72, 0x36, 0x7c, 0x39, 0x8d, 0x61, 0x06, 0x60, 0x38, 0xe1, 0x69, 0x86, 0x44, 0x8e, 0xbf,
        0xbc, 0x3d, 0x15, 0xed, 0xe0, 0xed, 0x36, 0x93, 0xe3, 0x90, 0x5e, 0x9a, 0x8c, 0x60, 0x1d,
        0x9d, 0x00, 0x2a, 0x06, 0x85, 0x3b, 0x97, 0x97, 0xef, 0x9a, 0xb1, 0x0c, 0xbd, 0xe1, 0x00,
        0x9c, 0x7d, 0x0f, 0x09,
    ];

    let ref_res: &[u8] = &res;
    let ref_ex: &[u8] = &expected;
    assert_eq!(ref_res, ref_ex);
}

#[test]
fn fill_shake() {
    const RATE: usize = 168;
    let mut shake = Keccak::new_shake128();
    shake.update(&[0x42; RATE / 2]);
    let mut shake2 = shake.clone();

    shake.update(&[0; RATE / 2]);
    shake2.fill_block();

    let mut res = [0; 32];
    let mut res2 = [0; 32];

    shake.finalize(&mut res);
    shake2.finalize(&mut res2);

    assert_eq!(res, res2);
}

#[test]
fn shake_xof() {
    let shake = Keccak::new_shake128();
    let mut xof = shake.xof();
    let mut output = [0; 32];

    for _ in 0..16 {
        xof.squeeze(&mut output);
    }

    assert_eq!(
        output,
        [
            0x43, 0xE4, 0x1B, 0x45, 0xA6, 0x53, 0xF2, 0xA5, 0xC4, 0x49, 0x2C, 0x1A, 0xDD, 0x54,
            0x45, 0x12, 0xDD, 0xA2, 0x52, 0x98, 0x33, 0x46, 0x2B, 0x71, 0xA4, 0x1A, 0x45, 0xBE,
            0x97, 0x29, 0x0B, 0x6F
        ]
    );

    let mut shake = Keccak::new_shake128();
    let mut output = [0; 32];

    for _ in 0..10 {
        shake.update(&[0xa3; 20]);
    }

    let mut xof = shake.xof();
    for _ in 0..16 {
        xof.squeeze(&mut output);
    }

    assert_eq!(
        output,
        [
            0x44, 0xC9, 0xFB, 0x35, 0x9F, 0xD5, 0x6A, 0xC0, 0xA9, 0xA7, 0x5A, 0x74, 0x3C, 0xFF,
            0x68, 0x62, 0xF1, 0x7D, 0x72, 0x59, 0xAB, 0x07, 0x52, 0x16, 0xC0, 0x69, 0x95, 0x11,
            0x64, 0x3B, 0x64, 0x39
        ]
    );
}
