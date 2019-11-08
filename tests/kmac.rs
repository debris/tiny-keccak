use tiny_keccak::{Kmac, Hasher};

#[test]
fn test_kmac128() {
    let key = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F";
    let data = b"\x00\x01\x02\x03";
    let custom = b"";
    let output = b"\xE5\x78\x0B\x0D\x3E\xA6\xF7\xD3\xA4\x29\xC5\x70\x6A\xA4\x3A\x00\xFA\xDB\xD7\xD4\x96\x28\x83\x9E\x31\x87\x24\x3F\x45\x6E\xE1\x4E";

    let mut buf = vec![0; output.len()];
    let mut kmac = Kmac::v128(key, custom);
    kmac.update(data);
    kmac.finalize(&mut buf);
    assert_eq!(buf, output);

    let key = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F";
    let data = b"\x00\x01\x02\x03";
    let custom = b"My Tagged Application";
    let output = b"\x3B\x1F\xBA\x96\x3C\xD8\xB0\xB5\x9E\x8C\x1A\x6D\x71\x88\x8B\x71\x43\x65\x1A\xF8\xBA\x0A\x70\x70\xC0\x97\x9E\x28\x11\x32\x4A\xA5";

    let mut buf = vec![0; output.len()];
    let mut kmac = Kmac::v128(key, custom);
    kmac.update(data);
    kmac.finalize(&mut buf);
    assert_eq!(buf, output);

    let key = b"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F";
    let data = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\
                    \x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\
                    \x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F\
                    \x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\
                    \x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\
                    \xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF\
                    \xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7";
    let custom = b"My Tagged Application";
    let output = b"\x1F\x5B\x4E\x6C\xCA\x02\x20\x9E\x0D\xCB\x5C\xA6\x35\xB8\x9A\x15\xE2\x71\xEC\xC7\x60\x07\x1D\xFD\x80\x5F\xAA\x38\xF9\x72\x92\x30";

    let mut buf = vec![0; output.len()];
    let mut kmac = Kmac::v128(key, custom);
    kmac.update(data);
    kmac.finalize(&mut buf);
    assert_eq!(buf, output);
}