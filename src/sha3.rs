use core::marker::PhantomData;

use crate::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakState, Version, V224, V256, V384, V512};


/// The `SHA3` hash functions defined in [`FIPS-202`].
///
/// [`FIPS-202`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
///
/// # Usage
///
/// ```toml
/// [dependencies]
/// tiny-keccak = { version = "2.0.0", features = ["sha3"] }
/// ```
///
/// # Example
///
/// ```
/// # use tiny_keccak::{Hasher, Sha3};
/// #
/// # fn main() {
/// let input = b"hello world";
/// let mut output = [0; 32];
/// let expected = b"\
///     \x64\x4b\xcc\x7e\x56\x43\x73\x04\x09\x99\xaa\xc8\x9e\x76\x22\xf3\
///     \xca\x71\xfb\xa1\xd9\x72\xfd\x94\xa3\x1c\x3b\xfb\xf2\x4e\x39\x38\
/// ";
/// let mut sha3 = Sha3::v256();
/// sha3.update(input);
/// sha3.finalize(&mut output);
/// assert_eq!(expected, &output);
/// # }
/// ```
#[derive(Clone)]
pub struct Sha3<V: Version> {
    state: KeccakState<KeccakF>,
    _v: PhantomData<V>,
}


impl Sha3<V224> {
    /// Creates  new [`Sha3`] hasher with a security level of 224 bits.
    ///
    /// [`Sha3`]: struct.Sha3.html
    pub fn v224() -> Self {
        Sha3::new(224)
    }
}

impl Default for Sha3<V224> {
    fn default() -> Self { Sha3::v224() }
}

impl Sha3<V256> {
    /// Creates  new [`Sha3`] hasher with a security level of 256 bits.
    ///
    /// [`Sha3`]: struct.Sha3.html
    pub fn v256() -> Self {
        Sha3::new(256)
    }
}

impl Default for Sha3<V256> {
    fn default() -> Self { Sha3::v256() }
}

impl Sha3<V384> {
    /// Creates  new [`Sha3`] hasher with a security level of 384 bits.
    ///
    /// [`Sha3`]: struct.Sha3.html
    pub fn v384() -> Sha3<V384> {
        Sha3::new(384)
    }
}

impl Default for Sha3<V384> {
    fn default() -> Self { Sha3::v384() }
}

impl Sha3<V512> {
    /// Creates  new [`Sha3`] hasher with a security level of 512 bits.
    ///
    /// [`Sha3`]: struct.Sha3.html
    pub fn v512() -> Sha3<V512> {
        Sha3::new(512)
    }
}

impl Default for Sha3<V512> {
    fn default() -> Self { Sha3::v512() }
}

impl <V: Version> Sha3<V> {
    const DELIM: u8 = 0x06;

    fn new(bits: usize) -> Self {
        Self {
            state: KeccakState::new(bits_to_rate(bits), Self::DELIM),
            _v: PhantomData,
        }
    }
}


impl <V: Version>Hasher for Sha3<V> {
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}

/// [`digest::FixedOutput`] implementation allows [`Sha3`] to be used as a [`digest::Digest`]
impl <V: Version> digest::FixedOutput for Sha3<V>
{
    type OutputSize = V;

    fn finalize_into(self, out: &mut digest::generic_array::GenericArray<u8, Self::OutputSize>) {
        self.finalize(out);
    }

    fn finalize_into_reset(&mut self, out: &mut digest::generic_array::GenericArray<u8, Self::OutputSize>) {
        self.clone().finalize(out);
        self.state.reset()
    }
}

impl <V: Version>digest::Update for Sha3<V>{
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.state.update(data.as_ref())
    }
}

impl <V: Version>digest::Reset for Sha3<V>{
    fn reset(&mut self) {
        self.state.reset()
    }
}
