//! The `Keccak` hash functions.

use core::marker::PhantomData;

use super::{bits_to_rate, keccakf::KeccakF, Hasher, KeccakState, Version, V224, V256, V384, V512};

/// The `Keccak` hash functions defined in [`Keccak SHA3 submission`].
///
/// # Usage
///
/// ```toml
/// [dependencies]
/// tiny-keccak = { version = "2.0.0", features = ["keccak"] }
/// ```
///
/// [`Keccak SHA3 submission`]: https://keccak.team/files/Keccak-submission-3.pdf
#[derive(Clone)]
pub struct Keccak<V: Version> {
    state: KeccakState<KeccakF>,
    _v: PhantomData<V>,
}


impl Keccak<V224> {
    /// Creates  new [`Keccak`] hasher with a security level of 224 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v224() -> Self {
        Keccak::new(224)
    }
}

impl Default for Keccak<V224> {
    fn default() -> Self { Keccak::v224() }
}

impl Keccak<V256> {
    /// Creates  new [`Keccak`] hasher with a security level of 256 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v256() -> Self {
        Keccak::new(256)
    }
}

impl Default for Keccak<V256> {
    fn default() -> Self { Keccak::v256() }
}

impl Keccak<V384> {
    /// Creates  new [`Keccak`] hasher with a security level of 384 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v384() -> Self {
        Keccak::new(384)
    }
}

impl Default for Keccak<V384> {
    fn default() -> Self { Keccak::v384() }
}

impl Keccak<V512> {
    /// Creates  new [`Keccak`] hasher with a security level of 512 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v512() -> Self {
        Keccak::new(512)
    }
}

impl Default for Keccak<V512> {
    fn default() -> Self { Keccak::v512() }
}

impl <V: Version>Keccak<V> {
    const DELIM: u8 = 0x01;

    fn new(bits: usize) -> Self {
        Keccak {
            state: KeccakState::new(bits_to_rate(bits), Self::DELIM),
            _v: PhantomData,
        }
    }
}

impl <V: Version> Hasher for Keccak<V> {
    /// Absorb additional input. Can be called multiple times.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let mut keccak = Keccak::v256();
    /// keccak.update(b"hello");
    /// keccak.update(b" world");
    /// # }
    /// ```
    fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// Pad and squeeze the state to the output.
    ///
    /// # Example
    ///
    /// ```
    /// # use tiny_keccak::{Hasher, Keccak};
    /// #
    /// # fn main() {
    /// # let keccak = Keccak::v256();
    /// # let mut output = [0u8; 32];
    /// keccak.finalize(&mut output);
    /// # }
    /// #
    /// ```
    fn finalize(self, output: &mut [u8]) {
        self.state.finalize(output);
    }
}

/// [`digest::FixedOutput`] implementation allows [`Sha3`] to be used as a [`digest::Digest`]
impl <V: Version> digest::FixedOutput for Keccak<V>
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

impl <V: Version>digest::Update for Keccak<V>{
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.state.update(data.as_ref())
    }
}


impl <V: Version>digest::Reset for Keccak<V>{
    fn reset(&mut self) {
        self.state.reset()
    }
}
