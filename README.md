# libkeccak-tiny

An implementation of the FIPS-202-defined SHA-3 and SHAKE functions.

The `Keccak-f[1600]` permutation is fully unrolled; it's nearly as fast
as the Keccak team's optimized permutation.

## Building

```bash
cargo build
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tiny-keccak = "0.3"
```

and this to your crate root:

```rust
extern crate tiny_keccak;
```
