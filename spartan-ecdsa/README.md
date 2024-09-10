# `spartan-ecdsa`: proving knowledge of ECDSA sigantures with Spartan2

For secp256k1 signatures it uses 8033 constraints, proofs are 6183 bytes (uncompressed), prover time is 242ms verifier time is 43ms (on Greg's workstation, six cores @ 3.6GHz).

## Building and running tests 
Install [`rustup`](https://rustup.rs/) following instructions in the link (we use stable rust).

To run end-to-end and unit tests:

```text
cargo test --release --features print-trace -- --nocapture
```

