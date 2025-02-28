# `ecdsa-pop`: proving knowledge of ECDSA signatures for device binding

This library proves knowledge of ECDSA signatures, specifically signatures on the NIST P256 curve. 
We use a fork of Spartan NIZK instantiated over the curve T-256. This curve forms a chain with P256, so the circuit for scalar multiplication uses no non-native arithmetic. 

Note that this is not a general proof of knowledge of ECDSA signatures, we only
handle the special case when only the signer's public key must be kept secret.
This is useful for device binding in Crescent, when the signatures are fresh
for each use of the credential, and the message that is signed is a public
value (a random challenge from the verifier). 

The ECC gadgets for scalar multiplication are adapted from [Nova](https://github.com/microsoft/Nova/blob/b7f5be7bb5d8cc4a93d1363347359743fa30d161/src/gadgets/ecc.rs#L1)

The gadgets for non-native field arithmetic are from [bellpepper-gadgets](https://github.com/lurk-lab/bellpepper-gadgets/tree/main/crates/emulated).  They were forked to work with an earlier version of bellpepper-core (version 2.0) that is supported by Spartan-t256.

The code in `neptune` is a fork of [Neptune](https://github.com/lurk-lab/neptune) modified to work with bellpepper-core version 2.0.

## Building and running tests 

To run end-to-end and unit tests:

```text
cargo test --release --features print-trace -- --nocapture
```

