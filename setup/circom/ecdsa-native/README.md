# Native circuits for ECDSA over secp256k1
This folder implements a circom program to verify ECDSA signatures over secp256k1. Crucially, it defines the circuit over the scalar field of secq256k1 and hence can perform base field operations over secp256k1 natively. Here's the number of constraints.

srinath@DESKTOP-94CCMS9:~/gitrepos/NovaResearch/creds/crescent/circom/ecdsa-native$ ./compile.sh
template instances: 17
non-linear constraints: 8471
linear constraints: 1
public inputs: 1
public outputs: 0
private inputs: 0
private outputs: 0
wires: 8460
labels: 18746
Written successfully: build/ecdsa_native.r1cs
Written successfully: build/ecdsa_native.sym
Written successfully: build/ecdsa_native_js/ecdsa_native.wasm
Everything went okay, circom safe

## Circom version
This code assumes that `circom` is run with the base field of `secp256k1` (or the scalar field of `secq256k1`). There is a fork of circom with this support and it can be installed from: [`circom-seq`](https://github.com/DanTehrani/circom-secq) 

## Code lineage
Code in `ecdsa_native.circom` was written by Srinath Setty. Code in `circom-secp256k1` folder comes from the third-party [`spartan-ecdsa`](https://github.com/personaelabs/spartan-ecdsa) project. This code is a library for performing basic elliptic curve operations over the base field of `secp256k1`.