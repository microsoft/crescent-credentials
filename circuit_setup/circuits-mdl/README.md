## Circuits for ECDSA 

In the `circuit_setup/circuits-mdl/ecdsa-p256` directory, we have forked the ECDSA-p256 circuit from
```
git clone https://github.com/privacy-scaling-explorations/circom-ecdsa-p256.git
```
HEAD was at 5b916ea when forked. 
some supporting gadgets also come from https://github.com/SleepingShell/circom-pairing
(circom-ecdsa-p256 depends on circom-pairing)

The fork of circom-ecdsa that's in 
[zk passport](https://github.com/zk-passport/openpassport/tree/main/circuits/circuits/utils/circom-ecdsa)
is essentially the same circuit as we're using. 

As in the JWT case, we need to install `circomlib` in `circuits`
```
git clone https://github.com/iden3/circomlib.git
```

## Performance notes

Witness generation is very slow; e.g, 8 minutes on a workstation.  It may be
slow because of th 4MB of precomputed data, since 8 minutes is much slower than
witness generation for circuits that have many more constraints (e.g., a
circuit with 6M constraints takes well under 1 minute)

The slowness is caused by the call to `WebAssembly.compile()`, used to compile
the wasm module. We could investigate caching this, since it's common to every
proof generation operation (hopefully that's easier with Wasmer in Rust).
Compiling the C++ version of Circom's output also takes many minutes, again
probably because of all the precomputed data the circuit relies on.

Another alternative may be to compute the precomputed data on the fly with
Circom functions; if this can be done in a way that is sound.

Our application might also prefer an implementation with a larger number of
constraints, and less precomputed data. 


