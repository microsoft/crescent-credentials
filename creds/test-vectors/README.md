This directory contains pre-generated data.  For example, for the `rs256` example token we'll find
```
[4.0K]  rs256                           // Each example token has it's own directory
├── [4.0K]  cache                       // Cached output of the one-time operations that are slow
│   ├── [ 39K]  client_state.bin        // This contains the user's proof, generated once per token
│   └── [580M]  groth16_params.bin      // These are the Groth16 circuit-specific system parameters 
                                        // (common to all users with a particular token type)
├── [ 249]  io_locations.sym            // Encodes the positions of the outputs of the Groth16 circuit
├── [595M]  main_c.r1cs                 // The R1CS instance associated with the Groth16 circuit
├── [6.3M]  main.wasm                   // WASM for witness generation (used by the Groth16 prover)
├── [  36]  prover_aux.json             // Auxiliary info the prover needs to create presentation proofs
├── [ 18K]  prover_inputs.json          // Inputs known to the prover for the Groth16 circuit
└── [ 818]  public_IOs.json             // Public inputs/outputs for the Groth16 circuit
```

After running one of the examples for the first time the cache will be populated.  On subsequent runs it'll be used.

The other data all comes from the code in `crescent/setup`.