# bellpepper-emulated

### ---
02/23/2025 (gregz): Forked from [public bellpepper-gadgets repo](https://github.com/lurk-lab/bellpepper-gadgets)
when head was at 2f90c6b90402128dd06b44d5d7f4cf1d9785a1ed.  The reason to fork was to be able to access internal sturctures of `EmulatedFieldElement` in order to convert from `AllocatedNum`.  Also had to change some instanced of `alloc_infalliable` so that the emulated gadgets work with an older version of `bellpepper-core`.
### ---

Nonnative arithmetic library using [bellpepper](https://github.com/argumentcomputer/bellpepper) inspired by the [emulated](https://github.com/Consensys/gnark/tree/master/std/math/emulated) package in [Gnark](https://github.com/Consensys/gnark)

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.