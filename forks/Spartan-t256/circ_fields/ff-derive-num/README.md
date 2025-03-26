# ff-derive-num

This crate provides a derive macro for [num-traits::Num] and associated traits
for [ff::Field] implementations derived with the [ff-derive] crate.

[num-traits::Num]: https://docs.rs/num-traits
[ff::Field]: https://docs.rs/ff
[ff-derive]: https://docs.rs/ff-derive

## example

```rust
use ff::PrimeField;         // ff should be used with the "derive" feature!
use ff_derive_num::Num;

#[derive(PrimeField,Num)]
#[PrimeFieldModulus = "70386805592835581672624750593"]
#[PrimeFieldGenerator = "17"]
#[PrimeFieldReprEndianness = "little"]
pub struct Ft([u64; 2]);
```

## license

Copyright 2021 Riad S. Wahby

You may choose either the [Apache-2.0] license or the [MIT] license.

Unless you explicitly state otherwise, any contribution you submit will also be dual-licensed.

[Apache-2.0]: https://www.apache.org/licenses/LICENSE-2.0
[MIT]: https://opensource.org/licenses/MIT
