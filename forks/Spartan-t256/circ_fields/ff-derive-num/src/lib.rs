// Copyright 2021 Riad S. Wahby <rsw@cs.stanford.edu>
//
// This file is part of ff-derive-num
//
// Licensed under EITHER:
//
// - The Apache License, Version 2.0 (see LICENSE-apache or
//   https://www.apache.org/licenses/LICENSE-2.0).
//
// - The MIT License (see LICENSE-mit or
//   https://opensource.org/licenses/MIT).
//
// This file may not be copied, modified, or distributed
// except according to the terms of ONE of these licenses,
// at your discretion.
#![deny(missing_docs)]

/*! Derive ::num_traits::Num and associated traits for ::ff::Field types derived using ::ff_derive

# example

```rust
use ff::PrimeField;         // ff should be used with the "derive" feature!
use ff_derive_num::Num;

#[derive(PrimeField,Num)]
#[PrimeFieldModulus = "70386805592835581672624750593"]
#[PrimeFieldGenerator = "17"]
#[PrimeFieldReprEndianness = "little"]
pub struct Ft([u64; 2]);
```
*/

use quote::quote;
use syn::DeriveInput;

/// Proc macro for Num derivation
#[proc_macro_derive(Num)]
pub fn num_traits_num(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let ident = ast.ident;
    let mut toks = proc_macro2::TokenStream::new();
    toks.extend(quote! {
        impl ::num_traits::Num for #ident {
            type FromStrRadixErr = ::std::num::ParseIntError;

            fn from_str_radix(s: &str, r: u32)-> Result<Self, Self::FromStrRadixErr> {
                if s.is_empty() {
                    // hack
                    return Err(u32::from_str_radix(s, r).err().unwrap());
                }

                if s == "0" {
                    return Ok(<Self as ::ff::Field>::ZERO);
                }

                let mut res = <Self as ::ff::Field>::ZERO;
                let radix = Self::from(r as u64);
                let mut first_digit = true;
                for c in s.chars() {
                    match c.to_digit(r) {
                        Some(c) => {
                            if first_digit {
                                if c == 0 {
                                    return Err(u32::from_str_radix("3", 2).err().unwrap());
                                }
                                first_digit = false;
                            }

                            res *= &radix;
                            res += Self::from(c as u64);
                        }
                        None => {
                            return Err(u32::from_str_radix("3", 2).err().unwrap());
                        }
                    }
                }
                Ok(res)
            }
        }

        impl ::num_traits::Zero for #ident {
            fn zero() -> Self {
                <Self as ::ff::Field>::ZERO
            }

            fn is_zero(&self) -> bool {
                bool::from(<Self as ::ff::Field>::is_zero(self))
            }
        }

        impl ::num_traits::One for #ident {
            fn one() -> Self {
                <Self as ::ff::Field>::ONE
            }

            fn is_one(&self) -> bool {
                self == &<Self as ::ff::Field>::ONE
            }
        }

        #[allow(clippy::suspicious_arithmetic_impl)]
        impl ::std::ops::Div<#ident> for #ident {
            type Output = Self;

            #[must_use]
            fn div(self, rhs: Self) -> Self {
                use ::ff::Field;
                self * <Self as ::ff::Field>::invert(&rhs).unwrap()
            }
        }

        #[allow(clippy::suspicious_arithmetic_impl)]
        impl ::std::ops::Div<&#ident> for #ident {
            type Output = Self;

            fn div(self, rhs: &Self) -> Self {
                self * <Self as ::ff::Field>::invert(rhs).unwrap()
            }
        }

        impl ::std::ops::Rem<#ident> for #ident {
            type Output = Self;

            #[must_use]
            fn rem(self, rhs: Self) -> Self {
                if bool::from(<Self as ::ff::Field>::is_zero(&self)) {
                    panic!("divide by zero");
                }

                <Self as ::ff::Field>::ZERO
            }
        }

        impl ::std::ops::Rem<&#ident> for #ident {
            type Output = Self;

            #[must_use]
            fn rem(self, rhs: &Self) -> Self {
                if bool::from(<Self as ::ff::Field>::is_zero(&self)) {
                    panic!("divide by zero");
                }

                <Self as ::ff::Field>::ZERO
            }
        }

        impl ::num_traits::ops::mul_add::MulAdd for #ident {
            type Output = Self;

            fn mul_add(mut self, a: Self, b: Self) -> Self {
                self *= &a;
                self += &b;
                self
            }
        }

        impl ::num_traits::ops::mul_add::MulAdd<&#ident, &#ident> for #ident {
            type Output = Self;

            fn mul_add(mut self, a: &Self, b: &Self) -> Self {
                self *= a;
                self += b;
                self
            }
        }
    });

    toks.into()
}
