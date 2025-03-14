/// Definition of parameters for base field of T256
pub mod fq;
pub use self::fq::*;
/// Definition of parameters for scalar field of T256
pub mod fr;
pub use self::fr::*;

#[cfg(test)]
mod tests;
