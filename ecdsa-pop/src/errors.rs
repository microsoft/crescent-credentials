//! This module defines errors returned by the library.
use core::fmt::Debug;
//use neptune::error;
use thiserror::Error;

/// Errors returned by Crescent
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ECDSAError {
  /// Catch-all error
  #[error("Unspecified error")]
  GenericError
}
