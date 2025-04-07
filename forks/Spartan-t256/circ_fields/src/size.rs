//! Heap Size helpers for use with [datasize].

use num_bigint::BigInt;

/// Measure memory footprint of an integer
pub fn estimate_heap_size_integer(i: &BigInt) -> usize {
    // a guess
    (i.bits() as usize + 7) / 8
}
