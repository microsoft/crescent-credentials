#!/bin/sh

# Invoke clippy with this command to allow some lints

RUSTFLAGS="--deny warnings" cargo clippy --release --tests -- \
    -A clippy::needless_range_loop \
    -A clippy::same_item_push \
    -A clippy::should_implement_trait \
    -A clippy::result_large_err

