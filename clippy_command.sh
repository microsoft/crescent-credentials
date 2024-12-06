#!/bin/sh

# Invoke clippy with this command to allow some lints

cargo clippy --tests -- \
    -A clippy::needless_range_loop \
    -A clippy::same_item_push \
    -A clippy::should_implement_trait \
    -A clippy::result_large_err

