#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo run --locked -p veil-core --example golden -- crates/veil-core/tests/fixtures
