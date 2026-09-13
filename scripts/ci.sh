#!/usr/bin/env bash
# run the ci checks in workflow order.
set -euo pipefail

echo "==> fmt"
cargo fmt --all -- --check

echo "==> clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> test"
cargo test --all-features

echo "==> doc"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

echo "==> package"
CARGO_TARGET_DIR=target/package-check cargo package --allow-dirty

echo "==> verify the shipped corpus"
DIVINATE_DOGFOOD_TARGET=target/dogfood
CARGO_TARGET_DIR="$DIVINATE_DOGFOOD_TARGET" cargo run --quiet --bin divinate -- verify --state dossiers/sbom-diff/repeated/.evidence

echo "==> dogfood configured collection"
CARGO_TARGET_DIR="$DIVINATE_DOGFOOD_TARGET" cargo run --quiet --bin divinate -- collect
CARGO_TARGET_DIR="$DIVINATE_DOGFOOD_TARGET" cargo run --quiet --bin divinate -- verify

echo "==> schemas"
if python3 -c "import jsonschema" >/dev/null 2>&1; then
    python3 scripts/validate-schemas.py
else
    echo "skipped: pip install jsonschema"
fi

echo "==> deny"
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    echo "skipped: cargo install cargo-deny"
fi

echo "==> coverage"
if command -v cargo-llvm-cov >/dev/null 2>&1; then
    cargo llvm-cov --all-features --summary-only --fail-under-lines 70
else
    echo "skipped: cargo install cargo-llvm-cov"
fi

echo "all checks passed"
