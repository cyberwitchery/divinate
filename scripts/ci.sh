#!/usr/bin/env bash
# run the ci checks in workflow order.
set -euo pipefail

skipped=()

skip() {
    echo "skipped: $2"
    skipped+=("$1: $2")
}

# list the skips on every exit path. a failing step keeps its own status, and a
# run that skipped a check fails.
report() {
    local status=$?
    if [ "${#skipped[@]}" -gt 0 ]; then
        echo "not all checks ran, install the missing tools and run again:" >&2
        printf '  %s\n' "${skipped[@]}" >&2
        if [ "$status" -eq 0 ]; then
            status=1
        fi
    fi
    exit "$status"
}
trap report EXIT

echo "==> fmt"
cargo fmt --all -- --check

echo "==> clippy"
cargo clippy --all-targets --all-features -- -D warnings

echo "==> test"
cargo test --all-features

echo "==> msrv"
if rustup toolchain list 2>/dev/null | grep -q '^1\.95'; then
    cargo +1.95 check --all-targets --all-features
else
    skip "msrv" "rustup toolchain install 1.95"
fi

echo "==> doc"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

echo "==> package"
CARGO_TARGET_DIR=target/package-check cargo package --allow-dirty

echo "==> verify the shipped corpus"
DIVINATE_DOGFOOD_TARGET=target/dogfood
CARGO_TARGET_DIR="$DIVINATE_DOGFOOD_TARGET" cargo run --quiet --bin divinate -- verify --state dossiers/sbom-diff/repeated/.evidence

echo "==> dogfood configured collection"
CARGO_TARGET_DIR="$DIVINATE_DOGFOOD_TARGET" cargo build --quiet --bins
export PATH="$PWD/$DIVINATE_DOGFOOD_TARGET/debug:$PATH"
CARGO_TARGET_DIR="$DIVINATE_DOGFOOD_TARGET" cargo run --quiet --bin divinate -- collect
CARGO_TARGET_DIR="$DIVINATE_DOGFOOD_TARGET" cargo run --quiet --bin divinate -- verify

echo "==> schemas"
if python3 -c "import jsonschema" >/dev/null 2>&1; then
    captures="$(mktemp -d)"
    DIVINATE_PACK_PROTOCOL_CAPTURE="$captures" cargo test --quiet --test pack pack_protocol_messages
    python3 scripts/validate-schemas.py "$captures"
    rm -rf "$captures"
else
    skip "schemas" "pip install jsonschema"
fi

echo "==> deny"
if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny check
else
    skip "deny" "cargo install cargo-deny"
fi

echo "==> unsafe budget"
if command -v unsafe-budget >/dev/null 2>&1; then
    unsafe-budget check
else
    skip "unsafe budget" "cargo install unsafe-budget"
fi

echo "==> coverage"
if command -v cargo-llvm-cov >/dev/null 2>&1; then
    cargo llvm-cov --all-features --summary-only --fail-under-lines 70
else
    skip "coverage" "cargo install cargo-llvm-cov"
fi

if [ "${#skipped[@]}" -eq 0 ]; then
    echo "all checks passed"
fi
