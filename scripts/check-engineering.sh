#!/usr/bin/env bash
# Registered acceptance entrypoint: run only after exact human CLI approval.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
source scripts/prototype-env.sh
export CARGO_TARGET_DIR="$PROTOTYPE_ROOT/.local/checker-target"
case "${1:-}" in
  tests)
    cargo test --workspace --offline --locked
    python3 scripts/check-source-version.py
    python3 scripts/check-first-example.py
    python3 scripts/check-engineering-docs.py
    python3 scripts/test-native-packaging.py
    python3 scripts/test-ubuntu-qualification.py
    python3 scripts/test-platform-support.py
    ;;
  benchmark)
    cargo build -p checker-core --example fingerprint-benchmark --offline --locked
    python3 scripts/benchmark-fingerprint.py --binary .local/checker-target/debug/examples/fingerprint-benchmark --output .local/engineering/fingerprint-benchmark.json
    ;;
  *) echo 'Usage: check-engineering.sh {tests|benchmark}' >&2; exit 2 ;;
esac
