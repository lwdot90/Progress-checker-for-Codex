#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/prototype-env.sh"
export CARGO_TARGET_DIR="$PROTOTYPE_ROOT/.local/checker-target"
cd -- "$PROTOTYPE_ROOT"
exec cargo build --locked -p checker-cli --bin progress-checker "$@"
