#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/prototype-env.sh"
cd -- "$PROTOTYPE_ROOT/.local/source/codex/codex-rs"
exec cargo build --locked -p codex-cli --bin codex "$@"
