#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/prototype-env.sh"
prototype_binary="$PROTOTYPE_ROOT/.local/source/codex/codex-rs/target/debug/codex"
if [[ ! -x "$prototype_binary" ]]; then
    printf 'Prototype binary is not built. Run scripts/build-prototype.sh first.\n' >&2
    exit 1
fi
# Keep prototype login, history, and visibility files apart from the stock CLI.
export CODEX_HOME="${CODEX_HOME:-$PROTOTYPE_ROOT/.local/codex-home}"
mkdir -p -- "$CODEX_HOME"
exec "$prototype_binary" "$@"
