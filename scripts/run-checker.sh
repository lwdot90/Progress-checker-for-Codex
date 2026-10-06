#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/prototype-env.sh"
checker_binary="$PROTOTYPE_ROOT/.local/checker-target/debug/progress-checker"
if [[ ! -x "$checker_binary" ]]; then
    printf 'Checker binary is not built. Run scripts/build-checker.sh first.\n' >&2
    exit 1
fi
# Preserve the caller's working directory for the default --root . argument.
exec "$checker_binary" "$@"
