#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/prototype-env.sh"
# Upstream terminal tests assert ANSI color bytes even when the caller disables colors.
unset NO_COLOR
cd -- "$PROTOTYPE_ROOT/.local/source/codex/codex-rs"
exec just test -p codex-tui --test-threads "${PROTOTYPE_TEST_THREADS:-2}" "$@"
