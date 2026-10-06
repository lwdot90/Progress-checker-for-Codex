#!/usr/bin/env bash
set -euo pipefail
# Supply --root and --state-dir before this wrapper's implicit serve subcommand.
exec "$(dirname -- "${BASH_SOURCE[0]}")/run-checker.sh" "$@" serve
