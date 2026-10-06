#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/prototype-env.sh"
checker_mcp_binary="$PROTOTYPE_ROOT/.local/checker-target/debug/progress-checker-mcp"
if [[ ! -x "$checker_mcp_binary" ]]; then
    printf 'MCP binary is not built. Run scripts/build-service.sh first.\n' >&2
    exit 1
fi
exec "$checker_mcp_binary" "$@"
