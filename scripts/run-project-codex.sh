#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
checker_state_base="${XDG_DATA_HOME:-$HOME/.local/share}/progress-checker"
checker_socket="$(python3 - "$project_root" "$checker_state_base" <<'PY'
import hashlib, os, sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
print(Path(sys.argv[2]) / ('ipc-' + hashlib.sha256(os.fsencode(root)).hexdigest()[:24] + '.sock'))
PY
)"
export PROGRESS_CHECKER_SOCKET="$checker_socket"
checker_market_key="${checker_socket##*/ipc-}"
checker_market_key="${checker_market_key%.sock}"
# This fork launcher attaches its MCP server explicitly; avoid loading a second
# copy of the project's native plugin from a different Codex profile.
checker_native_plugin="progress-checker@progress-local-${checker_market_key:0:12}"
exec "$project_root/scripts/run-prototype.sh" --no-daemon --no-alt-screen \
    --cd "$project_root" \
    -c "plugins.\"$checker_native_plugin\".enabled=false" \
    -c "mcp_servers.progress_checker.command=\"$project_root/.local/checker-target/debug/progress-checker-mcp\"" \
    -c "mcp_servers.progress_checker.args=[\"--root\",\"$project_root\",\"--state-dir\",\"$checker_state_base\"]" "$@"
