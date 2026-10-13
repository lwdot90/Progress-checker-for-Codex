# Native gateway candidate

This Rust crate is a development candidate. It has not been built or tested and is
not a functioning Windows delivery. It deliberately requires a backend contract
that does not exist yet and therefore fails closed during tracking today.

No arguments selects `%LOCALAPPDATA%\ProgressChecker`; `--state-dir` must be
absolute. `--version` reports the compiled candidate version. Initialization
requires the adjacent plugin manifest version to match. Tool definitions come
from native `progress-checker-mcp.exe --describe-tools`. No project is inferred
from the launch working directory.

Explicit `checker_track_project` latches an absolute canonical root, rejects
plugin/state overlaps, and delegates safe project setup and writer lifecycle to:

```
progress-checker.exe --root ROOT --state-dir STATE track-project --protocol native-gateway-v1
```

The future compiled backend must return success only after Git exact-root
validation, protected state ACL setup, safe create-only initial configuration,
managed instructions preserving user content, and authenticated single-writer
readiness. Receipt JSON must include `protocol: native-gateway-v1`, exact
`canonical_root`, exact `state_directory`, and `writer_ready: true`. This operation
cannot approve or execute checks. Current CLI lacks this subcommand; failure
returns `NATIVE_BACKEND_UNAVAILABLE` rather than starting an unsafe fallback.

After readiness, the gateway starts native MCP with explicit root/state and
forwards calls. Frames, ids and requests are bounded; backend exchanges time out.
Read-only tracking requests are denied. Failed activation cannot rebind the
connection to another root. EOF closes the adapter, not the shared writer.

Remaining review: validate native reparse/ACL/canonicalization semantics,
strict tool argument schemas, cancellation/shutdown process trees,
backend terminal authority, and qualified installation. Root alone builds/tests. The existing Python gateway and frozen plugin payload
are unchanged. Linux can compile this crate and inspect `--version`; normal
startup refuses execution outside native Windows.

`--describe-platform` emits static artifact capability JSON on development hosts;
all native approval/check/qualification fields remain false. It is artifact
inspection, not runtime support evidence. State identity canonicalizes its nearest
existing ancestor without creating storage, rejects dot components and existing
reparse/symlink ancestors, and validates exact canonical activation receipts.
The backend must repeat handle-based identity/ACL verification before any mutation
to close races; gateway preflight is not a security boundary.
