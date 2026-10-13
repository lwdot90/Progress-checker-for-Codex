# Service architecture assessment

The service earns its place by serializing evidence and approval operations for concurrent sessions. Its cost is real: the installed 0.4 stack currently comprises five processes, including Python launchers/supervision, a Rust MCP adapter and one Rust writer. The next source candidate has not been benchmarked as a complete stack.

## Observed resource cost

A dated idle snapshot on this Fedora x86_64 host recorded **99,232 KiB summed RSS** across the five installed 0.4 processes, about 97 MiB. Shared pages can be counted more than once; this is not unique physical memory, a peak measurement or a cross-platform result. [Public resource snapshot](receipts/service-resources.json) records roles and values. The observation is of the installed release, not the new 0.5 source build.

## What the writer provides

One project writer owns accepted configuration revisions, implementation claims, immutable attempts and evidence. It reconciles source/environment changes and prerequisite status so multiple Codex sessions do not independently declare contradictory progress. The protected local socket lets MCP, status tools and the human CLI consume the same service identity.

The live approval flow obtains a human confirmation through the packaged CLI without stopping the writer. Revision/config/command/executable binding and single-use challenges prevent a plan submission or a read-only MCP request from creating approval. The service also maintains cancellation, restart retention and a single execution queue.

## Real isolation boundary

The writer and Codex run as the **same OS user**; separate processes do not create a separate OS privilege boundary. The runner's bubblewrap namespace isolates configured check execution from the private state outside the mounted worktree. Kernel peer/process/TTY checks protect the approval endpoint and operation identity. Those properties do not stop an unrestricted host process running as the same user from inspecting or modifying files that user can access. An agent with unrestricted shell/filesystem tools is outside that restricted-check boundary. Repository instructions alone are not a security boundary.

Public tool observations and implementation notes are not authenticated checker evidence. The private writer's evidence, exact definitions and current source/environment state remain authoritative for its verification claims.

## Alternatives and decision

| Alternative | Benefit | What it would need to preserve |
|---|---|---|
| Put all state directly in each MCP process | Fewer components for one session | Cross-session locking, cancellation, coherent revision state and human approval coordination still need a shared authority. |
| One Rust global gateway with embedded project service | Remove Python launcher/supervisor overhead | Safe root binding, writer lifetime, portable installation, idle cleanup and failure behavior need a new implementation and qualification. |
| Import CI results only | No local runner | Current local worktree freshness and exact local approval workflow would be different product features. |

Keep one writer for now. The main simplification candidate is consolidating the launcher/supervision stack, not deleting the consistency authority. Measure cold startup, idle lifetime and real-user concurrency before committing to that rewrite. The production fingerprint benchmark separately measures hashing; it must not be presented as total status latency or service-memory performance.
