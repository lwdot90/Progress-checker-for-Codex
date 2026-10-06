# Linux beta launch

Accepted follow-up scope: publish this plugin to
`lwdot90/Progress-checker-for-Codex`, substitute an isolated Linux sandbox for
an independent-machine recipient trial, and establish the public-directory path.
The original eight delivery requirements remain intact. This follow-up adds
launch requirements; it does not turn implementation claims into verification.

1. **Recipient sandbox trial.** Install the frozen archive without source,
   Rust, host credentials, or host mounts. Qualify discovery, upgrade, and
   removal; then human-approve one exact fixture command, run it through the
   checker, and inspect current verification, source-change staleness, and
   restart retention. All 75 package assertions passed. Approved execution, restart,
   staleness, failure, and update/removal evidence retention passed. This qualifies the stated container environment only.
2. **Public beta delivery.** Depends on recipient trial. Publish reviewed native
   source and a prerelease with the frozen Linux archive, SHA256SUMS, and INSTALL.md.
   Confirm asset bytes match the published checksum and links are usable.
   Published as v0.2.1-dev on 2026-10-06. The archive upload digest
   matches the frozen checksum; installation and qualification guides are attached.
3. **Directory readiness.** Depends on public beta delivery. Resolve official
   local-MCP submission support, provide required publisher metadata and policy
   URLs, and complete the official review process. Directory approval is external
   and remains pending; the beta uses the release installer.

The sandbox uses Fedora 44, Codex 0.160.0, UID 1000, no network, and zero Linux
capabilities. The outer test container allows nested namespaces using
`seccomp=unconfined`, `label=disable`, and `unmask=ALL`; product sandbox and
approval rules are unchanged. This is not a default-container compatibility claim.

These launch outcomes are tracked separately from the original development
checker configuration. No original check definitions or human grants are changed
for publishing. Missing launch evidence must remain explicit.

## Global-install follow-up — 2026-10-06

Added requirements: one user-level installation/update, explicit per-project
activation through conversation, and isolated plans/claims/evidence for multiple
projects. Original delivery requirements and legacy support remain.

Implemented in 0.3.0-dev. Validation: ten MCP unit tests, 75 source-free native
global integration assertions (including shared writer and missing-grant refusal),
and a current passing previously approved synthetic check through the new gateway.
Root checker records three added implementation claims separately from configured
verification. Root check approval remains pending after the explicit plan revision.
Directory submission remains external and pending.
