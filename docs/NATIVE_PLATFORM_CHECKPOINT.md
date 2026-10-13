# Native platform checkpoint

Unreleased source checkpoint saved at the owner’s request before battery shutdown. Installed 0.4 and its pinned native marketplace payload are unchanged.

Native Windows means Windows/MSVC, not WSL. Windows, macOS and Ubuntu runtime support is not qualified. New native preparation paths refuse execution pending independent native sandbox, state, identity and human approval qualification.

Workspace cross-target typechecks previously passed Linux, Windows GNU/MSVC and Apple arm64 before the final review fixes; those last fixes still need fresh compilation. Native CI and Windows metadata-only friend bundle are prepared, not yet observed running. No downloadable qualified Windows release is claimed.

Approved checker batch `batch-1791865727973138149-21802-1285`: development suite failed the split UTF-8 credential-redaction boundary fixture. Benchmark and plan checks passed, but source changed during the batch, so evidence is stale. Redaction boundary fix is being reviewed; rerun approved checks before describing success. Full host-sensitive regression acceptance remains unresolved.

Next: finish and rerun the redaction regression, refresh all native typechecks, inspect CI builds, produce and hash a prebuilt Windows diagnostic bundle, then arrange the friend’s native Windows trial. macOS requires a real Mac. Keep full security acceptance separate from the partial development suite.
