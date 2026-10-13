# Source candidate 0.5.0-dev

The main branch contains an unreleased source candidate. Native installation still selects the frozen 0.4.0-dev payload; source changes here do not update an installed plugin.

This candidate aligns source and runtime versions, rejects mismatched package binaries, redacts known credential arguments from logs, clarifies command restrictions, and adds a runnable greeting example. It preserves the existing system-executable and sandbox policies. Ubuntu and macOS support remain future work.

## Validation

The candidate compiled successfully. The configured production-fingerprint benchmark passed with current evidence after documentation updates. See [measurements and limitations](FINGERPRINT_PERFORMANCE.md).

The configured full regression suite failed inside the checker sandbox: tests require the host account database and root-owned system executable identities, which the outer sandbox hides. This remains a failed acceptance run.

The developer subsequently ran the complete regression entrypoint in a host terminal and reported its final version, example and architecture checks passing. The entrypoint stops on an earlier failed command, but the full Cargo output was not supplied. [Human-reported diagnostic receipt](receipts/engineering-host-report.json). This is not authenticated checker verification.

Before releasing an installable 0.5 package, resolve the regression acceptance environment and complete package/runtime qualification. No frozen archive, payload commit or release tag was changed.
