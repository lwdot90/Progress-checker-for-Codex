# Native Windows prebuilt friend trial

The first trial needs **no Rust, Visual Studio, Python, installation or approval**.
A reviewed CI artifact will contain native binaries, source commit, Cargo lock
hash, file checksums and `collect-windows-prebuilt.ps1`. No friend bundle has been
qualified yet. The owner must review the actual artifact before sharing it.

1. Download the artifact supplied by the owner for the exact reviewed source
   commit. Verify its separately supplied ZIP SHA-256, then extract into a new
   local directory. This is a development artifact, not an installer.
2. Read `artifact-manifest.json` and the PowerShell collector. The collector checks
   the three binary hashes before executing **only `--version`**, under a bounded
   kill-on-close Windows Job. It reads no Codex settings, home files, environment
   dumps, checker private state or command logs. Binary/ancestor handles stay
   pinned while hashes are checked and probes run; children receive a fixed
   Windows-system environment. If process/reader retirement cannot be confirmed,
   the collector terminates its PowerShell process before reusing handles.
3. From that extracted directory, run in ordinary PowerShell:

   ```powershell
   .\collect-windows-prebuilt.ps1
   ```

   Do not disable execution policy globally. If your organization's policy blocks
   the reviewed script, report that result to the owner.
4. Review `windows-diagnostics.json` and send only that file to the owner. It
   contains the exact source commit, Cargo lock hash, OS version/architecture and
   bounded binary version/hash results. Failures withhold arbitrary executable
   output and local error paths.

Expected blocked capabilities are project activation, qualified human approval,
native sandbox execution and installation/update. This trial does not invoke
those capabilities, create a tracked project, start a service or run tests/checks.
A successful version probe is artifact feedback, not proof of native Windows
runtime support. A later recipient trial needs a qualified backend first.

The source-build alternative remains `scripts/prepare-windows-trial.py`; it has
additional developer-tool prerequisites and is unnecessary for this first trial.

If the collector terminates without producing JSON, report only that outcome.
Do not share crash dumps, Windows error reports or a terminal transcript.
