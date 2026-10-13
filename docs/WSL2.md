# Windows through WSL2

Status: qualification scaffold only. Progress Checker is **not yet qualified on WSL2**. Native Windows is a separate implementation and qualification target. The frozen 0.4 release remains unchanged.

WSL2 runs a Linux kernel in a managed virtual machine; WSL1 uses a different architecture. Linux system call compatibility alone does not prove that this checker's sandbox, approvals or process cleanup work. [Microsoft: comparing WSL versions](https://learn.microsoft.com/en-us/windows/wsl/compare-versions).

## Intended first trial

Use a separately qualified Ubuntu Linux package inside WSL2, with Codex and the checker both running inside the same distribution. Confirm `VERSION 2` from a Windows terminal with `wsl --list --verbose`, and retain the Windows build, WSL version, distribution version, kernel and package hashes with the recipient receipt. No Windows-side executable forwarding is part of this candidate.

Put the repository under a Linux path such as `~/projects/example`, rather than `/mnt/c/Users/...`. Microsoft recommends keeping projects in the filesystem used by their tools because cross-filesystem operations affect performance. [Microsoft: WSL interoperability](https://learn.microsoft.com/en-us/windows/dev-environment/wsl-interop).

Windows drive mounts also need a separate correctness assessment for permissions, executable trust, symlinks, filename case and file mutation detection. A path beginning `/mnt/c` is only a warning heuristic; bind mounts and custom mount locations mean the path cannot establish the filesystem's properties. Do not claim drive-mount compatibility from a Linux-filesystem trial.

## Read-only prerequisite observation

Inside the candidate distribution:

```bash
python3 scripts/qualify-wsl.py --project "$PWD"
```

This prints JSON containing kernel hints, distribution metadata, executable ownership and namespace policy files. It runs no subprocesses, starts no containers, creates no namespaces, installs nothing and cannot approve checks. It always reports `not_verified`: WSL kernel markers and permissive sysctls are observations, not passing execution evidence. The report includes local paths; review it before sharing.

## Required release evidence

1. Qualify the underlying Ubuntu release, inventory provider and trusted system executables. Preserve environment freshness and fail closed if dependencies or inventory cannot be established.
2. Install a source-free release into a clean WSL2 distribution. Track an ordinary Linux-filesystem project and inspect the submitted plan.
3. Have the human approve the exact configured command through the packaged CLI in a separate terminal in that distribution. Never feed the confirmation prompt automatically.
4. Execute passing and failing checks through the checker. Verify timeout, cancellation, descendant cleanup, bounded/redacted logs and inability to read private approval/evidence state from the restricted check.
5. Verify source and system-package changes stale evidence, and changed plans invalidate grants. Check shared-writer restart and abrupt client disconnect behavior.
6. Test changed-version update and removal. Record failures without turning off AppArmor or namespace restrictions globally or substituting an unrestricted host command for the sandboxed check.
7. Repeat restart/reconnect after the human shuts down and reopens WSL. Record Windows, WSL and Linux versions separately; a Linux receipt does not qualify native Windows.

Unprivileged namespace availability varies with kernel and distribution policy. Read-only observations cannot establish that bubblewrap will launch with the required restrictions. A blocked sandbox must produce an actionable failure and remain unverified.

No WSL2 test host was available in the current Fedora development session. Ubuntu and WSL2 runtime qualification remain pending; this document does not advertise installation support.
