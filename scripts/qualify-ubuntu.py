#!/usr/bin/env python3
"""Collect bounded Ubuntu recipient observations, never approval or check evidence."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import subprocess
import stat
import re
import time


def observe(argv):
    """Bound subprocess lifetime and output without shell interpretation."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    except OSError as error:
        return {"argv": argv, "error": str(error)}
    import signal
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for name in captured:
        selector.register(getattr(process, name), selectors.EVENT_READ, name)
    deadline = time.monotonic() + 10
    error = None
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                error = "Observation exceeded ten-second limit"
                break
            for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if len(captured[key.data]) + len(chunk) > 65536:
                    error = "Observation exceeded 64-KiB stream limit"
                    break
                captured[key.data].extend(chunk)
            if error:
                break
    finally:
        selector.close()
        if not error:
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                error = "Observation exceeded ten-second limit"
        if error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=2)
        process.stdout.close()
        process.stderr.close()
    return {"argv": argv, "exit_code": process.returncode, "error": error,
            **{name: {"text": bytes(data).decode("utf-8", "replace")} for name, data in captured.items()}}


def archive_identity(path):
    limit = 256 * 1024 * 1024
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("Archive must be a regular nonsymlink file no larger than 256 MiB")
        size = 0
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError("Archive grew beyond 256 MiB during hashing")
            digest.update(chunk)
        after = os.fstat(source.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if size != before.st_size or any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError("Archive changed during hashing")
    return {"filename": path.name, "size_bytes": size, "sha256": digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-podman", metavar="UBUNTU_IMAGE_DIGEST",
                        help="Write a proposed container build/run recipe; execute nothing")
    parser.add_argument("--artifact-profile", choices=("debug", "release", "unknown"), default="unknown",
                        help="Declared artifact profile; not independently inferred from archive contents")
    parser.add_argument("--apt-sources-file", type=Path,
                        help="Optional reviewed snapshot-pinned deb822 Ubuntu sources for prepared build context")
    args = parser.parse_args()
    if args.apt_sources_file and not args.prepare_podman:
        parser.error("--apt-sources-file applies only to --prepare-podman")
    identity = archive_identity(args.archive)
    if identity["sha256"] != args.sha256:
        parser.error("Archive checksum differs from reviewed artifact")
    if args.prepare_podman:
        image = args.prepare_podman
        if not re.fullmatch(r"(?:docker\.io/library/)?ubuntu@sha256:[a-f0-9]{64}", image):
            parser.error("Use a pinned official Ubuntu image digest, verified as Ubuntu 24.04")
        archive = str(args.archive.absolute())
        harness = str(Path(__file__).resolve())
        output_directory = str(args.output.absolute().parent)
        if Path(output_directory).resolve() in (Path.home().resolve(), Path.cwd().resolve(), Path("/")):
            parser.error("Use a dedicated output directory, not host home, checkout root or filesystem root")
        if any(":" in value or "\n" in value for value in (archive, harness, output_directory)):
            parser.error("Podman mount paths cannot contain colons or newlines")
        apt_sources = None
        if args.apt_sources_file:
            apt_sources = archive_identity(args.apt_sources_file)
            if apt_sources["size_bytes"] > 65536:
                parser.error("Reviewed apt sources must be at most 64 KiB")
            apt_sources["input_path"] = str(args.apt_sources_file.absolute())
            apt_sources["build_context_name"] = "reviewed-ubuntu.sources"
            apt_sources["snapshot_contents_verified"] = False
        apt_copy = "COPY reviewed-ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources\n" if apt_sources else ""
        recipe = {
            "schema_version": 1, "status": "prepared_not_executed",
            "artifact": identity,
            "base_image": image,
            "artifact_profile_declared": args.artifact_profile,
            "artifact_profile_verified": False,
            "apt_sources": apt_sources,
            "reproducible_build_established": False,
            "containerfile": f"FROM {image}\n{apt_copy}RUN apt-get update && apt-get install -y --no-install-recommends python3 git bubblewrap dpkg && rm -rf /var/lib/apt/lists/*\nRUN getent passwd 1000 >/dev/null || useradd --uid 1000 --create-home recipient\nUSER 1000:1000\n",
            "build_argv": ["podman", "build", "--pull=never", "--tag", "localhost/progress-checker-ubuntu-prerequisites", "--file", "REVIEWED_CONTAINERFILE", "EMPTY_BUILD_CONTEXT"],
            "run_argv": ["podman", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                         "--cap-drop=ALL", "--security-opt=no-new-privileges", "--userns=keep-id:uid=1000,gid=1000",
                         "--user=1000:1000", "--pids-limit=64", "--memory=512m", "--cpus=1", "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
                         "--volume", f"{archive}:/inputs/package.tar.gz:ro",
                         "--volume", f"{harness}:/inputs/qualify-ubuntu.py:ro",
                         "--volume", f"{output_directory}:/output:rw,Z",
                         "REVIEWED_BUILT_IMAGE_ID", "/usr/bin/python3", "/inputs/qualify-ubuntu.py",
                         "--archive", "/inputs/package.tar.gz", "--sha256", identity["sha256"],
                         "--artifact-profile", args.artifact_profile,
                         "--output", "/output/ubuntu-prerequisites.json"],
            "approval": "Review and human-approve exact final commands before acceptance execution; this recipe grants nothing",
            "limitations": ["Base digest must independently be verified as Ubuntu 24.04 x86_64",
                            "Optional apt sources are hashed but not semantically verified; without reviewed snapshot sources apt dependencies are unpinned",
                            "Build needs package-network access; recipient observation runtime has no network",
                            "No source checkout or host home is mounted",
                            "No privileged, AppArmor-disable or seccomp-disable flags are supplied",
                            "Read-only inputs are not relabeled; SELinux denial must be addressed with reviewed dedicated input copies",
                            "This recipe observes prerequisites only, not sandbox execution or ordinary-host support"],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x") as destination:
            json.dump(recipe, destination, indent=2)
            destination.write("\n")
        print(f"Prepared only: {args.output}")
        return
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            release[key] = value.strip('"')
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04" or platform.machine() != "x86_64":
        parser.error("This scaffold targets an actual Ubuntu 24.04 x86_64 recipient")
    if os.geteuid() == 0:
        parser.error("Use an ordinary recipient account; root cannot qualify ordinary-user behavior")
    probes = {
        "python": ["/usr/bin/python3", "--version"],
        "git": ["/usr/bin/git", "--version"],
        "bubblewrap": ["/usr/bin/bwrap", "--version"],
        "dpkg_query": ["/usr/bin/dpkg-query", "--version"],
    }
    report = {
        "schema_version": 1,
        "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "incomplete",
        "scope": "recipient prerequisites only; no installation or configured checks executed",
        "platform": {"id": release["ID"], "version": release["VERSION_ID"],
                     "machine": platform.machine(), "kernel": platform.release(), "euid": os.geteuid()},
        "artifact": identity,
        "artifact_profile_declared": args.artifact_profile,
        "artifact_profile_verified": False,
        "observations": {name: observe(argv) for name, argv in probes.items()},
        "required_evidence": {name: "missing" for name in [
            "source_free_install", "native_codex_discovery", "track_project", "human_cli_approval",
            "passing_check", "failing_check", "source_staleness", "environment_staleness",
            "restart", "changed_version_update", "removal", "sandbox_adversarial_checks"]},
        "limitations": ["Container prerequisites cannot establish ordinary-host AppArmor compatibility",
                        "No approval tokens or private evidence records are read or written",
                        "This receipt cannot establish Ubuntu support"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidentally replacing an earlier observation.
    with args.output.open("x") as destination:
        json.dump(report, destination, indent=2)
        destination.write("\n")
    print(f"Incomplete prerequisite receipt: {args.output}")


if __name__ == "__main__":
    main()
