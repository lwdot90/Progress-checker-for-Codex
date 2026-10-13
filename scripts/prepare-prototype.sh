#!/usr/bin/env bash
# Explicit local source/toolchain/helper setup. Does not build Codex or run project checks.
set -euo pipefail

prototype_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
local_root="$prototype_root/.local"
source_dir="$local_root/source/codex"
pinned_commit="a956835d020762cb2b570053af06f643a11c0ecc"
patch_path="$prototype_root/patches/codex-progress-panel.patch"

if (( $# != 0 )); then
    printf 'Usage: bash scripts/prepare-prototype.sh\n' >&2
    exit 1
fi
for command in curl git python3 mktemp install; do
    if ! command -v "$command" >/dev/null 2>&1; then
        printf 'Required command is unavailable: %s\n' "$command" >&2
        exit 1
    fi
done
if [[ -e "$source_dir" || -L "$source_dir" ]]; then
    printf 'Source already exists; refusing to replace it: %s\n' "$source_dir" >&2
    exit 1
fi
for output in "$local_root" "$local_root/source" "$local_root/cargo" "$local_root/rustup"; do
    if [[ -L "$output" ]]; then
        printf 'Local setup destination must not be a symlink: %s\n' "$output" >&2
        exit 1
    fi
done
if [[ ! -f "$patch_path" || ! -f "$prototype_root/upstream-base/MANIFEST.json" ]]; then
    printf 'The pinned baseline manifest and generated prototype patch are required.\n' >&2
    exit 1
fi

mkdir -p -- "$local_root/source"
work_dir="$(mktemp -d "$local_root/source/.prepare.XXXXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

python3 - "$prototype_root/COMPATIBILITY.json" > "$work_dir/helpers.tsv" <<'PY'
import json
import re
import sys

expected = {
    "just": (
        "1.58.0",
        "https://github.com/casey/just/releases/download/1.58.0/just-1.58.0-x86_64-unknown-linux-musl.tar.gz",
        "tar.gz",
    ),
    "cargo-nextest": (
        "0.9.146",
        "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-0.9.146/cargo-nextest-0.9.146-x86_64-unknown-linux-musl.tar.gz",
        "tar.gz",
    ),
    "dotslash": (
        "0.5.9",
        "https://github.com/facebook/dotslash/releases/download/v0.5.9/dotslash-linux-musl.x86_64.tar.gz",
        "tar.gz",
    ),
    "bazel": (
        "9.0.0",
        "https://github.com/bazelbuild/bazel/releases/download/9.0.0/bazel-9.0.0-linux-x86_64",
        "binary",
    ),
}
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        helpers = json.load(stream).get("helpers")
    if not isinstance(helpers, dict):
        raise ValueError("Missing pinned helpers in COMPATIBILITY.json")
    for name, (version, url, artifact_kind) in expected.items():
        helper = helpers.get(name)
        if not isinstance(helper, dict):
            raise ValueError(f"Missing helper pin: {name}")
        if helper.get("version") != version or helper.get("url") != url:
            raise ValueError(f"Helper version or release URL does not match the pin: {name}")
        digest = helper.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"Missing or malformed helper SHA-256 pin: {name}")
        if name == "bazel" and digest != "c44a93f25398c68f904fa1d19b61d321de6c0d2f09dca375d7bc0dc9b9428403":
            raise ValueError("Bazel SHA-256 does not match the verified official release")
        print(f"{name}\t{url}\t{digest}\t{artifact_kind}")
except (OSError, ValueError, AttributeError) as error:
    print(f"Helper pin validation failed: {error}", file=sys.stderr)
    sys.exit(1)
PY

printf 'Fetching the exact Codex commit into a staged Git checkout.\n'
staged_source="$work_dir/codex"
git -c init.defaultBranch=prototype init --quiet "$staged_source"
git -C "$staged_source" remote add origin https://github.com/openai/codex.git
git -C "$staged_source" fetch --depth 1 origin "$pinned_commit" || {
    printf 'Pinned source fetch failed; no source tree was installed. Check network/DNS access.\n' >&2
    exit 1
}
git -C "$staged_source" checkout --quiet --detach "$pinned_commit"
if [[ "$(git -C "$staged_source" rev-parse HEAD)" != "$pinned_commit" ]]; then
    printf 'Fetched source did not resolve to the pinned commit.\n' >&2
    exit 1
fi
python3 "$prototype_root/scripts/check-source.py" "$staged_source"
printf 'Checking and applying the embedded panel patch.\n'
git -C "$staged_source" apply --check "$patch_path"
git -C "$staged_source" apply "$patch_path"

export CARGO_HOME="$local_root/cargo"
export RUSTUP_HOME="$local_root/rustup"
export UV_CACHE_DIR="$local_root/uv-cache"
export DOTSLASH_CACHE="$local_root/dotslash-cache"
printf 'Installing Rust 1.95.0 under .local without changing the global PATH.\n'
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init \
    --output "$work_dir/rustup-init" || {
    printf 'Rustup download failed; no source tree was installed. Check network/DNS access.\n' >&2
    exit 1
}
curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256 \
    --output "$work_dir/rustup-init.sha256" || {
    printf 'Rustup checksum download failed; installer was not executed and source was not published.\n' >&2
    exit 1
}
python3 - "$work_dir/rustup-init" "$work_dir/rustup-init.sha256" <<'PY'
import hashlib
from pathlib import Path
import re
import sys

installer, checksum_path = map(Path, sys.argv[1:])
checksum_fields = checksum_path.read_text(encoding="ascii").split()
if not checksum_fields or not re.fullmatch(r"[0-9a-f]{64}", checksum_fields[0]):
    raise ValueError("Malformed official Rustup installer checksum")
if hashlib.sha256(installer.read_bytes()).hexdigest() != checksum_fields[0]:
    raise ValueError("Rustup installer checksum mismatch; installer will not run")
PY

chmod u+x "$work_dir/rustup-init"
"$work_dir/rustup-init" -y --no-modify-path --profile minimal \
    --default-host x86_64-unknown-linux-gnu --default-toolchain 1.95.0 \
    --component rustfmt --component clippy --component rust-src || {
    printf 'Local Rust installation failed; source was not published. Any partial tools remain under .local.\n' >&2
    exit 1
}

printf 'Installing checksum-pinned prebuilt helpers without compiling them.\n'
while IFS=$'\t' read -r helper helper_url helper_sha artifact_kind; do
    curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
        "$helper_url" --output "$work_dir/$helper.download" || {
        printf 'Pinned helper download failed: %s. Source was not published.\n' "$helper" >&2
        exit 1
    }
    python3 - "$work_dir/$helper.download" "$helper_sha" "$helper" "$work_dir" "$artifact_kind" <<'PY'
import hashlib
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive_path, expected, name, destination, artifact_kind = sys.argv[1:]
if hashlib.sha256(Path(archive_path).read_bytes()).hexdigest() != expected:
    raise ValueError(f"Helper artifact checksum mismatch: {name}")
if artifact_kind == "binary":
    Path(destination, name).write_bytes(Path(archive_path).read_bytes())
elif artifact_kind == "tar.gz":
    with tarfile.open(archive_path, "r:gz") as archive:
        matches = [m for m in archive.getmembers() if m.isfile() and PurePosixPath(m.name).name == name]
        if len(matches) != 1:
            raise ValueError(f"Expected exactly one helper binary: {name}")
        stream = archive.extractfile(matches[0])
        if stream is None:
            raise ValueError(f"Cannot read helper binary: {name}")
        Path(destination, name).write_bytes(stream.read())
else:
    raise ValueError(f"Unsupported helper artifact format: {artifact_kind}")
PY
    install -m 755 -- "$work_dir/$helper" "$CARGO_HOME/bin/$helper"
done < "$work_dir/helpers.tsv"

# Staging beside the destination keeps this rename on one filesystem.
# --no-clobber protects a tree created while the downloads were in progress.
mv --no-clobber -T -- "$staged_source" "$source_dir"
if [[ -d "$staged_source" ]]; then
    printf 'A source tree appeared during setup; it was left untouched.\n' >&2
    exit 1
fi
printf 'Prepared patched source at %s. No Codex build or project test was run.\n' "$source_dir"
printf 'Use the local environment and validation commands in README.md.\n'
