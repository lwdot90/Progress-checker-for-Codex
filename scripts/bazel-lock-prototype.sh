#!/usr/bin/env bash
# Refresh and verify the upstream Bazel lockfile with project-local tools and caches.
set -euo pipefail

if (( $# != 0 )); then
    printf 'Usage: scripts/bazel-lock-prototype.sh\nRuns just bazel-lock-update followed by just bazel-lock-check.\n'
    if [[ $# == 1 && ( "$1" == '--help' || "$1" == '-h' ) ]]; then
        exit 0
    fi
    exit 2
fi

source "$(dirname -- "${BASH_SOURCE[0]}")/prototype-env.sh"
prototype_source="$PROTOTYPE_ROOT/.local/source/codex"
export PROTOTYPE_BAZEL_BINARY="$CARGO_HOME/bin/bazel"
export PROTOTYPE_BAZEL_ROOT="$PROTOTYPE_ROOT/.local/bazel"
prototype_just="$CARGO_HOME/bin/just"
if [[ ! -x "$PROTOTYPE_BAZEL_BINARY" || ! -x "$prototype_just" ]]; then
    printf 'Project-local Bazel and just are required. Run scripts/prepare-prototype.sh in a fresh copy first.\n' >&2
    exit 1
fi
if [[ ! -f "$prototype_source/.bazelversion" || "$(< "$prototype_source/.bazelversion")" != '9.0.0' ]]; then
    printf 'The pinned Codex source requiring Bazel 9.0.0 is unavailable.\n' >&2
    exit 1
fi

for directory in "$PROTOTYPE_ROOT/.local" "$PROTOTYPE_BAZEL_ROOT" \
    "$PROTOTYPE_BAZEL_ROOT/output" "$PROTOTYPE_BAZEL_ROOT/repository-cache" \
    "$PROTOTYPE_BAZEL_ROOT/repo-contents-cache" "$PROTOTYPE_BAZEL_ROOT/disk-cache" \
    "$PROTOTYPE_BAZEL_ROOT/tmp" "$PROTOTYPE_BAZEL_ROOT/java-home"; do
    if [[ -L "$directory" ]]; then
        printf 'Bazel local destination must not be a symlink: %s\n' "$directory" >&2
        exit 1
    fi
done
mkdir -p -- "$PROTOTYPE_BAZEL_ROOT/tmp" "$PROTOTYPE_BAZEL_ROOT/java-home"
export TMPDIR="$PROTOTYPE_BAZEL_ROOT/tmp"
export BAZEL_OUTPUT_USER_ROOT="$PROTOTYPE_BAZEL_ROOT/output"
export BAZEL_REPOSITORY_CACHE="$PROTOTYPE_BAZEL_ROOT/repository-cache"
export BAZEL_REPO_CONTENTS_CACHE="$PROTOTYPE_BAZEL_ROOT/repo-contents-cache"
# The upstream check helper enables remote services when this key is inherited.
unset BUILDBUDDY_API_KEY

prototype_shim="$(mktemp -d "$PROTOTYPE_BAZEL_ROOT/.wrapper.XXXXXXXX")"
trap 'rm -rf -- "$prototype_shim"' EXIT
cat > "$prototype_shim/bazel" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
startup_args=()
while [[ "${1:-}" == -* ]]; do
    startup_args+=("$1")
    shift
done
if [[ "${1:-}" != 'mod' ]]; then
    printf 'The prototype Bazel wrapper only supports module lockfile commands.\n' >&2
    exit 2
fi
shift
exec "$PROTOTYPE_BAZEL_BINARY" "${startup_args[@]}" \
    --batch --nosystem_rc --nohome_rc \
    "--output_user_root=$PROTOTYPE_BAZEL_ROOT/output" \
    --host_jvm_args=-Xms128m --host_jvm_args=-Xmx1024m \
    "--host_jvm_args=-Duser.home=$PROTOTYPE_BAZEL_ROOT/java-home" \
    "--host_jvm_args=-Djava.io.tmpdir=$PROTOTYPE_BAZEL_ROOT/tmp" \
    mod "$@" \
    "--repository_cache=$PROTOTYPE_BAZEL_ROOT/repository-cache" \
    "--repo_contents_cache=$PROTOTYPE_BAZEL_ROOT/repo-contents-cache" \
    "--disk_cache=$PROTOTYPE_BAZEL_ROOT/disk-cache" \
    --loading_phase_threads=1
SH
chmod u+x -- "$prototype_shim/bazel"
export PATH="$prototype_shim:$PATH"
export CODEX_BAZEL_BIN="$prototype_shim/bazel"
cd -- "$prototype_source"
"$prototype_just" bazel-lock-update
"$prototype_just" bazel-lock-check
