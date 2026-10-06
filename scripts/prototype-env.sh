#!/usr/bin/env bash
# Source this file to keep the prototype toolchain and caches in the project.
PROTOTYPE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export PROTOTYPE_ROOT
export CARGO_HOME="$PROTOTYPE_ROOT/.local/cargo"
export RUSTUP_HOME="$PROTOTYPE_ROOT/.local/rustup"
export UV_CACHE_DIR="$PROTOTYPE_ROOT/.local/uv-cache"
export UV_PYTHON_INSTALL_DIR="$PROTOTYPE_ROOT/.local/uv-python"
export DOTSLASH_CACHE="$PROTOTYPE_ROOT/.local/dotslash-cache"
export PATH="$CARGO_HOME/bin:$PATH"
# The baseline machine has 8 GiB RAM. One compiler keeps the desktop usable.
export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_INCREMENTAL=0
