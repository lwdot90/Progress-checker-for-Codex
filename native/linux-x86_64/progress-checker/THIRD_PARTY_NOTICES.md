# Third-party notices for Progress Checker

The backend and native plugin are licensed under Apache-2.0; see `LICENSE`.
Third-party components retain their own licenses and copyright notices.

This inventory covers all **110 external packages** in the backend `Cargo.lock`.
It includes build, test, optional, and other-platform dependencies and is not a claim that
every listed crate is linked into the Linux executables. Four local workspace crates
are covered by the project license. The Codex fork, Codex executable, Rust compiler,
Python, Git, bubblewrap, and system libraries are not distributed in this package.

`third-party/inventory.json` records exact versions, declared license expressions,
registry checksums, and hashes of the retained notice files. The lockfile digest binds
this inventory to its reviewed dependency resolution. Rebuild these notices when
that resolution changes with `python3 scripts/generate-plugin-notices.py`.

Original license, copyright, notice, and author files are retained verbatim under
`third-party/crates/`. Dual-license alternatives are preserved; mandatory combined
terms such as unicode-ident's Unicode-3.0 license are included.
For 8 cached packages that omit standalone license text, `LICENSE-SUPPLIED`
provides the standard Apache-2.0 text (with LLVM exception where declared), selected
from the package's explicit Cargo license alternatives. These files are labeled in
the inventory and are not represented as original files shipped by those crates.

The installed Rust 1.95.0 standard-library copyright document and its license texts
are under `third-party/rust-standard-library/`. This preserves linked-library
attribution without claiming that the complete toolchain is distributed.

System dependencies must be supplied by the recipient's operating system. This
inventory does not qualify another target, a changed toolchain, a different link
configuration, or a future dependency update. The release archive remains subject
to the project's separate behavioral and distribution acceptance gates.

| Crate | Version | Declared license | Retained material |
| --- | --- | --- | --- |
| android_system_properties | 0.1.5 | MIT/Apache-2.0 | [upstream files](third-party/crates/android_system_properties-0.1.5/) |
| anstream | 0.6.21 | MIT OR Apache-2.0 | [upstream files](third-party/crates/anstream-0.6.21/) |
| anstyle | 1.0.13 | MIT OR Apache-2.0 | [upstream files](third-party/crates/anstyle-1.0.13/) |
| anstyle-parse | 0.2.7 | MIT OR Apache-2.0 | [upstream files](third-party/crates/anstyle-parse-0.2.7/) |
| anstyle-query | 1.1.5 | MIT OR Apache-2.0 | [upstream files](third-party/crates/anstyle-query-1.1.5/) |
| anstyle-wincon | 3.0.11 | MIT OR Apache-2.0 | [upstream files](third-party/crates/anstyle-wincon-3.0.11/) |
| anyhow | 1.0.103 | MIT OR Apache-2.0 | [upstream files](third-party/crates/anyhow-1.0.103/) |
| autocfg | 1.5.0 | Apache-2.0 OR MIT | [upstream files](third-party/crates/autocfg-1.5.0/) |
| bitflags | 2.13.1 | MIT OR Apache-2.0 | [upstream files](third-party/crates/bitflags-2.13.1/) |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | [upstream files](third-party/crates/block-buffer-0.10.4/) |
| bumpalo | 3.19.1 | MIT OR Apache-2.0 | [upstream files](third-party/crates/bumpalo-3.19.1/) |
| bytes | 1.12.1 | MIT | [upstream files](third-party/crates/bytes-1.12.1/) |
| cc | 1.2.55 | MIT OR Apache-2.0 | [upstream files](third-party/crates/cc-1.2.55/) |
| cfg-if | 1.0.4 | MIT OR Apache-2.0 | [upstream files](third-party/crates/cfg-if-1.0.4/) |
| chrono | 0.4.43 | MIT OR Apache-2.0 | [upstream files](third-party/crates/chrono-0.4.43/) |
| clap | 4.5.58 | MIT OR Apache-2.0 | [upstream files](third-party/crates/clap-4.5.58/) |
| clap_builder | 4.5.58 | MIT OR Apache-2.0 | [upstream files](third-party/crates/clap_builder-4.5.58/) |
| clap_derive | 4.5.55 | MIT OR Apache-2.0 | [upstream files](third-party/crates/clap_derive-4.5.55/) |
| clap_lex | 1.0.0 | MIT OR Apache-2.0 | [upstream files](third-party/crates/clap_lex-1.0.0/) |
| colorchoice | 1.0.4 | MIT OR Apache-2.0 | [upstream files](third-party/crates/colorchoice-1.0.4/) |
| core-foundation-sys | 0.8.7 | MIT OR Apache-2.0 | [upstream files](third-party/crates/core-foundation-sys-0.8.7/) |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | [upstream files](third-party/crates/cpufeatures-0.2.17/) |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | [upstream files](third-party/crates/crypto-common-0.1.7/) |
| digest | 0.10.7 | MIT OR Apache-2.0 | [upstream files](third-party/crates/digest-0.10.7/) |
| equivalent | 1.0.2 | Apache-2.0 OR MIT | [upstream files](third-party/crates/equivalent-1.0.2/) |
| errno | 0.3.14 | MIT OR Apache-2.0 | [upstream files](third-party/crates/errno-0.3.14/) |
| fastrand | 2.3.0 | Apache-2.0 OR MIT | [upstream files](third-party/crates/fastrand-2.3.0/) |
| find-msvc-tools | 0.1.9 | MIT OR Apache-2.0 | [upstream files](third-party/crates/find-msvc-tools-0.1.9/) |
| foldhash | 0.1.5 | Zlib | [upstream files](third-party/crates/foldhash-0.1.5/) |
| futures-core | 0.3.34 | MIT OR Apache-2.0 | [upstream files](third-party/crates/futures-core-0.3.34/) |
| futures-macro | 0.3.34 | MIT OR Apache-2.0 | [upstream files](third-party/crates/futures-macro-0.3.34/) |
| futures-sink | 0.3.34 | MIT OR Apache-2.0 | [upstream files](third-party/crates/futures-sink-0.3.34/) |
| futures-task | 0.3.34 | MIT OR Apache-2.0 | [upstream files](third-party/crates/futures-task-0.3.34/) |
| futures-util | 0.3.34 | MIT OR Apache-2.0 | [upstream files](third-party/crates/futures-util-0.3.34/) |
| generic-array | 0.14.7 | MIT | [upstream files](third-party/crates/generic-array-0.14.7/) |
| getrandom | 0.4.2 | MIT OR Apache-2.0 | [upstream files](third-party/crates/getrandom-0.4.2/) |
| hashbrown | 0.15.5 | MIT OR Apache-2.0 | [upstream files](third-party/crates/hashbrown-0.15.5/) |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | [upstream files](third-party/crates/hashbrown-0.17.1/) |
| heck | 0.5.0 | MIT OR Apache-2.0 | [upstream files](third-party/crates/heck-0.5.0/) |
| hmac | 0.12.1 | MIT OR Apache-2.0 | [upstream files](third-party/crates/hmac-0.12.1/) |
| iana-time-zone | 0.1.65 | MIT OR Apache-2.0 | [upstream files](third-party/crates/iana-time-zone-0.1.65/) |
| iana-time-zone-haiku | 0.1.2 | MIT OR Apache-2.0 | [upstream files](third-party/crates/iana-time-zone-haiku-0.1.2/) |
| id-arena | 2.3.0 | MIT/Apache-2.0 | [upstream files](third-party/crates/id-arena-2.3.0/) |
| indexmap | 2.14.0 | Apache-2.0 OR MIT | [upstream files](third-party/crates/indexmap-2.14.0/) |
| is_terminal_polyfill | 1.70.2 | MIT OR Apache-2.0 | [upstream files](third-party/crates/is_terminal_polyfill-1.70.2/) |
| itoa | 1.0.17 | MIT OR Apache-2.0 | [upstream files](third-party/crates/itoa-1.0.17/) |
| js-sys | 0.3.85 | MIT OR Apache-2.0 | [upstream files](third-party/crates/js-sys-0.3.85/) |
| leb128fmt | 0.1.0 | MIT OR Apache-2.0 | [upstream files](third-party/crates/leb128fmt-0.1.0/) |
| libc | 0.2.186 | MIT OR Apache-2.0 | [upstream files](third-party/crates/libc-0.2.186/) |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [upstream files](third-party/crates/linux-raw-sys-0.12.1/) |
| log | 0.4.34 | MIT OR Apache-2.0 | [upstream files](third-party/crates/log-0.4.34/) |
| memchr | 2.8.1 | Unlicense OR MIT | [upstream files](third-party/crates/memchr-2.8.1/) |
| mio | 1.2.0 | MIT | [upstream files](third-party/crates/mio-1.2.0/) |
| num-traits | 0.2.19 | MIT OR Apache-2.0 | [upstream files](third-party/crates/num-traits-0.2.19/) |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | [upstream files](third-party/crates/once_cell-1.21.4/) |
| once_cell_polyfill | 1.70.2 | MIT OR Apache-2.0 | [upstream files](third-party/crates/once_cell_polyfill-1.70.2/) |
| pin-project-lite | 0.2.16 | Apache-2.0 OR MIT | [upstream files](third-party/crates/pin-project-lite-0.2.16/) |
| prettyplease | 0.2.37 | MIT OR Apache-2.0 | [upstream files](third-party/crates/prettyplease-0.2.37/) |
| proc-macro2 | 1.0.106 | MIT OR Apache-2.0 | [upstream files](third-party/crates/proc-macro2-1.0.106/) |
| quote | 1.0.45 | MIT OR Apache-2.0 | [upstream files](third-party/crates/quote-1.0.45/) |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | [supplied declared alternative](third-party/crates/r-efi-6.0.0/) |
| rustix | 1.1.4 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [upstream files](third-party/crates/rustix-1.1.4/) |
| rustversion | 1.0.22 | MIT OR Apache-2.0 | [upstream files](third-party/crates/rustversion-1.0.22/) |
| semver | 1.0.27 | MIT OR Apache-2.0 | [upstream files](third-party/crates/semver-1.0.27/) |
| serde | 1.0.228 | MIT OR Apache-2.0 | [upstream files](third-party/crates/serde-1.0.228/) |
| serde_core | 1.0.228 | MIT OR Apache-2.0 | [upstream files](third-party/crates/serde_core-1.0.228/) |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 | [upstream files](third-party/crates/serde_derive-1.0.228/) |
| serde_json | 1.0.149 | MIT OR Apache-2.0 | [upstream files](third-party/crates/serde_json-1.0.149/) |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | [upstream files](third-party/crates/sha2-0.10.9/) |
| shlex | 1.3.0 | MIT OR Apache-2.0 | [upstream files](third-party/crates/shlex-1.3.0/) |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 | [upstream files](third-party/crates/signal-hook-registry-1.4.8/) |
| slab | 0.4.12 | MIT | [upstream files](third-party/crates/slab-0.4.12/) |
| socket2 | 0.6.3 | MIT OR Apache-2.0 | [upstream files](third-party/crates/socket2-0.6.3/) |
| strsim | 0.11.1 | MIT | [upstream files](third-party/crates/strsim-0.11.1/) |
| subtle | 2.6.1 | BSD-3-Clause | [upstream files](third-party/crates/subtle-2.6.1/) |
| syn | 2.0.117 | MIT OR Apache-2.0 | [upstream files](third-party/crates/syn-2.0.117/) |
| syn | 3.0.3 | MIT OR Apache-2.0 | [upstream files](third-party/crates/syn-3.0.3/) |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | [upstream files](third-party/crates/tempfile-3.27.0/) |
| tokio | 1.52.3 | MIT | [upstream files](third-party/crates/tokio-1.52.3/) |
| tokio-macros | 2.7.0 | MIT | [upstream files](third-party/crates/tokio-macros-2.7.0/) |
| tokio-util | 0.7.18 | MIT | [upstream files](third-party/crates/tokio-util-0.7.18/) |
| typenum | 1.20.0 | MIT OR Apache-2.0 | [upstream files](third-party/crates/typenum-1.20.0/) |
| unicode-ident | 1.0.22 | (MIT OR Apache-2.0) AND Unicode-3.0 | [upstream files](third-party/crates/unicode-ident-1.0.22/) |
| unicode-xid | 0.2.6 | MIT OR Apache-2.0 | [upstream files](third-party/crates/unicode-xid-0.2.6/) |
| utf8parse | 0.2.2 | Apache-2.0 OR MIT | [upstream files](third-party/crates/utf8parse-0.2.2/) |
| version_check | 0.9.5 | MIT/Apache-2.0 | [upstream files](third-party/crates/version_check-0.9.5/) |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [upstream files](third-party/crates/wasi-0.11.1+wasi-snapshot-preview1/) |
| wasip2 | 1.0.2+wasi-0.2.9 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [supplied declared alternative](third-party/crates/wasip2-1.0.2+wasi-0.2.9/) |
| wasip3 | 0.4.0+wasi-0.3.0-rc-2026-01-06 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [supplied declared alternative](third-party/crates/wasip3-0.4.0+wasi-0.3.0-rc-2026-01-06/) |
| wasm-bindgen | 0.2.108 | MIT OR Apache-2.0 | [upstream files](third-party/crates/wasm-bindgen-0.2.108/) |
| wasm-bindgen-macro | 0.2.108 | MIT OR Apache-2.0 | [upstream files](third-party/crates/wasm-bindgen-macro-0.2.108/) |
| wasm-bindgen-macro-support | 0.2.108 | MIT OR Apache-2.0 | [upstream files](third-party/crates/wasm-bindgen-macro-support-0.2.108/) |
| wasm-bindgen-shared | 0.2.108 | MIT OR Apache-2.0 | [upstream files](third-party/crates/wasm-bindgen-shared-0.2.108/) |
| wasm-encoder | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [supplied declared alternative](third-party/crates/wasm-encoder-0.244.0/) |
| wasm-metadata | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [supplied declared alternative](third-party/crates/wasm-metadata-0.244.0/) |
| wasmparser | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [supplied declared alternative](third-party/crates/wasmparser-0.244.0/) |
| windows-core | 0.62.2 | MIT OR Apache-2.0 | [upstream files](third-party/crates/windows-core-0.62.2/) |
| windows-implement | 0.60.2 | MIT OR Apache-2.0 | [upstream files](third-party/crates/windows-implement-0.60.2/) |
| windows-interface | 0.59.3 | MIT OR Apache-2.0 | [upstream files](third-party/crates/windows-interface-0.59.3/) |
| windows-link | 0.2.1 | MIT OR Apache-2.0 | [upstream files](third-party/crates/windows-link-0.2.1/) |
| windows-result | 0.4.1 | MIT OR Apache-2.0 | [upstream files](third-party/crates/windows-result-0.4.1/) |
| windows-strings | 0.5.1 | MIT OR Apache-2.0 | [upstream files](third-party/crates/windows-strings-0.5.1/) |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | [upstream files](third-party/crates/windows-sys-0.61.2/) |
| wit-bindgen | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [upstream files](third-party/crates/wit-bindgen-0.51.0/) |
| wit-bindgen-core | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [upstream files](third-party/crates/wit-bindgen-core-0.51.0/) |
| wit-bindgen-rust | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [upstream files](third-party/crates/wit-bindgen-rust-0.51.0/) |
| wit-bindgen-rust-macro | 0.51.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [upstream files](third-party/crates/wit-bindgen-rust-macro-0.51.0/) |
| wit-component | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [supplied declared alternative](third-party/crates/wit-component-0.244.0/) |
| wit-parser | 0.244.0 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [supplied declared alternative](third-party/crates/wit-parser-0.244.0/) |
| zmij | 1.0.19 | MIT | [upstream files](third-party/crates/zmij-1.0.19/) |
