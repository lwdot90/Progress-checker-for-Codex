# Fingerprint performance

The approved checker benchmark ran the production Rust fingerprint function on synthetic Git repositories. These measurements cover full-content fingerprinting, not total status latency or cold service startup.

| Files | Content | Median | Maximum of five samples |
| --- | --- | --- | --- |
| 1,000 | 3.91 MiB | 320 ms | 347 ms |
| 10,000 | 39.06 MiB | 2284 ms | 2737 ms |

Observed on Fedora's 7.2.5-200.fc44.x86_64 kernel, eight logical CPUs, with a Cargo debug build using optimized SHA-2 compression. Five samples are too few to characterize tail latency; the reported nearest-rank p95 is the maximum sample. Filesystem cache state was not controlled.

Both fixtures detected a same-size edit with its modification time restored. Full-content hashing remains enabled. A size/mtime-only cache would miss this edit and cannot support trustworthy verification.

The 10,000-file measurement demonstrates a material cost. Future work should measure end-to-end status and representative user repositories before choosing an optimization; any cache must preserve content-change detection and freshness guarantees.

See [the dated receipt](receipts/fingerprint-benchmark.json). Reproduce through the configured `engineering-fingerprint-benchmark` check after exact human CLI approval. Its entrypoint is `scripts/check-engineering.sh benchmark`.
