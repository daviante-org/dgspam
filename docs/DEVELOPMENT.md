# Development & Verification Guide

`dgspamguard` is written in 100% safe, pure Rust (Edition 2021, MSRV `1.85+`) with zero C/OpenSSL library dependencies (`rustls` + `flate2` pure-Rust backend).

---

## 1. Local Toolchain & Containerized Builds

Run formatting, strict Clippy lints, and the unit/contract test suite:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked -- --nocapture
```

Or inside Podman/Docker without installing Rust on the host:

```bash
podman run --rm -v "$PWD:/work:Z" -w /work rust:1.99-alpine sh -ceu "
  apk add --no-cache musl-dev
  cargo clippy --locked --all-targets -- -D warnings
  cargo test --locked -- --nocapture
"
```

---

## 2. Building & Testing the `FROM scratch` Image

```bash
podman build -t localhost/dgspamguard:1.0.0 .

# Verify read-only rootfs + dropped capabilities + OpenShift arbitrary UID:
podman run --rm --read-only --cap-drop=ALL --user 1000670000:0 localhost/dgspamguard:1.0.0 --version
```

---

## 3. Exporting Snapshot Artifacts Locally

When running against a local PostgreSQL instance, you can trigger an immediate upstream feed sync and export all 9 `.gz` datasets, `bundle.tar.gz`, `manifest.json`, and `SHA256SUMS.txt` to disk:

```bash
dgspamguard sync --force --export-dir ./dist/snapshot
sha256sum -c ./dist/snapshot/SHA256SUMS.txt
```

---

## 4. Quality Gates Required Before Every Release

1. `cargo fmt --all -- --check` — zero formatting diffs.
2. `cargo clippy --locked --all-targets -- -D warnings` — zero compiler or lint warnings.
3. `cargo test --locked` — all normalization, compiler, shared-hosting subtraction, `dgmail-rules.json.gz` size cap (`<= 440 KB`), bundle verification, and OpenAPI 3.1 contract parity tests pass.
4. `helm lint charts/dgspamguard --strict` — zero Helm chart warnings.
5. OSV.dev `Cargo.lock` dependency audit & Trivy `CRITICAL,HIGH` image/filesystem scan — `0` vulnerabilities.
