# Security Policy

## Reporting a Vulnerability

Please report suspected security vulnerabilities privately to **`code@daviante.org`** rather than opening a public GitHub issue. Include:
- Affected component (`dgspamguard` binary, container image, Helm chart, or `openapi.yaml`) and version tag
- Reproduction steps or proof-of-concept payload
- Expected vs observed security boundary behavior

We acknowledge reports within **48 hours** and publish coordinated fixes with SemVer patch releases and GitHub Security Advisories.

---

## Security Architecture & Hardening Controls

1. **100% Read-Only HTTP Surface**:
   - The HTTP server exposes zero admin, sync, configuration, or mutating endpoints. All state changes require shell/exec access to `/usr/local/bin/dgspamguard` or direct PostgreSQL credentials.
2. **Strict SSRF & Redirect Allowlist (`src/sync.rs`)**:
   - Upstream feed fetches enforce `https://` exclusively, disable automatic cross-host redirects, and validate every initial URL and redirect target against `dgspamguard_allowed_hosts` before opening a socket.
   - Streamed response bodies are bounded (`128 MiB` compressed / `256 MiB` decompressed) to prevent decompression-bomb OOM attacks.
3. **Bootstrap Tarball & Path-Traversal Verification (`src/compiler.rs`)**:
   - `unpack_bootstrap_bundle` rejects symlinks, hardlinks, device nodes, absolute paths, `..` traversal segments, unexpected filenames, and any entry whose computed `SHA-256` or byte length mismatches `manifest.json` or `SHA256SUMS.txt`.
4. **Hardened `FROM scratch` Runtime**:
   - Compiled statically against `musl` with pure-Rust `rustls` (zero OpenSSL, `glibc`, `/bin/sh`, or package manager in the runtime image).
   - Runs as `UID 10001:0` with `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, and `seccompProfile: RuntimeDefault`.
5. **Cryptographic Supply-Chain Provenance**:
   - Official container images (`ghcr.io/daviante-org/dgspamguard`) and Helm charts (`ghcr.io/daviante-org/charts/dgspamguard`) are attested with GitHub OIDC SLSA build provenance (`actions/attest-build-provenance@v4`).
   - Verify any release image with:
     ```bash
     gh attestation verify oci://ghcr.io/daviante-org/dgspamguard:1.0.0 --owner daviante-org
     ```
