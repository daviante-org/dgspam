# ==============================================================================
# DGSPAMGUARD Threat & Mail Intelligence Service — Multi-Platform Scratch Container
# ==============================================================================
# Pure-Rust static musl binary packaged into `FROM scratch` (~10 MB, zero shell,
# zero OS package attack surface). Compatible out of the box with:
#   - Docker Engine & Docker Compose
#   - Podman (rootless & rootful) & Podman Compose / Systemd Quadlets
#   - Kubernetes (Pod Security Standards: "restricted" / runAsNonRoot: true)
#   - Red Hat OpenShift Container Platform ("restricted-v2" SCC arbitrary UIDs)
#
# Published exclusively to GitHub Container Registry:
#   ghcr.io/daviante-org/dgspamguard
# ==============================================================================

FROM docker.io/library/rust:1.99-alpine AS builder

RUN apk upgrade --no-cache \
    && apk add --no-cache musl-dev ca-certificates

WORKDIR /build

# 1. Pre-compile and cache all locked third-party crates once per Cargo.lock
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'pub fn _dep_stub() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked --bin dgspamguard \
    && rm -rf src target/release/deps/dgspamguard* target/release/deps/libdgspamguard* target/release/dgspamguard* target/release/.fingerprint/dgspamguard-*

# 2. Compile DGSPAMGUARD application source against cached dependencies
COPY src ./src
COPY openapi.yaml ./openapi.yaml
COPY assets ./assets

RUN find src -type f -exec touch {} + \
    && cargo build --release --locked --bin dgspamguard \
    && mkdir -p /rootfs/usr/local/bin /rootfs/etc/ssl/certs /rootfs/app /rootfs/tmp/dgspamguard-cache \
    && cp /build/target/release/dgspamguard /rootfs/usr/local/bin/dgspamguard \
    && chmod 0755 /rootfs/usr/local/bin/dgspamguard \
    && cp /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt \
    && cp /build/openapi.yaml /rootfs/app/openapi.yaml \
    && cp -R /build/assets /rootfs/app/assets \
    && printf 'dgspamguard:x:10001:0:DGSPAMGUARD:/tmp:/sbin/nologin\n' > /rootfs/etc/passwd \
    && printf 'root:x:0:dgspamguard\n' > /rootfs/etc/group \
    && chown -R 10001:0 /rootfs/app /rootfs/tmp \
    && chmod -R g=u /rootfs/app /rootfs/tmp \
    && chmod 1777 /rootfs/tmp

FROM scratch

LABEL org.opencontainers.image.title="DGSPAMGUARD Threat & Mail Intelligence Service" \
      org.opencontainers.image.description="Self-hosted domain, URL, email taxonomy, malware attachment hash, DNS RPZ & mail rule intelligence engine compiled in Rust." \
      org.opencontainers.image.vendor="Daviante" \
      org.opencontainers.image.authors="Daviante <code@daviante.org>" \
      org.opencontainers.image.url="https://daviante.org" \
      org.opencontainers.image.source="https://github.com/daviante-org/dgspamguard" \
      org.opencontainers.image.documentation="https://github.com/daviante-org/dgspamguard/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PATH=/usr/local/bin:/usr/bin:/bin \
    HOME=/tmp \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    DGSPAMGUARD_HOST=0.0.0.0 \
    DGSPAMGUARD_PORT=8091 \
    DGSPAMGUARD_SWAGGER_ENABLED=true \
    DGSPAMGUARD_ASSETS_DIR=/app/assets \
    DGSPAMGUARD_CACHE_DIR=/tmp/dgspamguard-cache

COPY --from=builder /rootfs/ /

WORKDIR /app

USER 10001:0

EXPOSE 8091

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/dgspamguard", "healthcheck"]

CMD ["/usr/local/bin/dgspamguard", "serve"]
