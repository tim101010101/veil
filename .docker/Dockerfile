# syntax=docker/dockerfile:1
FROM debian:trixie-slim AS build
ARG BOOTSTRAP_MISE_VERSION=2026.10.3
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git build-essential pkg-config xz-utils \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://mise.run | MISE_VERSION="${BOOTSTRAP_MISE_VERSION}" sh
ENV PATH="/root/.local/bin:${PATH}" \
    MISE_EXEC_AUTO_INSTALL=false
WORKDIR /src
COPY mise.toml mise.lock ./
RUN mise trust -q && mise install rust
COPY . .
RUN mise exec -- cargo build --release --locked --package veil-daemon

FROM debian:trixie-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin veil \
 && install -d -o 10001 -g 10001 -m 0700 /data
COPY --from=build /src/target/release/veild /usr/local/bin/veild
ENV VEIL_BIND=0.0.0.0:8080 \
    VEIL_LOG=info \
    VEIL_DB=/data/veil.db
VOLUME /data
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8080/readyz"]
ENTRYPOINT ["/usr/local/bin/veild"]
