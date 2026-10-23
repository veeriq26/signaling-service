FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/veeriq-signaling /usr/local/bin/veeriq-signaling

USER 65532:65532
ENV VEERIQ_SIGNAL_PROXY_TLS=true
ENV RUST_LOG=info

CMD ["/usr/local/bin/veeriq-signaling"]
