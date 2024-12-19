FROM rust:1.83-slim-bullseye as builder

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y pkg-config libssl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/src/app/target \
    cargo fetch

COPY src ./src
COPY .sqlx ./.sqlx

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release && \
    mv target/release/ark /ark

FROM rust:1.83-slim-bullseye

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install sqlx-cli --no-default-features --features postgres

COPY --from=builder /ark /ark
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY migrations ./migrations

CMD ["/entrypoint.sh"]
