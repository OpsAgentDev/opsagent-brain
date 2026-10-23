# syntax=docker/dockerfile:1
FROM rust:1.99-bookworm AS builder
WORKDIR /src
COPY . .
# Cache mounts keep the registry and target dir between builds; the binary is copied out of the mount.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release -p opsagent-brain --bin opsagent-brain \
    && cp target/release/opsagent-brain /opsagent-brain

FROM debian:bookworm-slim
# A shell is needed: Railway runs the pre-deploy command through one.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home opsagent
COPY --from=builder /opsagent-brain /usr/local/bin/opsagent-brain
WORKDIR /app
COPY templates ./templates
USER opsagent
ENV APP_ENV=production PORT=3000
EXPOSE 3000
CMD ["opsagent-brain", "start"]
