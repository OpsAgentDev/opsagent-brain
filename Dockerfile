# syntax=docker/dockerfile:1
FROM rust:1.99-bookworm AS builder
WORKDIR /src
COPY . .
# No BuildKit cache mounts: Railway requires a per-service mount id, and api, worker and
# scheduler all build from this file.
RUN cargo build --release -p opsagent-brain --bin opsagent-brain \
    && cp target/release/opsagent-brain /opsagent-brain

FROM debian:bookworm-slim
# A shell is needed: Railway runs the pre-deploy command through one.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home opsagent
COPY --from=builder /opsagent-brain /usr/local/bin/opsagent-brain
WORKDIR /app
COPY templates ./templates
USER opsagent
ENV APP_ENV=production PORT=3000
EXPOSE 3000
CMD ["opsagent-brain", "start"]
