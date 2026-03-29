# syntax=docker/dockerfile:1.7

# --- Build base ---

FROM alpine:3.23.3 AS chef

ARG RUST_LOG=info
ARG CUSTOM_SETUP=""

ENV RUST_LOG=${RUST_LOG}
ENV CC=clang
ENV CXX=clang++

RUN set -eu; \
    if [ -n "$CUSTOM_SETUP" ]; then \
      echo "$CUSTOM_SETUP" | base64 -d > /tmp/custom-setup.sh; \
      chmod +x /tmp/custom-setup.sh; \
      /bin/sh -eu /tmp/custom-setup.sh; \
      rm -f /tmp/custom-setup.sh; \
    fi

RUN apk update && apk add --no-cache \
    build-base \
    cargo \
    clang \
    clang-dev \
    linux-headers \
    openssl-dev

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    cargo install cargo-chef --locked

WORKDIR /srv

# --- Dependency planning ---

FROM chef AS planner

COPY . .

RUN cargo chef prepare --recipe-path recipe.json

# --- Dependency build ---

FROM chef AS cacher

COPY --from=planner /srv/recipe.json recipe.json

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/srv/target \
    cargo chef cook --release --recipe-path recipe.json

# --- Application build ---

FROM chef AS builder

COPY . .

RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/srv/target \
    cargo build --release && \
    cp /srv/target/release/journal-sdk /tmp/journal-sdk

# --- Deploy ---

FROM alpine:3.23.3

WORKDIR /srv
ARG CUSTOM_SETUP=""

RUN set -eu; \
    if [ -n "$CUSTOM_SETUP" ]; then \
      echo "$CUSTOM_SETUP" | base64 -d > /tmp/custom-setup.sh; \
      chmod +x /tmp/custom-setup.sh; \
      /bin/sh -eu /tmp/custom-setup.sh; \
      rm -f /tmp/custom-setup.sh; \
    fi

COPY --from=builder /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=builder /usr/lib/libstdc++.so.6* /usr/lib/
COPY --from=builder /tmp/journal-sdk ./journal-sdk

ENTRYPOINT ["./journal-sdk"]

CMD ["--port", "80", "--database", "db"]
