# --- Build ---

FROM alpine:3.23.3 AS builder

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

# Install OS dependencies
RUN apk update
RUN apk add cargo
RUN apk add clang
RUN apk add clang-dev
RUN apk add openssl-dev
RUN apk add build-base
RUN apk add linux-headers

# Build SDK
WORKDIR /srv
COPY . . 
RUN cargo build --release

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
COPY --from=builder /srv/target/release/journal-sdk .

ENTRYPOINT ["./journal-sdk"]

CMD ["--port", "80", "--database", "db"]
