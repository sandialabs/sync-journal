# --- Build ---

FROM alpine:3.23.3 AS builder

ARG RUST_LOG=info

ENV RUST_LOG=${RUST_LOG}
ENV CC=clang
ENV CXX=clang++

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
COPY --from=builder /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=builder /usr/lib/libstdc++.so.6* /usr/lib/
COPY --from=builder /srv/target/release/journal-sdk .

ENTRYPOINT ["./journal-sdk"]

CMD ["--port", "80", "--database", "db"]
