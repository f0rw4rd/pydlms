# Oracle image for the Rust DLMS crates (tests/interop/PROTOCOL.md).
#
#   docker build -t pydlms-interop-rust-dlms tests/interop/rust-dlms
#
#   docker run --rm -i pydlms-interop-rust-dlms                # dlms-cosem-rs oracle
#   docker run --rm -i pydlms-interop-rust-dlms push-parser    # dlms_cosem (reitermarkus)
#   docker run --rm -p 4059:4059 pydlms-interop-rust-dlms server [--ciphered]
#   docker run --rm --network host pydlms-interop-rust-dlms client 127.0.0.1:4059 [--ciphered]
#
# Pinned: dlms-cosem-rs =0.1.0 (crates.io, git cf414f570cfc74f3acbda83e960e287cc3cb316f,
# MIT OR Apache-2.0) and dlms_cosem =0.2.0 (crates.io, git
# 5a431d59287ae726e464e57405952c811942dadd, MIT OR Apache-2.0); every transitive
# dependency through Cargo.lock (--locked). Both crates are fetched from crates.io at
# build time and run here only; nothing of theirs is copied into pydlms.

FROM rust:1.90-slim-bookworm@sha256:64232e656c058f4468e8d024e990acff04f0fd5a5c0a88a574dc37773d7325c9 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && cp target/release/rust-dlms-oracle /usr/local/bin/

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
COPY --from=build /usr/local/bin/rust-dlms-oracle /usr/local/bin/rust-dlms-oracle
EXPOSE 4059
ENTRYPOINT ["/usr/local/bin/rust-dlms-oracle"]
