# esphome-libs/dlms_parser (C++20, Apache-2.0) as a push-parser oracle
# speaking tests/interop/PROTOCOL.md (ops: hello, push, frame).
# Pinned to tag v2.2.0 = a80697723e9c52887e9cfdcb2729821dc47cc619, the same
# commit our vendored captures in tests/fixtures/dlms_parser/ come from.
# AES-GCM through the library's own mbedTLS backend (Debian libmbedtls-dev).
#
# Build: docker build -t pydlms-interop-esphome tests/interop/push-parsers/esphome
FROM debian:trixie-slim AS build
ARG DLMS_PARSER_COMMIT=a80697723e9c52887e9cfdcb2729821dc47cc619
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates g++ git libmbedtls-dev \
 && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/esphome-libs/dlms_parser /src \
 && git -C /src checkout --quiet "$DLMS_PARSER_COMMIT"
COPY adapter.cpp /src/adapter.cpp
RUN g++ -std=c++20 -O2 -Wall -I/src/src -o /usr/local/bin/dlms-parser-oracle \
      /src/adapter.cpp /src/src/dlms_parser/*.cpp -lmbedcrypto

FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libmbedcrypto16 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m oracle
COPY --from=build /usr/local/bin/dlms-parser-oracle /usr/local/bin/dlms-parser-oracle
USER oracle
ENTRYPOINT ["/usr/local/bin/dlms-parser-oracle"]
