# tshark >= 4.6 (Debian sid) for the independent-dissector interop test.
# Wireshark 4.4 has no DLMS/COSEM dissector; 4.6 ships "dlms" and "cosem".
#
# Build: docker build -t pydlms-tshark tests/integration/tshark
FROM debian:sid
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m tshark
USER tshark
WORKDIR /work
ENTRYPOINT ["tshark"]
