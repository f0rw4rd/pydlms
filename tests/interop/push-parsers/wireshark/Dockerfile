# Wireshark's DLMS/COSEM dissector (packet-cosem.c, GPL-2.0-or-later) as an
# oracle speaking tests/interop/PROTOCOL.md. Built on the repo's tshark image
# so the dissector version is the one tests/integration/test_tshark.py pins
# (tshark 4.6.9-1+b1 from Debian sid at the time of writing; `hello` reports
# the version actually installed).
#
# Build:
#   docker build -t pydlms-tshark tests/integration/tshark
#   docker build -t pydlms-interop-wireshark tests/interop/push-parsers/wireshark
FROM pydlms-tshark
USER root
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
COPY adapter.py /opt/adapter.py
USER tshark
ENTRYPOINT ["python3", "-I", "/opt/adapter.py"]
