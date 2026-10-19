# Independent wired M-Bus peers for pydlms's MbusLink and MbusServer
# (no DLMS in either peer; they check the EN 13757-2 link layer):
#
# * rscada/libmbus (BSD-3-Clause), pinned below, as an M-Bus master:
#   master.c sends SND_NKE / selection, SND_UD and REQ_UD2 with FCB built
#   by libmbus and verifies our RSP_UD frames with mbus_frame_verify.
# * addiva-elektronik/mbus-device (MIT) on the addiva-elektronik/libmbus
#   fork it needs, as an M-Bus slave: answers SND_NKE with E5 and REQ_UD2
#   with one canned RSP_UD, selection by secondary address. It runs on a
#   PTY that socat bridges to a TCP port (an M-Bus gateway; --network host).
#
# Build: docker build -t pydlms-interop-mbus tests/interop/mbus
FROM debian:trixie-slim AS build
ARG LIBMBUS_COMMIT=de08e23783cae85d1cb7b06eaed544634e942fed
ARG ADDIVA_LIBMBUS_COMMIT=756ab8eae728f8100cfbe9382076fdb498c4a4d6
ARG MBUS_DEVICE_COMMIT=2364bdac698e2c448dd54fa8df1117518940d1d8
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates gcc make autoconf automake libtool libltdl-dev pkg-config git \
 && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/rscada/libmbus /src/libmbus \
 && git -C /src/libmbus checkout --quiet "$LIBMBUS_COMMIT" \
 && git clone https://github.com/addiva-elektronik/libmbus /src/addiva-libmbus \
 && git -C /src/addiva-libmbus checkout --quiet "$ADDIVA_LIBMBUS_COMMIT" \
 && git clone https://github.com/addiva-elektronik/mbus-device /src/mbus-device \
 && git -C /src/mbus-device checkout --quiet "$MBUS_DEVICE_COMMIT"
RUN for d in libmbus addiva-libmbus; do \
      cd /src/$d && mkdir -p m4 && autoreconf -fi -Wnone \
      && ./configure --prefix=/opt/$d && make -j"$(nproc)" \
      && make install >/dev/null || exit 1; \
    done
COPY master.c /src/master.c
RUN gcc -O2 -Wall -I/opt/libmbus/include -o /opt/libmbus/bin/mbus-dlms-master /src/master.c \
      -L/opt/libmbus/lib -lmbus -lm -Wl,-rpath,/opt/libmbus/lib \
 && cd /src/mbus-device \
 && PKG_CONFIG_PATH=/opt/addiva-libmbus/lib/pkgconfig make \
      LDFLAGS=-Wl,-rpath,/opt/addiva-libmbus/lib \
 && install -D mbus-device /opt/addiva-libmbus/bin/mbus-device

FROM debian:trixie-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends socat \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -m peer
COPY --from=build /opt /opt
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
USER peer
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
