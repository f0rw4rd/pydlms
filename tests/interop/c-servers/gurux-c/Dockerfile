# GuruxDLMS.c (ANSI C, GPL-2.0 / commercial) as a separate process for the
# pydlms interop harness.
#
#   docker build -t pydlms-interop-gurux-c tests/interop/c-servers/gurux-c
#
# Default command: the oracle adapter (tests/interop/PROTOCOL.md, op data).
# "client <args>": GuruxDLMSClientExample (phase 4, reads pydlms simulate).
# "server": GuruxDLMSServerExample, ports from its main.c startServers:
#   4060 SN/HDLC  4061 LN/HDLC  4062 SN/wrapper  4063 LN/wrapper
#   4064 LN/HDLC with IEC 62056-21 mode E
FROM debian:bookworm-slim AS build
ARG GURUX_C_COMMIT=11a4fefe69b70452e00a8812a05ac97d99237c87
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git init /src && cd /src \
    && git remote add origin https://github.com/Gurux/GuruxDLMS.c \
    && git fetch --depth 1 origin "$GURUX_C_COMMIT" \
    && git checkout --detach FETCH_HEAD
WORKDIR /src/development
RUN mkdir -p obj lib && make
WORKDIR /src/GuruxDLMSServerExample
# Two build fixes, neither touching Gurux sources:
# - _getch() is called but not defined for Linux at this commit (shim).
# - DATAFILE/IMAGEFILE/TRACEFILE are tentative definitions in a header
#   included twice; GCC >= 10 defaults to -fno-common, so restore -fcommon.
COPY getch_linux.c src/getch_linux.c
RUN mkdir -p obj bin && make CFLAGS="-std=gnu99 -Wall -I. -fcommon" \
    && test -x bin/gurux.dlms.server.bin
WORKDIR /src/GuruxDLMSClientExample
# The Linux branch of com_initializeOpticalHead() lacks the Windows branch's
# "no serial port: return 0" guard and calls tcsetattr(-1) on every TCP
# connection ("Failed to Open port. tcsetattr failed."). Add the same guard.
RUN sed -i 's|^    struct termios options;$|    struct termios options;\n    if (connection->comPort == -1) return 0; /* pydlms harness */|' \
        src/communication.c \
    && grep -q 'pydlms harness' src/communication.c
RUN mkdir -p obj bin && make CFLAGS="-std=gnu99 -Wall -I. -fcommon" \
    && test -x bin/gurux.dlms.client.bin
COPY adapter.c /src/adapter/adapter.c
RUN gcc -std=gnu99 -O1 -Wall -DGURUX_C_COMMIT="\"$GURUX_C_COMMIT\"" \
        -o /src/adapter/gurux-c-adapter /src/adapter/adapter.c \
        -I/src/development/include -L/src/development/lib -lgurux_dlms_c -lm

FROM debian:bookworm-slim
RUN useradd -m meter
# main() derives data.csv/trace.txt/empty.bin from the directory part of
# argv[0] and fclose()s the trace file unchecked: it segfaults when started
# through PATH (no '/') or from a directory it cannot write. Hence an
# absolute path into a directory the server user owns.
COPY --from=build --chown=meter /src/GuruxDLMSServerExample/bin/gurux.dlms.server.bin /home/meter/srv/
COPY --from=build /src/adapter/gurux-c-adapter /usr/local/bin/
COPY --from=build /src/GuruxDLMSClientExample/bin/gurux.dlms.client.bin /usr/local/bin/
COPY entry.sh /usr/local/bin/entry.sh
USER meter
WORKDIR /home/meter/srv
EXPOSE 4060 4061 4062 4063 4064
ENTRYPOINT ["/usr/local/bin/entry.sh"]
