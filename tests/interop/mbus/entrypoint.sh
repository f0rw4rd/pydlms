#!/bin/sh
# master HOST PORT ADDRESS [--secondary ID16] APDU_HEX...  libmbus as M-Bus master
# device ADDRESS PORT                                     mbus-device on 127.0.0.1:PORT
set -e
case "$1" in
  master)
    shift
    exec /opt/libmbus/bin/mbus-dlms-master "$@"
    ;;
  device)
    socat pty,link=/tmp/dev,raw,echo=0 pty,link=/tmp/bus,raw,echo=0 &
    while [ ! -e /tmp/dev ] || [ ! -e /tmp/bus ]; do sleep 0.1; done
    # -p: 8N1, a PTY does not model parity (pydlms connects over TCP).
    /opt/addiva-libmbus/bin/mbus-device -p -d -a "$2" /tmp/dev &
    echo "mbus-device ready on address $2"
    # One connection at a time (no fork): two readers on one PTY would split
    # the bytes between them. Run with --network host.
    while true; do
      socat "tcp-listen:$3,bind=127.0.0.1,reuseaddr" file:/tmp/bus,raw,echo=0 || sleep 0.1
    done
    ;;
  *)
    echo "usage: master ... | device ADDRESS PORT" >&2
    exit 2
    ;;
esac
