#!/bin/sh
# Default: the PROTOCOL.md oracle adapter. "server [args]": the example
# server (default base port 4060). "client <args>": the example client. Absolute path on purpose, see Dockerfile.
if [ "$1" = "server" ]; then
    shift
    [ $# -eq 0 ] && set -- -p 4060
    # Line-buffered so "Press Enter to close application." reaches docker logs.
    exec stdbuf -oL /home/meter/srv/gurux.dlms.server.bin "$@"
fi
if [ "$1" = "client" ]; then
    shift
    exec /usr/local/bin/gurux.dlms.client.bin "$@"
fi
exec /usr/local/bin/gurux-c-adapter "$@"
