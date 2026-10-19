# github.com/cB-Sigma/dlms (Go, Apache-2.0) as a pydlms interop oracle,
# server and client.
#
#   docker build -t pydlms-interop-go-dlms tests/interop/go-dlms
#   docker run --rm -i pydlms-interop-go-dlms                 # oracle (PROTOCOL.md)
#   docker run --rm -p 4059:4059 pydlms-interop-go-dlms server  # meter, TCP wrapper
#   docker run --rm --network host pydlms-interop-go-dlms client -port 4059 ...
#   docker run --rm -p 4059:4059 pydlms-interop-go-dlms iec21 -wake fast  # IEC 62056-21
#   docker run --rm -p 4059:4059 pydlms-interop-go-dlms hdlc -modulo128   # HDLC, SNRME
#
# The library is cloned at a pinned commit; its A-XDR/xDLMS codec is the
# dependency gitlab.com/circutor-library/gosem v1.3.4 (MIT), pinned by the
# library's go.sum. shim/*.go are copied into the library's packages: they
# only export unexported functions (the server's AARQ parser, the client's
# opening of ciphered APDUs) for the adapter and add no behaviour.
FROM golang:1.25 AS build
ARG DLMS_COMMIT=26360a13e5d8f1da0fba1758118adaaa00be2ccf
RUN git clone https://github.com/cB-Sigma/dlms.git /src/dlms \
    && git -C /src/dlms checkout --detach "$DLMS_COMMIT" \
    && test "$(git -C /src/dlms rev-parse HEAD)" = "$DLMS_COMMIT"
COPY shim/cosem_interop.go /src/dlms/cosem/zz_interop.go
COPY shim/server_interop.go /src/dlms/server/zz_interop.go
COPY adapter /src/adapter
WORKDIR /src/adapter
RUN go mod tidy && go vet . && CGO_ENABLED=0 go build -trimpath -o /godlms .

FROM scratch
COPY --from=build /godlms /godlms
EXPOSE 4059
ENTRYPOINT ["/godlms"]
