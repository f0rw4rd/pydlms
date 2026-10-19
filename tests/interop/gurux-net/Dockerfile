# Gurux.DLMS.Net (GPL-2.0-only) as an interop oracle speaking
# tests/interop/PROTOCOL.md on stdin/stdout. The library is fetched at a
# pinned commit and built here; it only runs as a separate process. No Gurux
# code is copied into pydlms. Adapter: Program.cs (which Gurux API answers
# each op is listed at its top).
#
# Build:  docker build -t pydlms-interop-gurux-net tests/interop/gurux-net
# Run:    python -m tests.interop.compare pydlms-interop-gurux-net
#         echo "data 0601020304" | docker run --rm -i pydlms-interop-gurux-net
#         docker run --rm --network host pydlms-interop-gurux-net client HOST PORT none
#         (phase 4: the Gurux client reading a server, see Reverse.cs)

ARG GURUX_REPO=https://github.com/Gurux/Gurux.DLMS.Net.git
# Same pin as tests/integration/gurux and tests/integration/gurux_client.
ARG GURUX_COMMIT=6f263019caab62eb038dad7b1fa130edc7097081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG GURUX_REPO
ARG GURUX_COMMIT
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
WORKDIR /src
RUN git init -q . \
 && git remote add origin "$GURUX_REPO" \
 && git fetch -q --depth 1 origin "$GURUX_COMMIT" \
 && git checkout -q FETCH_HEAD
# Build-only changes to our copy, no behaviour change:
#  1. Build only netstandard2.1 and skip NuGet packing (the 8.0 SDK cannot
#     restore the net9/net10/net4x targets).
#  2. Expose the library's internals to the adapter assembly ("gxoracle"),
#     so it can call the decoder (GXCommon.GetData) and AES-GCM
#     (GXSecure.DecryptAesGcm) that the public client wraps.
RUN sed -i 's#<TargetFrameworks>.*</TargetFrameworks>#<TargetFrameworks>netstandard2.1</TargetFrameworks>#; s#<GeneratePackageOnBuild>true#<GeneratePackageOnBuild>false#' \
        Development/Gurux.DLMS.Net.csproj \
 && echo '[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("gxoracle")]' \
        > Development/OracleInternals.cs
COPY gxoracle.csproj Program.cs Reverse.cs /adapter/
RUN dotnet build -c Release -o /out /adapter/gxoracle.csproj \
 && cp LICENSE /out/GURUX-LICENSE

FROM mcr.microsoft.com/dotnet/runtime:8.0
ARG GURUX_COMMIT
LABEL org.opencontainers.image.source="https://github.com/Gurux/Gurux.DLMS.Net" \
      org.opencontainers.image.revision="${GURUX_COMMIT}" \
      org.opencontainers.image.licenses="GPL-2.0-only"
ENV GURUX_COMMIT=${GURUX_COMMIT} DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
COPY --from=build /out /app
ENTRYPOINT ["dotnet", "/app/gxoracle.dll"]
