# The Gurux.DLMS.Net *client* library as an independent generator of
# general-ciphering (0xDD, one-pass Diffie-Hellman) and general-signing
# (0xDF) APDUs, which pydlms must decrypt and verify. GPL-2.0-only; fetched
# and built here, only run as a separate process. No Gurux code is copied
# into pydlms.
#
# Build:  docker build -t pydlms-gurux-client tests/integration/gurux_client
# Run:    docker run --rm pydlms-gurux-client MODE SIGN_PRIV KA_PUB SIGN_PUB
#         MODE is general-ciphering or general-signing; keys are hex (P-256
#         private scalar, public X||Y). Prints one WRAPPER frame per line.
#         docker run --rm -i pydlms-gurux-client translate simple [EK AK]
#         is GXDLMSTranslator as an XML oracle (tests/gurux_xml_corpus.py).

ARG GURUX_REPO=https://github.com/Gurux/Gurux.DLMS.Net.git
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
# Build fix: only netstandard2.1, no NuGet packing (see ../gurux/Dockerfile).
#
# Defect fixes in Development/GXDLMS.cs. They change only *whether* Gurux
# signs; the APDU encoding (Cipher1) is upstream code:
#  1. ShoudSign() treats every Signing mode, one-pass DH included, as
#     general-signing; Cipher1 then dereferences a missing ephemeral key
#     (NullReferenceException). Sign only for Signing.GeneralSigning.
#  2. Cipher1 drops the signature of a general-signing APDU unless
#     Cipher.Signing is set, emitting 0xDF without a signature. Always sign.
#  3. With 1 fixed, key agreement must still be routed to Cipher1.
#  4. Cipher1 truncates the agreed key to 16 octets for every suite; suite 2
#     (AES-256) needs 32. GenerateKDF itself returns the full SHA-384 output.
#  5. The one-pass DH key-ciphered-data length is hardcoded 0x80 (P-256:
#     64-octet point + 64-octet signature); P-384 writes 192 octets.
RUN sed -i 's#<TargetFrameworks>.*</TargetFrameworks>#<TargetFrameworks>netstandard2.1</TargetFrameworks>#; s#<GeneratePackageOnBuild>true#<GeneratePackageOnBuild>false#' \
        Development/Gurux.DLMS.Net.csproj \
 && sed -i 's#(p.settings.Cipher != null \&\& p.settings.Cipher.Signing != Signing.None);#(p.settings.Cipher != null \&\& p.settings.Cipher.Signing == Signing.GeneralSigning);#' \
        Development/GXDLMS.cs \
 && sed -i 's#if (sign \&\& p.settings.Cipher.Signing != Signing.None)#if (sign)#' \
        Development/GXDLMS.cs \
 && sed -i 's#^\(\s*\)!sign)$#\1!(sign || (p.settings.Cipher != null \&\& p.settings.Cipher.Signing != Signing.None)))#' \
        Development/GXDLMS.cs \
 && sed -i 's#kdf.SubArray(0, 16),#kdf.SubArray(0, c.SecuritySuite == SecuritySuite.Suite2 ? 32 : 16),#' \
        Development/GXDLMS.cs \
 && grep -q 'Suite2 ? 32 : 16' Development/GXDLMS.cs \
 && sed -i 's#GXCommon.SetObjectCount(0x80, reply);#GXCommon.SetObjectCount(2 * (c.EphemeralKeyPair.Key.RawValue.Length - 1), reply);#' \
        Development/GXDLMS.cs \
 && grep -q 'SetObjectCount(2 \* (c.EphemeralKeyPair' Development/GXDLMS.cs \
 && test "$(grep -c 'Signing == Signing.GeneralSigning);' Development/GXDLMS.cs)" -ge 1 \
 && grep -q '^\s*if (sign)$' Development/GXDLMS.cs \
 && grep -q '!(sign || (p.settings.Cipher' Development/GXDLMS.cs
COPY gxclient.csproj Program.cs /harness/
RUN dotnet build -c Release -o /out /harness/gxclient.csproj \
 && cp LICENSE /out/GURUX-LICENSE

FROM mcr.microsoft.com/dotnet/runtime:8.0
ARG GURUX_COMMIT
LABEL org.opencontainers.image.source="https://github.com/Gurux/Gurux.DLMS.Net" \
      org.opencontainers.image.revision="${GURUX_COMMIT}" \
      org.opencontainers.image.licenses="GPL-2.0-only"
COPY --from=build /out /app
ENTRYPOINT ["dotnet", "/app/gxclient.dll"]
