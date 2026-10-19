# Gurux.DLMS.Simulator.Net as a black-box interop target for pydlms
# integration tests. The simulator is GPL-2.0-only; it is fetched and built
# here and only talked to over TCP. No Gurux code is copied into pydlms.
#
# Build:  docker build -t pydlms-gurux-sim tests/integration/gurux
# Run:    docker run --rm -p 4061:4060 -e SIM_IFACE=WRAPPER pydlms-gurux-sim
# See README.md next to this file for every mode and its client parameters.

ARG GURUX_REPO=https://github.com/Gurux/Gurux.DLMS.Net.git
# Pinned commit of Gurux.DLMS.Net (2026-09-22). The simulator lives in its
# Gurux.DLMS.Simulator.Net/ subdirectory.
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
# Local build fixes, applied to our copy only:
#  1. The library multi-targets net10/net9/net4x, which the 8.0 SDK cannot
#     restore; build only netstandard2.1 and skip NuGet packing.
#  2. The simulator targets net9.0; retarget to net8.0 (LTS).
#  3. The simulator blocks on Console.ReadKey(), which throws without a TTY
#     (docker without -it, nohup). Sleep forever instead when stdin is not a
#     console.
RUN sed -i 's#<TargetFrameworks>.*</TargetFrameworks>#<TargetFrameworks>netstandard2.1</TargetFrameworks>#; s#<GeneratePackageOnBuild>true#<GeneratePackageOnBuild>false#' \
        Development/Gurux.DLMS.Net.csproj \
 && sed -i 's#<TargetFramework>net9.0</TargetFramework>#<TargetFramework>net8.0</TargetFramework>#' \
        Gurux.DLMS.Simulator.Net/Gurux.DLMS.Simulator.Net.csproj \
 && sed -i 's#^\(\s*\)ConsoleKey k;#\1if (Console.IsInputRedirected) { Thread.Sleep(Timeout.Infinite); }\n\1ConsoleKey k;#' \
        Gurux.DLMS.Simulator.Net/Program.cs \
 && grep -c 'IsInputRedirected' Gurux.DLMS.Simulator.Net/Program.cs
RUN dotnet build -c Release -o /out Gurux.DLMS.Simulator.Net/Gurux.DLMS.Simulator.Net.csproj \
 && mkdir -p /templates \
 && cp Gurux.DLMS.Simulator.Net/*.xml Gurux.DLMS.Simulator.Net/Templates/*.xml /templates/ \
 && cp LICENSE /out/GURUX-LICENSE

FROM mcr.microsoft.com/dotnet/runtime:8.0
ARG GURUX_COMMIT
LABEL org.opencontainers.image.source="https://github.com/Gurux/Gurux.DLMS.Net" \
      org.opencontainers.image.revision="${GURUX_COMMIT}" \
      org.opencontainers.image.licenses="GPL-2.0-only"
COPY --from=build /out /app
COPY --from=build /templates /templates
# SIM_TEMPLATE: a file name under /templates, or an absolute path to a
# template mounted into the container. SIM_IFACE: WRAPPER or HDLC.
ENV SIM_PORT=4060 \
    SIM_IFACE=WRAPPER \
    SIM_TEMPLATE=GMacWithAuthenticationEncyption.xml \
    SIM_TRACE=Info
EXPOSE 4060
# The simulator may rewrite its template, so it runs on a copy in /tmp.
ENTRYPOINT ["/bin/sh", "-c", "case \"$SIM_TEMPLATE\" in /*) t=\"$SIM_TEMPLATE\";; *) t=\"/templates/$SIM_TEMPLATE\";; esac; cp \"$t\" /tmp/sim.xml && exec dotnet /app/Gurux.DLMS.Simulator.Net.dll -p \"$SIM_PORT\" -i \"$SIM_IFACE\" -t \"$SIM_TRACE\" -x /tmp/sim.xml \"$@\"", "sim"]
