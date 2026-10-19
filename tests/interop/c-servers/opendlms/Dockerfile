# opendlms (Anthony Rabine, MIT) meter simulator as a separate process for
# the pydlms interop sweep.
#
#   docker build -t pydlms-interop-opendlms tests/interop/c-servers/opendlms
#
# github.com/arabine/opendlms answers 404 since at least 2026-10-16; the
# fetch uses github.com/desitn/opendlms, which carries the same commits
# (author anthony@rabine.fr, MIT LICENSE). Pinned to its HEAD.
#
# examples/metersimulator: TCP wrapper (IEC 62056-47) on port 4063,
# client SAP 16 (public) and 1 (management), server SAP 1.
FROM debian:bookworm-slim AS build
ARG OPENDLMS_REPO=https://github.com/desitn/opendlms
ARG OPENDLMS_COMMIT=c3a4846f79d21cbe70c16313fd517cc4ba4e66e8
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN git init /src && cd /src \
    && git remote add origin "$OPENDLMS_REPO" \
    && git fetch --depth 1 origin "$OPENDLMS_COMMIT" \
    && git checkout --detach FETCH_HEAD
WORKDIR /src/examples/metersimulator/build
RUN cmake .. && make && test -x metersimulator

FROM debian:bookworm-slim
RUN useradd -m meter
COPY --from=build /src/examples/metersimulator/build/metersimulator /usr/local/bin/
USER meter
WORKDIR /home/meter
EXPOSE 4063
# stdbuf: the simulator logs with printf; line-buffer it for `docker logs`.
ENTRYPOINT ["stdbuf", "-oL", "-eL", "metersimulator"]
