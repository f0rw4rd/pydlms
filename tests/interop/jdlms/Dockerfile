# OpenMUC jDLMS as an interop oracle, server and client for pydlms
# (tests/interop/PROTOCOL.md).
#
# jDLMS is GPL-3.0 (license block of its Maven Central POM). It is fetched
# here at a pinned version and only ever run as a separate process; no jDLMS
# code is copied into pydlms. src/*.java is our glue: it maps jDLMS objects to
# the oracle JSON model and wires DlmsServer / DlmsConnection.
#
# Build:  docker build -t pydlms-interop-jdlms tests/interop/jdlms
# Run:    docker run --rm -i pydlms-interop-jdlms                  (oracle, stdin/stdout)
#         docker run --rm -p 4059:4059 pydlms-interop-jdlms server [none|lls|hls5]
#         docker run --rm --network host pydlms-interop-jdlms client HOST PORT [none|lls|hls5]

ARG JDLMS_VERSION=1.8.0

FROM maven:3.9.9-eclipse-temurin-17 AS build
ARG JDLMS_VERSION
WORKDIR /b
COPY pom.xml .
RUN sed -i "s#<version>1.8.0</version>#<version>${JDLMS_VERSION}</version>#" pom.xml \
 && mvn -q -B dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory=/b/lib \
 && test -f "/b/lib/jdlms-${JDLMS_VERSION}.jar"
COPY src/ src/
RUN mkdir classes \
 && javac -Xlint:-options --release 11 -nowarn -d classes -cp '/b/lib/*' src/*.java \
 && jar cfe /b/jdlms-interop.jar Main -C classes .

FROM eclipse-temurin:17-jre
ARG JDLMS_VERSION
LABEL org.opencontainers.image.source="https://www.openmuc.org/dlms-cosem/" \
      org.opencontainers.image.version="${JDLMS_VERSION}" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"
COPY --from=build /b/lib /app/lib
COPY --from=build /b/jdlms-interop.jar /app/
EXPOSE 4059
ENTRYPOINT ["java", "-cp", "/app/jdlms-interop.jar:/app/lib/*", "Main"]
CMD ["oracle"]
