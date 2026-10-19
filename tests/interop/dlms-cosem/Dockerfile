# dlms-cosem (pwitab) as an interop oracle, at the last MIT-licensed commit.
#
# 0747b15 (2022-12-29) is 21.3.2 plus VisibleStringData; every later commit is
# under the Business Source License 1.1 (THIRD_PARTY.md). Nothing from this
# image is copied into pydlms; it only runs as a separate process.
#
# Build: docker build -t pydlms-interop-dlms-cosem tests/interop/dlms-cosem
FROM python:3.11.10-slim-bookworm
ARG DLMS_COSEM_COMMIT=0747b152b91f40ff13c415dc35d208f63676f501
# Dependency pins contemporary with the commit (setup.py lower bounds).
RUN pip install --no-cache-dir \
        attrs==22.2.0 pyserial==3.5 cryptography==38.0.4 asn1crypto==1.5.1 \
        python-dateutil==2.8.2 typing-extensions==4.4.0 \
 && pip install --no-cache-dir --no-deps \
        "https://github.com/pwitab/dlms-cosem/archive/${DLMS_COSEM_COMMIT}.tar.gz" \
 && echo "${DLMS_COSEM_COMMIT}" > /etc/dlms-cosem-commit
RUN useradd -m oracle
COPY adapter.py client_reverse.py /opt/oracle/
USER oracle
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-I", "/opt/oracle/adapter.py"]
