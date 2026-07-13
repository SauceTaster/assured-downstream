FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ARG TARGETARCH
ARG VCS_REF=unknown

LABEL org.opencontainers.image.title="Assured Downstream Python Builder" \
      org.opencontainers.image.description="No-network, traced pure-Python package builder" \
      org.opencontainers.image.source="https://github.com/SauceTaster/assured-downstream" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.assured-downstream.builder.profile="python-wheel-v1"

COPY builders/python/requirements.lock /opt/assured-downstream/requirements.lock
COPY builders/python/entrypoint.py /opt/assured-downstream/entrypoint.py

RUN test "${TARGETARCH}" = "amd64" \
    && python -c "import hashlib, pathlib, urllib.request; url='https://deb.debian.org/debian/pool/main/libu/libunwind/libunwind8_1.6.2-3_amd64.deb'; target=pathlib.Path('/tmp/libunwind8.deb'); urllib.request.urlretrieve(url, target); actual=hashlib.sha256(target.read_bytes()).hexdigest(); expected='7b297868682836e4c87be349f17e4a56bc287586e3576503e84a5cb5485ce925'; assert actual == expected, (actual, expected)" \
    && python -c "import hashlib, pathlib, urllib.request; url='https://deb.debian.org/debian/pool/main/s/strace/strace_6.1-0.1_amd64.deb'; target=pathlib.Path('/tmp/strace.deb'); urllib.request.urlretrieve(url, target); actual=hashlib.sha256(target.read_bytes()).hexdigest(); expected='1942d086a6244a1a9643489d3b0aa604ac44b88991d6c69217a63a193671bd4f'; assert actual == expected, (actual, expected)" \
    && dpkg -i /tmp/libunwind8.deb /tmp/strace.deb \
    && rm -f /tmp/libunwind8.deb /tmp/strace.deb \
    && python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/assured-downstream/requirements.lock \
    && python -m pip check \
    && printf 'assured:x:65532:65532:Assured Downstream:/tmp/home:/usr/sbin/nologin\n' >> /etc/passwd \
    && printf 'assured:x:65532:\n' >> /etc/group \
    && chmod 0444 /opt/assured-downstream/requirements.lock \
    && chmod 0555 /opt/assured-downstream/entrypoint.py

ENV HOME=/tmp/home \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/usr/local/bin:/usr/bin:/bin \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INDEX=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    TZ=UTC

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["python", "-I", "/opt/assured-downstream/entrypoint.py"]
