# Hazmat analysis sandbox: the one image both backends run.
#   Modal:  modal.Image.from_dockerfile("sandbox/Dockerfile")
#   Docker: docker build --platform linux/amd64 -t hazmat-sandbox sandbox/
# Always linux/amd64, so local runs match Modal exactly.
#
# Static analysis only. Nothing in this image executes the sample.

FROM eclipse-temurin:25-jdk-noble

ARG GHIDRA_VERSION=12.2
ARG GHIDRA_BUILD=20261016
ARG CAPA_VERSION=10.0.0
ARG FLOSS_VERSION=3.2.0

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PATH=/opt/venv/bin:$PATH \
    GHIDRA_HOME=/opt/ghidra \
    CAPA_RULES=/opt/capa-rules \
    CAPA_SIGS=/opt/capa-sigs

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv python3-dev build-essential git unzip curl ca-certificates \
        binutils file yara \
    && rm -rf /var/lib/apt/lists/*

# Ghidra (headless analyzer + decompiler)
RUN curl -fsSL -o /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD}.zip" \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless

# capa (+ matching rules and library signatures), FLOSS, yara-python
RUN python3 -m venv /opt/venv \
    && pip install "flare-capa==${CAPA_VERSION}" "flare-floss==${FLOSS_VERSION}" yara-python \
    && git clone --depth 1 --branch "v${CAPA_VERSION}" https://github.com/mandiant/capa-rules "${CAPA_RULES}" \
    && git clone --depth 1 --branch "v${CAPA_VERSION}" --filter=blob:none --sparse https://github.com/mandiant/capa /tmp/capa \
    && git -C /tmp/capa sparse-checkout set sigs \
    && mv /tmp/capa/sigs "${CAPA_SIGS}" && rm -rf /tmp/capa

# Ghidra post-script that exports functions, imports, strings and decompiled C as JSON
COPY ghidra/ /opt/hazmat/ghidra/

# Run as an unprivileged user; /work holds the sample and outputs.
RUN useradd -m -u 1001 analyst && mkdir -p /work && chown analyst /work
USER analyst
WORKDIR /work
