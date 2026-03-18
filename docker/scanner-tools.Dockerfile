# syntax=docker/dockerfile:1.7

ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.30.0
ARG SYFT_VERSION=1.42.2
ARG NUCLEI_VERSION=3.7.1
ARG GRYPE_VERSION=0.109.1
ARG GO_VERSION=1.26.1
ARG SEMGREP_VERSION=1.156.0
ARG CHECKOV_VERSION=3.1.47

FROM python:3.11-slim AS scanner-tools

ARG TRIVY_VERSION
ARG GITLEAKS_VERSION
ARG SYFT_VERSION
ARG NUCLEI_VERSION
ARG GRYPE_VERSION
ARG GO_VERSION
ARG SEMGREP_VERSION
ARG CHECKOV_VERSION

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PATH="/usr/local/bin:/opt/scanner-venv/bin:/usr/local/go/bin:${PATH}"

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir requests

# Build patched Go scanner binaries once so the app images can reuse the cache.
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm -f /tmp/go.tgz

RUN python -m venv /opt/scanner-venv && \
    /opt/scanner-venv/bin/pip install --no-cache-dir --upgrade \
      "pip>=26.0.1" \
      "setuptools==80.9.0" \
      "wheel>=0.46.2"

COPY docker/semgrep-wrapper.sh /usr/local/bin/semgrep
RUN chmod 0755 /usr/local/bin/semgrep

RUN --mount=type=cache,target=/root/.cache/pip \
    /opt/scanner-venv/bin/pip install --no-cache-dir \
      "semgrep==${SEMGREP_VERSION}" && \
    /opt/scanner-venv/bin/pip install --no-cache-dir "checkov==${CHECKOV_VERSION}" && \
    /opt/scanner-venv/bin/pip install --no-cache-dir --upgrade --force-reinstall \
      "protobuf>=5.29.6,<6" \
      "jaraco.context>=6.1.0" \
      "wheel>=0.46.2" && \
    find /opt/scanner-venv/lib/python3.11/site-packages \
      \( -name 'protobuf-4*.dist-info' -o -name 'wheel-0.45*.dist-info' -o -name 'jaraco.context-5*.dist-info' -o -name 'jaraco_context-5*.dist-info' \) \
      -exec rm -rf {} +

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    GOBIN=/usr/local/bin go install "github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}"

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    GOBIN=/usr/local/bin CGO_ENABLED=0 go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}"

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    git clone --depth 1 --branch "v${TRIVY_VERSION}" https://github.com/aquasecurity/trivy.git /tmp/trivy-src && \
    cd /tmp/trivy-src && \
    go get github.com/docker/cli@v29.2.0 && \
    GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /usr/local/bin/trivy ./cmd/trivy

COPY orchestrator/scripts/fetch_binaries.py /tmp/fetch_binaries.py

RUN python /tmp/fetch_binaries.py \
      --syft-version "${SYFT_VERSION}" \
      --grype-version "${GRYPE_VERSION}" \
      --nuclei-version "${NUCLEI_VERSION}" && \
    semgrep --version && \
    checkov --version && \
    trivy --version && \
    gitleaks version && \
    syft version && \
    grype version && \
    nuclei -version
