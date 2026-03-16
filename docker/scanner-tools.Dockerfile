# syntax=docker/dockerfile:1.7

ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.30.0
ARG SYFT_VERSION=1.42.2
ARG NUCLEI_VERSION=3.7.1
ARG GRYPE_VERSION=0.109.1
ARG GO_VERSION=1.25.7

FROM python:3.11-slim AS scanner-tools

ARG TRIVY_VERSION
ARG GITLEAKS_VERSION
ARG SYFT_VERSION
ARG NUCLEI_VERSION
ARG GRYPE_VERSION
ARG GO_VERSION

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

ENV PATH="/usr/local/go/bin:${PATH}"

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    GOBIN=/usr/local/bin go install "github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}"

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
    trivy --version && \
    gitleaks version && \
    syft version && \
    grype version && \
    nuclei -version
