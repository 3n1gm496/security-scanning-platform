# syntax=docker/dockerfile:1.7

ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.30.0
ARG SYFT_VERSION=1.42.2
ARG NUCLEI_VERSION=3.7.1
ARG GRYPE_VERSION=0.109.1
ARG GO_VERSION=1.25.7

FROM python:3.11-slim AS scanner-builder

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

# Install modern Go toolchain to build patched scanner binaries from source.
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm -f /tmp/go.tgz

ENV PATH="/usr/local/go/bin:${PATH}"

# Build gitleaks from source with the patched Go toolchain.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    GOBIN=/usr/local/bin go install "github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}"

# Build trivy from source and bump docker/cli dependency to the fixed version.
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/root/go/pkg/mod \
    git clone --depth 1 --branch "v${TRIVY_VERSION}" https://github.com/aquasecurity/trivy.git /tmp/trivy-src && \
    cd /tmp/trivy-src && \
    go get github.com/docker/cli@v29.2.0 && \
    GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /usr/local/bin/trivy ./cmd/trivy

COPY orchestrator/scripts/fetch_binaries.py /tmp/fetch_binaries.py

# Install scanner binaries from GitHub releases with SHA-256 verification.
RUN python /tmp/fetch_binaries.py \
      --syft-version "${SYFT_VERSION}" \
      --grype-version "${GRYPE_VERSION}" \
      --nuclei-version "${NUCLEI_VERSION}" && \
    trivy --version && \
    gitleaks version && \
    syft version && \
    grype version && \
    nuclei -version

FROM python:3.11-slim

ARG TRIVY_VERSION
ARG GITLEAKS_VERSION
ARG SYFT_VERSION
ARG NUCLEI_VERSION
ARG GRYPE_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Use non-root user to avoid permission issues with host volumes
RUN groupadd -g 1000 scanuser && \
    useradd -u 1000 -g scanuser -m -s /bin/bash scanuser

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is the repository root. All COPY paths are relative to the
# repo root so that the shared common/ package can be included.
COPY orchestrator/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    pip install --no-cache-dir semgrep checkov bandit && \
    # Keep Trivy CI gate clean by reinstalling the patched packages after
    # checkov pins older vulnerable versions.
    pip uninstall -y wheel jaraco.context && \
    pip install --no-cache-dir --no-deps "wheel>=0.46.2" && \
    pip install --no-cache-dir "jaraco.context>=6.1.0" && \
    find /usr/local/lib/python3.11/site-packages -maxdepth 1 \
      \( -name 'wheel-0.45.1.dist-info' -o -name 'jaraco.context-5.3.0.dist-info' -o -name 'jaraco_context-5.3.0.dist-info' \) \
      -exec rm -rf {} +

COPY --from=scanner-builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=scanner-builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=scanner-builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=scanner-builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=scanner-builder /usr/local/bin/nuclei /usr/local/bin/nuclei

RUN trivy --version && \
    gitleaks version && \
    syft version && \
    grype version && \
    nuclei -version

# Install python-owasp-zap-v2.4 client library for ZAP REST API integration.
# This is a lightweight Python client; the actual ZAP server is expected to run
# as a separate container (see config/settings.yaml for setup instructions).
RUN pip install --no-cache-dir python-owasp-zap-v2.4

COPY orchestrator/ /app/orchestrator
COPY common/ /app/common

WORKDIR /app/orchestrator
RUN pip install -e . && \
    chown -R scanuser:scanuser /app

# Pre-download nuclei templates so the first scan does not need internet access.
# Templates are stored in ~/nuclei-templates (nuclei v3 default path).
# run_nuclei() always passes -duc (disable-update-check) to suppress update warnings at runtime.
USER scanuser
RUN nuclei -ut -duc 2>&1 | tail -5 \
    || echo "WARNING: nuclei template update failed — templates will be downloaded on first scan"

ENTRYPOINT ["python", "-m", "orchestrator.main"]
CMD ["--help"]
