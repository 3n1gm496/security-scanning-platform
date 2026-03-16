FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Pinned binary versions — update these ARGs to upgrade scanner binaries.
# Versions verified against GitHub releases on 2026-03-13.
ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.30.0
ARG SYFT_VERSION=1.42.2
ARG NUCLEI_VERSION=3.7.1
ARG GRYPE_VERSION=0.109.1
ARG GO_VERSION=1.25.7

# Use non-root user to avoid permission issues with host volumes
RUN groupadd -g 1000 scanuser && \
    useradd -u 1000 -g scanuser -m -s /bin/bash scanuser

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
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
    # Keep Trivy CI gate clean by forcing patched transitive packages.
    # Install wheel without deps to avoid upgrading packaging beyond checkov's pin.
    pip install --no-cache-dir --no-deps "wheel>=0.46.2" && \
    pip install --no-cache-dir "jaraco.context>=6.1.0"

# Install modern Go toolchain to build patched scanner binaries from source.
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm -f /tmp/go.tgz

ENV PATH="/usr/local/go/bin:${PATH}"

# Build gitleaks from source with the patched Go toolchain.
RUN GOBIN=/usr/local/bin go install "github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}"

# Build trivy from source and bump docker/cli dependency to the fixed version.
RUN git clone --depth 1 --branch "v${TRIVY_VERSION}" https://github.com/aquasecurity/trivy.git /tmp/trivy-src && \
    cd /tmp/trivy-src && \
    go get github.com/docker/cli@v29.2.0 && \
    GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /usr/local/bin/trivy ./cmd/trivy && \
    rm -rf /tmp/trivy-src

# Remove Go toolchain and module caches so the final runtime image does not
# retain build-only sources, sample secrets, or unnecessary attack surface.
RUN go clean -cache -modcache && \
    rm -rf /root/go /usr/local/go

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
