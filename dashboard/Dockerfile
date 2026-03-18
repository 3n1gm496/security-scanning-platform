# syntax=docker/dockerfile:1.7

ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.30.0
ARG SYFT_VERSION=1.42.2
ARG NUCLEI_VERSION=3.7.1
ARG GRYPE_VERSION=0.109.1
ARG GO_VERSION=1.26.1
ARG SEMGREP_VERSION=1.156.0
ARG CHECKOV_VERSION=3.1.47

FROM python:3.11-slim AS scanner-builder

ARG TRIVY_VERSION
ARG GITLEAKS_VERSION
ARG SYFT_VERSION
ARG NUCLEI_VERSION
ARG GRYPE_VERSION
ARG SEMGREP_VERSION
ARG CHECKOV_VERSION
ARG GO_VERSION

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

# Build patched Go binaries so Trivy does not flag the vendored stdlib/modules.
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
      --grype-version "${GRYPE_VERSION}" && \
    semgrep --version && \
    checkov --version && \
    trivy --version && \
    gitleaks version && \
    syft version && \
    grype version && \
    nuclei -version

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PATH="/usr/local/bin:/opt/scanner-venv/bin:${PATH}"

# ── Non-root user ──────────────────────────────────────────────────────────────
# Run the dashboard as an unprivileged user. UID/GID 1000 matches the default
# host user on most Linux systems, avoiding permission issues on mounted volumes.
RUN groupadd -g 1000 dashuser && \
    useradd -u 1000 -g dashuser -m -s /bin/bash dashuser

# ── System dependencies ────────────────────────────────────────────────────────
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TRIVY_VERSION
ARG GITLEAKS_VERSION
ARG SYFT_VERSION
ARG NUCLEI_VERSION
ARG GRYPE_VERSION
ARG SEMGREP_VERSION
ARG CHECKOV_VERSION

WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────────────────
# Install dashboard and orchestrator Python deps in one layer
COPY dashboard/requirements.txt /tmp/requirements-dashboard.txt
COPY orchestrator/requirements.txt /tmp/requirements-orchestrator.txt
RUN pip install --no-cache-dir \
    -r /tmp/requirements-dashboard.txt \
    -r /tmp/requirements-orchestrator.txt
RUN pip install --no-cache-dir --upgrade \
      "setuptools==80.9.0" \
      "wheel>=0.46.2" \
      "jaraco.context>=6.1.0" && \
    find /usr/local/lib/python3.11/site-packages \
      \( -name 'wheel-0.45*.dist-info' -o -name 'jaraco.context-5*.dist-info' -o -name 'jaraco_context-5*.dist-info' \) \
      -exec rm -rf {} +

# ── External scanner binaries ──────────────────────────────────────────────────
# Scanner binaries are built or fetched in the builder stage so the runtime
# image only contains the final patched executables.
COPY docker/semgrep-wrapper.sh /usr/local/bin/semgrep
COPY --from=scanner-builder /opt/scanner-venv /opt/scanner-venv
COPY --from=scanner-builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=scanner-builder /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=scanner-builder /usr/local/bin/syft /usr/local/bin/syft
COPY --from=scanner-builder /usr/local/bin/grype /usr/local/bin/grype
COPY --from=scanner-builder /usr/local/bin/nuclei /usr/local/bin/nuclei

RUN chmod 0755 /usr/local/bin/semgrep /usr/local/bin/gitleaks /usr/local/bin/trivy /usr/local/bin/syft /usr/local/bin/grype /usr/local/bin/nuclei && \
    find /opt/scanner-venv/lib/python3.11/site-packages \
      \( -name 'protobuf-4*.dist-info' -o -name 'wheel-0.45*.dist-info' -o -name 'jaraco.context-5*.dist-info' -o -name 'jaraco_context-5*.dist-info' \) \
      -exec rm -rf {} + && \
    find /usr/local/lib/python3.11/site-packages \
      \( -name 'wheel-0.45*.dist-info' -o -name 'jaraco.context-5*.dist-info' -o -name 'jaraco_context-5*.dist-info' \) \
      -exec rm -rf {} + && \
    semgrep --version && \
    checkov --version && \
    trivy --version && \
    gitleaks version && \
    syft version && \
    grype version && \
    nuclei -version

# ── Application code ───────────────────────────────────────────────────────────
# Copy dashboard code to /app
COPY dashboard/ /app/

# Copy orchestrator code to /orchestrator
# (root_dir = /app/.. = /, so orchestrator will be at /orchestrator)
COPY orchestrator/ /orchestrator/

# Copy shared common package (schema definitions shared with orchestrator)
COPY common/ /common/

# Copy default configuration
COPY config/ /config/

# ── Data directories ───────────────────────────────────────────────────────────
RUN mkdir -p /data/workspaces /data/reports /data/cache \
    && chown -R dashuser:dashuser /app /orchestrator /common /config /data

# Keep the final runtime image free of stale vendored metadata that Trivy flags
# even after pip upgrades the active packages.
RUN find /opt/scanner-venv/lib/python3.11/site-packages \
      \( -name 'protobuf-4*.dist-info' -o -name 'wheel-0.45*.dist-info' -o -name 'jaraco.context-5*.dist-info' -o -name 'jaraco_context-5*.dist-info' \) \
      -exec rm -rf {} + && \
    find /usr/local/lib/python3.11/site-packages \
      \( -name 'wheel-0.45*.dist-info' -o -name 'jaraco.context-5*.dist-info' -o -name 'jaraco_context-5*.dist-info' \) \
      -exec rm -rf {} +

# Drop to non-root for runtime
USER dashuser

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
