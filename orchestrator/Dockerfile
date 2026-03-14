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

# Use non-root user to avoid permission issues with host volumes
RUN groupadd -g 1000 scanuser && \
    useradd -u 1000 -g scanuser -m -s /bin/bash scanuser

RUN apt-get update && apt-get install -y --no-install-recommends \
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
    pip install --no-cache-dir semgrep checkov bandit

# Install Trivy (filesystem + container vulnerability scanner).
# Download the pre-built .tar.gz directly from GitHub releases to avoid
# relying on the install.sh wrapper script which queries the GitHub API
# and can fail in CI environments with rate-limited or restricted network access.
RUN TRIVY_ARCH="Linux-64bit" && \
    curl -sSfL \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
      -o /tmp/trivy.tar.gz && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    trivy --version

# Install Gitleaks (secret scanner).
RUN curl -sSfL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm /tmp/gitleaks.tar.gz && \
    gitleaks version

# Install Syft (SBOM generator).
# Same rationale as Trivy: direct asset download is more reliable in CI.
RUN SYFT_VERSION_PLAIN="${SYFT_VERSION#v}" && \
    curl -sSfL \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION_PLAIN}/syft_${SYFT_VERSION_PLAIN}_linux_amd64.tar.gz" \
      -o /tmp/syft.tar.gz && \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft && \
    rm /tmp/syft.tar.gz && \
    syft version

# Install Grype (vulnerability scanner for SBOMs and container images).
RUN GRYPE_VERSION_PLAIN="${GRYPE_VERSION#v}" && \
    curl -sSfL \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION_PLAIN}/grype_${GRYPE_VERSION_PLAIN}_linux_amd64.tar.gz" \
      -o /tmp/grype.tar.gz && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    rm /tmp/grype.tar.gz && \
    grype version

# Install Nuclei (web vulnerability scanner — best-effort; scan continues if unavailable).
RUN NUCLEI_VERSION_PLAIN="${NUCLEI_VERSION#v}" && \
    curl -sSfL \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION_PLAIN}/nuclei_${NUCLEI_VERSION_PLAIN}_linux_amd64.zip" \
      -o /tmp/nuclei.zip && \
    unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin && \
    rm /tmp/nuclei.zip && \
    nuclei -version \
    || echo "WARNING: nuclei install failed — tool will be skipped at runtime"

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
