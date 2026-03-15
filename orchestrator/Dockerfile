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

COPY orchestrator/scripts/fetch_binaries.py /tmp/fetch_binaries.py

# Install scanner binaries from GitHub releases with SHA-256 verification.
RUN python /tmp/fetch_binaries.py \
      --trivy-version "${TRIVY_VERSION}" \
      --gitleaks-version "${GITLEAKS_VERSION}" \
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
