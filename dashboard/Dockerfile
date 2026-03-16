FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

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

WORKDIR /app

ARG TRIVY_VERSION=0.69.3
ARG GITLEAKS_VERSION=8.30.0
ARG SYFT_VERSION=1.42.2
ARG NUCLEI_VERSION=3.7.1
ARG GRYPE_VERSION=0.109.1

# ── Python dependencies ────────────────────────────────────────────────────────
# Install dashboard and orchestrator Python deps in one layer
COPY dashboard/requirements.txt /tmp/requirements-dashboard.txt
COPY orchestrator/requirements.txt /tmp/requirements-orchestrator.txt
RUN pip install --no-cache-dir \
    -r /tmp/requirements-dashboard.txt \
    -r /tmp/requirements-orchestrator.txt \
    semgrep \
    checkov && \
    pip uninstall -y wheel jaraco.context && \
    pip install --no-cache-dir --no-deps "wheel>=0.46.2" && \
    pip install --no-cache-dir "jaraco.context>=6.1.0"

# ── External scanner binaries ──────────────────────────────────────────────────
# Versions pinned for reproducible builds — update periodically.
# All binaries are placed in /usr/local/bin for PATH availability.
COPY orchestrator/scripts/fetch_binaries.py /tmp/fetch_binaries.py
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

# Drop to non-root for runtime
USER dashuser

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
