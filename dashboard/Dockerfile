FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────────────────
# Install dashboard and orchestrator Python deps in one layer
COPY dashboard/requirements.txt /tmp/requirements-dashboard.txt
COPY orchestrator/requirements.txt /tmp/requirements-orchestrator.txt
RUN pip install --no-cache-dir \
    -r /tmp/requirements-dashboard.txt \
    -r /tmp/requirements-orchestrator.txt \
    semgrep \
    checkov

# ── External scanner binaries ──────────────────────────────────────────────────
# Versions pinned for reproducible builds — update periodically.
# All binaries are placed in /usr/local/bin for PATH availability.

# gitleaks v8.30.0 — secret scanning
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v8.30.0/gitleaks_8.30.0_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# trivy v0.69.3 — container/filesystem vulnerability scanner
RUN curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# syft v1.42.2 — SBOM generator
RUN curl -sSfL "https://github.com/anchore/syft/releases/download/v1.42.2/syft_1.42.2_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin syft \
    && chmod +x /usr/local/bin/syft

# grype v0.109.1 — SBOM vulnerability scanner
RUN curl -sSfL "https://github.com/anchore/grype/releases/download/v0.109.1/grype_0.109.1_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin grype \
    && chmod +x /usr/local/bin/grype

# nuclei v3.7.1 — pattern-based vulnerability scanner
RUN curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v3.7.1/nuclei_3.7.1_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# ── Application code ───────────────────────────────────────────────────────────
# Copy dashboard code to /app
COPY dashboard/ /app/

# Copy orchestrator code to /orchestrator
# (root_dir = /app/.. = /, so orchestrator will be at /orchestrator)
COPY orchestrator/ /orchestrator/

# Copy default configuration
COPY config/ /config/

# ── Data directories ───────────────────────────────────────────────────────────
RUN mkdir -p /data/workspaces /data/reports /data/cache

EXPOSE 8080
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
