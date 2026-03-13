FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Pinned binary versions — update these ARGs to upgrade scanner binaries
ARG TRIVY_VERSION=0.50.4
ARG GITLEAKS_VERSION=8.18.2
ARG SYFT_VERSION=1.0.1
ARG NUCLEI_VERSION=3.2.4
ARG GRYPE_VERSION=0.74.7

# Use non-root user to avoid permission issues with host volumes
RUN groupadd -g 1000 scanuser && \
    useradd -u 1000 -g scanuser -m -s /bin/bash scanuser

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is ./orchestrator (both CI and docker-compose use this directory
# as the build context). All COPY paths are relative to ./orchestrator/.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    pip install --no-cache-dir semgrep checkov bandit

# Install Trivy (filesystem + container vulnerability scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v${TRIVY_VERSION}

# Install Gitleaks (secret scanner)
RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# Install Syft (SBOM generator)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Install Nuclei and Grype via fetch_binaries.py (best-effort; scan continues if unavailable)
COPY scripts/fetch_binaries.py /tmp/fetch_binaries.py
RUN pip install --no-cache-dir requests && \
    python /tmp/fetch_binaries.py \
        --nuclei-version ${NUCLEI_VERSION} \
        --grype-version ${GRYPE_VERSION} \
    || echo "WARNING: nuclei/grype install failed — tools will be skipped at runtime"

COPY . /app/orchestrator

WORKDIR /app/orchestrator
RUN pip install -e . && \
    chown -R scanuser:scanuser /app

USER scanuser

ENTRYPOINT ["python", "-m", "orchestrator.main"]
CMD ["--help"]
