FROM python:3.11-slim

ARG TRIVY_VERSION=0.69.1
ARG GITLEAKS_VERSION=8.30.0
ARG SYFT_VERSION=1.42.1
# additional scanners added in later iteration
ARG BANDIT_VERSION=1.7.0
ARG NUCLEI_VERSION=8.8.11
ARG GRYPE_VERSION=0.69.1
# zap-cli will be installed via pip; ZAP binary downloaded separately
ARG ZAP_VERSION=2.17.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRIVY_CACHE_DIR=/data/cache/trivy

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    gnupg \
    tar \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY orchestrator/scripts /tmp/scripts
COPY orchestrator/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    # command‑line utilities required by new scanners
    && pip install --no-cache-dir semgrep checkov bandit

# NOTE: zap-cli is not installed automatically due to build environment restrictions.
# users can add it later in the running container or extend the Dockerfile with a
# git clone/pip install step when network access permits.

RUN wget -qO /tmp/trivy.deb "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb" \
    && apt-get update && apt-get install -y /tmp/trivy.deb \
    && rm -f /tmp/trivy.deb \
    && rm -rf /var/lib/apt/lists/*

# install nuclei binary (ignore failure when offline)
# build nuclei from source with Go instead of relying on release archive
RUN apt-get update && apt-get install -y --no-install-recommends golang-go && \
    GOPATH=$(go env GOPATH) && \
    mkdir -p "$GOPATH/bin" && \
    # install latest nuclei via Go (module path includes major v2)
    go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    mv "$GOPATH/bin/nuclei" /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei || \
    echo "warning: failed to build nuclei, continuing without it"

# install grype binary (ignore failure when offline)
RUN if wget -qO /tmp/grype.tar.gz -L "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" && [ -s /tmp/grype.tar.gz ]; then \
        tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
        chmod +x /usr/local/bin/grype && \
        rm -f /tmp/grype.tar.gz; \
    else \
        echo "warning: failed to download grype binary, continuing without it"; \
    fi

# install OWASP ZAP headless distribution for zap-cli to drive
# the version string may be updated; network access is required
RUN ZAP_VERSION=${ZAP_VERSION} \
    && if wget -qO /tmp/zap.zip -L "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.zip" && [ -s /tmp/zap.zip ]; then \
           unzip -q /tmp/zap.zip -d /opt/ && \
           ln -s /opt/ZAP_${ZAP_VERSION}/zap.sh /usr/local/bin/zap.sh && \
           rm -f /tmp/zap.zip; \
       else \
           echo "warning: failed to download ZAP binary (check version), continuing without it"; \
       fi

RUN wget -qO /tmp/gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm -f /tmp/gitleaks.tar.gz

RUN wget -qO /tmp/syft.tar.gz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION#v}_linux_amd64.tar.gz" \
    && tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft \
    && chmod +x /usr/local/bin/syft \
    && rm -f /tmp/syft.tar.gz

# attempt to fetch release binaries via helper (best-effort)
RUN if python3 /tmp/scripts/fetch_binaries.py --nuclei-version "${NUCLEI_VERSION}" --grype-version "${GRYPE_VERSION}" --zap-version "${ZAP_VERSION}"; then \
            echo "fetch_binaries completed"; \
        else \
            echo "fetch_binaries encountered errors, continuing"; \
        fi

COPY orchestrator /app/orchestrator
COPY config /app/config
COPY demo /app/demo

RUN mkdir -p /data/reports /data/workspaces /data/cache/trivy

ENTRYPOINT ["python", "-m", "orchestrator.main"]
CMD ["--help"]
