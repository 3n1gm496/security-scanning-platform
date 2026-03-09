FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

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

COPY . /app/orchestrator

WORKDIR /app/orchestrator
RUN pip install -e . && \
    chown -R scanuser:scanuser /app

USER scanuser

ENTRYPOINT ["python", "-m", "orchestrator.main"]
CMD ["--help"]
