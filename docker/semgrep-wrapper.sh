#!/bin/sh

# Semgrep's OpenTelemetry stack emits a pkg_resources deprecation warning on
# stderr with modern setuptools. Suppress that noisy warning while preserving
# other process output and exit codes.
if [ -n "${PYTHONWARNINGS:-}" ]; then
  export PYTHONWARNINGS="${PYTHONWARNINGS},ignore:pkg_resources is deprecated as an API:UserWarning"
else
  export PYTHONWARNINGS="ignore:pkg_resources is deprecated as an API:UserWarning"
fi

exec /opt/scanner-venv/bin/pysemgrep "$@"
