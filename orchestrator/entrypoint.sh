#!/bin/sh
# Entrypoint for the orchestrator container.
# Ensures required /data subdirectories exist, fixes ownership when running as
# root (e.g. in CI environments where the bind-mount owner differs from the
# container UID), then drops to the unprivileged scanuser via gosu before
# running the application.
set -e

# Create required data directories if they don't already exist.
mkdir -p /data/workspaces /data/reports /data/cache 2>/dev/null || true

# When the container starts as root, fix ownership so that scanuser can
# write to /data even if the bind-mount directory was created by a different
# host UID.
if [ "$(id -u)" = "0" ]; then
    chown -R scanuser:scanuser /data 2>/dev/null || true
    exec gosu scanuser "$@"
fi

# Already running as a non-root user.
exec "$@"
