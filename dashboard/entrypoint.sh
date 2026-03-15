#!/bin/sh
# Entrypoint for the dashboard container.
# Ensures required /data subdirectories exist, fixes ownership when running as
# root (e.g. in CI environments where the bind-mount owner differs from the
# container UID), then drops to the unprivileged dashuser via gosu before
# running the application.
set -e

# Create required data directories if they don't already exist.
# The || true prevents failure when the bind-mount is read-only or /data is
# owned by a different user than the one running this script.
mkdir -p /data/workspaces /data/reports /data/cache 2>/dev/null || true

# When the container starts as root (the default when no --user flag is passed
# and the image has no USER instruction), fix ownership so that dashuser can
# write to /data even if the bind-mount directory was created by a different
# host UID.
if [ "$(id -u)" = "0" ]; then
    chown -R dashuser:dashuser /data 2>/dev/null || true
    exec gosu dashuser "$@"
fi

# Already running as a non-root user (e.g. the caller passed --user dashuser).
exec "$@"
