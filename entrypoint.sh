#!/bin/sh
set -e

PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Update dashgate user/group IDs if they differ from defaults
if [ "$PUID" != "1000" ] || [ "$PGID" != "1000" ]; then
    echo "Adjusting dashgate user to UID=$PUID GID=$PGID"

    # Modify group first (if GID changed)
    if [ "$PGID" != "1000" ]; then
        delgroup dashgate 2>/dev/null || true
        addgroup -g "$PGID" dashgate
    fi

    # Modify user
    deluser dashgate 2>/dev/null || true
    adduser -D -u "$PUID" -G dashgate dashgate
fi

# Ensure /config directory exists and has correct ownership
mkdir -p /config/icons
chown -R dashgate:dashgate /config

# Drop privileges and exec the main process
exec su-exec dashgate "$@"
