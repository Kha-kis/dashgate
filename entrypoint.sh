#!/bin/sh
set -e

PUID=${PUID:-1000}
PGID=${PGID:-1000}

# Update dashgate user/group IDs if they differ from defaults
if [ "$PUID" != "1000" ] || [ "$PGID" != "1000" ]; then
    echo "Adjusting dashgate user to UID=$PUID GID=$PGID"

    # Remove existing dashgate user
    deluser dashgate 2>/dev/null || true

    # Find or create group with target GID
    TARGET_GROUP=$(getent group "$PGID" | cut -d: -f1)
    if [ -z "$TARGET_GROUP" ]; then
        # GID doesn't exist, remove old group and create new one
        delgroup dashgate 2>/dev/null || true
        addgroup -g "$PGID" dashgate
        TARGET_GROUP="dashgate"
    fi

    # Create user with new UID in target group
    adduser -D -u "$PUID" -G "$TARGET_GROUP" dashgate
fi

# Ensure /config directory exists and has correct ownership
mkdir -p /config/icons
chown -R "$PUID:$PGID" /config

# Drop privileges and exec the main process
exec su-exec dashgate "$@"
