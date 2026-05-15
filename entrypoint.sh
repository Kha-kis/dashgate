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

# Ensure /config directory exists and has correct ownership.
# On NAS/FUSE filesystems (e.g., Unraid /mnt/user/appdata), chown may fail
# silently. Use chmod as a fallback to ensure the container doesn't crash.
mkdir -p /config/icons 2>/dev/null || {
	echo "Warning: could not create /config/icons, trying without parent dirs"
	mkdir -p /config/icons 2>/dev/null || true
}
chown -R "$PUID:$PGID" /config 2>/dev/null
# Verify that the dashgate user can write to /config.
# On FUSE/NAS filesystems (e.g., Unraid /mnt/user/appdata), chown may appear
# to succeed or fail silently without actually granting write access.
if ! su-exec dashgate touch /config/.write-test 2>/dev/null; then
	echo "Warning: dashgate user cannot write to /config"
	if [ "$(stat -c '%u' /config 2>/dev/null)" != "$PUID" ]; then
		echo "Warning: chown appears to have had no effect (FUSE/NAS filesystem?), falling back to chmod"
		chmod -R 750 /config 2>/dev/null || {
			echo "Warning: chmod also failed, container may have permission issues"
		}
	else
		echo "Warning: ownership is correct but write still failed"
	fi
elif [ "$(stat -c '%a' /config/icons 2>/dev/null)" != "750" ]; then
	chmod -R 750 /config 2>/dev/null || true
fi
rm -f /config/.write-test 2>/dev/null || true

# Add dashgate user to docker socket group if socket exists
DOCKER_SOCK="/var/run/docker.sock"
if [ -S "$DOCKER_SOCK" ]; then
	SOCK_GID=$(stat -c '%g' "$DOCKER_SOCK")
	SOCK_GROUP=$(getent group "$SOCK_GID" | cut -d: -f1)
	if [ -z "$SOCK_GROUP" ]; then
		# Create a group for the socket GID
		addgroup -g "$SOCK_GID" dockersock 2>/dev/null || true
		SOCK_GROUP="dockersock"
	fi
	addgroup dashgate "$SOCK_GROUP" 2>/dev/null || true
fi

# Drop privileges and exec the main process
exec su-exec dashgate "$@"
