# Upgrading DashGate

This guide covers the DashGate application in an existing Docker Compose installation. Set backup schedules, monitoring, off-host copies, and host-specific paths in your own infrastructure.

## Before upgrading

1. Read the target release notes for database or configuration changes. Record the current image digest and version.
2. Identify the persistent directory mounted at `/config`. Make a recoverable copy of that directory, your Compose file, and any adjacent `.env` file. To copy the SQLite database and its WAL files together, stop only the DashGate container while copying, then start it again. An operator with SQLite tooling can instead use SQLite's online backup API for the database while the service runs.
3. Keep the backup private and verify that its database opens with `PRAGMA quick_check` before changing the image.

Pin the target image to a published digest, validate Compose, and recreate only DashGate:

```bash
docker compose config -q
docker compose up -d --no-deps dashgate
```

## Verify the upgrade

Confirm that the running container uses the intended digest, is healthy, and reports the intended version:

```bash
docker inspect dashgate --format '{{.Config.Image}} {{.State.Health.Status}} {{.RestartCount}}'
curl -fsS http://127.0.0.1:1738/health
```

Check startup logs, run `PRAGMA quick_check` on the live database, and sign in through the normal browser route to exercise an admin workflow affected by the release.

## If a check fails

Preserve the current data and inspect the logs before reverting. A new release may have migrated the database, so an older binary may not be able to read it. If database restoration is required, stop DashGate first, move the current database and its `-wal`, `-shm`, and `-journal` files to a separate recovery directory, then restore the verified backup. Never overwrite a running SQLite database or leave an old WAL beside a restored snapshot. Restart DashGate only after checking the restored database.
