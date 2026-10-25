# Upgrading an existing Compose installation

Use `scripts/deploy_compose.py` on the Linux Docker host to upgrade one existing DashGate service. It requires Python 3, Docker Compose, permission to read and write the DashGate data and Compose files, and access to the image registry. The script uses Python's SQLite online backup, so the running WAL database can be backed up without stopping DashGate.

The script is intentionally for an **existing** installation with a digest-pinned `dashgate` image, a bind-mounted data directory containing `dashgate.db`, and a `.env` beside the Compose file. It does not set up a new installation or run on your workstation.

## Before the upgrade

1. Review the release and its CI. Find the target image's full multiarchitecture digest in the trusted registry, for example with `docker buildx imagetools inspect ghcr.io/kha-kis/dashgate:1.5.6`. Record the full `sha256:` value. Do not use a mutable `latest` tag for the deployment.
2. Confirm the host paths, the current container image (`docker inspect dashgate --format '{{.Config.Image}}'`), available disk space, and the current `/health` version. The current image must equal the image in Compose.
3. Transfer the checked-in script to the host, for example `scp scripts/deploy_compose.py media:/tmp/dashgate-deploy.py`. Transferring the file avoids shell quoting and Windows line-ending problems. Review the script from the same Git revision as the release before running it.

On the host, run the following with your actual paths, current image, target digest and target version:

```bash
current_image=$(docker inspect dashgate --format '{{.Config.Image}}')
target_image='ghcr.io/kha-kis/dashgate@sha256:REPLACE_WITH_64_HEX_DIGITS'

python3 /tmp/dashgate-deploy.py \
  --compose /opt/dashgate/docker-compose.yml \
  --data-dir /home/khak1s/.config/dashgate \
  --backup-root /home/khak1s/dashgate-backups \
  --expect-image "$current_image" \
  --target-image "$target_image" \
  --target-version 1.5.6
```

The script checks the current image, the Compose `/config` bind mount, and SQLite database before making changes. It creates a timestamped mode-0700 backup containing a consistent database snapshot, the other data files, Compose, `.env`, and checksums. It verifies the backup, pulls the target image, updates only DashGate's image pin, validates Compose, and recreates only `dashgate` with `--no-deps`. It succeeds only after Docker reports healthy, the running container uses the target image digest, `/health` reports the target version, and SQLite quick check returns `ok`.

The backup contains configuration and secrets. Keep it on protected storage, include it in your normal backup policy, and remove it only under that policy. The script does not print secret values or delete older backups.

## Daily verified backups

`scripts/backup_compose.py` creates the same consistent, checksum-verified backup without changing Compose or restarting DashGate. It reads the running version from the local `/health` endpoint and returns a nonzero status if health or backup verification fails. Keep the backup root outside the live data directory and private (mode 0700). Its `--keep` count applies only to backups bearing the scheduled-backup marker in that root; deployment backups in the parent directory are untouched.

For the `media` installation, the sample systemd units in `deploy/` run daily at 02:30 host time and retain 14 verified scheduled backups. Review paths and user before installing them. Transfer `scripts/backup_compose.py` and `scripts/deploy_compose.py` to `/opt/dashgate/`, install the units in `/etc/systemd/system/`, and run `systemd-analyze verify` on all three units. The service uses `flock` to prevent overlapping runs. Start it once manually, inspect `journalctl -u dashgate-backup.service`, and verify the new backup with `deploy_compose.verify_backup` before enabling the timer.

The sample service writes success, attempt, and last-success metrics atomically to the existing node-exporter textfile directory. Install `deploy/dashgate-backup-rules.yml` in Prometheus' rules directory, check it with `promtool check rules`, and reload Prometheus. Alertmanager then reports failed runs after five minutes and overdue successful backups after 36 hours. The systemd failure unit also writes a high-priority journal entry. A local backup does not protect against loss of the host, so copy verified backups to protected off-host storage under your normal backup policy.

## After the upgrade

Confirm the exact image, health and version:

```bash
docker inspect dashgate --format '{{.Config.Image}} {{.State.Health.Status}} {{.RestartCount}}'
curl -fsS http://127.0.0.1:1738/health
sqlite3 -readonly /home/khak1s/.config/dashgate/dashgate.db 'PRAGMA quick_check;'
```

Check recent DashGate logs for startup or migration errors. Sign in through the normal browser route and exercise one relevant admin workflow. For a release that changes discovery, dismiss a suitable unpublished route, verify it appears in Ignored, restore it, and verify the inbox and database return to their original state.

## If a check fails

The script reports the verified backup path. A failure before container recreation leaves the old container running; Compose is restored automatically if its edited form fails validation. Inspect the current Compose image and container before retrying.

After recreation is attempted, **do not automatically start the old image**. A new version may have migrated the database. First inspect the logs and release notes, decide whether the old binary can read the current database, and preserve any post-upgrade writes. If the old binary is compatible, restore the backed-up Compose file and recreate only DashGate:

```bash
cp -a BACKUP_DIR/docker-compose.yml /opt/dashgate/docker-compose.yml
docker compose -f /opt/dashgate/docker-compose.yml config -q
docker compose -f /opt/dashgate/docker-compose.yml up -d --no-deps dashgate
```

If the database must also be restored, stop **only** DashGate, move the live database and its `-wal`/`-shm`/`-journal` files into a separate timestamped recovery directory, copy `BACKUP_DIR/dashgate.db` into the data directory, and run `PRAGMA quick_check` before starting the old image. Restore the archived config and icons only if their post-backup changes can be discarded. Never copy a database snapshot over a running SQLite database or leave an old WAL beside the restored snapshot. Keep both the pre-upgrade backup and the moved live files until the recovered service has been verified.
