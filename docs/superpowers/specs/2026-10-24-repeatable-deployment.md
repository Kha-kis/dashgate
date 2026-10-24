# Repeatable Compose deployment

## Intent

An operator should be able to upgrade an existing DashGate Compose service without retyping a live database backup or image replacement procedure. The v1.5.5 upgrade exposed a Windows-to-SSH line-ending and quoting failure; the procedure should run as a checked-in Python file on the Linux host.

## Scope

- Add a standard-library-only `scripts/deploy_compose.py` for an existing Linux Compose installation. It takes explicit Compose, data, backup-root, expected-current-image, target-image, and target-version arguments. The runbook supplies the `media` instance example; the script does not store host credentials or secrets.
- Validate both image references as digest-pinned references and require the Compose file to contain the expected current image exactly once. Validate Compose and SQLite before changing anything.
- Make a timestamped mode-0700 backup outside the data directory: an online SQLite snapshot, a tar archive of the other data files (excluding live DB/WAL/SHM), the Compose file and adjacent `.env`, and SHA-256 checksums. Verify the snapshot and checksums before deployment.
- Pull the target image, atomically replace only the exact image reference, validate Compose again, and recreate only the named DashGate service with `--no-deps`.
- Poll Docker health and `/health` for the requested version, then run SQLite `PRAGMA quick_check` again. Report the backup location and result without printing configuration or secret values.
- Stop on a failed check. Before container recreation, restore the original Compose file if the edited file fails validation. After recreation is attempted, do not automatically roll back: a database migration may make an old binary incompatible. The runbook explains how to assess and perform a manual rollback using the saved backup.

## Verification

- Unit tests use temporary Compose/data directories and a fake Docker runner. Cover a WAL-mode online backup, digest mismatch with no changes, preserving unrelated Compose bytes, successful one-service rollout, and health/version failure with backup retained.
- Run a syntax check and unit tests locally. Review the script and runbook for data loss, secret exposure, and rollback hazards. Do not run the new script on production as part of implementing it.
