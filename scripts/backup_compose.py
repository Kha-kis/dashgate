#!/usr/bin/env python3
"""Create and retain verified backups for an existing DashGate Compose install."""

import argparse
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from typing import Callable

try:
    from . import deploy_compose
except ImportError:  # Direct execution on the Linux host.
    import deploy_compose


BACKUP_NAME = re.compile(r"^dashgate-\d+\.\d+\.\d+-\d{8}T\d{6}Z$")
MARKER = ".scheduled-backup"
SUCCESS_LINE = re.compile(r"^dashgate_backup_last_success_timestamp_seconds (\d+)$", re.MULTILINE)


def _validate(compose: Path, data_dir: Path, backup_root: Path, version: str, keep: int) -> None:
    if keep < 1:
        raise ValueError("keep must be at least one")
    if not deploy_compose.VERSION_RE.fullmatch(version):
        raise ValueError("version must be X.Y.Z")
    if not compose.is_file() or not (compose.parent / ".env").is_file():
        raise ValueError("Compose file and adjacent .env are required")
    if not data_dir.is_dir() or not (data_dir / "dashgate.db").is_file():
        raise ValueError("data directory and dashgate.db are required")
    data = data_dir.resolve()
    backup = backup_root.resolve()
    if backup == data or data in backup.parents:
        raise ValueError("backup root must be outside the data directory")
    if os.name != "nt" and backup_root.exists() and backup_root.stat().st_mode & 0o077:
        raise ValueError("backup root must be private (mode 0700)")


def _prune(backup_root: Path, keep: int) -> None:
    candidates = sorted(
        (path for path in backup_root.iterdir()
         if path.is_dir() and not path.is_symlink() and BACKUP_NAME.fullmatch(path.name)
         and (path / MARKER).is_file() and not (path / MARKER).is_symlink()),
        key=lambda path: path.name.rsplit("-", 1)[-1],
        reverse=True,
    )
    for path in candidates[keep:]:
        if path.parent.resolve() != backup_root.resolve():
            raise ValueError("backup path escaped backup root")
        shutil.rmtree(path)


def run_backup(
    compose: Path,
    data_dir: Path,
    backup_root: Path,
    version: str,
    keep: int = 14,
    stamp: str | None = None,
    verify: Callable[[Path], None] = deploy_compose.verify_backup,
) -> Path:
    _validate(compose, data_dir, backup_root, version, keep)
    config = deploy_compose.Config(
        compose=compose, data_dir=data_dir, backup_root=backup_root,
        expected_image="", target_image="", target_version=version,
    )
    backup = deploy_compose.create_backup(config, stamp=stamp)
    verify(backup)
    marker = backup / MARKER
    marker.write_text("created by scripts/backup_compose.py\n")
    if os.name != "nt":
        marker.chmod(0o600)
    _prune(backup_root, keep)
    return backup


def write_metrics(path: Path, success: bool, now: int | None = None) -> None:
    """Publish an atomic node-exporter textfile without losing last success."""
    now = int(time.time()) if now is None else now
    previous = SUCCESS_LINE.search(path.read_text()) if path.exists() else None
    last_success = now if success else int(previous.group(1)) if previous else 0
    content = (
        "# TYPE dashgate_backup_last_attempt_success gauge\n"
        f"dashgate_backup_last_attempt_success {int(success)}\n"
        "# TYPE dashgate_backup_last_attempt_timestamp_seconds gauge\n"
        f"dashgate_backup_last_attempt_timestamp_seconds {now}\n"
        "# TYPE dashgate_backup_last_success_timestamp_seconds gauge\n"
        f"dashgate_backup_last_success_timestamp_seconds {last_success}\n"
    )
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_name, 0o644)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--version", help="DashGate version; defaults to the local health endpoint")
    parser.add_argument("--health-url", default="http://127.0.0.1:1738/health")
    parser.add_argument("--keep", type=int, default=14)
    parser.add_argument("--metrics-file", type=Path,
                        help="node-exporter textfile path for backup alerts")
    args = parser.parse_args()
    try:
        version = args.version
        if version is None:
            health = deploy_compose.fetch_health(args.health_url)
            if health.get("status") != "ok":
                raise ValueError("DashGate health check failed")
            version = health.get("version", "")
        backup = run_backup(args.compose, args.data_dir, args.backup_root, version, args.keep)
    except (ValueError, OSError, sqlite3.Error, RuntimeError) as error:
        if args.metrics_file:
            try:
                write_metrics(args.metrics_file, success=False)
            except OSError:
                pass  # Service failure and stale metrics still raise an alert.
        # Do not print URLs, Compose content, or .env values into the journal.
        print(f"DashGate scheduled backup failed: {type(error).__name__}", file=sys.stderr)
        return 1
    if args.metrics_file:
        try:
            write_metrics(args.metrics_file, success=True)
        except OSError:
            print("DashGate backup succeeded but metrics publication failed", file=sys.stderr)
            return 1
    print(f"Verified DashGate backup: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
