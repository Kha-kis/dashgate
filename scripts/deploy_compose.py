#!/usr/bin/env python3
"""Safely upgrade one existing DashGate Compose service on its Linux host."""

import argparse
from contextlib import closing
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.request import urlopen


IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
DB_FILES = {"dashgate.db", "dashgate.db-wal", "dashgate.db-shm", "dashgate.db-journal"}
BACKUP_FILES = ("dashgate.db", "data-files.tar", "docker-compose.yml", ".env")


class DeploymentError(RuntimeError):
    """A deployment stopped after a backup may have been created."""


@dataclass
class Config:
    compose: Path
    data_dir: Path
    backup_root: Path
    expected_image: str
    target_image: str
    target_version: str
    health_url: str = "http://127.0.0.1:1738/health"


@dataclass(frozen=True)
class DeploymentResult:
    backup_dir: Path
    image: str
    version: str


def run_command(args: list[str]) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        # Compose errors can contain interpolated configuration. Do not echo them.
        raise DeploymentError(f"Command failed (exit {result.returncode}): {args[0]}")
    return result.stdout.strip()


def fetch_health(url: str) -> dict:
    with urlopen(url, timeout=5) as response:
        return json.loads(response.read(4096))


def quick_check(db_path: Path) -> None:
    with closing(sqlite3.connect(f"{db_path.resolve().as_uri()}?mode=ro", uri=True)) as db:
        result = db.execute("PRAGMA quick_check").fetchone()
    if not result or result[0] != "ok":
        raise DeploymentError("SQLite quick_check failed")


def _image_match(content: bytes, expected_image: str):
    pattern = re.compile(
        rb"(?m)^[ \t]*image:[ \t]*(" + re.escape(expected_image.encode()) + rb")(?=[ \t]*(?:#.*)?\r?$)"
    )
    matches = list(pattern.finditer(content))
    if len(matches) != 1:
        raise ValueError("expected current image must appear in exactly one Compose image line")
    return matches[0]


def validate(config: Config) -> None:
    if not IMAGE_RE.fullmatch(config.expected_image) or not IMAGE_RE.fullmatch(config.target_image):
        raise ValueError("both images must be full sha256 digest references")
    if config.expected_image.split("@")[0] != config.target_image.split("@")[0]:
        raise ValueError("current and target images must use the same repository")
    if config.expected_image == config.target_image:
        raise ValueError("target image is already configured")
    if not VERSION_RE.fullmatch(config.target_version):
        raise ValueError("target version must be X.Y.Z")
    if not config.compose.is_file() or not (config.compose.parent / ".env").is_file():
        raise ValueError("Compose file and adjacent .env are required")
    if not config.data_dir.is_dir() or not (config.data_dir / "dashgate.db").is_file():
        raise ValueError("data directory and dashgate.db are required")
    data = config.data_dir.resolve()
    backup = config.backup_root.resolve()
    if backup == data or data in backup.parents:
        raise ValueError("backup root must be outside the data directory")
    _image_match(config.compose.read_bytes(), config.expected_image)
    quick_check(config.data_dir / "dashgate.db")


def _digest(path: Path) -> str:
    hash_value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hash_value.update(block)
    return hash_value.hexdigest()


def list_backup_archive(path: Path) -> set[str]:
    with tarfile.open(path, "r") as archive:
        return {item.name.removeprefix("./") for item in archive.getmembers()}


def verify_backup(backup_dir: Path) -> None:
    manifest = json.loads((backup_dir / "checksums.json").read_text())
    if set(manifest) != set(BACKUP_FILES):
        raise DeploymentError("backup manifest is incomplete")
    for name, expected in manifest.items():
        if _digest(backup_dir / name) != expected:
            raise DeploymentError(f"backup checksum failed for {name}")
    quick_check(backup_dir / "dashgate.db")


def create_backup(config: Config, stamp: str | None = None) -> Path:
    # Only set permissions on directories created by this invocation.
    if not config.backup_root.exists():
        config.backup_root.mkdir(mode=0o700, parents=True)
        os.chmod(config.backup_root, 0o700)
    stamp = stamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = config.backup_root / f"dashgate-{config.target_version}-{stamp}"
    backup_dir.mkdir(mode=0o700)
    with closing(sqlite3.connect(config.data_dir / "dashgate.db")) as source:
        with closing(sqlite3.connect(backup_dir / "dashgate.db")) as target:
            source.backup(target)
    with tarfile.open(backup_dir / "data-files.tar", "w") as archive:
        for path in sorted(config.data_dir.rglob("*")):
            relative = path.relative_to(config.data_dir)
            if relative.parent == Path(".") and relative.name in DB_FILES:
                continue
            archive.add(path, arcname=relative.as_posix(), recursive=False)
    shutil.copy2(config.compose, backup_dir / "docker-compose.yml")
    shutil.copy2(config.compose.parent / ".env", backup_dir / ".env")
    manifest = {name: _digest(backup_dir / name) for name in BACKUP_FILES}
    (backup_dir / "checksums.json").write_text(json.dumps(manifest, indent=2) + "\n")
    verify_backup(backup_dir)
    return backup_dir


def _atomic_write(path: Path, content: bytes) -> None:
    original = path.stat()
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IMODE(original.st_mode))
        with os.fdopen(fd, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def replace_compose_image(config: Config) -> None:
    content = config.compose.read_bytes()
    match = _image_match(content, config.expected_image)
    start, end = match.span(1)
    _atomic_write(config.compose, content[:start] + config.target_image.encode() + content[end:])


def deploy(
    config: Config,
    run: Callable[[list[str]], str] = run_command,
    fetch_health: Callable[[str], dict] = fetch_health,
    sleep: Callable[[float], None] = time.sleep,
    attempts: int = 45,
) -> DeploymentResult:
    validate(config)
    compose_command = ["docker", "compose", "-f", str(config.compose)]
    run(compose_command + ["config", "-q"])
    rendered = json.loads(run(compose_command + ["config", "--format", "json"]))
    service = rendered.get("services", {}).get("dashgate", {})
    if service.get("image") != config.expected_image:
        raise ValueError("current image for DashGate service does not match expected pin")
    config_mounts = [volume for volume in service.get("volumes", []) if volume.get("target") == "/config"]
    if (len(config_mounts) != 1 or config_mounts[0].get("type") != "bind"
            or config_mounts[0].get("read_only", False)
            or Path(config_mounts[0].get("source", "")).resolve() != config.data_dir.resolve()):
        raise ValueError("DashGate /config bind mount does not match the writable data directory")
    backup_dir = create_backup(config)
    try:
        run(["docker", "pull", config.target_image])
        replace_compose_image(config)
        try:
            run(compose_command + ["config", "-q"])
        except Exception:
            _atomic_write(config.compose, (backup_dir / "docker-compose.yml").read_bytes())
            raise
        run(compose_command + ["up", "-d", "--no-deps", "dashgate"])
        for _ in range(attempts):
            status = run(["docker", "inspect", "dashgate", "--format", "{{.State.Health.Status}}"])
            if status == "healthy":
                try:
                    health = fetch_health(config.health_url)
                    if health.get("status") == "ok" and health.get("version") == config.target_version:
                        running_image = run(["docker", "inspect", "dashgate", "--format", "{{.Config.Image}}"])
                        if running_image != config.target_image:
                            raise DeploymentError("running image does not match target digest")
                        quick_check(config.data_dir / "dashgate.db")
                        return DeploymentResult(backup_dir, config.target_image, config.target_version)
                except (OSError, ValueError, json.JSONDecodeError):
                    pass
            sleep(2)
        raise DeploymentError("health endpoint did not report the requested version")
    except Exception as error:
        raise DeploymentError(
            f"Deployment stopped: {error}. Verified backup: {backup_dir}. "
            "Inspect the service and follow docs/deployment.md before any rollback."
        ) from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--expect-image", required=True)
    parser.add_argument("--target-image", required=True)
    parser.add_argument("--target-version", required=True)
    parser.add_argument("--health-url", default="http://127.0.0.1:1738/health")
    args = parser.parse_args()
    config = Config(
        compose=args.compose,
        data_dir=args.data_dir,
        backup_root=args.backup_root,
        expected_image=args.expect_image,
        target_image=args.target_image,
        target_version=args.target_version,
        health_url=args.health_url,
    )
    try:
        result = deploy(config)
    except (ValueError, DeploymentError, OSError, sqlite3.Error) as error:
        print(f"Deployment failed: {error}", file=sys.stderr)
        return 1
    print(f"DashGate {result.version} is healthy. Verified backup: {result.backup_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
