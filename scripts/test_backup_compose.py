"""Scheduled backup and retention tests."""

import sqlite3
from contextlib import closing
from contextlib import redirect_stderr
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import backup_compose, deploy_compose


class ScheduledBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.compose = self.root / "docker-compose.yml"
        self.compose.write_text("services:\n  dashgate:\n    image: example@sha256:" + "a" * 64 + "\n")
        (self.root / ".env").write_text("SECRET=private\n")
        (self.data / "config.yaml").write_text("name: test\n")
        with closing(sqlite3.connect(self.data / "dashgate.db")) as db:
            db.execute("CREATE TABLE items (id INTEGER)")
            db.execute("INSERT INTO items VALUES (1)")
            db.commit()
        self.backups = self.root / "backups"

    def test_backup_verifies_snapshot_and_keeps_newest_two(self):
        for stamp in ("20261023T010000Z", "20261024T010000Z", "20261025T010000Z"):
            result = backup_compose.run_backup(
                self.compose, self.data, self.backups, "1.5.6", keep=2, stamp=stamp
            )
            deploy_compose.verify_backup(result)
        self.assertEqual(
            sorted(path.name for path in self.backups.iterdir()),
            ["dashgate-1.5.6-20261024T010000Z", "dashgate-1.5.6-20261025T010000Z"],
        )

    def test_retention_leaves_unrelated_and_symlink_entries(self):
        self.backups.mkdir()
        self.backups.chmod(0o700)
        unrelated = self.backups / "manual-copy"
        unrelated.mkdir()
        old = self.backups / "dashgate-1.5.6-20261020T010000Z"
        old.mkdir()
        (old / ".scheduled-backup").write_text("\n")
        outside = self.root / "outside"
        outside.mkdir()
        link = self.backups / "dashgate-1.5.6-20261019T010000Z"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError:
            link = None  # Windows without developer mode cannot create symlinks.
        result = backup_compose.run_backup(
            self.compose, self.data, self.backups, "1.5.6", keep=1,
            stamp="20261025T010000Z",
        )
        self.assertTrue(result.exists())
        self.assertFalse(old.exists())
        self.assertTrue(unrelated.exists())
        if link is not None:
            self.assertTrue(link.is_symlink())
        self.assertTrue(outside.exists())

    def test_retention_orders_by_timestamp_across_versions(self):
        older = backup_compose.run_backup(
            self.compose, self.data, self.backups, "9.0.0", keep=2,
            stamp="20261020T010000Z",
        )
        newest = backup_compose.run_backup(
            self.compose, self.data, self.backups, "1.0.0", keep=1,
            stamp="20261025T010000Z",
        )
        self.assertFalse(older.exists())
        self.assertTrue(newest.exists())

    def test_invalid_paths_do_not_delete_existing_backup(self):
        self.backups.mkdir()
        self.backups.chmod(0o700)
        old = self.backups / "dashgate-1.5.6-20261020T010000Z"
        old.mkdir()
        (old / ".scheduled-backup").write_text("\n")
        with self.assertRaisesRegex(ValueError, "outside the data directory"):
            backup_compose.run_backup(
                self.compose, self.data, self.data / "backups", "1.5.6", keep=1
            )
        self.assertTrue(old.exists())

    def test_failed_verification_does_not_prune(self):
        self.backups.mkdir()
        self.backups.chmod(0o700)
        old = self.backups / "dashgate-1.5.6-20261020T010000Z"
        old.mkdir()
        (old / ".scheduled-backup").write_text("\n")
        with self.assertRaises(Exception):
            backup_compose.run_backup(
                self.compose, self.data, self.backups, "1.5.6", keep=1,
                stamp="20261025T010000Z", verify=lambda path: (_ for _ in ()).throw(ValueError("bad")),
            )
        self.assertTrue(old.exists())

    def test_metrics_keep_last_success_when_next_run_fails(self):
        metrics = self.root / "dashgate-backup.prom"
        backup_compose.write_metrics(metrics, success=True, now=100)
        backup_compose.write_metrics(metrics, success=False, now=200)
        content = metrics.read_text()
        self.assertIn("dashgate_backup_last_attempt_success 0\n", content)
        self.assertIn("dashgate_backup_last_attempt_timestamp_seconds 200\n", content)
        self.assertIn("dashgate_backup_last_success_timestamp_seconds 100\n", content)

    def test_command_publishes_failure_metric(self):
        metrics = self.root / "dashgate-backup.prom"
        argv = ["backup_compose.py", "--compose", str(self.compose),
                "--data-dir", str(self.root / "missing"),
                "--backup-root", str(self.backups), "--version", "1.5.6",
                "--metrics-file", str(metrics)]
        with patch.object(sys, "argv", argv), redirect_stderr(io.StringIO()):
            self.assertEqual(backup_compose.main(), 1)
        self.assertIn("dashgate_backup_last_attempt_success 0\n", metrics.read_text())
        self.assertFalse(self.backups.exists())


if __name__ == "__main__":
    unittest.main()
