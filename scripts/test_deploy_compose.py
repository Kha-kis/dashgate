"""Safety tests for the Compose deployment helper."""

from contextlib import closing
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts import deploy_compose


OLD = "ghcr.io/kha-kis/dashgate@sha256:" + "1" * 64
NEW = "ghcr.io/kha-kis/dashgate@sha256:" + "2" * 64


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.compose = self.root / "docker-compose.yml"
        self.original = f"services:\n  dashgate:\n    image: {OLD}\n    environment:\n      MODE: production\n"
        self.compose.write_text(self.original)
        (self.root / ".env").write_text("PRIVATE_SENTINEL=keep-secret\n")
        (self.data / "config.yaml").write_text("secret: preserve\n")
        icons = self.data / "icons"
        icons.mkdir()
        (icons / "icon.svg").write_text("<svg/>")
        self.db = sqlite3.connect(self.data / "dashgate.db")
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY)")
        self.db.execute("INSERT INTO items VALUES (1)")
        self.db.commit()
        self.backups = self.root / "backups"
        self.config = deploy_compose.Config(
            compose=self.compose,
            data_dir=self.data,
            backup_root=self.backups,
            expected_image=OLD,
            target_image=NEW,
            target_version="1.5.6",
            health_url="http://127.0.0.1:1738/health",
        )

    def rendered_compose(self, source=None):
        return json.dumps({"services": {"dashgate": {"image": OLD, "volumes": [{
            "type": "bind", "source": str(source or self.data.resolve()),
            "target": "/config", "read_only": False,
        }]}}})

    def test_rejects_wrong_current_pin_without_writes(self):
        self.config.expected_image = "ghcr.io/kha-kis/dashgate@sha256:" + "3" * 64
        calls = []
        with self.assertRaisesRegex(ValueError, "current image"):
            deploy_compose.deploy(self.config, run=lambda args: calls.append(args))
        self.assertEqual(calls, [])
        self.assertEqual(self.compose.read_text(), self.original)
        self.assertFalse(self.backups.exists())

    def test_online_backup_includes_committed_wal_data_and_excludes_live_db_files(self):
        backup = deploy_compose.create_backup(self.config, stamp="20261024T120000Z")
        with closing(sqlite3.connect(backup / "dashgate.db")) as copy:
            self.assertEqual(copy.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(copy.execute("SELECT COUNT(*) FROM items").fetchone()[0], 1)
        self.assertEqual((backup / ".env").read_text(), "PRIVATE_SENTINEL=keep-secret\n")
        self.assertEqual((backup / "docker-compose.yml").read_text(), self.original)
        if os.name != "nt":
            self.assertEqual((backup.stat().st_mode & 0o777), 0o700)
        names = deploy_compose.list_backup_archive(backup / "data-files.tar")
        self.assertIn("config.yaml", names)
        self.assertIn("icons/icon.svg", names)
        self.assertNotIn("dashgate.db", names)
        self.assertNotIn("dashgate.db-wal", names)
        self.assertNotIn("dashgate.db-shm", names)
        self.assertNotIn("dashgate.db-journal", names)
        self.assertIn("dashgate.db-journal", deploy_compose.DB_FILES)
        deploy_compose.verify_backup(backup)

    def test_existing_backup_root_permissions_are_preserved(self):
        self.backups.mkdir()
        before = self.backups.stat().st_mode & 0o777
        deploy_compose.create_backup(self.config, stamp="20261024T120000Z")
        self.assertEqual(self.backups.stat().st_mode & 0o777, before)

    def test_rejects_data_dir_that_is_not_compose_bind_mount(self):
        other = self.root / "other-data"
        other.mkdir()
        calls = []
        def run(args):
            calls.append(args)
            return self.rendered_compose(source=other) if args[-3:] == ["config", "--format", "json"] else ""
        with self.assertRaisesRegex(ValueError, "bind mount"):
            deploy_compose.deploy(self.config, run=run)
        self.assertFalse(self.backups.exists())
        self.assertEqual(self.compose.read_text(), self.original)

    def test_compose_replacement_changes_only_exact_pin(self):
        deploy_compose.replace_compose_image(self.config)
        self.assertEqual(self.compose.read_text(), self.original.replace(OLD, NEW))

    def test_rollout_recreates_only_dashgate_and_checks_version(self):
        calls = []

        def run(args):
            calls.append(args)
            if args[-3:] == ["config", "--format", "json"]:
                return self.rendered_compose()
            if args[-1] == "{{.Config.Image}}":
                return NEW
            return "healthy" if args[:2] == ["docker", "inspect"] else ""

        result = deploy_compose.deploy(
            self.config,
            run=run,
            fetch_health=lambda url: {"status": "ok", "version": "1.5.6"},
            sleep=lambda seconds: None,
            attempts=1,
        )
        self.assertTrue(result.backup_dir.is_dir())
        self.assertEqual(self.compose.read_text(), self.original.replace(OLD, NEW))
        self.assertIn(["docker", "pull", NEW], calls)
        self.assertIn(["docker", "compose", "-f", str(self.compose), "up", "-d", "--no-deps", "dashgate"], calls)
        self.assertEqual(calls[0][-2:], ["config", "-q"])
        self.assertIn(["docker", "inspect", "dashgate", "--format", "{{.Config.Image}}"], calls)

    def test_wrong_running_image_fails_after_recreate(self):
        def run(args):
            if args[-3:] == ["config", "--format", "json"]:
                return self.rendered_compose()
            if args[-1] == "{{.Config.Image}}":
                return OLD
            return "healthy" if args[:2] == ["docker", "inspect"] else ""
        with self.assertRaisesRegex(deploy_compose.DeploymentError, "running image"):
            deploy_compose.deploy(self.config, run=run,
                fetch_health=lambda url: {"status": "ok", "version": "1.5.6"},
                sleep=lambda seconds: None, attempts=1)
        self.assertEqual(len(list(self.backups.iterdir())), 1)

    def test_wrong_health_version_keeps_verified_backup_and_reports_it(self):
        def run(args):
            if args[-3:] == ["config", "--format", "json"]:
                return self.rendered_compose()
            if args[-1] == "{{.Config.Image}}":
                return NEW
            return "healthy" if args[:2] == ["docker", "inspect"] else ""

        with self.assertRaises(deploy_compose.DeploymentError) as caught:
            deploy_compose.deploy(
                self.config,
                run=run,
                fetch_health=lambda url: {"status": "ok", "version": "1.5.5"},
                sleep=lambda seconds: None,
                attempts=2,
            )
        self.assertIn(str(self.backups), str(caught.exception))
        self.assertEqual(len(list(self.backups.iterdir())), 1)
        self.assertEqual(self.compose.read_text(), self.original.replace(OLD, NEW))

    def test_invalid_edited_compose_restores_original_before_recreate(self):
        calls = []

        def run(args):
            calls.append(args)
            if args[-3:] == ["config", "--format", "json"]:
                return self.rendered_compose()
            if args[-2:] == ["config", "-q"] and len([call for call in calls if call[-2:] == ["config", "-q"]]) == 2:
                raise RuntimeError("invalid Compose")
            return ""

        with self.assertRaises(deploy_compose.DeploymentError):
            deploy_compose.deploy(self.config, run=run)
        self.assertEqual(self.compose.read_text(), self.original)
        self.assertEqual(len(list(self.backups.iterdir())), 1)
        self.assertFalse(any("up" in call for call in calls))


if __name__ == "__main__":
    unittest.main()
