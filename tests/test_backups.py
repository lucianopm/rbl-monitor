"""Backup retention tests: exclusively temporary directories."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cleanup_backups import prune


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name).resolve()
        self.root = self.app / 'backups'
        self.root.mkdir()

    def snapshot(self, day):
        folder = self.root / f'202610{day:02d}-120000-abcdef123456'
        folder.mkdir()
        (folder / 'app-before.tar').write_bytes(b'test fixture')
        (folder / 'monitor.db').write_bytes(b'test fixture')
        return folder

    def test_preview_does_not_remove(self):
        for day in range(1,9):
            self.snapshot(day)
        self.assertEqual(len(prune(self.app)),3)
        self.assertEqual(len(list(self.root.iterdir())),8)

    def test_keeps_five_newest_by_timestamp_not_mtime(self):
        entries = [self.snapshot(day) for day in range(1,9)]
        (entries[0] / 'recently-touched').touch()
        self.assertEqual(len(prune(self.app,apply=True)),3)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),[p.name for p in entries[3:]])

    def test_preserves_protected_rollback_even_if_clock_changed(self):
        entries = [self.snapshot(day) for day in range(1,9)]
        prune(self.app,apply=True,protect=str(entries[0]))
        self.assertTrue(entries[0].is_dir())
        self.assertEqual(len(list(self.root.iterdir())),5)

    def test_unknown_and_incomplete_directories_preserved(self):
        for day in range(1,9):
            self.snapshot(day)
        for name in ('manual-backup','20261009-120000-abcdef123456','20269999-120000-abcdef123456'):
            (self.root / name).mkdir()
        prune(self.app,apply=True)
        for name in ('manual-backup','20261009-120000-abcdef123456','20269999-120000-abcdef123456'):
            self.assertTrue((self.root/name).is_dir())

    def test_five_or_fewer_untouched_and_idempotent(self):
        for day in range(1,6):
            self.snapshot(day)
        self.assertEqual(prune(self.app,apply=True),[])
        self.assertEqual(prune(self.app,apply=True),[])

    def test_backup_root_symlink_refused(self):
        original = Path.is_symlink
        with patch.object(Path,'is_symlink',lambda entry: entry == self.root or original(entry)):
            with self.assertRaises(ValueError):
                prune(self.app,apply=True)

    def test_nested_symlink_snapshot_preserved(self):
        entries = [self.snapshot(day) for day in range(1,8)]
        marker = entries[0] / 'monitor.db'
        original = Path.is_symlink
        with patch.object(Path,'is_symlink',lambda entry: entry == marker or original(entry)):
            prune(self.app,apply=True)
        self.assertTrue(entries[0].exists())

    def test_external_protected_target_refused(self):
        with self.assertRaises(ValueError):
            prune(self.app,apply=True,protect=str(self.app))


if __name__ == '__main__':
    unittest.main()
