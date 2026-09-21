import tempfile
import time
import unittest
from pathlib import Path

from aidefender.config import get_config
from aidefender.events import load_events
from aidefender.network import Connection, flag_connection
from aidefender.processes import ProcessInfo, flag_process
from aidefender.protect import protection_cycle
from aidefender.signatures import builtin_db
from aidefender.watcher import BurstDetector, FileGuard, poll_once, should_skip_path


def make_cfg(tmp: Path):
    cfg = get_config(tmp / "cfg")
    cfg.ensure_dirs()
    cfg.file_settle_seconds = 0
    cfg.file_cooldown_seconds = 0
    cfg.burst_file_threshold = 3
    cfg.burst_window_seconds = 30
    cfg.watch_paths = [str(tmp / "watch")]
    cfg.auto_quarantine = False
    return cfg


class RealtimeTest(unittest.TestCase):
    def test_skip_partial_downloads(self):
        cfg = make_cfg(Path(tempfile.mkdtemp()))
        self.assertIsNotNone(should_skip_path("/tmp/foo.crdownload", cfg))
        self.assertIsNotNone(should_skip_path("/tmp/foo.part", cfg))
        self.assertIsNone(should_skip_path("/tmp/invoice.pdf", cfg))

    def test_handle_malicious_file_and_event_log(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            target = tmp / "watch"
            target.mkdir()
            bad = target / "note.txt"
            bad.write_text("dropper mentions mimikatz\n", encoding="utf-8")
            guard = FileGuard()
            finding = guard.handle(str(bad), cfg, action="created", db=builtin_db())
            self.assertIsNotNone(finding)
            self.assertEqual(finding.verdict, "malicious")
            events = load_events(cfg, limit=20)
            self.assertTrue(any(e.kind == "file" and e.severity == "malicious" for e in events))

    def test_poll_once_detects_new_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            watch = tmp / "watch"
            watch.mkdir()
            prev = {}
            snap, findings = poll_once([watch], prev, cfg, db=builtin_db())
            self.assertEqual(findings, [])
            (watch / "new.txt").write_text("hello world benign\n", encoding="utf-8")
            snap2, findings2 = poll_once([watch], snap, cfg, db=builtin_db())
            self.assertTrue(any(f.path.endswith("new.txt") for f in findings2), findings2)
            self.assertIn(str(watch / "new.txt"), snap2)

    def test_poll_once_quarantines_when_enabled(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            cfg.auto_quarantine = True
            watch = tmp / "watch"
            watch.mkdir()
            bad = watch / "bad.txt"
            bad.write_text("token mimikatz\n", encoding="utf-8")
            guard = FileGuard()
            finding = guard.handle(str(bad), cfg, db=builtin_db())
            self.assertEqual(finding.verdict, "malicious")
            self.assertFalse(bad.exists())
            from aidefender.quarantine import list_quarantine
            self.assertEqual(len(list_quarantine(cfg)), 1)

    def test_poll_tick_auto_quarantine_logs_threat(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            cfg.auto_quarantine = True
            watch = tmp / "watch"
            watch.mkdir()
            prev = {}
            snap, _ = poll_once([watch], prev, cfg, db=builtin_db())
            dropped = watch / "dropped.txt"
            dropped.write_text("token mimikatz\n", encoding="utf-8")
            _, findings = poll_once([watch], snap, cfg, db=builtin_db())
            self.assertTrue(any(f.verdict == "malicious" for f in findings), findings)
            self.assertFalse(dropped.exists())
            from aidefender.quarantine import list_quarantine
            self.assertEqual(len(list_quarantine(cfg)), 1)
            events = load_events(cfg, limit=20)
            self.assertTrue(any(e.kind == "file" and e.severity == "malicious" for e in events))

    def test_hash_cache_skips_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            watch = tmp / "watch"
            watch.mkdir()
            f = watch / "same.txt"
            f.write_text("stable content\n", encoding="utf-8")
            guard = FileGuard()
            first = guard.handle(str(f), cfg, db=builtin_db())
            self.assertIsNotNone(first)
            second = guard.handle(str(f), cfg, db=builtin_db())
            self.assertIsNone(second)

    def test_burst_detector(self):
        det = BurstDetector(window=30, threshold=3)
        self.assertIsNone(det.record("/d/a"))
        self.assertIsNone(det.record("/d/b"))
        hit = det.record("/d/c")
        self.assertIsNotNone(hit)
        self.assertIn("burst", hit)

    def test_flag_process_and_connection(self):
        proc = flag_process(ProcessInfo(pid=9, name="powershell.exe", cmdline="powershell -enc AAAA"))
        self.assertTrue(proc.suspicious)
        conn = flag_connection(Connection(local="10.0.0.2:1234", remote="127.0.0.2:4444", status="ESTABLISHED"))
        self.assertTrue(conn.suspicious)
        listen = flag_connection(Connection(local="0.0.0.0:4444", remote="0.0.0.0:0", status="LISTEN"))
        self.assertTrue(listen.suspicious)

    def test_protection_cycle_sees_watched_payload(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            watch = tmp / "watch"
            watch.mkdir()
            (watch / "payload.txt").write_text("contains mimikatz\n", encoding="utf-8")
            state = protection_cycle(cfg, extra_paths=[str(watch)], scan_persist=False, watch_files=True)
            self.assertTrue(any(f.verdict == "malicious" for f in state.file_findings), state.file_findings)


if __name__ == "__main__":
    unittest.main()
