import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from aidefender.config import get_config
from aidefender.network import Connection, flag_connection
from aidefender.processes import ProcessInfo, flag_process
from aidefender.scanner import scan_file
from aidefender.signatures import builtin_db, load_db, merge_feed
from aidefender.updater import maybe_update, update_signatures


LIVE_TOKEN = "aidefender-live-intel-token-9f3c"


def make_cfg(tmp: Path):
    cfg = get_config(tmp / "cfg")
    cfg.ensure_dirs()
    cfg.auto_update_definitions = True
    cfg.definition_update_interval_seconds = 900
    return cfg


def start_feed_stub(payload: dict):
    body = json.dumps(payload).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            return

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    return httpd, f"http://127.0.0.1:{port}/signatures.json"


class IntelUpdateTest(unittest.TestCase):
    def test_merge_feed_adds_hash_string_and_c2(self):
        db = builtin_db()
        added = merge_feed(
            db,
            {
                "version": "test-feed",
                "info": "test bulletin",
                "hashes": {"aaa": "Test:Hash"},
                "strings": {LIVE_TOKEN: "Test:LiveToken"},
                "network": {"ips": {"203.0.113.9": "C2:Doc"}, "ports": {"9999": "C2:TestPort"}},
                "processes": {"names": {"evilproc": "Malware:Evil"}, "cmdline": {"--steal-cookies": "Stealer:Flag"}},
                "families": {"testdrop": {"kind": "dropper"}},
            },
        )
        self.assertGreaterEqual(added["strings"], 1)
        self.assertEqual(db.match_strings(LIVE_TOKEN)[0], "Test:LiveToken")
        self.assertEqual(db.ips["203.0.113.9"], "C2:Doc")
        self.assertEqual(db.ports[9999], "C2:TestPort")
        self.assertIn("testdrop", db.families)

    def test_update_from_http_stub_then_scan_hits(self):
        httpd, url = start_feed_stub({
            "version": "live-stub-1",
            "info": "stub intel bulletin",
            "strings": {LIVE_TOKEN: "Test:LiveToken"},
            "network": {"ips": {"198.51.100.7": "C2:Stub"}},
        })
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            cfg.signatures_url = url
            result = update_signatures(cfg=cfg, quiet=True)
            self.assertTrue(result.ok, result.error)
            self.assertEqual(result.version, "live-stub-1")
            sample = tmp / "sample.txt"
            sample.write_text(f"payload {LIVE_TOKEN} inside\n", encoding="utf-8")
            finding = scan_file(sample, db=load_db(cfg.signatures_file), cfg=cfg)
            self.assertEqual(finding.verdict, "malicious")
            self.assertTrue(any("LiveToken" in r for r in finding.reasons), finding.reasons)

    def test_failed_fetch_keeps_existing_db(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            cfg.signatures_url = "http://127.0.0.1:1/missing.json"
            before = load_db(cfg.signatures_file)
            n_strings = len(before.strings)
            result = update_signatures(cfg=cfg, quiet=True)
            self.assertFalse(result.ok)
            after = load_db(cfg.signatures_file)
            self.assertEqual(len(after.strings), n_strings)
            self.assertTrue(after.match_strings("mimikatz"))

    def test_maybe_update_skips_inside_interval(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = make_cfg(Path(td))
            cfg.definition_update_interval_seconds = 3600
            from aidefender.updater import save_intel_state
            save_intel_state(cfg, {"last_success": 9_999_999_999, "version": "cached"})
            result = maybe_update(cfg, now=10_000_000_000, quiet=True)
            self.assertTrue(result.skipped)

    def test_local_file_source_and_process_intel(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            feed = tmp / "feed.json"
            feed.write_text(json.dumps({
                "version": "file-feed",
                "processes": {"names": {"totally-unique-malware-bin": "Malware:Unique"}},
                "strings": {"totally-unique-malware-bin": "Malware:Unique-String"},
            }), encoding="utf-8")
            result = update_signatures(source=str(feed), cfg=cfg, quiet=True)
            self.assertTrue(result.ok, result.error)
            db = load_db(cfg.signatures_file)
            proc = flag_process(
                ProcessInfo(pid=1, name="totally-unique-malware-bin", cmdline=""),
                extra_names=db.process_names,
            )
            self.assertTrue(proc.suspicious)
            conn = flag_connection(
                Connection(local="10.0.0.1:1", remote="127.0.0.2:80", status="ESTABLISHED"),
                bad_ips=set(db.ips) | {"127.0.0.2"},
            )
            self.assertTrue(conn.suspicious)

    def test_webshell_and_ransomware_builtin_strings(self):
        db = builtin_db()
        self.assertTrue(db.match_strings("eval($_post['x']".lower()))
        self.assertTrue(db.match_strings("your files have been encrypted"))
        self.assertTrue(db.match_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))


if __name__ == "__main__":
    unittest.main()
