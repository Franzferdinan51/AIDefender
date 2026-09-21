import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from aidefender import __version__
from aidefender.ai import analyze_artifacts
from aidefender.config import get_config
from aidefender.geoip import fetch_ip_api
from aidefender.updater import fetch_json


def _ua(req) -> str:
    return req.get_header("User-agent") or req.headers.get("User-Agent") or ""


class UserAgentTest(unittest.TestCase):
    def test_intel_fetch_json_sends_package_user_agent(self):
        seen = {"ua": ""}
        body = b'{"version":"ua-feed","strings":{}}'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen["ua"] = self.headers.get("User-Agent") or ""
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
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        port = httpd.server_address[1]
        payload = fetch_json(f"http://127.0.0.1:{port}/signatures.json")
        self.assertEqual(payload.get("version"), "ua-feed")
        self.assertEqual(seen["ua"], f"AIDefender/{__version__}")
        self.assertNotIn("AIDefender/0.4", seen["ua"])
        self.assertNotIn("AIDefender/0.7", seen["ua"])

    def test_geo_lookup_sends_package_user_agent(self):
        captured = []

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

            def read(self):
                return b'{"status":"success","country":"Lab"}'

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return FakeResp()

        with patch("aidefender.geoip.urllib.request.urlopen", fake_urlopen):
            data = fetch_ip_api("203.0.113.9", timeout=1.0)
        self.assertEqual(data.get("country"), "Lab")
        self.assertTrue(captured)
        ua = _ua(captured[0])
        self.assertEqual(ua, f"AIDefender/{__version__}")
        self.assertNotIn("AIDefender/0.4", ua)
        self.assertNotIn("AIDefender/0.7", ua)

    def test_ai_post_sends_package_user_agent(self):
        from openai_stub import start_openai_stub, stop_openai_stub

        httpd, url = start_openai_stub(verdict="suspicious", reason="ua")
        self.addCleanup(stop_openai_stub, httpd)
        with tempfile.TemporaryDirectory() as td:
            cfg = get_config(Path(td) / "cfg")
            cfg.ensure_dirs()
            cfg.local_ai_base_url = url
            cfg.local_ai_model = "stub-model"
            cfg.cloud_ai_base_url = ""
            cfg.ai_timeout_seconds = 2.0
            result = analyze_artifacts(
                {
                    "path": "x",
                    "sha256": "abc",
                    "scan_verdict": "clean",
                    "score": 0,
                    "reasons": [],
                    "features": {},
                    "signature_malicious": False,
                    "sample_text": "hello",
                    "sample_hex": "00",
                },
                cfg=cfg,
            )
        self.assertEqual(result.verdict, "suspicious")
        ua = httpd.recorded["user_agent"]
        self.assertEqual(ua, f"AIDefender/{__version__}")
        self.assertNotIn("AIDefender/0.4", ua)
