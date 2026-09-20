import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliTest(unittest.TestCase):
    def run_cli(self, *args: str, cwd: Path):
        return subprocess.run(
            [sys.executable, "-m", "aidefender", *args],
            capture_output=True, text=True, cwd=str(cwd), timeout=60,
        )

    def test_scan_clean_and_malicious(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfgdir = tmp / "cfg"
            clean = tmp / "clean.txt"
            clean.write_text("just a harmless readme\n", encoding="utf-8")
            res = self.run_cli("--config-dir", str(cfgdir), "scan", str(clean), cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

            # NOTE: do not use the live EICAR string on disk; macOS blocks it.
            bad = tmp / "bad.txt"
            bad.write_text("cli test token: mimikatz\n", encoding="utf-8")
            res = self.run_cli("--config-dir", str(cfgdir), "scan", str(bad), cwd=ROOT)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("MALICIOUS", res.stdout)

    def test_status_json(self):
        with tempfile.TemporaryDirectory() as td:
            res = self.run_cli("--config-dir", str(Path(td) / "cfg"), "--json", "status", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertIn("signatures", payload)

    def test_help_lists_analyze(self):
        res = self.run_cli("--help", cwd=ROOT)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        for name in ("scan", "quarantine", "processes", "network", "update", "daemon", "status", "analyze"):
            self.assertIn(name, res.stdout)

    def test_analyze_json_uses_local_stub(self):
        from openai_stub import start_openai_stub, stop_openai_stub

        httpd, url = start_openai_stub(verdict="suspicious", reason="cli-stub")
        self.addCleanup(stop_openai_stub, httpd)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfgdir = tmp / "cfg"
            sample = tmp / "note.txt"
            sample.write_text("just a harmless readme\n", encoding="utf-8")
            res = self.run_cli(
                "--config-dir", str(cfgdir), "--json",
                "analyze", str(sample),
                "--local-url", url,
                "--model", "stub-model",
                "--timeout", "2",
                cwd=ROOT,
            )
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertIsInstance(payload, list)
            analysis = payload[0].get("analysis")
            self.assertIsNotNone(analysis)
            self.assertEqual(analysis["verdict"], "suspicious")
            self.assertIn("confidence", analysis)
            self.assertTrue(analysis["reasons"])

    def test_analyze_unavailable_when_stub_down(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            sample = tmp / "note.txt"
            sample.write_text("just a harmless readme\n", encoding="utf-8")
            res = self.run_cli(
                "--config-dir", str(tmp / "cfg"), "--json",
                "analyze", str(sample),
                "--local-url", "http://127.0.0.1:1/v1",
                "--cloud-url", "",
                "--timeout", "1",
                cwd=ROOT,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            analysis = payload[0].get("analysis")
            self.assertEqual(analysis["verdict"], "unavailable")


if __name__ == "__main__":
    unittest.main()
