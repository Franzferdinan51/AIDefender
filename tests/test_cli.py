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


if __name__ == "__main__":
    unittest.main()
