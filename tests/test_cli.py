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
        for name in (
            "scan", "analyze", "protect", "monitor", "quarantine", "processes",
            "network", "update", "daemon", "events", "status", "engines",
            "memory", "service", "ui", "intrusion",
            "allow", "block", "diag", "capture", "inspect", "act", "tools",
            "ai", "config",
        ):
            self.assertIn(name, res.stdout)
        scan_help = self.run_cli("scan", "--help", cwd=ROOT)
        self.assertEqual(scan_help.returncode, 0, scan_help.stdout + scan_help.stderr)
        self.assertIn("--ai", scan_help.stdout)
        self.assertIn("opt-in", scan_help.stdout)

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

    def test_protect_once_and_daemon_once(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfgdir = tmp / "cfg"
            watch = tmp / "watch"
            watch.mkdir()
            bad = watch / "drop.txt"
            bad.write_text("realtime token: mimikatz\n", encoding="utf-8")
            res = self.run_cli(
                "--config-dir", str(cfgdir), "--json",
                "protect", "--once", str(watch),
                cwd=ROOT,
            )
            self.assertIn(res.returncode, (0, 1), res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertIn("files", payload)
            self.assertTrue(
                any(f.get("verdict") == "malicious" for f in payload["files"]),
                res.stdout,
            )

            from aidefender.config import get_config, save_config
            cfg = get_config(cfgdir)
            cfg.watch_paths = [str(watch)]
            save_config(cfg)
            res2 = self.run_cli(
                "--config-dir", str(cfgdir),
                "daemon", "--once", "--no-protect",
                cwd=ROOT,
            )
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)

    def test_monitor_seconds_stops(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            watch = tmp / "w"
            watch.mkdir()
            res = self.run_cli(
                "--config-dir", str(tmp / "cfg"),
                "monitor", str(watch), "--seconds", "0.4", "--poll-interval", "0.1",
                cwd=ROOT,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("monitor", res.stdout.lower())

    def test_update_from_local_feed_twice(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfgdir = tmp / "cfg"
            feed = tmp / "feed.json"
            token = "aidefender-cli-intel-token"
            feed.write_text(json.dumps({
                "version": "cli-feed",
                "info": "cli bulletin",
                "strings": {token: "Test:CliToken"},
            }), encoding="utf-8")
            for _ in range(2):
                res = self.run_cli(
                    "--config-dir", str(cfgdir), "--json",
                    "update", "--source", str(feed),
                    cwd=ROOT,
                )
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                payload = json.loads(res.stdout)
                self.assertTrue(payload.get("ok"), payload)
                self.assertEqual(payload.get("version"), "cli-feed")
            sample = tmp / "hit.txt"
            sample.write_text(f"see {token}\n", encoding="utf-8")
            scan = self.run_cli("--config-dir", str(cfgdir), "scan", str(sample), cwd=ROOT)
            self.assertEqual(scan.returncode, 1, scan.stdout + scan.stderr)
            self.assertIn("MALICIOUS", scan.stdout)

    def test_scan_ai_opt_in_escalates_via_cli(self):
        from openai_stub import start_openai_stub, stop_openai_stub

        httpd, url = start_openai_stub(verdict="malicious", reason="cli-scan-ai")
        self.addCleanup(stop_openai_stub, httpd)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfgdir = tmp / "cfg"
            sample = tmp / "gray.txt"
            sample.write_text("odd but not a known signature token\n", encoding="utf-8")
            self.assertEqual(
                self.run_cli("--config-dir", str(cfgdir), "config", "set",
                             "local_ai_base_url", url, cwd=ROOT).returncode, 0)
            self.assertEqual(
                self.run_cli("--config-dir", str(cfgdir), "config", "set",
                             "cloud_ai_base_url", "", cwd=ROOT).returncode, 0)
            offline = self.run_cli(
                "--config-dir", str(cfgdir), "--json", "scan", str(sample), cwd=ROOT)
            self.assertEqual(offline.returncode, 0, offline.stdout + offline.stderr)
            offline_payload = json.loads(offline.stdout)
            self.assertNotEqual(offline_payload[0]["verdict"], "malicious")
            self.assertFalse(offline_payload[0].get("analysis"))
            res = self.run_cli(
                "--config-dir", str(cfgdir), "--json", "scan", "--ai", str(sample), cwd=ROOT)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertEqual(payload[0]["verdict"], "malicious")
            self.assertTrue(any("ai-powered escalate" in r for r in payload[0]["reasons"]))
            self.assertEqual(payload[0]["analysis"]["verdict"], "malicious")

    def test_engines_and_service_cli(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfgdir = tmp / "cfg"
            res = self.run_cli("--config-dir", str(cfgdir), "--json", "engines", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertIn("on_access", payload)
            self.assertIn("clamd", payload)
            self.assertIn("definitions", payload)
            self.assertIn("counts", payload["definitions"])
            self.assertIn("local_ai", payload)
            self.assertIn("reachable", payload["local_ai"])
            self.assertIn("base_url", payload["local_ai"])
            self.assertIn("model", payload["local_ai"])
            dest = tmp / "unit.plist"
            ins = self.run_cli(
                "--config-dir", str(cfgdir), "service", "install", "--dest", str(dest), cwd=ROOT,
            )
            self.assertEqual(ins.returncode, 0, ins.stdout + ins.stderr)
            self.assertTrue(dest.exists())
            un = self.run_cli(
                "--config-dir", str(cfgdir), "service", "uninstall", "--dest", str(dest), cwd=ROOT,
            )
            self.assertEqual(un.returncode, 0, un.stdout + un.stderr)
            self.assertFalse(dest.exists())

    def test_intrusion_help_firewall_is_opt_in(self):
        res = self.run_cli("intrusion", "--help", cwd=ROOT)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("--firewall", res.stdout)
        compact = "".join(res.stdout.lower().split())
        self.assertIn("opt-in", compact)

    def test_intrusion_cli_json(self):
        with tempfile.TemporaryDirectory() as td:
            res = self.run_cli(
                "--config-dir", str(Path(td) / "cfg"), "--json",
                "intrusion", "--no-geo", "--no-block",
                cwd=ROOT,
            )
            self.assertIn(res.returncode, (0, 1), res.stdout + res.stderr)
            payload = json.loads(res.stdout or "[]")
            self.assertIsInstance(payload, list)

    def test_help_lists_ai_and_config(self):
        res = self.run_cli("--help", cwd=ROOT)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("ai", res.stdout)
        self.assertIn("config", res.stdout)

    def test_config_set_get_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            cfgdir = str(Path(td) / "cfg")
            res = self.run_cli("--config-dir", cfgdir, "config", "set", "local_ai_model", "lm-model", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            res = self.run_cli("--config-dir", cfgdir, "--json", "config", "get", "local_ai_model", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual(json.loads(res.stdout)["local_ai_model"], "lm-model")

    def test_config_set_clamps_and_rejects_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            cfgdir = str(Path(td) / "cfg")
            res = self.run_cli("--config-dir", cfgdir, "config", "set", "heuristic_malicious", "999", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("clamped", res.stdout)
            res = self.run_cli("--config-dir", cfgdir, "config", "get", "heuristic_malicious", cwd=ROOT)
            self.assertIn("100", res.stdout)
            res = self.run_cli("--config-dir", cfgdir, "config", "set", "cloud_ai_api_key", "sekret", cwd=ROOT)
            self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
            res = self.run_cli("--config-dir", cfgdir, "--json", "config", "get", cwd=ROOT)
            payload = json.loads(res.stdout)
            self.assertNotIn("cloud_ai_api_key", payload)
            self.assertIn("local_ai_base_url", payload)

    def test_ai_use_persists_preset(self):
        with tempfile.TemporaryDirectory() as td:
            cfgdir = str(Path(td) / "cfg")
            res = self.run_cli("--config-dir", cfgdir, "--json", "ai", "use", "lmstudio", "--model", "m", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertEqual(payload["url"], "http://127.0.0.1:1234/v1")
            self.assertEqual(payload["model"], "m")

    def test_ai_status_always_reports(self):
        # Probes the live network, so reachability varies — but the command
        # itself must always exit 0 with a parseable backends list.
        with tempfile.TemporaryDirectory() as td:
            res = self.run_cli("--config-dir", str(Path(td) / "cfg"), "--json", "ai", "status", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            payload = json.loads(res.stdout)
            self.assertIn("backends", payload)
            self.assertTrue(any(b["name"] == "lmstudio" for b in payload["backends"]))


if __name__ == "__main__":
    unittest.main()
