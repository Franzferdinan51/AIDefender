import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from aidefender.act import stop_process
from aidefender.allowlist import add_entry, is_ip_allowed
from aidefender.capture import parse_tcpdump_text, summarize_flows
from aidefender.catalog import tool_catalog
from aidefender.config import get_config
from aidefender.diag import parse_arp_text, parse_listeners, parse_route_text
from aidefender.network import Connection, flag_connection
from aidefender.scanner import scan_file
from aidefender.signatures import builtin_db

ROOT = Path(__file__).resolve().parents[1]


class AgentDefenseTest(unittest.TestCase):
    def test_allowlist_file_skips_signature(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = get_config(tmp / "cfg")
            cfg.ensure_dirs()
            target = tmp / "lab.txt"
            target.write_text("this mentions mimikatz in a lab sample\n", encoding="utf-8")
            before = scan_file(target, db=builtin_db(), cfg=cfg)
            self.assertEqual(before.verdict, "malicious")
            add_entry(cfg, "path", str(target), note="known lab file")
            after = scan_file(target, db=builtin_db(), cfg=cfg)
            self.assertEqual(after.verdict, "clean")
            self.assertTrue(any("allowlisted" in r for r in after.reasons))

    def test_allowlist_ip_skips_network_flag(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = get_config(Path(td) / "cfg")
            cfg.ensure_dirs()
            attacker = "203.0.113.77"
            conn = Connection(local="10.0.0.5:22", remote=f"{attacker}:4444", status="ESTABLISHED")
            flagged = flag_connection(conn, bad_ips={attacker}, bad_ports={4444}, cfg=cfg)
            self.assertTrue(flagged.suspicious)
            add_entry(cfg, "ip", attacker, note="office jump box")
            conn2 = Connection(local="10.0.0.5:22", remote=f"{attacker}:4444", status="ESTABLISHED")
            skipped = flag_connection(conn2, bad_ips={attacker}, bad_ports={4444}, cfg=cfg)
            self.assertFalse(skipped.suspicious)
            self.assertIsNotNone(is_ip_allowed(cfg, attacker))

    def test_cidr_allowlist(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = get_config(Path(td) / "cfg")
            cfg.ensure_dirs()
            add_entry(cfg, "cidr", "203.0.113.0/24", note="lab net")
            self.assertIsNotNone(is_ip_allowed(cfg, "203.0.113.9"))
            self.assertIsNone(is_ip_allowed(cfg, "198.51.100.9"))

    def test_tcpdump_parse_and_flows(self):
        text = (
            "12:00:00.001 IP 203.0.113.77.443 > 10.0.0.5.51234: Flags [S], seq 1\n"
            "12:00:00.002 IP 10.0.0.5.51234 > 203.0.113.77.443: Flags [S.], seq 2\n"
            "12:00:00.003 IP 203.0.113.77.443 > 10.0.0.5.51234: Flags [.], seq 3\n"
        )
        pkts = parse_tcpdump_text(text)
        self.assertEqual(len(pkts), 3)
        self.assertEqual(pkts[0]["src"], "203.0.113.77")
        self.assertEqual(pkts[0]["sport"], "443")
        flows = summarize_flows(pkts)
        self.assertTrue(any(f["packets"] == 2 and f["src"] == "203.0.113.77" for f in flows))

    def test_arp_and_route_parsers(self):
        arp = parse_arp_text("? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n")
        self.assertEqual(arp[0]["ip"], "192.168.1.1")
        self.assertEqual(arp[0]["mac"], "aa:bb:cc:dd:ee:ff")
        routes = parse_route_text("Destination Gateway Flags\ndefault 192.168.1.1 UGSc\n")
        self.assertEqual(routes[0]["destination"], "default")
        listeners = parse_listeners([
            Connection(local="0.0.0.0:22", remote="0.0.0.0:0", status="LISTEN"),
            Connection(local="10.0.0.5:9", remote="1.1.1.1:80", status="ESTABLISHED"),
        ])
        self.assertEqual(len(listeners), 1)
        self.assertEqual(listeners[0]["port"], 22)

    def test_stop_process_refuses_pid1_and_self(self):
        self.assertFalse(stop_process(1)["ok"])
        self.assertFalse(stop_process(0)["ok"])
        import os
        self.assertFalse(stop_process(os.getpid())["ok"])

    def test_catalog_lists_agent_actions(self):
        names = {t["name"] for t in tool_catalog()}
        for needed in ("scan", "diag", "capture", "allow-add", "block-add", "inspect-ip", "intrusion", "stop-process"):
            self.assertIn(needed, names)


class AgentCliTest(unittest.TestCase):
    def run_cli(self, *args: str, cwd: Path):
        return subprocess.run(
            [sys.executable, "-m", "aidefender", *args],
            capture_output=True, text=True, cwd=str(cwd), timeout=60,
        )

    def test_tools_and_allow_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            cfgdir = str(Path(td) / "cfg")
            res = self.run_cli("--config-dir", cfgdir, "--json", "tools", cwd=ROOT)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            catalog = json.loads(res.stdout)
            self.assertTrue(any(t["name"] == "diag" for t in catalog))
            add = self.run_cli(
                "--config-dir", cfgdir, "--json", "allow", "add",
                "--ip", "203.0.113.77", "--note", "lab",
                cwd=ROOT,
            )
            self.assertEqual(add.returncode, 0, add.stdout + add.stderr)
            listed = self.run_cli("--config-dir", cfgdir, "--json", "allow", "list", cwd=ROOT)
            data = json.loads(listed.stdout)
            self.assertIn("203.0.113.77", data["ips"])
            blk = self.run_cli(
                "--config-dir", cfgdir, "--json", "block", "add", "--ip", "198.51.100.9",
                cwd=ROOT,
            )
            self.assertEqual(blk.returncode, 0, blk.stdout + blk.stderr)
            diag = self.run_cli("--config-dir", cfgdir, "--json", "diag", "tools", cwd=ROOT)
            self.assertEqual(diag.returncode, 0, diag.stdout + diag.stderr)
            tools = json.loads(diag.stdout)
            self.assertTrue(any(t["name"] == "netstat" or t["name"] == "ss" for t in tools))


if __name__ == "__main__":
    unittest.main()
