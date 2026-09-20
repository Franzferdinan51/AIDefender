import json
import tempfile
import unittest
from pathlib import Path

from aidefender.blocklist import load_blocked
from aidefender.config import get_config
from aidefender.geoip import enrich_ip, format_location
from aidefender.intrusion import (
    AuthEvent,
    evaluate_intrusions,
    parse_auth_text,
    parse_who_text,
    parse_windows_4625,
)
from aidefender.ipaddr import is_public_ip, is_non_routable
from aidefender.network import Connection, flag_connection


ATTACKER = "203.0.113.77"


def make_cfg(tmp: Path):
    cfg = get_config(tmp / "cfg")
    cfg.ensure_dirs()
    cfg.intrusion_auto_block = True
    cfg.intrusion_firewall_block = False
    cfg.intrusion_geo = True
    cfg.intrusion_brute_threshold = 4
    cfg.intrusion_scan_ports = 8
    cfg.intrusion_window_seconds = 300
    return cfg


def stub_geo(ip: str, timeout: float = 3.0) -> dict:
    return {
        "status": "success",
        "country": "Latveria",
        "regionName": "Doomstadt",
        "city": "Castle",
        "isp": "EvilNet",
        "org": "Doom Corp",
        "as": "AS64500",
        "lat": 1.0,
        "lon": 2.0,
        "query": ip,
        "reverse": "evil.example.net",
    }


class IntrusionTest(unittest.TestCase):
    def test_ip_classification(self):
        self.assertTrue(is_non_routable("10.0.0.8"))
        self.assertTrue(is_non_routable("127.0.0.1"))
        self.assertTrue(is_public_ip(ATTACKER))
        self.assertFalse(is_public_ip("192.168.1.10"))

    def test_parse_ssh_and_who_and_windows(self):
        ssh = parse_auth_text(
            "sshd[12]: Failed password for root from 203.0.113.77 port 51111 ssh2\n"
            "sshd: Invalid user admin from 198.51.100.9\n"
            "cron: hello world\n"
        )
        self.assertEqual(len(ssh), 2)
        self.assertEqual(ssh[0].ip, ATTACKER)
        who = parse_who_text("duckets pts/0        Sep 20 10:00 (203.0.113.77)\nconsole login\n")
        self.assertEqual(who[0].ip, ATTACKER)
        win = parse_windows_4625(
            "Event ID: 4625\nAccount Name:\tAdministrator\nSource Network Address:\t203.0.113.77\n"
        )
        self.assertEqual(win[0].ip, ATTACKER)

    def test_inbound_session_blocks_and_enriches(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = make_cfg(Path(td))
            conn = Connection(
                local="10.0.0.5:22",
                remote=f"{ATTACKER}:54321",
                status="ESTABLISHED",
            )
            _state, alerts = evaluate_intrusions(
                [conn],
                [],
                cfg=cfg,
                enrich=True,
                fetch=stub_geo,
                apply_blocks=True,
            )
            self.assertTrue(alerts)
            hit = alerts[0]
            self.assertEqual(hit.ip, ATTACKER)
            self.assertEqual(hit.category, "inbound-session")
            self.assertEqual(hit.geo.get("country"), "Latveria")
            self.assertIn("Castle", format_location(hit.geo))
            self.assertEqual(hit.action, "blocked-local")
            blocked = load_blocked(cfg)
            self.assertIn(ATTACKER, blocked)
            flagged = flag_connection(
                Connection(local="10.0.0.5:99", remote=f"{ATTACKER}:1", status="ESTABLISHED"),
                bad_ips=set(blocked),
            )
            self.assertTrue(flagged.suspicious)

    def test_brute_force_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = make_cfg(Path(td))
            auths = [
                AuthEvent(ip=ATTACKER, message=f"Failed password attempt {i}", user="root")
                for i in range(4)
            ]
            _state, alerts = evaluate_intrusions(
                [],
                auths,
                cfg=cfg,
                enrich=False,
                apply_blocks=True,
            )
            cats = {a.category for a in alerts}
            self.assertIn("brute-force", cats)

    def test_port_scan_distinct_sensitive_ports(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = make_cfg(Path(td))
            conns = [
                Connection(local=f"10.0.0.5:{port}", remote=f"{ATTACKER}:{40000+port}", status="SYN_RECV")
                for port in (22, 23, 3389, 445, 5900, 21, 3306, 5432)
            ]
            _state, alerts = evaluate_intrusions(
                conns,
                [],
                cfg=cfg,
                enrich=False,
                apply_blocks=False,
            )
            self.assertTrue(any(a.category == "port-scan" for a in alerts), [a.category for a in alerts])

    def test_private_ips_are_not_intruders(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = make_cfg(Path(td))
            conn = Connection(local="10.0.0.5:22", remote="10.0.0.9:4444", status="ESTABLISHED")
            _state, alerts = evaluate_intrusions([conn], [], cfg=cfg, enrich=False, apply_blocks=True)
            self.assertEqual(alerts, [])

    def test_enrich_stub_and_private_skip(self):
        info = enrich_ip(ATTACKER, fetch=stub_geo, do_dns=False)
        self.assertEqual(info["country"], "Latveria")
        private = enrich_ip("10.1.2.3", fetch=stub_geo, do_dns=False)
        self.assertEqual(private["source"], "private")


if __name__ == "__main__":
    unittest.main()
