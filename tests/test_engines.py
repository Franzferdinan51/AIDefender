import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from aidefender.binary import analyze_binary
from aidefender.clamd import scan_bytes_clamd
from aidefender.config import get_config
from aidefender.engines import engine_status
from aidefender.heuristics import analyze_file
from aidefender.memory import scan_process_images
from aidefender.onaccess import fanotify_supported, parse_fanotify_metadata
from aidefender.processes import ProcessInfo
from aidefender.service import install_service, service_installed, uninstall_service
from aidefender.signatures import builtin_db


def start_clamd_stub(found: bool = True, name: str = "Eicar-Test-Signature"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def loop():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(0.6)
                buf = b""
                try:
                    while True:
                        piece = conn.recv(4096)
                        if not piece:
                            break
                        buf += piece
                        if buf.startswith(b"PING"):
                            conn.sendall(b"PONG\n")
                            buf = b""
                            break
                        if b"zINSTREAM" in buf and len(buf) > 16:
                            break
                except OSError:
                    pass
                if buf.startswith(b"PING"):
                    continue
                if found:
                    conn.sendall(f"stream: {name} FOUND\n".encode())
                else:
                    conn.sendall(b"stream: OK\n")

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return srv, port, stop


class EngineTest(unittest.TestCase):
    def test_pe_injection_and_packer_heuristics(self):
        blob = (
            b"MZ"
            + b"\x00" * 40
            + b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00UPX0\x00"
        )
        delta, reasons, feat = analyze_binary(blob, "pe")
        self.assertGreaterEqual(delta, 40)
        self.assertIn("pe_injection_apis", feat)
        self.assertIn("packer", feat)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "drop.exe"
            p.write_bytes(blob)
            result = analyze_file(p)
            self.assertGreaterEqual(result.score, 40)
            self.assertTrue(result.features.get("pe_injection_apis"))

    def test_fanotify_metadata_parse_and_capability(self):
        packed = struct.pack("IBBHQii", 24, 3, 0, 24, 8, 5, 99)
        meta = parse_fanotify_metadata(packed)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["pid"], 99)
        self.assertEqual(meta["fd"], 5)
        ok, reason = fanotify_supported()
        self.assertIsInstance(ok, bool)
        self.assertTrue(reason)

    def test_clamd_instream_found(self):
        srv, port, stop = start_clamd_stub(found=True, name="Win.Test.Stub")
        self.addCleanup(stop.set)
        self.addCleanup(srv.close)
        hit = scan_bytes_clamd(b"hello", f"127.0.0.1:{port}", timeout=2)
        self.assertEqual(hit, "Win.Test.Stub")
        miss = scan_bytes_clamd(b"hello", "127.0.0.1:1", timeout=0.5)
        self.assertIsNone(miss)

    def test_service_install_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = get_config(Path(td) / "cfg")
            cfg.ensure_dirs()
            dest = Path(td) / "ai.aidefender.protect.plist"
            path = install_service(cfg, dest=dest)
            self.assertTrue(path.exists())
            text = path.read_text(encoding="utf-8")
            self.assertIn("aidefender", text)
            self.assertIn("protect", text)
            self.assertTrue(service_installed(dest))
            self.assertTrue(uninstall_service(dest))
            self.assertFalse(service_installed(dest))

    def test_process_image_scan_hits_signature(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = get_config(tmp / "cfg")
            cfg.ensure_dirs()
            exe = tmp / "fake.bin"
            exe.write_text("contains mimikatz payload\n", encoding="utf-8")
            procs = [ProcessInfo(pid=4242, name="fake", cmdline=str(exe), exe=str(exe))]
            findings = scan_process_images(cfg, processes=procs)
            self.assertTrue(any(f.verdict == "malicious" for f in findings), findings)

    def test_engine_status_shape(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = get_config(Path(td) / "cfg")
            cfg.ensure_dirs()
            st = engine_status(cfg)
            self.assertIn("on_access", st)
            self.assertIn("clamd", st)
            self.assertIn("service", st)
            self.assertFalse(st["kernel_minifilter"])
            json.dumps(st)  # must be serializable


if __name__ == "__main__":
    unittest.main()
