import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class UiPackagingTest(unittest.TestCase):
    def test_electron_sources_exist(self):
        ui = ROOT / "ui"
        for rel in (
            "package.json",
            "main.js",
            "preload.js",
            "renderer/index.html",
            "renderer/app.js",
            "renderer/styles.css",
        ):
            self.assertTrue((ui / rel).is_file(), rel)

    def test_package_json_is_electron_builder_app(self):
        data = json.loads((ROOT / "ui" / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(data["main"], "main.js")
        self.assertIn("electron-builder", data["devDependencies"])
        self.assertEqual(data["build"]["productName"], "AIDefender")
        self.assertIn("dmg", data["build"]["mac"]["target"])
        self.assertIn("nsis", data["build"]["win"]["target"])
        self.assertIn("AppImage", data["build"]["linux"]["target"])

    def test_main_js_spawns_json_cli(self):
        text = (ROOT / "ui" / "main.js").read_text(encoding="utf-8")
        self.assertIn("spawn", text)
        self.assertIn("-m", text)
        self.assertIn("aidefender", text)
        self.assertIn("aidefender:run", text)

    def test_renderer_calls_json_commands(self):
        js = (ROOT / "ui" / "renderer" / "app.js").read_text(encoding="utf-8")
        html = (ROOT / "ui" / "renderer" / "index.html").read_text(encoding="utf-8")
        self.assertIn('<script src="app.js">', html)
        self.assertNotIn("require(", js)
        self.assertNotIn("module.exports", js)
        self.assertIn("--json", js)
        for needle in (
            "status", "scan", "protect", "update", "intrusion", "engines",
            "quarantine", "allow", "diag", "processes", "network", "events", "analyze",
        ):
            self.assertIn(needle, js, needle)
            self.assertIn(needle, html, needle)
        for needle in ("settings", "ai", "config"):
            self.assertIn(needle, js, needle)
            self.assertIn(needle, html, needle)
        for argv in (
            '["scan"]',
            '["protect", "--once"]',
            '["quarantine", "list"]',
            '["update"]',
            '["intrusion"]',
            '["engines"]',
            '["status"]',
            '["allow", "list"]',
            '["allow", "add"]',
            '["allow", "remove"]',
            '["diag"]',
            '["processes"]',
            '["network"]',
            '["events"',
            '["analyze"]',
            '["ai", "status"]',
            '["ai", "use"]',
            '["ai", "test"]',
            '["config", "get"]',
            '["config", "set"]',
        ):
            self.assertIn(argv, js, argv)
        for tab in (
            'data-tab="dash"', 'data-tab="scan"', 'data-tab="protect"',
            'data-tab="quarantine"', 'data-tab="intel"', 'data-tab="intrusion"',
            'data-tab="engines"', 'data-tab="analyze"', 'data-tab="allow"',
            'data-tab="diag"', 'data-tab="processes"', 'data-tab="network"',
            'data-tab="events"', 'data-tab="settings"',
        ):
            self.assertIn(tab, html, tab)
        self.assertIn("window.aidefender", js)

    def test_release_workflow_publishes_binaries(self):
        wf = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("pyinstaller", wf)
        self.assertIn("electron-builder", wf)
        self.assertIn("action-gh-release", wf)
        self.assertIn("tags:", wf)
        names = [
            "aidefender-linux-x64",
            "aidefender-macos-arm64",
            "aidefender-windows-x64.exe",
        ]
        for name in names:
            self.assertIn(name, wf)
        self.assertEqual(len(names), len(set(names)))
        publish = wf.split("Publish GitHub Release", 1)[-1]
        self.assertIn("aidefender-linux-x64", publish)
        self.assertIn("aidefender-macos-arm64", publish)
        self.assertIn("aidefender-windows-x64.exe", publish)
        files_lines = [
            ln.strip().rstrip("\\")
            for ln in publish.split("files:", 1)[-1].splitlines()
            if ln.strip()
        ]
        self.assertNotIn("artifacts/**/*", files_lines)
        self.assertNotIn("artifacts/**/aidefender", files_lines)

    def test_readme_documents_shipped_product(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        for needle in (
            "aidefender scan",
            "aidefender intrusion",
            "intrusion --firewall",
            "opt-in",
            "pip install",
            "python -m unittest discover",
            "blocked-ips.json",
            "local_ai_base_url",
            "Franzferdinan51/AIDefender/releases",
            "aidefender --json tools",
            "allow add",
            "aidefender diag",
            "allowlist.json",
            "rogue-AI",
            "DDOS",
            "counter-AI",
            "Local-first AI assist",
            "AI-powered opt-in",
            "scan --ai",
            "antivirus",
            "quarantine",
            "real-time protect",
            "user-mode",
            "minifilter",
            "volumetric",
            "unsigned",
            "0.11.0",
            "v0.11.0",
            "local_ai",
        ):
            self.assertIn(needle, text, needle)
        self.assertNotIn("AIDefender.Setup.0.9.0.exe on some tags", text)
        self.assertNotIn("latest tagged GitHub Release is **v0.9.0**", text)
        self.assertNotIn("it lags this `main` tree", text)

    def test_readme_names_desktop_operator_surfaces(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        start = text.find("## Desktop UI")
        self.assertGreater(start, -1)
        section = text[start : start + 1600]
        for needle in (
            "npm start",
            "aidefender ui",
            "allowlist",
            "diag",
            "processes",
            "network",
            "events",
            "analyze",
            "settings",
        ):
            self.assertIn(needle, section, needle)

    def test_pyinstaller_spec_exists(self):
        spec = (ROOT / "packaging" / "aidefender.spec").read_text(encoding="utf-8")
        self.assertIn("aidefender", spec)
        self.assertIn("signatures.json", spec)


if __name__ == "__main__":
    unittest.main()
