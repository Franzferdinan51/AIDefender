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
        text = (ROOT / "ui" / "renderer" / "app.js").read_text(encoding="utf-8")
        self.assertIn('--json', text.replace("'", '"') or "--json")
        self.assertIn("scan", text)
        self.assertIn("update", text)
        self.assertIn("protect", text)

    def test_release_workflow_publishes_binaries(self):
        wf = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("pyinstaller", wf)
        self.assertIn("electron-builder", wf)
        self.assertIn("action-gh-release", wf)
        self.assertIn("tags:", wf)

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
        ):
            self.assertIn(needle, text, needle)

    def test_pyinstaller_spec_exists(self):
        spec = (ROOT / "packaging" / "aidefender.spec").read_text(encoding="utf-8")
        self.assertIn("aidefender", spec)
        self.assertIn("signatures.json", spec)


if __name__ == "__main__":
    unittest.main()
