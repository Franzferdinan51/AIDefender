import json
import tempfile
import unittest
from pathlib import Path

from aidefender import aibackends
from aidefender.aibackends import (
    BackendStatus,
    detect_backends,
    models_url,
    parse_model_ids,
    probe_backend,
    test_roundtrip,
    use_backend,
)
from aidefender.config import DefenderConfig, get_config


def fake_getter(payload: dict):
    def _get(url: str, timeout: float):
        _get.seen.append(url)
        if isinstance(payload, Exception):
            raise payload
        return payload
    _get.seen = []
    return _get


class BackendProbeTest(unittest.TestCase):
    def test_models_url(self):
        self.assertEqual(models_url("http://127.0.0.1:1234/v1"), "http://127.0.0.1:1234/v1/models")
        self.assertEqual(models_url("http://x/v1/"), "http://x/v1/models")
        self.assertEqual(models_url("http://x/v1/models"), "http://x/v1/models")
        self.assertEqual(models_url(""), "")

    def test_parse_openai_shape(self):
        payload = {"object": "list", "data": [{"id": "a", "object": "model"}, {"id": "b"}]}
        self.assertEqual(parse_model_ids(payload), ["a", "b"])

    def test_parse_string_items_and_dedupe(self):
        payload = {"data": ["a", "a", "b"]}
        self.assertEqual(parse_model_ids(payload), ["a", "b"])

    def test_parse_ollama_shape(self):
        payload = {"models": [{"name": "llama3.2:latest"}, {"name": "qwen:7b"}]}
        self.assertEqual(parse_model_ids(payload), ["llama3.2:latest", "qwen:7b"])

    def test_parse_empty(self):
        self.assertEqual(parse_model_ids({}), [])
        self.assertEqual(parse_model_ids({"data": []}), [])

    def test_probe_success(self):
        status = probe_backend("lmstudio", "http://127.0.0.1:1234/v1",
                               getter=fake_getter({"data": [{"id": "m1"}, {"id": "m2"}]}))
        self.assertTrue(status.reachable)
        self.assertEqual(status.models, ["m1", "m2"])
        self.assertEqual(status.error, "")

    def test_probe_failure_never_raises(self):
        status = probe_backend("ollama", "http://127.0.0.1:11434/v1",
                               getter=fake_getter(ConnectionError("down")))
        self.assertFalse(status.reachable)
        self.assertIn("down", status.error)

    def test_probe_empty_base(self):
        status = probe_backend("x", "", getter=fake_getter({}))
        self.assertFalse(status.reachable)
        self.assertIn("empty", status.error)

    def test_detect_marks_active_and_custom(self):
        cfg = DefenderConfig(local_ai_base_url="http://127.0.0.1:1234/v1")
        results = detect_backends(cfg, getter=fake_getter({"data": []}), include_lms=False)
        names = [r.name for r in results]
        self.assertIn("lmstudio", names)
        self.assertIn("ollama", names)
        active = [r for r in results if "active" in r.source]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].name, "lmstudio")

        cfg2 = DefenderConfig(local_ai_base_url="http://10.0.0.9:8080/v1")
        results2 = detect_backends(cfg2, getter=fake_getter({"data": []}), include_lms=False)
        customs = [r for r in results2 if r.name == "custom"]
        self.assertEqual(len(customs), 1)
        self.assertIn("active", customs[0].source)

    def test_use_preset_and_custom(self):
        cfg = DefenderConfig()
        use_backend(cfg, "lmstudio", model="my-model")
        self.assertEqual(cfg.local_ai_base_url, "http://127.0.0.1:1234/v1")
        self.assertEqual(cfg.local_ai_model, "my-model")
        use_backend(cfg, "OLLAMA")
        self.assertEqual(cfg.local_ai_base_url, "http://127.0.0.1:11434/v1")
        use_backend(cfg, "http://10.1.2.3:8000/v1/")
        self.assertEqual(cfg.local_ai_base_url, "http://10.1.2.3:8000/v1")
        with self.assertRaises(ValueError):
            use_backend(cfg, "   ")

    def test_roundtrip_ok_with_fake_poster(self):
        def poster(url, headers, body, timeout):
            envelope = {"choices": [{"message": {"content": '{"verdict":"clean"}'}}]}
            return 200, json.dumps(envelope)
        result = test_roundtrip("http://127.0.0.1:1234/v1", "m", poster=poster)
        self.assertTrue(result["ok"])
        self.assertIn("verdict", result["reply_preview"])

    def test_roundtrip_failure_is_clean_dict(self):
        def poster(url, headers, body, timeout):
            raise ConnectionError("refused")
        result = test_roundtrip("http://127.0.0.1:1234/v1", "m", poster=poster)
        self.assertFalse(result["ok"])
        self.assertIn("refused", result["error"])

    def test_status_dataclass_serializes(self):
        status = BackendStatus(name="x", base_url="http://u", reachable=True, models=["m"])
        self.assertEqual(status.to_dict()["models"], ["m"])


if __name__ == "__main__":
    unittest.main()
