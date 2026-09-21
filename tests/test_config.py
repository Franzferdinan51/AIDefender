import unittest

from aidefender.config import (
    DefenderConfig,
    coerce_value,
    redacted_dict,
    validate_config,
)


class ConfigHardeningTest(unittest.TestCase):
    def test_coerce_types(self):
        self.assertTrue(coerce_value("auto_quarantine", "yes"))
        self.assertFalse(coerce_value("auto_quarantine", "0"))
        self.assertEqual(coerce_value("ai_sample_bytes", "512"), 512)
        self.assertEqual(coerce_value("ai_timeout_seconds", "2.5"), 2.5)
        self.assertEqual(coerce_value("watch_paths", "a, b"), ["a", "b"])
        self.assertEqual(coerce_value("network_bad_ports", "1,2"), [1, 2])
        self.assertEqual(coerce_value("local_ai_model", " m "), "m")
        with self.assertRaises(ValueError):
            coerce_value("auto_quarantine", "maybe")
        with self.assertRaises(ValueError):
            coerce_value("ai_sample_bytes", "lots")
        with self.assertRaises(ValueError):
            coerce_value("cloud_ai_api_key", "x")
        with self.assertRaises(ValueError):
            coerce_value("nope", "x")

    def test_validate_clamps_thresholds(self):
        cfg = DefenderConfig(heuristic_suspicious=999, heuristic_malicious=-5)
        warnings = validate_config(cfg)
        self.assertEqual(cfg.heuristic_suspicious, 100)
        self.assertEqual(cfg.heuristic_malicious, 100)
        self.assertTrue(warnings)

    def test_validate_repairs_nonstr(self):
        cfg = DefenderConfig()
        cfg.ai_timeout_seconds = "bogus"  # type: ignore
        warnings = validate_config(cfg)
        self.assertIsInstance(cfg.ai_timeout_seconds, float)
        self.assertTrue(warnings)

    def test_redacted_dict_hides_keys(self):
        cfg = DefenderConfig(cloud_ai_api_key="sekret", local_ai_api_key="")
        data = redacted_dict(cfg)
        self.assertEqual(data["cloud_ai_api_key"], "***set***")
        self.assertEqual(data["local_ai_api_key"], "")
        self.assertIn("_api_key_hint", data)


if __name__ == "__main__":
    unittest.main()
