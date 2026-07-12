from __future__ import annotations

import unittest
from datetime import UTC, datetime

from detection_replay_lab.models import ValidationError, parse_timestamp, stable_id
from detection_replay_lab.normalize import Normalizer


class ModelTests(unittest.TestCase):
    def test_parses_rfc3339_and_epoch_to_utc(self) -> None:
        self.assertEqual(parse_timestamp("2026-01-02T03:04:05Z").tzinfo, UTC)
        self.assertEqual(parse_timestamp(0), datetime(1970, 1, 1, tzinfo=UTC))

    def test_rejects_invalid_timestamp(self) -> None:
        with self.assertRaisesRegex(ValidationError, "invalid timestamp"):
            parse_timestamp("yesterday-ish")

    def test_stable_id_is_deterministic_and_domain_separated(self) -> None:
        self.assertEqual(stable_id("a", "b"), stable_id("a", "b"))
        self.assertNotEqual(stable_id("a", "b"), stable_id("ab"))


class NormalizerTests(unittest.TestCase):
    def test_maps_sysmon_aliases_without_discarding_original(self) -> None:
        event = Normalizer().normalize(
            {
                "UtcTime": "2026-01-02T03:04:05Z",
                "EventID": 1,
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": "powershell.exe -enc AAAA",
                "Computer": "LAB-01",
            },
            index=1,
            source="sysmon.ndjson",
        )
        self.assertEqual(event.get("event.code"), 1)
        self.assertTrue(event.get("process.name").endswith("powershell.exe"))
        self.assertEqual(event.get("host.name"), "LAB-01")
        self.assertEqual(event.get("EventID"), 1)

    def test_requires_timestamp_and_valid_label(self) -> None:
        with self.assertRaisesRegex(ValidationError, "timestamp"):
            Normalizer().normalize({"EventID": 1})
        with self.assertRaisesRegex(ValidationError, "label"):
            Normalizer().normalize({"timestamp": 0, "label": "maybe"})


if __name__ == "__main__":
    unittest.main()
