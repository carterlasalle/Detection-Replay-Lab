from __future__ import annotations

import gzip
import json
import tempfile
import unittest
from pathlib import Path

from detection_replay_lab.events import event_from_stdin, load_events
from detection_replay_lab.models import ValidationError


class EventLoaderTests(unittest.TestCase):
    def test_loads_json_ndjson_csv_and_gzip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.json").write_text(
                json.dumps({"id": "one", "timestamp": 1}), encoding="utf-8"
            )
            (root / "two.ndjson").write_text('{"id":"two","timestamp":2}\n', encoding="utf-8")
            (root / "three.csv").write_text("id,timestamp\nthree,3\n", encoding="utf-8")
            with gzip.open(root / "four.ndjson.gz", "wt", encoding="utf-8") as stream:
                stream.write('{"id":"four","timestamp":4}\n')
            events = load_events([root])
        self.assertEqual({event.id for event in events}, {"one", "two", "three", "four"})

    def test_stdin_uses_logical_filename_and_rejects_non_objects(self) -> None:
        events = event_from_stdin('{"id":"one","timestamp":1}\n', filename="pipe.ndjson")
        self.assertEqual(events[0].source, "pipe.ndjson")
        with self.assertRaisesRegex(ValidationError, "object"):
            event_from_stdin("[1,2,3]", filename="pipe.json")


if __name__ == "__main__":
    unittest.main()
