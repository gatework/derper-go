import json
from pathlib import Path
import tempfile
import unittest

from compare_relay_benchmarks import compare


class PerformanceGateTests(unittest.TestCase):
    def write_trials(self, directory, rate=1, latency=1):
        for i in range(3):
            trial = Path(directory) / str(i)
            trial.mkdir()
            (trial / "comparison.json").write_text(json.dumps({
                "baseline": {"mbps": 100, "p99_us": 1000},
                "candidate": {"mbps": 100 * rate, "p99_us": 1000 * latency},
            }))

    def test_throughput_and_tail_latency_gate(self):
        for rate, latency, passed in [(1, 1, True), (.94, 1, False), (1, 1.11, False)]:
            with self.subTest(rate=rate, latency=latency), tempfile.TemporaryDirectory() as directory:
                self.write_trials(directory, rate, latency)
                self.assertEqual(compare(Path(directory)), passed)
                self.assertTrue((Path(directory) / "REPORT.md").is_file())

    def test_partial_and_empty_results_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                compare(Path(directory))
            self.write_trials(directory, rate=0)
            with self.assertRaises(ValueError):
                compare(Path(directory))
