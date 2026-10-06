import unittest
from correlate.evaluator import SecurityEvaluator, verdict_for_score
from correlate.process_tree import ProcessTree
from internal.models import Event, EventType
from report.generator import Generator


class EvaluationTests(unittest.TestCase):
    def evaluate(self, commands):
        tree = ProcessTree("test")
        tree.set_root_pid(10)
        events = []
        for index, (pid, ppid, argv) in enumerate(commands):
            event = Event("test", "container", index, EventType.PROCESS_EXEC,
                          pid, ppid, argv[0], argv=argv)
            tree.add_event(event)
            events.append(event)
        return tree, events, SecurityEvaluator(tree, events).evaluate()

    def test_boundaries(self):
        self.assertEqual([verdict_for_score(s) for s in (0, 15, 16, 49, 50, 100)],
                         ["SAFE", "SAFE", "SUSPICIOUS", "SUSPICIOUS", "MALICIOUS", "MALICIOUS"])

    def test_host_events_excluded(self):
        _, _, result = self.evaluate([(10, 1, ["python3", "main.py"]), (99, 1, ["nc", "-e", "sh"])])
        self.assertEqual(result.score, 0)

    def test_download_and_duplicate(self):
        _, _, result = self.evaluate([(10, 1, ["bash"]), (11, 10, ["curl", "https://example.com"]),
                                     (11, 10, ["curl", "https://example.com"])])
        self.assertEqual(result.score, 25)

    def test_reverse_shell_and_cap(self):
        _, _, result = self.evaluate([(10, 1, ["nc", "-e", "sh"]), (11, 10, ["sudo", "id"])])
        self.assertEqual((result.score, result.verdict), (100, "MALICIOUS"))

    def test_dropper(self):
        _, _, result = self.evaluate([(10, 1, ["bash"]), (11, 10, ["curl", "-o", "/tmp/payload", "https://example.com"]),
                                     (12, 10, ["chmod", "+x", "/tmp/payload"]), (13, 10, ["/tmp/payload"])])
        self.assertIn("dropper", [f.rule for f in result.findings])

    def test_report_and_tree(self):
        tree, events, result = self.evaluate([(11, 10, ["curl"]), (12, 10, ["echo"]), (10, 1, ["bash"])])
        reporter = Generator()
        reporter.events = events
        report = reporter.generate("test", tree, result, color=False)
        self.assertIn("├── curl", report)
        self.assertIn("FLAGGED: download", report)
        self.assertIn("Verdict: SUSPICIOUS", report)
        self.assertNotIn("\033", report)

    def test_missing_telemetry(self):
        _, _, result = self.evaluate([])
        self.assertTrue(any("No sandbox executions" in item for item in result.limitations))


if __name__ == "__main__":
    unittest.main()
