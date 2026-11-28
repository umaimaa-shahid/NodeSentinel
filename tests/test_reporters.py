import json
import os
import tempfile
import unittest

from nodesentinel.reporter.json_report import (
    build_report,
    write_json_report,
)

from nodesentinel.reporter.html_report import (
    generate_html_report,
    write_html_report,
)


class TestJSONReporter(unittest.TestCase):

    def setUp(self):
        self.target = "https://example.com"

        self.findings = [
            {
                "id": "HDR-001",
                "title": "Missing Content Security Policy",
                "severity": "High",
                "category": "Security Headers",
                "description": "The target does not have a Content Security Policy.",
                "recommendation": "Configure a suitable Content Security Policy.",
            },
            {
                "id": "BRUTE-002",
                "title": "No rate limiting detected",
                "severity": "Medium",
                "category": "Brute Force",
                "description": "The login endpoint did not show rate-limiting behavior.",
                "recommendation": "Implement login rate limiting.",
            },
        ]

    def test_build_report_returns_dictionary(self):
        report = build_report(self.target, self.findings)

        self.assertIsInstance(report, dict)

    def test_report_contains_target(self):
        report = build_report(self.target, self.findings)

        self.assertEqual(report["target"], self.target)

    def test_report_contains_findings(self):
        report = build_report(self.target, self.findings)

        self.assertEqual(report["total_findings"], 2)
        self.assertEqual(len(report["findings"]), 2)

    def test_report_contains_severity_summary(self):
        report = build_report(self.target, self.findings)

        self.assertIn("summary", report)
        self.assertIsInstance(report["summary"], dict)

        self.assertEqual(report["summary"]["High"], 1)
        self.assertEqual(report["summary"]["Medium"], 1)

    def test_write_json_report_creates_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "report.json")

            write_json_report(
                self.target,
                self.findings,
                output_path,
            )

            self.assertTrue(os.path.exists(output_path))

            with open(output_path, "r", encoding="utf-8") as file:
                saved_report = json.load(file)

            self.assertEqual(saved_report["target"], self.target)
            self.assertEqual(saved_report["total_findings"], 2)


class TestHTMLReporter(unittest.TestCase):

    def setUp(self):
        self.target = "https://example.com"

        self.findings = [
            {
                "id": "HDR-001",
                "title": "Missing Content Security Policy",
                "severity": "High",
                "category": "Security Headers",
                "description": "The target does not have a Content Security Policy.",
                "recommendation": "Configure a suitable Content Security Policy.",
            },
            {
                "id": "BRUTE-002",
                "title": "No rate limiting detected",
                "severity": "Medium",
                "category": "Brute Force",
                "description": "The login endpoint did not show rate-limiting behavior.",
                "recommendation": "Implement login rate limiting.",
            },
        ]

    def test_generate_html_returns_string(self):
        html = generate_html_report(self.target, self.findings)

        self.assertIsInstance(html, str)

    def test_html_contains_target(self):
        html = generate_html_report(self.target, self.findings)

        self.assertIn(self.target, html)

    def test_html_contains_finding_titles(self):
        html = generate_html_report(self.target, self.findings)

        self.assertIn("Missing Content Security Policy", html)
        self.assertIn("No rate limiting detected", html)

    def test_write_html_report_creates_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "report.html")

            write_html_report(
                self.target,
                self.findings,
                output_path,
            )

            self.assertTrue(os.path.exists(output_path))

            with open(output_path, "r", encoding="utf-8") as file:
                html = file.read()

            self.assertIn(self.target, html)


if __name__ == "__main__":
    unittest.main()