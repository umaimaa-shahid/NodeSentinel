import unittest
from unittest.mock import Mock, MagicMock

from nodesentinel.modules import headers, brute_force


class TestHeadersModule(unittest.TestCase):

    def setUp(self):
        self.session = Mock()
        self.response = MagicMock()

        self.response.status_code = 200
        self.response.url = "https://example.com"
        self.response.headers = {
            "Content-Type": "text/html"
        }

        self.response.raw.headers.getlist.return_value = []

        self.session.get.return_value = self.response

    def test_run_returns_list(self):
        findings = headers.run("https://example.com", self.session)

        self.assertIsInstance(findings, list)

    def test_missing_security_headers_are_detected(self):
        findings = headers.run("https://example.com", self.session)

        finding_ids = [finding.get("id", "") for finding in findings]

        self.assertTrue(
            any(finding_id.startswith("HDR-") for finding_id in finding_ids),
            "Expected missing security headers to be reported."
        )

    def test_wildcard_cors_is_detected(self):
        self.response.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }

        findings = headers.run("https://example.com", self.session)

        finding_ids = [finding.get("id", "") for finding in findings]

        self.assertTrue(
            any(finding_id.startswith("CORS-") for finding_id in finding_ids),
            "Expected wildcard CORS configuration to be reported."
        )


class TestBruteForceModule(unittest.TestCase):

    def setUp(self):
        self.session = Mock()

        self.response = Mock()
        self.response.status_code = 401
        self.response.headers = {}

        self.session.post.return_value = self.response

    def test_run_returns_list(self):
        findings = brute_force.run("https://example.com", self.session)

        self.assertIsInstance(findings, list)

    def test_login_endpoint_is_tested(self):
        brute_force.run("https://example.com", self.session)

        self.assertTrue(self.session.post.called)

    def test_rate_limit_response_is_detected(self):
        self.response.status_code = 429
        self.response.headers = {
            "Retry-After": "60"
        }

        findings = brute_force.run("https://example.com", self.session)

        finding_ids = [finding.get("id", "") for finding in findings]

        self.assertIn("BRUTE-001", finding_ids)

    def test_missing_rate_limiting_is_reported(self):
        findings = brute_force.run("https://example.com", self.session)

        finding_ids = [finding.get("id", "") for finding in findings]

        self.assertIn("BRUTE-002", finding_ids)


if __name__ == "__main__":
    unittest.main()