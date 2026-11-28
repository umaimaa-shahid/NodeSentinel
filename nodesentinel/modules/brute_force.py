import os
from urllib.parse import urljoin


def _finding(
    finding_id,
    title,
    severity,
    description,
    evidence,
    recommendation,
):
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "category": "Brute Force Protection",
    }


def run(target, session):
    """
    Perform a small, bounded login rate-limit check.

    Only use this against an application you own or have permission
    to test. The default endpoint is /login. You can override it by
    setting NODESENTINEL_LOGIN_PATH.

    Returns:
        A list of finding dictionaries.
    """
    findings = []

    login_path = os.getenv("NODESENTINEL_LOGIN_PATH", "/login")

    if not login_path.startswith("/"):
        login_path = "/" + login_path

    login_url = urljoin(target.rstrip("/") + "/", login_path.lstrip("/"))

    max_attempts = 5
    rate_limit_observed = False
    responses_received = 0

    for attempt in range(1, max_attempts + 1):
        try:
            response = session.post(
                login_url,
                json={
                    "username": "nodesentinel_test_user",
                    "email": "nodesentinel_test_user@example.invalid",
                    "password": "NodeSentinel_Invalid_Test_Password",
                },
                timeout=10,
                allow_redirects=False,
            )

            responses_received += 1

            status_code = response.status_code
            headers = response.headers

            retry_after = headers.get("Retry-After")
            remaining = headers.get("X-RateLimit-Remaining")

            if status_code in (423, 429):
                rate_limit_observed = True
                break

            if retry_after:
                rate_limit_observed = True
                break

            if remaining is not None:
                try:
                    if int(remaining) <= 0:
                        rate_limit_observed = True
                        break
                except ValueError:
                    pass

        except Exception as error:
            findings.append(
                _finding(
                    "BRUTE-ERROR",
                    "Login rate-limit check could not be completed",
                    "Informational",
                    "NodeSentinel could not complete the login endpoint test.",
                    str(error),
                    "Verify the login endpoint and ensure the authorized "
                    "test application is running.",
                )
            )
            return findings

    if rate_limit_observed:
        findings.append(
            _finding(
                "BRUTE-001",
                "Login rate limiting or lockout behavior observed",
                "Informational",
                "The login endpoint returned a response or header indicating "
                "that rate limiting or account lockout may be active.",
                (
                    f"Rate-limit behavior observed after "
                    f"{responses_received} request(s)."
                ),
                "Verify that the protection is consistently enforced, "
                "applies to relevant login attempts, and is supported by "
                "appropriate monitoring.",
            )
        )

    else:
        findings.append(
            _finding(
                "BRUTE-002",
                "No login rate limiting observed",
                "Medium",
                f"The login endpoint accepted {responses_received} test "
                "request(s) without an identifiable rate-limit or lockout "
                "response.",
                (
                    f"{responses_received} bounded test requests were sent. "
                    "No HTTP 429, HTTP 423, Retry-After header, or exhausted "
                    "X-RateLimit-Remaining value was observed."
                ),
                "Implement login rate limiting, progressive delays, and "
                "appropriate account protection. Avoid relying on a single "
                "control.",
            )
        )

    return findings