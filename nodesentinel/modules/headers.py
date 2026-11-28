from urllib.parse import urlparse


def _finding(
    finding_id,
    title,
    severity,
    description,
    evidence,
    recommendation,
    category="HTTP Security",
):
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "category": category,
    }


def get_cookie_headers(response):
    """
    Return individual Set-Cookie header values where the HTTP library
    exposes them. Fall back to the combined response header otherwise.
    """
    try:
        raw_headers = response.raw.headers
        cookies = raw_headers.getlist("Set-Cookie")

        if cookies:
            return cookies
    except (AttributeError, TypeError):
        pass

    cookie_header = response.headers.get("Set-Cookie")

    if cookie_header:
        return [cookie_header]

    return []


def check_security_headers(response, findings):
    headers = response.headers
    url_scheme = urlparse(response.url).scheme.lower()

    if not headers.get("Content-Security-Policy"):
        findings.append(
            _finding(
                "HDR-001",
                "Content-Security-Policy header missing",
                "Medium",
                "The response does not include a Content-Security-Policy "
                "header. A suitable CSP can help reduce the impact of "
                "certain content injection attacks.",
                "Content-Security-Policy header was not present.",
                "Define and configure a restrictive Content-Security-Policy "
                "appropriate for the application.",
            )
        )

    csp = headers.get("Content-Security-Policy", "").lower()

    if (
        not headers.get("X-Frame-Options")
        and "frame-ancestors" not in csp
    ):
        findings.append(
            _finding(
                "HDR-002",
                "Clickjacking protection missing",
                "Medium",
                "The response does not include X-Frame-Options or a "
                "Content-Security-Policy frame-ancestors directive.",
                "Neither X-Frame-Options nor CSP frame-ancestors was found.",
                "Configure X-Frame-Options or use the CSP frame-ancestors "
                "directive to control which sites can embed the page.",
            )
        )

    if url_scheme == "https" and not headers.get("Strict-Transport-Security"):
        findings.append(
            _finding(
                "HDR-003",
                "Strict-Transport-Security header missing",
                "Medium",
                "The HTTPS response does not include an HSTS header.",
                "Strict-Transport-Security header was not present.",
                "Configure Strict-Transport-Security with an appropriate "
                "max-age value. Consider includeSubDomains only if all "
                "subdomains support HTTPS.",
            )
        )


def check_cors(response, findings):
    headers = response.headers

    allow_origin = headers.get("Access-Control-Allow-Origin", "")
    allow_credentials = headers.get(
        "Access-Control-Allow-Credentials", ""
    ).lower()

    if not allow_origin:
        return

    if allow_origin == "*" and allow_credentials == "true":
        findings.append(
            _finding(
                "CORS-001",
                "Wildcard CORS origin used with credentials",
                "Medium",
                "The server returns a wildcard Access-Control-Allow-Origin "
                "value together with Access-Control-Allow-Credentials: true. "
                "Browsers reject this combination, but it indicates an "
                "inconsistent CORS configuration.",
                (
                    "Access-Control-Allow-Origin: *; "
                    "Access-Control-Allow-Credentials: true"
                ),
                "Use an explicit allowlist of trusted origins. Do not combine "
                "a wildcard origin with credentialed requests.",
                "CORS",
            )
        )

    elif (
        allow_origin == "https://nodesentinel-test.invalid"
        and allow_credentials == "true"
    ):
        findings.append(
            _finding(
                "CORS-002",
                "CORS reflects an untrusted test origin with credentials",
                "High",
                "The server returned the supplied test origin and enabled "
                "credentialed cross-origin requests. This may indicate "
                "unsafe origin reflection.",
                (
                    "The supplied Origin was reflected in "
                    "Access-Control-Allow-Origin and credentials were enabled."
                ),
                "Validate incoming origins against a strict allowlist. "
                "Never reflect arbitrary Origin values.",
                "CORS",
            )
        )

    elif allow_origin == "https://nodesentinel-test.invalid":
        findings.append(
            _finding(
                "CORS-003",
                "CORS reflects the supplied test origin",
                "Low",
                "The server returned the origin supplied by NodeSentinel. "
                "This may indicate dynamic origin reflection.",
                (
                    "Access-Control-Allow-Origin matched "
                    "https://nodesentinel-test.invalid."
                ),
                "Verify that the application checks origins against a "
                "strict allowlist before returning them.",
                "CORS",
            )
        )


def _parse_cookie_attributes(cookie):
    parts = [part.strip() for part in cookie.split(";")[1:] if part.strip()]
    attributes = {}

    for part in parts:
        if "=" in part:
            attr_name, attr_value = part.split("=", 1)
            attributes[attr_name.strip().lower()] = attr_value.strip().lower()
        else:
            attributes[part.lower()] = True

    return attributes


def check_cookies(response, findings):
    cookies = get_cookie_headers(response)

    for index, cookie in enumerate(cookies, start=1):
        first_part = cookie.split(";", 1)[0]
        cookie_name = (
            first_part.split("=", 1)[0].strip()
            if "=" in first_part
            else "unknown"
        )
        attributes = _parse_cookie_attributes(cookie)

        if "httponly" not in attributes:
            findings.append(
                _finding(
                    f"COOKIE-{index:03d}-HTTPONLY",
                    f"Cookie {cookie_name} missing HttpOnly",
                    "Medium",
                    "The cookie does not include the HttpOnly attribute. "
                    "Client-side scripts may be able to access it.",
                    cookie,
                    "Set the HttpOnly attribute on cookies that do not "
                    "need to be accessed by JavaScript.",
                    "Cookies",
                )
            )

        if "secure" not in attributes:
            findings.append(
                _finding(
                    f"COOKIE-{index:03d}-SECURE",
                    f"Cookie {cookie_name} missing Secure",
                    "Medium",
                    "The cookie does not include the Secure attribute.",
                    cookie,
                    "Set the Secure attribute so the cookie is only sent "
                    "over HTTPS.",
                    "Cookies",
                )
            )

        samesite_value = attributes.get("samesite")

        if samesite_value not in {"strict", "lax", "none"}:
            findings.append(
                _finding(
                    f"COOKIE-{index:03d}-SAMESITE",
                    f"Cookie {cookie_name} missing SameSite",
                    "Low",
                    "The cookie does not explicitly define a SameSite policy.",
                    cookie,
                    "Set an appropriate SameSite value, such as Lax or "
                    "Strict, based on the application's requirements.",
                    "Cookies",
                )
            )

        elif samesite_value == "none" and "secure" not in attributes:
            findings.append(
                _finding(
                    f"COOKIE-{index:03d}-SAMESITE-SECURE",
                    f"Cookie {cookie_name} uses SameSite=None without Secure",
                    "Medium",
                    "A cookie using SameSite=None should also include Secure.",
                    cookie,
                    "Add the Secure attribute when using SameSite=None.",
                    "Cookies",
                )
            )


def run(target, session):
    """
    Run HTTP header, CORS, and cookie checks against the target.

    Args:
        target: Base URL of the authorized target application.
        session: requests.Session-compatible object.

    Returns:
        A list of finding dictionaries.
    """
    findings = []

    try:
        response = session.get(
            target,
            headers={
                "Origin": "https://nodesentinel-test.invalid"
            },
            timeout=10,
            allow_redirects=True,
        )

        check_security_headers(response, findings)
        check_cors(response, findings)
        check_cookies(response, findings)

    except Exception as error:
        findings.append(
            _finding(
                "HDR-ERROR",
                "HTTP security checks could not be completed",
                "Informational",
                "NodeSentinel could not retrieve the target response.",
                str(error),
                "Verify that the target is reachable and that the URL is correct.",
            )
        )

    return findings
