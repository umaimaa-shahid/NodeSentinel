"""Target / scan configuration for NodeSentinel."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

DEFAULT_WEAK_SECRETS = [
    "secret", "password", "123456", "12345678", "admin", "changeme", "jwt",
    "jwt_secret", "jwtsecret", "your-256-bit-secret", "supersecret", "mysecret",
    "key", "test", "default", "letmein", "qwerty", "node", "express", "token",
]


@dataclass
class Endpoint:
    """An endpoint to probe for NoSQL injection."""
    path: str
    method: str = "POST"
    # Baseline (benign, expected-to-fail) parameters, e.g. login credentials.
    params: Dict[str, str] = field(
        default_factory=lambda: {"username": "nodesentinel", "password": "invalid-pass-123"}
    )
    location: str = "json"  # "json" | "query" | "form"

    @classmethod
    def parse(cls, spec: str) -> "Endpoint":
        """Parse 'METHOD:/path' or just '/path' (defaults to POST, JSON body)."""
        if ":" in spec and not spec.startswith("/"):
            method, path = spec.split(":", 1)
            method = method.upper()
        else:
            method, path = "POST", spec
        location = "query" if method == "GET" else "json"
        return cls(path=path, method=method, location=location)


@dataclass
class ScanConfig:
    target: str
    endpoints: List[Endpoint] = field(default_factory=list)
    timeout: float = 10.0
    verify_tls: bool = True
    headers: Dict[str, str] = field(default_factory=dict)

    # JWT settings
    token: Optional[str] = None            # supply a token directly, or...
    login_path: Optional[str] = None       # ...obtain one by logging in
    login_creds: Dict[str, str] = field(default_factory=dict)
    token_field: str = "token"             # JSON key holding the token in login response
    protected_path: Optional[str] = None   # endpoint that requires auth (for alg:none test)
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    max_lifetime_seconds: int = 24 * 3600  # longer than this is flagged "excessive"
    wordlist_path: Optional[str] = None    # extra weak-secret candidates, one per line

    def __post_init__(self) -> None:
        parsed = urlparse(self.target)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Invalid target URL: {self.target!r} (need http:// or https://)")
        self.target = self.target.rstrip("/")

    def secret_candidates(self) -> List[str]:
        words = list(DEFAULT_WEAK_SECRETS)
        if self.wordlist_path:
            with open(self.wordlist_path, encoding="utf-8", errors="ignore") as fh:
                words += [ln.strip() for ln in fh if ln.strip()]
        return list(dict.fromkeys(words))

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["endpoints"] = [Endpoint(**e) for e in raw.get("endpoints", [])]
        return cls(**raw)
