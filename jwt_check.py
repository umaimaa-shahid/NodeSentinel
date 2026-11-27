"""JWT security checks: alg:none, missing/long expiry, weak HMAC secrets."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Dict, List, Optional, Tuple

from engine import Finding, ScannerModule

HMAC_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def parse_jwt(token: str) -> Optional[Tuple[Dict, Dict, str]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(b64url_decode(parts[0])), json.loads(b64url_decode(parts[1])), parts[2]
    except (ValueError, UnicodeDecodeError):
        return None


class JWTCheckModule(ScannerModule):
    name = "jwt"
    description = "Checks alg:none acceptance, token expiry and weak HMAC secrets."

    def run(self) -> List[Finding]:
        token = self.cfg.token or self._login()
        if not token:
            return [Finding(self.name, "No JWT available to test", "info", self.cfg.target,
                            "Provide --token, or --login-path with --login-creds.")]
        parsed = parse_jwt(token)
        if not parsed:
            return [Finding(self.name, "Supplied token is not a valid JWT", "info",
                            self.cfg.target, "Expected three base64url segments.")]
        header, payload, _ = parsed
        findings = self._check_expiry(payload)
        findings += self._check_weak_secret(token, header)
        findings += self._check_alg_none(token, payload)
        return findings

    # -- token acquisition ------------------------------------------------
    def _login(self) -> Optional[str]:
        if not self.cfg.login_path:
            return None
        resp = self.client.request("POST", self.cfg.login_path, json=self.cfg.login_creds)
        if resp is None:
            return None
        try:
            body = resp.json()
        except ValueError:
            return None
        return self._find_key(body, self.cfg.token_field)

    @staticmethod
    def _find_key(obj, key: str) -> Optional[str]:
        if isinstance(obj, dict):
            if isinstance(obj.get(key), str):
                return obj[key]
            for v in obj.values():
                found = JWTCheckModule._find_key(v, key)
                if found:
                    return found
        return None

    # -- checks -----------------------------------------------------------
    def _check_expiry(self, payload: Dict) -> List[Finding]:
        exp = payload.get("exp")
        where = "token claims"
        if exp is None:
            return [Finding(self.name, "JWT has no expiry (exp) claim", "medium", where,
                            "Token never expires if stolen.",
                            "Set a short 'exp' (e.g. 15 min) and use refresh tokens.")]
        if not isinstance(exp, (int, float)):
            return [Finding(self.name, "JWT 'exp' claim is not numeric", "low", where, f"exp={exp!r}")]
        start = payload.get("iat") if isinstance(payload.get("iat"), (int, float)) else time.time()
        lifetime = exp - start
        if lifetime > self.cfg.max_lifetime_seconds:
            return [Finding(self.name, "JWT lifetime is excessive", "low", where,
                            f"Lifetime ~{lifetime/3600:.1f}h exceeds limit of "
                            f"{self.cfg.max_lifetime_seconds/3600:.1f}h.",
                            "Shorten access-token lifetime and rotate with refresh tokens.")]
        return []

    def _check_weak_secret(self, token: str, header: Dict) -> List[Finding]:
        alg = header.get("alg")
        digest = HMAC_ALGS.get(alg)
        if not digest:
            return []
        signing_input, sig = token.rsplit(".", 1)
        try:
            expected = b64url_decode(sig)
        except ValueError:
            return []
        for cand in self.cfg.secret_candidates():
            mac = hmac.new(cand.encode(), signing_input.encode(), digest).digest()
            if hmac.compare_digest(mac, expected):
                return [Finding(self.name, "JWT signed with a weak/guessable HMAC secret",
                                "critical", "token signature",
                                f"Secret matched wordlist entry '{cand}' ({alg}).",
                                "Use a random secret of 32+ bytes from a secrets manager "
                                "and rotate it; existing tokens are forgeable.")]
        return []

    def _auth_headers(self, token: str) -> Dict[str, str]:
        return {self.cfg.auth_header: f"{self.cfg.auth_scheme} {token}".strip()}

    def _check_alg_none(self, token: str, payload: Dict) -> List[Finding]:
        path = self.cfg.protected_path
        if not path:
            return [Finding(self.name, "alg:none test skipped", "info", self.cfg.target,
                            "Provide --protected-path (an endpoint requiring auth) to enable it.")]
        valid = self.client.request("GET", path, headers=self._auth_headers(token))
        anon = self.client.request("GET", path)
        if valid is None or anon is None:
            return []
        if valid.status_code >= 400:
            return [Finding(self.name, "alg:none test skipped", "info", path,
                            f"Valid token was rejected ({valid.status_code}); cannot compare.")]
        if anon.status_code < 400:
            return [Finding(self.name, "alg:none test inconclusive", "info", path,
                            "Endpoint is accessible without a token; choose a protected path.")]
        for alg in ("none", "None", "NONE", "nOnE"):
            forged = f"{b64url_encode(json.dumps({'alg': alg, 'typ': 'JWT'}).encode())}." \
                     f"{b64url_encode(json.dumps(payload).encode())}."
            resp = self.client.request("GET", path, headers=self._auth_headers(forged))
            if resp is not None and resp.status_code < 400:
                return [Finding(self.name, "Server accepts unsigned JWT (alg: none)", "critical",
                                path, f"alg='{alg}' token returned {resp.status_code} "
                                      f"while anonymous returned {anon.status_code}.",
                                "Pin the allowed algorithms in your verify() call "
                                "(e.g. jsonwebtoken: {algorithms: ['HS256']}).")]
        return []
