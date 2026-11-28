"""NoSQL (MongoDB-style) operator-injection detection."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from engine import Finding, ScannerModule
from config import Endpoint

ERROR_SIGNATURES = [
    "mongoerror", "mongoservererror", "casterror", "mongoose", "bsontypeerror",
    "unknown operator", "$where", "e11000", "cannot read propert",
]

# (label, operator expression)
OPERATORS: List[Tuple[str, Dict]] = [
    ("$ne", {"$ne": None}),
    ("$gt", {"$gt": ""}),
    ("$regex", {"$regex": ".*"}),
]

REMEDIATION = (
    "Validate that inputs are plain strings, reject objects/operator keys "
    "(e.g. express-mongo-sanitize), and use schema-typed queries."
)


class NoSQLInjectionModule(ScannerModule):
    name = "nosql"
    description = "Detects NoSQL operator injection ($ne/$gt/$regex) in request parameters."

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        if not self.cfg.endpoints:
            return [Finding(self.name, "No endpoints configured for NoSQL testing", "info",
                            self.cfg.target, "Pass --endpoint 'POST:/login' or use a config file.")]
        for ep in self.cfg.endpoints:
            findings.extend(self._test_endpoint(ep))
        return findings

    # -- request building -------------------------------------------------
    def _send(self, ep: Endpoint, params: Dict, operator: Optional[Dict] = None, label: str = ""):
        if operator is None:
            data = dict(params)
            kw = self._kwargs(ep.location, data)
        elif ep.location == "json":
            kw = {"json": {k: operator for k in params}}
        else:  # query / form use bracket syntax: key[$ne]=value
            (op, val), = operator.items()
            flat = {f"{k}[{op}]": ("" if val is None else str(val)) for k in params}
            kw = self._kwargs(ep.location, flat)
        return self.client.request(ep.method, ep.path, **kw)

    @staticmethod
    def _kwargs(location: str, data: Dict) -> Dict:
        return {"json": data} if location == "json" else (
            {"params": data} if location == "query" else {"data": data})

    # -- analysis ---------------------------------------------------------
    def _test_endpoint(self, ep: Endpoint) -> List[Finding]:
        label = f"{ep.method} {ep.path}"
        baseline = self._send(ep, ep.params)
        if baseline is None:
            return [Finding(self.name, "Endpoint unreachable", "info", label,
                            "Baseline request failed; see errors.")]
        out: List[Finding] = []
        base_text = baseline.text.lower()
        for op_label, op in OPERATORS:
            resp = self._send(ep, ep.params, op)
            if resp is None:
                continue
            body = resp.text.lower()
            sig = next((s for s in ERROR_SIGNATURES if s in body and s not in base_text), None)
            auth_bypass = baseline.status_code >= 400 and resp.status_code < 400
            status_diff = resp.status_code != baseline.status_code and resp.status_code < 500
            size_diff = (
                resp.status_code == baseline.status_code and len(baseline.content) > 0
                and abs(len(resp.content) - len(baseline.content)) / len(baseline.content) > 0.5
            )
            if auth_bypass:
                out.append(Finding(
                    self.name, f"NoSQL operator injection accepted ({op_label})", "high", label,
                    f"Baseline returned {baseline.status_code}; payload {op_label} returned "
                    f"{resp.status_code}. Likely authentication/filter bypass.", REMEDIATION))
                break
            if sig:
                out.append(Finding(
                    self.name, f"Database error leaked on operator payload ({op_label})", "medium",
                    label, f"Response contains '{sig}' (status {resp.status_code}).", REMEDIATION))
                break
            if status_diff or size_diff:
                out.append(Finding(
                    self.name, f"Behaviour changes with operator payload ({op_label})", "low", label,
                    f"Baseline {baseline.status_code}/{len(baseline.content)}B vs "
                    f"{resp.status_code}/{len(resp.content)}B. Possible injection; verify manually.",
                    REMEDIATION))
                break
        return out
