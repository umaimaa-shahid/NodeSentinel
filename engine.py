"""Scanner core: Finding model, HTTP client, module interface and engine."""
from __future__ import annotations

import importlib
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests

from config import ScanConfig

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    module: str
    title: str
    severity: str          # info | low | medium | high | critical
    endpoint: str
    evidence: str
    remediation: str = ""


class HttpClient:
    """Thin requests wrapper: shared session, timeouts, never raises."""

    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "NodeSentinel/0.1", **cfg.headers})
        self.errors: List[str] = []

    def url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return urljoin(self.cfg.target + "/", path.lstrip("/"))

    def request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        url = self.url(path)
        try:
            return self.session.request(
                method.upper(), url,
                timeout=self.cfg.timeout,
                verify=self.cfg.verify_tls,
                allow_redirects=False,
                **kwargs,
            )
        except requests.exceptions.SSLError as e:
            self.errors.append(f"TLS error for {url}: {e}")
        except requests.exceptions.Timeout:
            self.errors.append(f"Timeout after {self.cfg.timeout}s for {url}")
        except requests.exceptions.ConnectionError as e:
            self.errors.append(f"Connection failed for {url}: {e}")
        except requests.exceptions.RequestException as e:
            self.errors.append(f"Request error for {url}: {e}")
        return None


class ScannerModule(ABC):
    """Common interface every detection module implements."""

    name: str = "base"
    description: str = ""

    def __init__(self, cfg: ScanConfig, client: HttpClient):
        self.cfg = cfg
        self.client = client

    @abstractmethod
    def run(self) -> List[Finding]:
        """Run the checks and return any findings."""


# name -> "module_path:ClassName" (lazy so one broken module can't break the CLI)
MODULE_REGISTRY: Dict[str, str] = {
    "nosql": "modules.nosql:NoSQLInjectionModule",
    "jwt": "modules.jwt_check:JWTCheckModule",
    # Umaima's modules (Workstream 3): class names below are the agreed contract.
    "headers": "modules.headers:SecurityHeadersModule",
    "bruteforce": "modules.brute_force:BruteForceModule",
}


class ScanEngine:
    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg
        self.client = HttpClient(cfg)
        self.findings: List[Finding] = []
        self.module_errors: List[str] = []

    @staticmethod
    def available_modules() -> List[str]:
        return sorted(MODULE_REGISTRY)

    def _load(self, name: str) -> ScannerModule:
        mod_path, cls_name = MODULE_REGISTRY[name].split(":")
        cls = getattr(importlib.import_module(mod_path), cls_name)
        return cls(self.cfg, self.client)

    def run(self, selected: Optional[List[str]] = None) -> List[Finding]:
        for name in selected or self.available_modules():
            if name not in MODULE_REGISTRY:
                self.module_errors.append(f"Unknown module: {name}")
                continue
            try:
                self.findings.extend(self._load(name).run())
            except ModuleNotFoundError as e:
                self.module_errors.append(f"Module '{name}' skipped (not installed yet): {e.name}")
            except Exception as e:  # keep scanning even if one module fails
                self.module_errors.append(f"Module '{name}' crashed: {type(e).__name__}: {e}")
        self.findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
        return self.findings

    def to_json(self) -> str:
        return json.dumps(
            {
                "target": self.cfg.target,
                "findings": [asdict(f) for f in self.findings],
                "errors": self.client.errors + self.module_errors,
            },
            indent=2,
        )

    def to_text(self) -> str:
        lines = [f"NodeSentinel report for {self.cfg.target}", "=" * 60]
        if not self.findings:
            lines.append("No findings.")
        for f in self.findings:
            lines += [
                f"[{f.severity.upper()}] {f.title}  ({f.module})",
                f"  Endpoint : {f.endpoint}",
                f"  Evidence : {f.evidence}",
            ]
            if f.remediation:
                lines.append(f"  Fix      : {f.remediation}")
            lines.append("")
        errs = self.client.errors + self.module_errors
        if errs:
            lines.append("Errors:")
            lines += [f"  - {e}" for e in errs]
        return "\n".join(lines)
