#!/usr/bin/env python3
"""NodeSentinel - security scanner for Node.js/Express APIs (NoSQLi + JWT)."""
from __future__ import annotations

import argparse
import json
import sys

from config import Endpoint, ScanConfig
from engine import ScanEngine


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nodesentinel",
        description="Scan a Node.js API you own or are authorized to test.")
    p.add_argument("url", nargs="?", help="Target base URL, e.g. http://localhost:3000")
    p.add_argument("-c", "--config", help="JSON config file (CLI flags override it)")
    p.add_argument("-e", "--endpoint", action="append", default=[],
                   help="Endpoint to test for NoSQLi, 'METHOD:/path' (repeatable)")
    p.add_argument("-m", "--modules", help=f"Comma-separated modules (default: all: "
                                           f"{','.join(ScanEngine.available_modules())})")
    p.add_argument("--token", help="JWT to analyse")
    p.add_argument("--login-path", help="Login endpoint used to obtain a JWT")
    p.add_argument("--login-creds", help='JSON creds, e.g. \'{"username":"a","password":"b"}\'')
    p.add_argument("--token-field", help="JSON key of token in login response (default: token)")
    p.add_argument("--protected-path", help="Auth-protected endpoint for the alg:none test")
    p.add_argument("--wordlist", help="Extra weak-secret wordlist file")
    p.add_argument("--timeout", type=float, help="Request timeout in seconds")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    p.add_argument("-o", "--output", choices=["text", "json"], default="text")
    return p


def make_config(args: argparse.Namespace) -> ScanConfig:
    if args.config:
        cfg = ScanConfig.from_file(args.config)
        if args.url:
            cfg.target = args.url.rstrip("/")
    elif args.url:
        cfg = ScanConfig(target=args.url)
    else:
        raise ValueError("Provide a target URL or --config")
    if args.endpoint:
        cfg.endpoints = [Endpoint.parse(e) for e in args.endpoint]
    for attr, val in {
        "token": args.token, "login_path": args.login_path,
        "token_field": args.token_field, "protected_path": args.protected_path,
        "wordlist_path": args.wordlist, "timeout": args.timeout,
    }.items():
        if val is not None:
            setattr(cfg, attr, val)
    if args.login_creds:
        cfg.login_creds = json.loads(args.login_creds)
    if args.insecure:
        cfg.verify_tls = False
    return cfg


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = make_config(args)
    except (ValueError, OSError, TypeError, json.JSONDecodeError) as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2
    engine = ScanEngine(cfg)
    engine.run(args.modules.split(",") if args.modules else None)
    print(engine.to_json() if args.output == "json" else engine.to_text())
    return 1 if any(f.severity != "info" for f in engine.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
