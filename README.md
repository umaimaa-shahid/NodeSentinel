# NodeSentinel

NodeSentinel is a command-line security scanner for Node.js and Express APIs. It currently supports checks for NoSQL operator injection and JWT configuration weaknesses, and reports findings as severity-ranked text or JSON.

> Only scan systems you own or have explicit permission to test.

## Features

- **NoSQL injection checks**: Tests configured endpoints with MongoDB-style `$ne`, `$gt`, and `$regex` operators.
- **JWT checks**:
  - Detects missing or excessive `exp` lifetimes.
  - Tests HMAC tokens against a built-in weak-secret wordlist.
  - Optionally tests whether a protected endpoint accepts an unsigned `alg: none` token.
- **Text and JSON reports**: Print human-readable results or structured JSON for scripts and CI.
- **Configurable HTTP requests**: Set custom headers, timeout, and TLS verification.

## Requirements

- Python 3.9 or newer
- `pip`

## Installation

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick start

Scan a target for JWT issues with a known token:

```bash
python3 main.py http://localhost:3000 \
  --token "eyJ..." \
  --modules jwt
```

Test NoSQL injection behavior on a login endpoint:

```bash
python3 main.py http://localhost:3000 \
  --endpoint "POST:/api/login" \
  --modules nosql
```

NoSQL endpoints can be repeated:

```bash
python3 main.py http://localhost:3000 \
  --endpoint "POST:/api/login" \
  --endpoint "GET:/api/users"
```

GET endpoints use query parameters; POST endpoints use JSON bodies. The default JSON parameter names are `username` and `password`, with a baseline value that should be invalid.

## JWT options

Supply a token directly:

```bash
python3 main.py http://localhost:3000 \
  --token "$TOKEN" \
  --protected-path "/api/profile" \
  --modules jwt
```

Or obtain a token through a login endpoint:

```bash
python3 main.py http://localhost:3000 \
  --login-path "/api/login" \
  --login-creds '{"username":"test","password":"test"}' \
  --token-field "token" \
  --protected-path "/api/profile" \
  --modules jwt
```

Use `--wordlist` to add candidate weak secrets to the built-in HMAC secret list:

```bash
python3 main.py http://localhost:3000 \
  --token "$TOKEN" \
  --wordlist "./secrets.txt" \
  --modules jwt
```

## Configuration file

Targets and endpoint details can be stored in a JSON file:

```json
{
  "target": "http://localhost:3000",
  "timeout": 10,
  "verify_tls": true,
  "headers": {
    "X-Scanner": "NodeSentinel"
  },
  "endpoints": [
    {
      "path": "/api/login",
      "method": "POST",
      "params": {
        "username": "nodesentinel",
        "password": "invalid-pass-123"
      },
      "location": "json"
    }
  ],
  "token": null,
  "login_path": "/api/login",
  "login_creds": {
    "username": "test",
    "password": "test"
  },
  "token_field": "token",
  "protected_path": "/api/profile",
  "wordlist_path": null
}
```

Run it with:

```bash
python3 main.py --config scan.json --modules nosql,jwt
```

Command-line flags override values loaded from the config file.

## Output

Human-readable text is the default:

```bash
python3 main.py http://localhost:3000 --modules jwt --token "$TOKEN"
```

For JSON output:

```bash
python3 main.py http://localhost:3000 --modules jwt --token "$TOKEN" --output json
```

JSON reports include the target, findings, and any HTTP or module errors.

## CLI options

| Option | Description |
| --- | --- |
| `url` | Target base URL |
| `-c, --config` | Load settings from a JSON file |
| `-e, --endpoint` | Add `METHOD:/path`; repeat to test multiple endpoints |
| `-m, --modules` | Comma-separated modules; `nosql` and `jwt` are implemented currently |
| `--token` | JWT to analyze |
| `--login-path` | Endpoint used to obtain a JWT |
| `--login-creds` | JSON credentials used for login |
| `--token-field` | JSON key containing the token (default: `token`) |
| `--protected-path` | Authentication-protected endpoint for the `alg: none` check |
| `--wordlist` | Additional weak-secret candidates, one per line |
| `--timeout` | HTTP request timeout in seconds |
| `--insecure` | Disable TLS certificate verification |
| `-o, --output` | Output format: `text` or `json` |

Run `python3 main.py --help` for the complete built-in help.

## Exit codes

- `0`: No non-informational findings
- `1`: One or more low, medium, high, or critical findings
- `2`: Invalid configuration or command-line input