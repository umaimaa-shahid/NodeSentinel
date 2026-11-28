# NodeSentinel

NodeSentinel is a command-line security scanner for Node.js and Express APIs. It helps identify common web application security weaknesses and generates severity-ranked findings in text or JSON format.

The project also provides two functionally identical Express + MongoDB demo applications: one intentionally vulnerable and one hardened. These applications allow NodeSentinel to be evaluated against known security weaknesses and their corresponding protections.

> **Safety:** Only scan systems you own or have explicit permission to test. The vulnerable demo application is strictly for local educational testing. Never expose it to a public network or use real credentials or personal data.

## Features

### Security Detection

- **NoSQL injection:** Tests configured endpoints with MongoDB-style `$ne`, `$gt`, and `$regex` operators.
- **JWT security:** Checks token expiration, weak HMAC secrets, and whether protected endpoints accept unsigned `alg: none` tokens.
- **Security headers, CORS and cookies:** Includes checks for missing security headers, unsafe CORS configurations, and insecure cookie attributes.
- **Brute-force exposure:** Performs a bounded number of login attempts and checks for observable rate-limiting protections.

### Reporting

- Human-readable text output.
- Structured JSON reports.
- Severity-ranked findings.

### Demo Applications

- Vulnerable Express + MongoDB application.
- Hardened Express + MongoDB application.
- Matching API endpoints for comparison.
- Seeded test accounts and sample data.
- Automated end-to-end verification scripts.

## Project Structure

```text
NodeSentinel/
├── nodesentinel/
│   ├── modules/
│   │   ├── headers.py
│   │   └── brute_force.py
│   └── reporter/
│       ├── html_report.py
│       └── json_report.py
├── tests/
│   ├── test_modules.py
│   └── test_reporters.py
├── reports/
│   ├── evaluation-notes.md
│   └── evaluation.json
├── demo-app/
│   ├── vulnerable/
│   ├── secure/
│   ├── package.json
│   ├── docker-compose.yml
│   ├── seed.js
│   └── README.md
├── requirements.txt
└── README.md
```

*The scanner's CLI entry point and any additional engine files should also be included in this structure when confirmed in the repository.*

## Requirements

### Scanner

- Python 3.9 or newer
- pip

### Demo Applications

- Node.js 18 or newer
- npm
- MongoDB 6 or newer, or Docker Desktop / Docker Engine

## Scanner Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/umaimaa-shahid/NodeSentinel.git
cd NodeSentinel
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Demo Applications

NodeSentinel includes two Express + MongoDB REST API variants.

| Variant | Directory | Default URL | Database |
|---|---|---|---|
| Vulnerable | `demo-app/vulnerable/` | `http://127.0.0.1:3001` | `demo_vulnerable` |
| Secure | `demo-app/secure/` | `http://127.0.0.1:3002` | `demo_secure` |

Both applications expose matching API routes. The vulnerable application contains deliberate security flaws, while the secure application implements corresponding security controls.

### 1. Start MongoDB

Navigate to the demo application directory:

```bash
cd demo-app
```

Using Docker:

```bash
docker compose up -d
```

Alternatively, start a local MongoDB service on:

```text
mongodb://127.0.0.1:27017
```

### 2. Install Demo Dependencies

From inside `demo-app/`:

```bash
npm run install:all
```

### 3. Configure Environment Variables

The default settings work with local MongoDB. To customize the configuration, copy the example files:

```bash
cp .env.example .env
cp vulnerable/.env.example vulnerable/.env
cp secure/.env.example secure/.env
```

For the secure application, configure a strong random `JWT_SECRET` of at least 32 characters.

### 4. Seed the Databases

From inside `demo-app/`:

```bash
npm run seed
```

This populates both databases with three users and ten sample products.

### 5. Start Both Applications

Open two terminals inside `demo-app/`.

**Terminal 1 — Vulnerable application:**

```bash
npm run start:vulnerable
```

**Terminal 2 — Secure application:**

```bash
npm run start:secure
```

The applications should be available at:

- Vulnerable: `http://127.0.0.1:3001`
- Secure: `http://127.0.0.1:3002`

Verify that both are running:

```bash
curl http://127.0.0.1:3001/api/health
curl http://127.0.0.1:3002/api/health
```

## Demo Test Credentials

| Username | Password | Role |
|---|---|---|
| `admin` | `Admin@123` | admin |
| `alice` | `Alice@123` | user |
| `bob` | `Bob@123` | user |

These credentials are for the local demo environment only.

## API Endpoints

Both demo applications expose the following routes:

| Method | Endpoint | Authentication | Description |
|---|---|---|---|
| GET | `/` | No | App status and session cookie |
| GET | `/api/health` | No | Health check |
| POST | `/api/login` | No | Login and JWT generation |
| POST | `/login` | No | Login alias |
| GET | `/api/profile` | Bearer JWT | Authenticated profile |
| GET | `/api/users/search?name=...` | No | User search |
| GET | `/api/products/search?q=...` | No | Product search |

## Vulnerable vs. Secure Applications

The demo applications cover four security vulnerability classes.

| Vulnerability Class | Vulnerable Application | Secure Application |
|---|---|---|
| NoSQL Injection | Raw request data is used in MongoDB queries, including a `$where` filter. | Input sanitization, strict Joi validation, password hashing, and escaped regex filters. |
| JWT Weaknesses | Weak signing secret, no expiration claim, and acceptance of unsigned tokens. | Strong environment-based secret, HS256 verification, token expiration, and rejection of `alg: none`. |
| Headers, CORS and Cookies | Missing security headers, wildcard CORS with credentials, and insecure cookie attributes. | Helmet security headers, explicit CORS allowlist, and HttpOnly, Secure, SameSite cookie attributes. |
| Brute-Force Exposure | No login rate limiting or account lockout. | Rate limiting, HTTP 429 responses, and account lockout after repeated failed attempts. |

## Running NodeSentinel

Once a demo application is running, use its URL as the scanner target.

### NoSQL Injection Check

```bash
python main.py http://127.0.0.1:3001 \
  --endpoint "POST:/api/login" \
  --modules nosql
```

### JWT Security Check

```bash
python main.py http://127.0.0.1:3001 \
  --login-path "/api/login" \
  --login-creds '{"username":"admin","password":"Admin@123"}' \
  --token-field "token" \
  --protected-path "/api/profile" \
  --modules jwt
```

Repeat the scans against `http://127.0.0.1:3002` to compare the hardened application.

### JSON Output

```bash
python main.py http://127.0.0.1:3001 \
  --modules jwt \
  --output json
```

### Configuration File

Scanner targets and endpoint details can be stored in a JSON configuration file:

```json
{
  "target": "http://127.0.0.1:3001",
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
    "username": "admin",
    "password": "Admin@123"
  },
  "token_field": "token",
  "protected_path": "/api/profile",
  "wordlist_path": null
}
```

Run:

```bash
python main.py --config scan.json --modules nosql,jwt
```

Command-line flags override configuration-file values.

## CLI Options

| Option | Description |
|---|---|
| `url` | Target base URL |
| `-c, --config` | Load settings from a JSON file |
| `-e, --endpoint` | Add a `METHOD:/path` endpoint |
| `-m, --modules` | Select scanner modules |
| `--token` | JWT to analyze |
| `--login-path` | Endpoint used to obtain a JWT |
| `--login-creds` | JSON login credentials |
| `--token-field` | JSON key containing the token |
| `--protected-path` | Protected endpoint for the unsigned-token check |
| `--wordlist` | Additional weak-secret candidates |
| `--timeout` | HTTP request timeout |
| `--insecure` | Disable TLS certificate verification |
| `-o, --output` | Output format: `text` or `json` |

Run the following for the complete built-in help:

```bash
python main.py --help
```

## Testing and Evaluation

Run the Python unit tests from the repository root:

```bash
python -m unittest discover -s tests -t . -v
```

Check Python syntax:

```bash
python -m compileall nodesentinel tests
```

For the demo applications, ensure MongoDB is running, both databases are seeded, and both servers are started.

From inside `demo-app/`, run:

```bash
npm run verify
```

Reset the demo databases after verification:

```bash
npm run seed
```

The evaluation compares scanner results against the known vulnerable and hardened application configurations. It considers detection success, false positives, false negatives, and execution status.

See `reports/evaluation-notes.md` and `reports/evaluation.json` for the evaluation methodology and recorded results.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No non-informational findings |
| `1` | One or more low, medium, high, or critical findings |
| `2` | Invalid configuration or command-line input |

## Safety Notice

The vulnerable demo application intentionally contains exploitable security weaknesses.

- Run both demo applications locally.
- Do not expose the vulnerable application to public networks.
- Do not use real credentials or personal data.
- Only scan applications you own or have explicit permission to test.
