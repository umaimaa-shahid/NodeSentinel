# NodeSentinel Demo-App Handoff Guide

This guide is for the NodeSentinel scanner authors (NoSQLi, JWT, Security Headers/CORS/Cookies, and Brute-Force modules) integrating against the `demo-app/` test targets.

> **Local Lab Only:** Both servers bind strictly to `127.0.0.1`. Never expose the vulnerable app publicly.

---

## 1. Base URLs & Ports

| Variant | Base URL | Port | MongoDB Database | Start Command (from `demo-app/`) |
| --- | --- | --- | --- | --- |
| **Vulnerable** | `http://127.0.0.1:3001` | `3001` | `demo_vulnerable` | `npm run start:vulnerable` |
| **Secure (Hardened)** | `http://127.0.0.1:3002` | `3002` | `demo_secure` | `npm run start:secure` |

---

## 2. Quick Setup & Resetting Databases

```bash
cd demo-app
docker compose up -d          # Starts MongoDB 7 on 127.0.0.1:27017
npm run install:all           # Installs root, vulnerable, and secure dependencies
npm run seed                  # Resets & seeds both demo_vulnerable and demo_secure
```

**Resetting after brute-force / lockout tests:**
Running brute-force tests against `http://127.0.0.1:3002` triggers both IP rate limiting (15 min window, restarts when the secure server restarts) and per-account lockout in MongoDB (`lockUntil`). To reset database state cleanly between scanner runs:

```bash
npm run seed
```

---

## 3. Test Credentials

Seeded into both `demo_vulnerable` (plaintext) and `demo_secure` (`bcryptjs` hashed):

| Username | Password | Role | Email |
| --- | --- | --- | --- |
| `admin` | `Admin@123` | `admin` | `admin@nodesentinel.local` |
| `alice` | `Alice@123` | `user` | `alice@nodesentinel.local` |
| `bob` | `Bob@123` | `user` | `bob@nodesentinel.local` |

Both databases also contain **10 seeded products** (`NS-001` through `NS-010`).

---

## 4. Endpoints & Example Requests

Both `:3001` and `:3002` expose the exact same routes:

### `GET /`
Returns app status JSON and sets a `session_id` cookie (useful for header/CORS/cookie scanners targeting the root URL).

```http
GET / HTTP/1.1
Host: 127.0.0.1:3001
Origin: https://nodesentinel-test.invalid
```

### `GET /api/health`
Returns server status and connected MongoDB database name.

```http
GET /api/health HTTP/1.1
Host: 127.0.0.1:3001
```

### `POST /api/login` (alias: `POST /login`)
Authenticates a user, sets the `session_id` cookie, and returns a JWT in the `token` field.

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:3001
Content-Type: application/json

{"username": "admin", "password": "Admin@123"}
```

Response (`200 OK`):
```json
{
  "message": "Login successful",
  "token": "<jwt>",
  "user": { "id": "...", "username": "admin", "role": "admin", "email": "admin@nodesentinel.local" }
}
```

### `GET /api/profile`
Protected endpoint requiring `Authorization: Bearer <token>` (or `session_id` cookie).

```http
GET /api/profile HTTP/1.1
Host: 127.0.0.1:3001
Authorization: Bearer <token>
```

### `GET /api/users/search?name=...` (alias: `GET /api/users`)
Queries users by username.

```http
GET /api/users/search?name=alice HTTP/1.1
Host: 127.0.0.1:3001
```

### `GET /api/products/search?q=...`
Searches products by name or category.

```http
GET /api/products/search?q=keyboard HTTP/1.1
Host: 127.0.0.1:3001
```

---

## 5. Seeded Vulnerabilities & Expected Scanner Findings

| Scanner Module | Target Endpoint(s) | Vulnerability in `:3001` (Vulnerable) | Expected Finding on `:3001` | Expected Result on `:3002` (Secure) |
| --- | --- | --- | --- | --- |
| **NoSQL Injection** (`nosql`) | `POST /api/login`, `GET /api/users/search`, `GET /api/products/search` | Raw `req.body` passed to `users.findOne({ username, password })`; raw `req.query.name` passed to `users.find()`; `req.query.q` interpolated into MongoDB `$where`. | **High** finding: operator injection (`$ne`, `$gt`) bypasses login (`200` vs baseline `401`) and expands query results. | **No findings** (returns `400` on operator objects via Joi + `express-mongo-sanitize`, `0` matches on literal `$where` string). |
| **JWT Weaknesses** (`jwt`) | `POST /api/login`, `GET /api/profile` | Signed with weak secret `secret123` *(pass via `--wordlist` if not in default list)*; no `exp` claim; `/api/profile` accepts unsigned `alg: "none"` tokens. | **Critical**: weak HMAC secret (`secret123`); **Critical**: `alg: none` accepted on `/api/profile`; **Medium**: missing `exp` claim. | **No findings** (strong 32+ char secret, `15m` expiry, pinned `HS256`, rejects `alg: none` with `401`). |
| **Headers, CORS & Cookies** (`headers`) | `GET /`, `POST /api/login` | No Helmet (`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security` absent); returns `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true`; `Set-Cookie: session_id=...` lacks `HttpOnly`, `Secure`, `SameSite`. | **Medium**: `HDR-001` (missing CSP), `HDR-002` (missing X-Frame-Options/frame-ancestors), `CORS-001` (wildcard origin + credentials), `COOKIE-001-HTTPONLY`, `COOKIE-001-SECURE`; **Low**: `COOKIE-001-SAMESITE`. | **No findings** (`helmet` CSP + `frame-ancestors 'none'` + `X-Frame-Options: DENY` + HSTS; untrusted `Origin` not reflected; cookie has `HttpOnly; Secure; SameSite=Strict`). |
| **Brute-Force Exposure** (`bruteforce`) | `POST /api/login` and `POST /login` | Unlimited failed login attempts accepted (`401` every time, no `429`/`423`, no `Retry-After`, no `X-RateLimit-Remaining`). | **Medium**: `BRUTE-002` (No login rate limiting observed). | **Informational**: `BRUTE-001` (Rate-limit observed via `X-RateLimit-Remaining: 0`, HTTP `429` + `Retry-After`, and/or HTTP `423` account lockout). |

> **Note on weak JWT wordlist:** `vulnerable/` uses `secret123` as its default `JWT_SECRET`. If your scanner's built-in wordlist does not include `secret123`, either pass `--wordlist` containing `secret123` or start `vulnerable/` with `JWT_SECRET=secret` (which is in the default wordlist).
