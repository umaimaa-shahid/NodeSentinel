# NodeSentinel Demo Applications

> **WARNING — LOCAL LAB USE ONLY**
> The `vulnerable/` application contains **deliberate security flaws** created solely for local educational testing and evaluating the NodeSentinel scanner's detection accuracy (true positives vs. false positives).
> **Never expose the vulnerable application to a public network, deploy it to production, or use it with real credentials or personal data.** Both servers bind to `127.0.0.1` by default.

## Overview

This directory provides two functionally identical Express + MongoDB REST APIs:

| Variant | Directory | Default URL | Default MongoDB Database | Purpose |
| --- | --- | --- | --- | --- |
| Vulnerable | `vulnerable/` | `http://127.0.0.1:3001` | `demo_vulnerable` | Seeded with the four target vulnerability classes |
| Secure (Hardened) | `secure/` | `http://127.0.0.1:3002` | `demo_secure` | Same API with security controls applied |

## Directory Structure

```text
demo-app/
├── package.json            # Convenience scripts: install:all, seed, start:vulnerable, start:secure
├── .env.example            # Root environment configuration template
├── docker-compose.yml      # Local MongoDB container bound to 127.0.0.1:27017
├── seed.js                 # Seeds both demo_vulnerable and demo_secure databases
├── vulnerable/
│   ├── package.json
│   ├── .env.example
│   ├── db.js
│   ├── server.js
│   ├── middleware/auth.js
│   └── routes/{auth,users,products}.js
├── secure/
│   ├── package.json
│   ├── .env.example
│   ├── db.js
│   ├── server.js
│   ├── middleware/{auth,rateLimit}.js
│   └── routes/{auth,users,products}.js
└── README.md
```

## Prerequisites

- **Node.js** 18+ and **npm**
- **MongoDB** 6+ running locally on `127.0.0.1:27017`, **or** Docker Desktop / Docker Engine

## 1. Start MongoDB

### Option A — Docker (recommended)

From inside `demo-app/`:

```bash
docker compose up -d
```

This starts MongoDB 7 bound exclusively to `127.0.0.1:27017`.

### Option B — Local MongoDB installation

Ensure the local `mongod` service is running on `mongodb://127.0.0.1:27017`.

## 2. Install Dependencies

From inside `demo-app/`:

```bash
npm run install:all
```

(Or install individually inside `demo-app/`, `demo-app/vulnerable/`, and `demo-app/secure/` with `npm install`.)

## 3. Configure Environment Variables (Optional)

Default settings work out of the box for local MongoDB. To customize ports, MongoDB URIs, JWT secrets, or allowed CORS origins, copy the template files:

```bash
cp .env.example .env
cp vulnerable/.env.example vulnerable/.env
cp secure/.env.example secure/.env
```

For the `secure/` app, set a strong random `JWT_SECRET` (at least 32 characters) in `secure/.env`.

## 4. Seed the Databases

From inside `demo-app/`:

```bash
npm run seed
```

This resets and populates both `demo_vulnerable` and `demo_secure` with 3 users and 10 sample products. Passwords are stored in plaintext in `demo_vulnerable` and hashed with `bcryptjs` in `demo_secure`.

### Test Credentials

| Username | Password | Role | Email |
| --- | --- | --- | --- |
| `admin` | `Admin@123` | `admin` | `admin@nodesentinel.local` |
| `alice` | `Alice@123` | `user` | `alice@nodesentinel.local` |
| `bob` | `Bob@123` | `user` | `bob@nodesentinel.local` |

## 5. Run the Applications

Open two terminals inside `demo-app/`:

```bash
# Terminal 1 — Vulnerable variant (http://127.0.0.1:3001)
npm run start:vulnerable

# Terminal 2 — Hardened variant (http://127.0.0.1:3002)
npm run start:secure
```

Verify both servers are running:

```bash
curl http://127.0.0.1:3001/api/health
curl http://127.0.0.1:3002/api/health
```

## API Endpoints

Both applications expose identical routes:

| Method | Path | Auth Required | Description |
| --- | --- | --- | --- |
| `GET` | `/` | No | App status response (sets `session_id` cookie) |
| `GET` | `/api/health` | No | Health check returning variant and connected DB name |
| `POST` | `/api/login` | No | Authenticates `{ username, password }`, sets cookie, returns JWT `token` |
| `POST` | `/login` | No | Alias for `/api/login` for scanner default path compatibility |
| `GET` | `/api/profile` | Bearer JWT | Returns authenticated user profile |
| `GET` | `/api/users/search?name=...` | No | Searches users by username (also aliased at `/api/users`) |
| `GET` | `/api/products/search?q=...` | No | Searches products by name or category |

## Vulnerability Classes vs. Hardened Controls

| Class | Affected Endpoint(s) | Vulnerable App (`:3001`) | Secure App (`:3002`) |
| --- | --- | --- | --- |
| **1. NoSQL Injection** | `POST /api/login`, `GET /api/users/search`, `GET /api/products/search` | Passes raw `req.body` and `req.query` directly into MongoDB queries; constructs a `$where` filter from `q` in product search. | Applies `express-mongo-sanitize`, validates all inputs strictly as strings with Joi (`convert: false`), hashes passwords with `bcryptjs` (`bcrypt.compare`), and replaces `$where` with escaped regex filters. |
| **2. JWT Weaknesses** | `POST /api/login`, `GET /api/profile` | Signs tokens using weak secret `secret123` with no `exp` claim; auth middleware accepts `alg: "none"` without signature verification. | Requires a strong 32+ char secret from env, pins verification to `{ algorithms: ['HS256'] }`, sets `expiresIn: '15m'`, and explicitly rejects `alg: "none"`. |
| **3. Headers, CORS & Cookies** | All routes (`GET /`, `POST /api/login`) | Omits Helmet (missing CSP, HSTS, `X-Frame-Options`); returns wildcard `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`; sets `session_id` cookie without `HttpOnly`, `Secure`, or `SameSite`. | Uses `helmet` (CSP with `frame-ancestors 'none'`, HSTS, `X-Frame-Options: DENY`), enforces an explicit CORS origin allowlist, and sets cookies with `HttpOnly`, `Secure`, and `SameSite=Strict`. |
| **4. Brute-Force Exposure** | `POST /api/login` (`/login`) | No rate limiting and no account lockout on repeated failed login attempts. | Enforces `express-rate-limit` (5 attempts per 15 min window with HTTP `429`, `Retry-After`, and `X-RateLimit-*` headers) plus per-account lockout (HTTP `423 Locked`) after 5 failed password attempts. |

## Verified Behavior

To run the automated end-to-end verification suite against both live servers (normal login, NoSQL injection `$ne`/`$gt`/`$where`, JWT weak secret & `alg:none`, brute-force rate limiting/lockout, and `Set-Cookie` security flags):

```bash
# Ensure MongoDB is running, databases are seeded, and both servers (:3001 and :3002) are started
npm run seed
npm run verify

# Reset any account lockout state created during brute-force testing
npm run seed
```

## Scanning with NodeSentinel

Once either demo app is running, run the NodeSentinel scanner against `http://127.0.0.1:3001` (vulnerable) and `http://127.0.0.1:3002` (secure) to compare detection results and verify zero false positives on the hardened variant.
