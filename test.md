# NodeSentinel Demo-App Verification & Test Results

This document records the live end-to-end verification results executed against both Express + MongoDB demo applications on branch `demo-app`.

## Test Environment

| Component | Configuration |
| --- | --- |
| **MongoDB** | Docker `mongo:7` (`nodesentinel-mongo`) on `127.0.0.1:27017` |
| **Vulnerable App** | `http://127.0.0.1:3001` (DB: `demo_vulnerable`) |
| **Secure App** | `http://127.0.0.1:3002` (DB: `demo_secure`) |
| **Verification Script** | `npm run verify` (`demo-app/verify.js`, Node.js native `fetch`) |

---

## 1. MongoDB Startup & Connectivity

Command: `docker compose up -d` inside `demo-app/`

```text
NAME                 IMAGE     COMMAND                  SERVICE   CREATED         STATUS                  PORTS
nodesentinel-mongo   mongo:7   "docker-entrypoint.s…"   mongodb   2 seconds ago   Up Less than a second   127.0.0.1:27017->27017/tcp
MongoDB reachable on 127.0.0.1:27017
```

---

## 2. Database Seeding Confirmation

Command: `npm run seed`

```text
[seed] Seeding vulnerable and secure MongoDB databases...
[seed] Seeded 'demo_vulnerable': 3 users, 10 products.
[seed] Seeded 'demo_secure': 3 users, 10 products.
[seed] Done.
```

Verified documents in both databases:

| Database | Seeded Users | Seeded Products |
| --- | --- | --- |
| `demo_vulnerable` | `admin` (`admin`), `alice` (`user`), `bob` (`user`) | 10 |
| `demo_secure` | `admin` (`admin`), `alice` (`user`), `bob` (`user`) | 10 |

---

## 3. Server Startup

- **Vulnerable (`:3001`):**
  ```text
  [vulnerable] Connected to MongoDB: demo_vulnerable
  [vulnerable] Server listening on http://127.0.0.1:3001
  [vulnerable] WARNING: Deliberately vulnerable test target. Local lab use only.
  ```
- **Secure (`:3002`):**
  ```text
  [secure] Connected to MongoDB: demo_secure
  [secure] Server listening on http://127.0.0.1:3002
  ```

---

## 4. Live Database Verification Results (`npm run verify`)

### PASS / FAIL Summary Table (9/9 Passed)

| Check | Result | Real Output / Details |
| --- | --- | --- |
| Health check (`:3001` & `:3002`) | **PASS** | `vuln=200(demo_vulnerable), secure=200(demo_secure)` |
| a. Normal login (`admin/Admin@123`) | **PASS** | `vuln=200 token=true, secure=200 token=true` |
| b1. NoSQL login (`{"$ne": null}`) | **PASS** | `vuln=200, secure=400` |
| b2. NoSQL login (`{"$gt": ""}`) | **PASS** | `vuln=200, secure=400` |
| c. Products search (`$where`) | **PASS** | `vuln(baseline=0, where=10), secure(where=0)` |
| d. Brute-force (6 wrong logins) | **PASS** | `vuln=[401,401,401,401,401,401], secure=[401,401,429,429,429,429]` |
| e1. JWT weak secret (`"secret123"`) | **PASS** | `vuln=200, secure=401` |
| e2. JWT `alg:none` acceptance/rejection | **PASS** | `vuln=200, secure=401` |
| f. Set-Cookie security flags | **PASS** | `vuln(H=false,S=false,SS=false) vs secure(H=true,S=true,SS=true)` |

---

### Set-Cookie Header Inspection (Login Response)

| Application | `Set-Cookie` Header | `HttpOnly` | `Secure` | `SameSite` |
| --- | --- | --- | --- | --- |
| **Vulnerable (`:3001`)** | `session_id=<jwt>; Path=/` | `false` | `false` | `false` |
| **Secure (`:3002`)** | `session_id=<jwt>; Max-Age=900; Path=/; Expires=...; HttpOnly; Secure; SameSite=Strict` | `true` | `true` | `true` (`Strict`) |

---

## 5. Post-Test Database Reset

After running `npm run verify`, `npm run seed` was executed to clear any failed-attempt / lockout state in `demo_secure`:

```text
[seed] Seeding vulnerable and secure MongoDB databases...
[seed] Seeded 'demo_vulnerable': 3 users, 10 products.
[seed] Seeded 'demo_secure': 3 users, 10 products.
[seed] Done.
```

---

## 6. Negative, Error-Path & Boundary Tests (Expected Failures / Rejections)

To confirm that both applications fail closed on malformed requests and that `secure` enforces both account lockout (`423`) and IP rate limiting (`429`), the following negative test cases were executed against the live servers:

| Negative / Boundary Test | Vulnerable (`:3001`) | Secure (`:3002`) | Observed Behavior |
| --- | --- | --- | --- |
| Unauthenticated `GET /api/profile` (no token) | `401` | `401` | Both reject missing Authorization header |
| Malformed JWT (`Bearer not-a-jwt`) on `/api/profile` | `401` | `401` | Both reject malformed tokens |
| Wrong-secret JWT on `/api/profile` | `401` | `401` | Both reject invalid HMAC signatures |
| Expired JWT (`exp` in past) on `/api/profile` | `401` | `401` | Both reject tokens with expired `exp` claim |
| Query NoSQLi `GET /api/users/search?name[$ne]=` | `200` (`count=3`: `admin,alice,bob`) | `400` (`Invalid search query parameter`) | Vulnerable dumps all 3 users; Secure rejects operator object |
| Unknown route `GET /api/does-not-exist` | `404` | `404` | Both return 404 |
| Untrusted `Origin: https://evil.example` on `GET /` | `ACAO=*` | `ACAO=null` (omitted) | Vulnerable sends wildcard CORS; Secure omits header |
| 6 consecutive wrong passwords for `bob` | `401,401,401,401,401,401` | `401,401,401,401,423,429` | Vulnerable never blocks; Secure locks account (`423`) on attempt 5 and rate-limits (`429`) on attempt 6 |
| Missing `password` field on `POST /api/login` | `400` | `400` (`429` once rate-limited) | Rejects incomplete login payload |

---

## 7. Known Edge Cases & Limitations (Where Checks Fail or Miss)

Useful for the project's security analysis (false negatives & test-environment limitations):

1. **Weak JWT wordlist mismatch (potential false negative):** `vulnerable/` signs tokens with `secret123` by default. If the scanner runs without `--wordlist` containing `secret123`, its default 20-word list will miss the weak secret unless `secret123` is added or `JWT_SECRET=secret` is set.
2. **HSTS & `Secure` cookie over local HTTP:** Both demo servers run over `http://127.0.0.1`. While `secure/` sends `Strict-Transport-Security` and `Set-Cookie: ...; Secure`, browsers and HTTPS-only checks (such as `HDR-003`) require TLS/HTTPS to evaluate HSTS enforcement.
3. **IP rate-limit vs. account lockout ordering:** When running multiple login tests from a single local IP (`127.0.0.1`), `express-rate-limit` (5 requests / 15 min) can return `429` before a specific user hits 5 wrong passwords (`423`). Restarting `secure/` clears the in-memory IP window, and `npm run seed` clears MongoDB's `lockUntil` field.

## How to Re-Run Locally

```bash
cd demo-app
docker compose up -d
npm run seed
# Start vulnerable (:3001) and secure (:3002) in separate terminals, then:
npm run verify
npm run seed
```
