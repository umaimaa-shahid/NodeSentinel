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

## How to Re-Run Locally

```bash
cd demo-app
docker compose up -d
npm run seed
# Start vulnerable (:3001) and secure (:3002) in separate terminals, then:
npm run verify
npm run seed
```
