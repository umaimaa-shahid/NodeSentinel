const crypto = require('crypto');

const VULN_URL = (process.env.VULN_URL || 'http://127.0.0.1:3001').replace(/\/$/, '');
const SECURE_URL = (process.env.SECURE_URL || 'http://127.0.0.1:3002').replace(/\/$/, '');

function b64url(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function signHs256(payload, secret) {
  const headerSeg = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadSeg = b64url(JSON.stringify(payload));
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const sig = crypto.createHmac('sha256', secret).update(signingInput).digest();
  return `${signingInput}.${b64url(sig)}`;
}

function makeAlgNoneToken(payload) {
  const headerSeg = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payloadSeg = b64url(JSON.stringify(payload));
  return `${headerSeg}.${payloadSeg}.`;
}

function getSetCookie(res) {
  if (typeof res.headers.getSetCookie === 'function') {
    const list = res.headers.getSetCookie();
    if (list && list.length) return list.join('; ');
  }
  return res.headers.get('set-cookie') || '';
}

function inspectCookieFlags(cookieHeader) {
  const lower = cookieHeader.toLowerCase();
  return {
    HttpOnly: lower.includes('httponly'),
    Secure: lower.includes('secure'),
    SameSite: lower.includes('samesite='),
  };
}

async function reqJson(baseUrl, path, { method = 'GET', headers = {}, body = undefined } = {}) {
  const init = {
    method,
    headers: { ...headers },
  };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(`${baseUrl}${path}`, init);
  let data = null;
  const text = await res.text();
  try {
    data = JSON.parse(text);
  } catch (_) {
    data = text;
  }
  return { status: res.status, headers: res.headers, setCookie: getSetCookie(res), data };
}

async function main() {
  const results = [];
  const record = (name, passed, details) => {
    results.push({ name, status: passed ? 'PASS' : 'FAIL', details });
  };

  // Health check
  const vHealth = await reqJson(VULN_URL, '/api/health');
  const sHealth = await reqJson(SECURE_URL, '/api/health');
  record(
    'Health check (:3001 & :3002)',
    vHealth.status === 200 && sHealth.status === 200,
    `vuln=${vHealth.status}(${vHealth.data && vHealth.data.database}), secure=${sHealth.status}(${sHealth.data && sHealth.data.database})`
  );

  // a. Normal login admin/Admin@123 on BOTH apps
  const vLogin = await reqJson(VULN_URL, '/api/login', {
    method: 'POST',
    body: { username: 'admin', password: 'Admin@123' },
  });
  const sLogin = await reqJson(SECURE_URL, '/api/login', {
    method: 'POST',
    body: { username: 'admin', password: 'Admin@123' },
  });
  record(
    'a. Normal login (admin/Admin@123)',
    vLogin.status === 200 &&
      Boolean(vLogin.data && vLogin.data.token) &&
      sLogin.status === 200 &&
      Boolean(sLogin.data && sLogin.data.token),
    `vuln=${vLogin.status} token=${Boolean(vLogin.data && vLogin.data.token)}, secure=${sLogin.status} token=${Boolean(sLogin.data && sLogin.data.token)}`
  );

  // f. Print Set-Cookie headers & check flags
  const vFlags = inspectCookieFlags(vLogin.setCookie);
  const sFlags = inspectCookieFlags(sLogin.setCookie);
  console.log('\n--- Set-Cookie Inspection ---');
  console.log(`[vulnerable :3001] Set-Cookie: ${vLogin.setCookie || '(none)'}`);
  console.log(`[vulnerable :3001] Flags: HttpOnly=${vFlags.HttpOnly}, Secure=${vFlags.Secure}, SameSite=${vFlags.SameSite}`);
  console.log(`[secure     :3002] Set-Cookie: ${sLogin.setCookie || '(none)'}`);
  console.log(`[secure     :3002] Flags: HttpOnly=${sFlags.HttpOnly}, Secure=${sFlags.Secure}, SameSite=${sFlags.SameSite}`);
  console.log('-----------------------------\n');

  record(
    'f. Set-Cookie security flags',
    Boolean(vLogin.setCookie) &&
      !vFlags.HttpOnly &&
      !vFlags.Secure &&
      !vFlags.SameSite &&
      Boolean(sLogin.setCookie) &&
      sFlags.HttpOnly &&
      sFlags.Secure &&
      sFlags.SameSite,
    `vuln(H=${vFlags.HttpOnly},S=${vFlags.Secure},SS=${vFlags.SameSite}) vs secure(H=${sFlags.HttpOnly},S=${sFlags.Secure},SS=${sFlags.SameSite})`
  );

  // b. NoSQL injection on /api/login: {$ne: null} and {$gt: ""}
  const nePayload = { username: 'admin', password: { $ne: null } };
  const vNe = await reqJson(VULN_URL, '/api/login', { method: 'POST', body: nePayload });
  const sNe = await reqJson(SECURE_URL, '/api/login', { method: 'POST', body: nePayload });
  record(
    'b1. NoSQL login ($ne: null)',
    vNe.status === 200 && Boolean(vNe.data && vNe.data.token) && (sNe.status === 400 || sNe.status === 401),
    `vuln=${vNe.status}, secure=${sNe.status}`
  );

  const gtPayload = { username: 'admin', password: { $gt: '' } };
  const vGt = await reqJson(VULN_URL, '/api/login', { method: 'POST', body: gtPayload });
  const sGt = await reqJson(SECURE_URL, '/api/login', { method: 'POST', body: gtPayload });
  record(
    'b2. NoSQL login ($gt: "")',
    vGt.status === 200 && Boolean(vGt.data && vGt.data.token) && (sGt.status === 400 || sGt.status === 401),
    `vuln=${vGt.status}, secure=${sGt.status}`
  );

  // c. Product search $where test
  const whereQuery = encodeURIComponent("') || true || ('");
  const vProdBase = await reqJson(VULN_URL, '/api/products/search?q=nonexistent_item_999');
  const vProdWhere = await reqJson(VULN_URL, `/api/products/search?q=${whereQuery}`);
  const sProdWhere = await reqJson(SECURE_URL, `/api/products/search?q=${whereQuery}`);
  record(
    'c. Products search ($where)',
    vProdBase.status === 200 &&
      vProdBase.data.count === 0 &&
      vProdWhere.status === 200 &&
      vProdWhere.data.count === 10 &&
      sProdWhere.status === 200 &&
      sProdWhere.data.count === 0,
    `vuln(baseline=${vProdBase.data && vProdBase.data.count}, where=${vProdWhere.data && vProdWhere.data.count}), secure(where=${sProdWhere.data && sProdWhere.data.count})`
  );

  // e. JWT checks (run before brute-force so rate limiter doesn't interfere with anything)
  const weakToken = signHs256({ sub: '1', username: 'admin', role: 'admin' }, 'secret123');
  const vWeakJwt = await reqJson(VULN_URL, '/api/profile', {
    headers: { Authorization: `Bearer ${weakToken}` },
  });
  const sWeakJwt = await reqJson(SECURE_URL, '/api/profile', {
    headers: { Authorization: `Bearer ${weakToken}` },
  });
  record(
    'e1. JWT weak secret ("secret123")',
    vWeakJwt.status === 200 && sWeakJwt.status === 401,
    `vuln=${vWeakJwt.status}, secure=${sWeakJwt.status}`
  );

  const noneToken = makeAlgNoneToken({ sub: '1', username: 'admin', role: 'admin' });
  const vNoneJwt = await reqJson(VULN_URL, '/api/profile', {
    headers: { Authorization: `Bearer ${noneToken}` },
  });
  const sNoneJwt = await reqJson(SECURE_URL, '/api/profile', {
    headers: { Authorization: `Bearer ${noneToken}` },
  });
  record(
    'e2. JWT alg:none acceptance/rejection',
    vNoneJwt.status === 200 && sNoneJwt.status === 401,
    `vuln=${vNoneJwt.status}, secure=${sNoneJwt.status}`
  );

  // d. Brute-force: 6 wrong-password logins in a row
  const vStatuses = [];
  const sStatuses = [];
  for (let i = 0; i < 6; i++) {
    const vr = await reqJson(VULN_URL, '/api/login', {
      method: 'POST',
      body: { username: 'bob', password: `WrongPass_${i}` },
    });
    vStatuses.push(vr.status);

    const sr = await reqJson(SECURE_URL, '/api/login', {
      method: 'POST',
      body: { username: 'bob', password: `WrongPass_${i}` },
    });
    sStatuses.push(sr.status);
  }
  const vulnNeverBlocked = vStatuses.every((s) => s !== 429 && s !== 423);
  const secureBlocked = sStatuses.some((s) => s === 429 || s === 423);
  record(
    'd. Brute-force (6 wrong logins)',
    vulnNeverBlocked && secureBlocked,
    `vuln=[${vStatuses.join(',')}], secure=[${sStatuses.join(',')}]`
  );

  // Print PASS/FAIL table
  console.log('Check                                    | Result | Details');
  console.log('-----------------------------------------+--------+--------------------------------------------------');
  for (const r of results) {
    console.log(`${r.name.padEnd(40)} | ${r.status.padEnd(6)} | ${r.details}`);
  }

  const failed = results.filter((r) => r.status !== 'PASS');
  console.log(`\nSummary: ${results.length - failed.length}/${results.length} checks passed.`);
  if (failed.length > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Verification error:', err);
  process.exit(1);
});
