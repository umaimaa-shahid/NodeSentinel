const jwt = require('jsonwebtoken');

// VULNERABILITY: Weak JWT Secret (guessable wordlist secret)
const JWT_SECRET = process.env.JWT_SECRET || process.env.VULN_JWT_SECRET || 'secret123';

function signToken(user) {
  const payload = {
    sub: String(user._id),
    username: user.username,
    role: user.role,
  };

  // VULNERABILITY: Missing JWT Expiry (no exp claim) & Weak HMAC Secret
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

function decodeBase64UrlJson(segment) {
  const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  let token = null;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.cookies && req.cookies.session_id) {
    token = req.cookies.session_id;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return res.status(401).json({ error: 'Malformed token' });
    }

    const header = decodeBase64UrlJson(parts[0]);

    // VULNERABILITY: JWT alg:none Acceptance (accepts unsigned tokens without verifying signature)
    if (typeof header.alg === 'string' && header.alg.toLowerCase() === 'none') {
      req.user = decodeBase64UrlJson(parts[1]);
      return next();
    }

    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token', details: err.message });
  }
}

module.exports = { JWT_SECRET, signToken, authenticate };
