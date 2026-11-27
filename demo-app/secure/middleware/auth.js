const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const ALLOWED_ALGORITHMS = ['HS256'];
const TOKEN_EXPIRY = '15m';

function resolveJwtSecret() {
  const configured = process.env.JWT_SECRET || process.env.SECURE_JWT_SECRET;
  if (configured && configured.length >= 32) {
    return configured;
  }

  console.warn(
    '[secure] WARNING: JWT_SECRET not set or shorter than 32 characters; generating an ephemeral strong secret for this process.'
  );
  return crypto.randomBytes(32).toString('hex');
}

const JWT_SECRET = resolveJwtSecret();

function signToken(user) {
  const payload = {
    sub: String(user._id),
    username: user.username,
    role: user.role,
  };

  return jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: TOKEN_EXPIRY,
  });
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  let token = null;

  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else if (req.cookies && typeof req.cookies.session_id === 'string') {
    token = req.cookies.session_id;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  try {
    const decodedComplete = jwt.decode(token, { complete: true });
    if (
      !decodedComplete ||
      !decodedComplete.header ||
      typeof decodedComplete.header.alg !== 'string' ||
      !ALLOWED_ALGORITHMS.includes(decodedComplete.header.alg)
    ) {
      return res.status(401).json({ error: 'Unsupported or unsigned JWT algorithm rejected' });
    }

    req.user = jwt.verify(token, JWT_SECRET, {
      algorithms: ALLOWED_ALGORITHMS,
    });
    return next();
  } catch (_) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = { signToken, authenticate, ALLOWED_ALGORITHMS, TOKEN_EXPIRY };
