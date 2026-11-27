const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '.env') });
dotenv.config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const mongoSanitize = require('express-mongo-sanitize');
const { connectDB, getDB } = require('./db');
const { router: authRouter, handleLogin } = require('./routes/auth');
const { loginRateLimiter } = require('./middleware/rateLimit');
const usersRouter = require('./routes/users');
const productsRouter = require('./routes/products');

const app = express();

app.disable('x-powered-by');

// Security headers: CSP, HSTS, X-Frame-Options, etc.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    frameguard: { action: 'deny' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
    },
  })
);

// Explicit CORS allowlist (never reflects untrusted origins or combines '*' with credentials)
const allowedOrigins = (
  process.env.CORS_ALLOWED_ORIGINS || 'http://127.0.0.1:3002,http://localhost:3002'
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(null, false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(cookieParser());

// Strip MongoDB operator keys ($ and .) from req.body, req.query, and req.params
app.use(mongoSanitize({ allowDots: false }));

app.get('/', (req, res) => {
  res.cookie('session_id', 'hardened-guest-session', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000,
  });

  res.status(200).json({
    app: 'NodeSentinel Demo App (Secure)',
    endpoints: [
      'GET /api/health',
      'POST /api/login',
      'GET /api/profile',
      'GET /api/users/search?name=...',
      'GET /api/products/search?q=...',
    ],
  });
});

app.get('/api/health', (req, res) => {
  let dbName = null;
  try {
    dbName = getDB().databaseName;
  } catch (_) {
    dbName = 'disconnected';
  }
  res.status(200).json({
    status: 'ok',
    variant: 'secure',
    database: dbName,
  });
});

// Mount API routes and rate-limited /login compatibility alias
app.use('/api', authRouter);
app.use('/api', usersRouter);
app.use('/api', productsRouter);
app.post('/login', loginRateLimiter, handleLogin);

const HOST = process.env.HOST || process.env.SECURE_HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || process.env.SECURE_PORT || 3002);

async function start() {
  try {
    await connectDB();
    const server = app.listen(PORT, HOST, () => {
      console.log(`[secure] Server listening on http://${HOST}:${PORT}`);
    });
    return server;
  } catch (err) {
    console.error('[secure] Startup failed:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  start();
}

module.exports = { app, start };
