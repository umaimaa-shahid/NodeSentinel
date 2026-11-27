const path = require('path');
const dotenv = require('dotenv');

dotenv.config({ path: path.join(__dirname, '.env') });
dotenv.config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const cookieParser = require('cookie-parser');
const { connectDB, getDB } = require('./db');
const { router: authRouter, handleLogin } = require('./routes/auth');
const usersRouter = require('./routes/users');
const productsRouter = require('./routes/products');

const app = express();

// Express extended query parser allows nested query objects (e.g. bracket notation)
app.set('query parser', 'extended');

// VULNERABILITY: Missing Security Headers (Helmet is intentionally omitted: no CSP, HSTS, or X-Frame-Options)

// VULNERABILITY: Permissive Wildcard CORS with Credentials
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  return next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', (req, res) => {
  // VULNERABILITY: Insecure Cookie Configuration (missing HttpOnly, Secure, and SameSite flags)
  res.cookie('session_id', 'demo-guest-session');

  res.status(200).json({
    app: 'NodeSentinel Demo App (Vulnerable)',
    warning: 'FOR LOCAL EDUCATIONAL TESTING ONLY - NEVER DEPLOY PUBLICLY',
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
    variant: 'vulnerable',
    database: dbName,
  });
});

// Mount API routes and /login compatibility alias
app.use('/api', authRouter);
app.use('/api', usersRouter);
app.use('/api', productsRouter);
app.post('/login', handleLogin);

const HOST = process.env.HOST || process.env.VULN_HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || process.env.VULN_PORT || 3001);

async function start() {
  try {
    await connectDB();
    const server = app.listen(PORT, HOST, () => {
      console.log(`[vulnerable] Server listening on http://${HOST}:${PORT}`);
      console.log('[vulnerable] WARNING: Deliberately vulnerable test target. Local lab use only.');
    });
    return server;
  } catch (err) {
    console.error('[vulnerable] Startup failed:', err.message);
    process.exit(1);
  }
}

if (require.main === module) {
  start();
}

module.exports = { app, start };
