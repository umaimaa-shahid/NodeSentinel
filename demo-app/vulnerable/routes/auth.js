const express = require('express');
const { getDB } = require('../db');
const { signToken, authenticate } = require('../middleware/auth');

const router = express.Router();

// VULNERABILITY: Brute-Force Exposure (no rate limiting or account lockout on login)
async function handleLogin(req, res) {
  try {
    const { username, password } = req.body || {};

    if (username === undefined || password === undefined) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    const db = getDB();

    // VULNERABILITY: NoSQL Injection (passes raw req.body fields directly into MongoDB query)
    const user = await db.collection('users').findOne({ username, password });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = signToken(user);

    // VULNERABILITY: Insecure Cookie Configuration (missing HttpOnly, Secure, and SameSite flags)
    res.cookie('session_id', token);

    return res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: String(user._id),
        username: user.username,
        role: user.role,
        email: user.email,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Login failed', details: err.message });
  }
}

router.post('/login', handleLogin);

router.get('/profile', authenticate, async (req, res) => {
  try {
    const db = getDB();
    const user = await db.collection('users').findOne(
      { username: req.user.username },
      { projection: { password: 0 } }
    );

    if (!user) {
      return res.status(200).json({
        user: {
          id: req.user.sub || null,
          username: req.user.username || null,
          role: req.user.role || null,
        },
      });
    }

    return res.status(200).json({
      user: {
        id: String(user._id),
        username: user.username,
        role: user.role,
        email: user.email,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to load profile', details: err.message });
  }
});

module.exports = { router, handleLogin };
