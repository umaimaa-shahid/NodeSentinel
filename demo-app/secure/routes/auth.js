const express = require('express');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const { getDB } = require('../db');
const { signToken, authenticate } = require('../middleware/auth');
const { loginRateLimiter } = require('../middleware/rateLimit');

const router = express.Router();

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000; // 15 minutes

const loginSchema = Joi.object({
  username: Joi.string().trim().min(1).max(64).required(),
  password: Joi.string().min(1).max(128).required(),
});

async function handleLogin(req, res) {
  try {
    const { error, value } = loginSchema.validate(req.body, {
      convert: false,
      stripUnknown: true,
    });

    if (error) {
      return res.status(400).json({ error: 'Invalid username or password format' });
    }

    const { username, password } = value;
    const db = getDB();
    const users = db.collection('users');

    const user = await users.findOne({ username: String(username) });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const now = new Date();
    if (user.lockUntil && new Date(user.lockUntil) > now) {
      const retrySeconds = Math.ceil((new Date(user.lockUntil).getTime() - now.getTime()) / 1000);
      res.setHeader('Retry-After', String(Math.max(1, retrySeconds)));
      return res.status(423).json({
        error: 'Account temporarily locked due to too many failed login attempts.',
      });
    }

    const passwordMatches = await bcrypt.compare(password, user.passwordHash || '');

    if (!passwordMatches) {
      const attempts = (user.failedLoginAttempts || 0) + 1;
      const update = { failedLoginAttempts: attempts };
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        update.lockUntil = new Date(Date.now() + LOCK_DURATION_MS);
      }

      await users.updateOne({ _id: user._id }, { $set: update });

      if (attempts >= MAX_FAILED_ATTEMPTS) {
        res.setHeader('Retry-After', String(LOCK_DURATION_MS / 1000));
        return res.status(423).json({
          error: 'Account temporarily locked due to too many failed login attempts.',
        });
      }

      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.failedLoginAttempts || user.lockUntil) {
      await users.updateOne(
        { _id: user._id },
        { $set: { failedLoginAttempts: 0, lockUntil: null } }
      );
    }

    const token = signToken(user);

    res.cookie('session_id', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 15 * 60 * 1000,
    });

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
  } catch (_) {
    return res.status(500).json({ error: 'Authentication service error' });
  }
}

router.post('/login', loginRateLimiter, handleLogin);

router.get('/profile', authenticate, async (req, res) => {
  try {
    const db = getDB();
    const user = await db.collection('users').findOne(
      { username: String(req.user.username) },
      { projection: { passwordHash: 0, failedLoginAttempts: 0, lockUntil: 0 } }
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({
      user: {
        id: String(user._id),
        username: user.username,
        role: user.role,
        email: user.email,
      },
    });
  } catch (_) {
    return res.status(500).json({ error: 'Unable to load profile' });
  }
});

module.exports = { router, handleLogin };
