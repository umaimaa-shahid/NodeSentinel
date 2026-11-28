const express = require('express');
const Joi = require('joi');
const { getDB } = require('../db');

const router = express.Router();

const userSearchSchema = Joi.object({
  name: Joi.string().trim().max(64).optional(),
  username: Joi.string().trim().max(64).optional(),
});

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function handleUserSearch(req, res) {
  try {
    const { error, value } = userSearchSchema.validate(req.query, {
      convert: false,
    });

    if (error) {
      return res.status(400).json({ error: 'Invalid search query parameter' });
    }

    const db = getDB();
    const rawName = value.name !== undefined ? value.name : value.username;
    const filter = rawName
      ? { username: { $regex: escapeRegex(rawName), $options: 'i' } }
      : {};

    const users = await db
      .collection('users')
      .find(filter, {
        projection: { passwordHash: 0, failedLoginAttempts: 0, lockUntil: 0 },
      })
      .toArray();

    return res.status(200).json({
      count: users.length,
      users: users.map((u) => ({
        id: String(u._id),
        username: u.username,
        role: u.role,
        email: u.email,
      })),
    });
  } catch (_) {
    return res.status(500).json({ error: 'User search failed' });
  }
}

router.get('/users/search', handleUserSearch);
router.get('/users', handleUserSearch);

module.exports = router;
