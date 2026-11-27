const express = require('express');
const { getDB } = require('../db');

const router = express.Router();

// VULNERABILITY: NoSQL Injection in Query Endpoint (unsanitized req.query passed into MongoDB filter)
async function handleUserSearch(req, res) {
  try {
    const db = getDB();
    const name = req.query.name !== undefined ? req.query.name : req.query.username;

    const filter = name !== undefined && name !== '' ? { username: name } : {};
    const users = await db
      .collection('users')
      .find(filter, { projection: { password: 0 } })
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
  } catch (err) {
    return res.status(500).json({ error: 'User search failed', details: err.message });
  }
}

router.get('/users/search', handleUserSearch);
router.get('/users', handleUserSearch);

module.exports = router;
