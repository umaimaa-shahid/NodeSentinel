const rateLimit = require('express-rate-limit');

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 5, // Allow up to 5 login attempts per IP per window
  standardHeaders: true,
  legacyHeaders: true,
  handler: (req, res) => {
    res.setHeader('Retry-After', String(15 * 60));
    return res.status(429).json({
      error: 'Too many login attempts. Please try again later.',
    });
  },
});

module.exports = { loginRateLimiter };
