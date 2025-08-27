const rateLimit = require('express-rate-limit');

//Rate Limiter
const rateLimiter = (windowMs, max) => {
  return rateLimit({
    windowMs: windowMs, //Time
    max: max, // Limit
    standardHeaders: true,
    legacyHeaders: false,

    // Key generator
    keyGenerator: (req, res) => {
      const ip = req.ip;
      const userAgent = req.headers['user-agent'] || 'unknown-agent';
      return `${ip}-${userAgent}`;
    },

    // handler message
    handler: (req, res, next, options) => {
      const retryAfterSeconds = Math.ceil(options.windowMs / 1000);
      return res.status(429).json({
        message: "Too many requests, please try again later.",
        retryAfterSeconds,
        request_status: false,
        status: false,
      });
    }
  });
};

module.exports = rateLimiter;