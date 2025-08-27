const geoip = require('geoip-lite');
const logger = require('./logger');
const sanitizeLogData = require('./sanitizeLogData');

function requestLogger(req, res, next) {
  const startHrTime = process.hrtime();

  const ip =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress?.replace(/^::ffff:/, '') ||
    req.ip;

  const geo = geoip.lookup(ip) || {};
  const isLocalhost = ['127.0.0.1', '::1'].includes(ip);
  const location = isLocalhost ? 'Localhost' : (geo.city ? `${geo.city}, ${geo.country}` : geo.country || 'Unknown');

  const method = req.method;
  const url = req.originalUrl;
  const userAgent = req.headers['user-agent'];
  const userId = req.user?.Users_ID || 'anonymous';
  const isPrivateIP = /^(10\.|192\.168\.|127\.|172\.(1[6-9]|2[0-9]|3[0-1]))/.test(ip);

  if (!isPrivateIP) {
    logger.log('http', `[User: ${userId}] → ${method} ${url} from IP ${ip} (${location}) | UA: ${userAgent}`);
  }

  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    if (logger.isLevelEnabled('debug')) {
      try {
        const rawBody = JSON.stringify(sanitizeLogData(req.body));
        const limitedBody = rawBody.length > 1000
          ? rawBody.substring(0, 1000) + '...[TRUNCATED]'
          : rawBody;

        logger.debug(`[User: ${userId}] Request Body: ${limitedBody}`);
      } catch (err) {
        logger.debug(`[User: ${userId}] Request Body: [UNREADABLE]`);
      }
    }
  }

  res.on('finish', () => {
    const [sec, nano] = process.hrtime(startHrTime);
    const durationMs = (sec * 1e3 + nano / 1e6).toFixed(2);

    const message = `[User: ${userId}] ← ${res.statusCode} ${method} ${url} | ${durationMs} ms from ${ip}`;

    if (durationMs > 1000) {
      logger.warn(`[SLOW] ${message}`);
    }

    if (res.statusCode >= 500) {
      logger.error(message);
    } else if (res.statusCode >= 400) {
      logger.warn(message);
    } else {
      logger.info(message);
    }
  });

  next();
}

module.exports = requestLogger;
