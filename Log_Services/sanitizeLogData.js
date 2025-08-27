function sanitizeLogData(data) {
  const sensitiveFields = [
    'password',
    'otp',
    'token',
    'users_password',
    'current_password',
    'new_password',
    'access_token',
    'refresh_token'
  ];

  function mask(obj) {
    if (!obj || typeof obj !== 'object') return obj;

    const copy = Array.isArray(obj) ? [...obj] : { ...obj };

    for (const key in copy) {
      const lowerKey = key.toLowerCase();

      if (sensitiveFields.includes(lowerKey)) {
        copy[key] = '[MASKED]';
      } else if (typeof copy[key] === 'object') {
        copy[key] = mask(copy[key]);
      }
    }

    return copy;
  }

  return mask(data);
}

module.exports = sanitizeLogData;
