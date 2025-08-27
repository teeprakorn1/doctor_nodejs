const jwt = require('jsonwebtoken');

const VerifyTokens_Website = (req, res, next) => {
  const token = req.cookies?.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is required.', status: false });
  }

  try {
    const decoded = jwt.verify(token, process.env.PRIVATE_TOKEN_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token.', status: false });
  }
};

module.exports = VerifyTokens_Website;