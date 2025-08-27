const xss = require('xss');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const express = require('express');
const bcrypt = require('bcrypt');
const cookieParser = require("cookie-parser");
const helmet = require('helmet');

const YAML = require('yamljs');
const swaggerUi = require('swagger-ui-express');

require('dotenv').config();

const db = require('./Server_Services/databaseClient');
const requestLogger = require('./Log_Services/requestLogger');
const RateLimiter = require('./Rate_Limiter/LimitTime');
const GenerateTokens = require('./Jwt_Tokens/Tokens_Generator');
const VerifyTokens = require('./Jwt_Tokens/Tokens_Verification');

const app = express();
const saltRounds = 14;
const isProduction = process.env.ENV_MODE === "1";

const allowedOrigins = [
  process.env.WEB_CLIENT_URL_DEV,
  process.env.WEB_CLIENT_URL_PROD,
  process.env.WEB_CLIENT_URL_PROD_2,
  null
];

function sanitizeRequest(req, res, next) {
  for (let prop in req.body) {
    if (typeof req.body[prop] === 'string') {
      req.body[prop] = xss(req.body[prop]);
    }
  }

  for (let prop in req.query) {
    if (typeof req.query[prop] === 'string') {
      req.query[prop] = xss(req.query[prop]);
    }
  }

  for (let prop in req.params) {
    if (typeof req.params[prop] === 'string') {
      req.params[prop] = xss(req.params[prop]);
    }
  }

  next();
}

app.use(express.json());
app.use(sanitizeRequest);
app.use(requestLogger);
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
        "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
        "img-src": ["'self'", "data:", "blob:"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "connect-src": [
          "'self'",
          process.env.WEB_CLIENT_URL_DEV,
          process.env.WEB_CLIENT_URL_PROD,
          process.env.WEB_CLIENT_URL_PROD_2
        ],
        "frame-src": ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// CORS Configuration
app.use(cors({
  origin: (origin, callback) => {
    console.log('CORS origin:', origin);
    if (!origin) return callback(null, true);
    if (isProduction) {
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log('Blocked by CORS:', origin);
        callback(new Error('Not allowed by CORS'));
      }
    } else {
      callback(null, true);
    }
  },
  credentials: true,
}));

////////////////////////////////// SWAGGER CONFIG ///////////////////////////////////////
const swaggerDocument = YAML.load('./swagger.yaml');

if (isProduction) {
  app.use('/api-docs', (req, res) => {
    res.status(403).json({ message: 'Swagger UI is disabled in production' });
  });
} else {
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, { explorer: true }));
}

////////////////////////////////// TEST API ///////////////////////////////////////
// Server Test
app.get('/api/health', (req, res) => {
  res.json({ message: "Server is Running." ,status: true });
});

// Encrypt Test
app.post('/api/test/encrypt', RateLimiter(0.5 * 60 * 1000, 15), async (req, res) => {
  if (isProduction) {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false });
  }

  try {
    const { password } = req.body || {};
    if (!password) {
      return res.status(400).json({ message: 'Password is required.', status: false });
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    res.json({ message: hashedPassword, status: true });
  } catch (error) {
    console.error('Error encrypting password:', error);
    res.status(500).json({ message: 'Internal server error.', status: false });
  }
});

// Decrypt Test
app.post('/api/test/decrypt', RateLimiter(0.5 * 60 * 1000, 15), async (req, res) => {
  if (isProduction) {
    return res.status(403).json({ message: 'This API is not allowed in production.', status: false });
  }

  try {
    const { password, hash } = req.body || {};
    if (!password || !hash) {
      return res.status(400).json({ message: 'Password and hash are required.', status: false });
    }
    const isMatch = await bcrypt.compare(password, hash);
    if (isMatch) {
      return res.json({ message: 'The password is correct.', status: true });
    } else {
      return res.status(200).json({ message: 'The password is incorrect.', status: false });
    }
  } catch (error) {
    console.error('Error comparing password:', error);
    res.status(500).json({ message: 'Internal server error.', status: false });
  }
});

////////////////////////////////// Tokens API ///////////////////////////////////////
// Verify Token
app.post('/api/verifyToken', RateLimiter(0.5 * 60 * 1000, 15), VerifyTokens, (req, res) => {
  const userData = req.user;
  if (userData) {
    return res.status(200).json({
      Users_ID: userData.Users_ID,
      Users_Email: userData.Users_Email,
      Users_Username: userData.Users_Username,
      UsersType_ID: userData.UsersType_ID,
      Users_Type: userData.Users_Type,
      Login_Type: userData.Login_Type,
      message: 'Token is valid.',
      status: true,
    });
  }
  return res.status(402).json({ message: 'Invalid Token.', status: false });
});

/////////////////////////////////////////////////////////////////////////////////////

app.listen(process.env.SERVER_PORT, () => {
  console.log(`Example app listening on port ${process.env.SERVER_PORT}`)
});