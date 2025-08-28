const xss = require('xss');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const express = require('express');
const bcrypt = require('bcrypt');
const validator = require('validator');
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
  res.json({ message: "Server is Running.", status: true });
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
      message: 'Token is valid.',
      status: true,
    });
  }
  return res.status(402).json({ message: 'Invalid Token.', status: false });
});

////////////////////////////////// Authentication API ///////////////////////////////////////
// API Login Website
app.post('/api/login', RateLimiter(1 * 60 * 1000, 5), async (req, res) => {
  let { Users_Email, Users_Password } = req.body || {};

  if (!Users_Email || !Users_Password ||
    typeof Users_Email !== 'string' || typeof Users_Password !== 'string') {
    return res.status(400).json({ message: 'Please fill in the correct parameters as required.', status: false });
  }

  Users_Email = xss(validator.escape(Users_Email));
  Users_Password = xss(Users_Password);

  try {
    const sql = `SELECT Users_ID, Users_Email, Users_Username, Users_Password, Users_Type
      FROM users WHERE (Users_Username = ? OR Users_Email = ?) AND (Users_Type = 'patient' OR Users_Type = 'doctor') AND Users_IsActive = 1`;

    db.query(sql, [Users_Email, Users_Email], async (err, result) => {
      if (err) {
        console.error('Database error (users)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length === 0) {
        return res.status(401).json({ message: "Email or password is incorrect.", status: false });
      }

      const user = result[0];
      const passwordMatch = await bcrypt.compare(Users_Password, user.Users_Password);
      if (!passwordMatch) {
        return res.status(401).json({ message: "Email or password is incorrect.", status: false });
      }

      // Check Users_Type
      let sql_users_type, users_type_name_id;
      if (user.Users_Type === 'patient') {
        sql_users_type = "SELECT Patient_ID FROM patient WHERE Users_ID = ?";
        users_type_name_id = 'Patient_ID';
      } else if (user.Users_Type === 'doctor') {
        sql_users_type = "SELECT Doctor_ID FROM doctor WHERE Users_ID = ?";
        users_type_name_id = 'Doctor_ID';
      } else {
        return res.status(400).json({ message: 'Invalid user type.', status: false });
      }

      db.query(sql_users_type, [user.Users_ID], async (err, result_users_type) => {
        if (err) {
          console.error('Database error (user type)', err);
          return res.status(500).json({ message: 'An error occurred on the server.', status: false });
        }

        if (result_users_type.length === 0) {
          return res.status(404).json({ message: 'User type details not found.', status: false });
        }

        const userType = result_users_type[0];
        const UsersType_ID = userType[users_type_name_id];

        const token = GenerateTokens(
          user.Users_ID,
          user.Users_Email,
          user.Users_Username,
          UsersType_ID,
          user.Users_Type
        );

        res.cookie("token", token, {
          httpOnly: true,
          secure: isProduction,
          sameSite: isProduction ? "None" : "Lax",
          domain: isProduction ? process.env.COOKIE_DOMAIN_PROD : undefined,
          maxAge: 60 * 60 * 1000
        });

        res.status(200).json({
          message: "The login was successful.",
          status: true
        });
      });
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API Logout Website
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'None' : 'Lax',
    domain: isProduction ? process.env.COOKIE_DOMAIN_PROD : undefined
  });
  res.status(200).json({ message: 'Logged out successfully.', status: true });
});

// API Patient Register
app.post('/api/register/patient', RateLimiter(1 * 60 * 1000, 5), async (req, res) => {
  let { Users_Email, Users_Username, Users_Password, Patient_FirstName,
    Patient_LastName, Patient_Phone, Patient_Gender, Patient_MedicalHistory } = req.body || {};

  if (!Users_Email || !Users_Username || !Users_Password || !Patient_FirstName || !Patient_LastName || !Patient_Gender) {
    return res.status(400).json({ message: 'Please fill in all required fields.', status: false });
  }

  Users_Email = xss(Users_Email);
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }
  Users_Email = validator.normalizeEmail(Users_Email);

  Users_Username = xss(Users_Username);
  if (!validator.isAlphanumeric(Users_Username) || Users_Username.length < 3 || Users_Username.length > 20) {
    return res.status(400).json({ message: 'Username must be 3-20 characters and alphanumeric.', status: false });
  }

  Users_Password = xss(Users_Password);
  if (!validator.isStrongPassword(Users_Password, { minLength: 8, minNumbers: 1, minSymbols: 0, minUppercase: 1, minLowercase: 1 })) {
    return res.status(400).json({ message: 'Password is not strong enough.', status: false });
  }

  Patient_FirstName = xss(Patient_FirstName);
  if (!/^[A-Za-zก-ฮะ-๛\s]+$/.test(Patient_FirstName)) {
    return res.status(400).json({ message: 'First name must contain only Thai or English letters.', status: false });
  }

  Patient_LastName = xss(Patient_LastName);
  if (!/^[A-Za-zก-ฮะ-๛\s]+$/.test(Patient_LastName)) {
    return res.status(400).json({ message: 'Last name must contain only Thai or English letters.', status: false });
  }

  Patient_Phone = Patient_Phone ? xss(Patient_Phone) : null;
  if (Patient_Phone && !validator.isMobilePhone(Patient_Phone, 'th-TH')) {
    return res.status(400).json({ message: 'Invalid phone number.', status: false });
  }

  Patient_Gender = xss(Patient_Gender);
  if (!['Male', 'Female'].includes(Patient_Gender)) {
    return res.status(400).json({ message: 'Gender must be either Male or Female.', status: false });
  }

  Patient_MedicalHistory = Patient_MedicalHistory ? xss(Patient_MedicalHistory) : null;

  try {
    const hashedPassword = await bcrypt.hash(Users_Password, saltRounds);

    db.query('START TRANSACTION', async (err) => {
      if (err) return res.status(500).json({ message: 'Database error', status: false });

      const sqlUser = `INSERT INTO users (Users_Email, Users_Username, Users_Password, Users_Type)
                       VALUES (?, ?, ?, 'patient')`;
      db.query(sqlUser, [Users_Email, Users_Username, hashedPassword], (err, userResult) => {
        if (err) {
          db.query('ROLLBACK', () => { });
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Email or username already exists.', status: false });
          }
          console.error('Insert Users Error:', err);
          return res.status(500).json({ message: 'Database error', status: false });
        }

        const Users_ID = userResult.insertId;

        const sqlPatient = `INSERT INTO patient 
          (Patient_FirstName, Patient_LastName, Patient_Phone, Patient_Gender, Patient_MedicalHistory, Users_ID)
          VALUES (?, ?, ?, ?, ?, ?)`;
        db.query(sqlPatient, [Patient_FirstName, Patient_LastName, Patient_Phone, Patient_Gender, Patient_MedicalHistory, Users_ID], (err, patientResult) => {
          if (err) {
            db.query('ROLLBACK', () => { });
            console.error('Insert Patient Error:', err);
            return res.status(500).json({ message: 'Database error', status: false });
          }

          db.query('COMMIT', (err) => {
            if (err) {
              db.query('ROLLBACK', () => { });
              console.error('Commit Error:', err);
              return res.status(500).json({ message: 'Database error', status: false });
            }

            res.status(201).json({
              message: 'Patient registered successfully.',
              status: true,
              Users_ID: Users_ID,
              Patient_ID: patientResult.insertId
            });
          });
        });
      });
    });
  } catch (err) {
    console.error('Register Patient Error:', err);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

////////////////////////////////// PROFILE API ///////////////////////////////////////
// API Get Profile Data by Token
app.get('/api/profile/get', RateLimiter(0.5 * 60 * 1000, 24), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const usersTypeID = userData.UsersType_ID;
  const usersType = userData.Users_Type;

  if (!usersType || !usersTypeID) {
    return res.status(400).json({ message: "Missing user type or ID.", status: false });
  }

  try {
    const usersType_upper = usersType.charAt(0).toUpperCase() + usersType.slice(1);
    const tableName = db.escapeId(usersType);
    const columnName = db.escapeId(`${usersType_upper}_ID`);

    let sql;

    if (usersType === 'doctor') {
      sql = `SELECT ty.*, u.Users_Email, u.Users_Type, st.Specialty_Name FROM((${tableName} ty INNER JOIN specialty st ON 
      ty.Specialty_ID = st.Specialty_ID) INNER JOIN users u ON ty.Users_ID = u.Users_ID)  WHERE ${columnName} = ? LIMIT 1`;
    } else if (usersType === 'patient') {
      sql = `SELECT ty.*, u.Users_Email, u.Users_Type FROM(${tableName} ty INNER JOIN users u ON 
      ty.Users_ID = u.Users_ID) WHERE ${columnName} = ? LIMIT 1`;
    } else {
      return res.status(400).json({ message: "Invalid user type.", status: false });
    }

    db.query(sql, [usersTypeID], (err, result) => {
      if (err) {
        console.error('Database error (profile data)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        const profileData = result[0];
        profileData['Users_Type_Table'] = usersType;
        profileData['message'] = 'Profile data retrieved successfully.';
        profileData['status'] = true;
        res.status(200).json(profileData);
      } else {
        return res.status(404).json({ message: 'No profile data found for this user.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

/////////////////////////////////////////////////////////////////////////////////////

app.listen(process.env.SERVER_PORT, () => {
  console.log(`Example app listening on port ${process.env.SERVER_PORT}`)
});