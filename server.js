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
  process.env.WEB_CLIENT_URL_PROD_3,
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

  Users_Email = xss(Users_Email.trim());
  if (!validator.isEmail(Users_Email)) {
    return res.status(400).json({ message: 'Invalid email format.', status: false });
  }

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

//API Edit Patient Profile
app.put('/api/profile/patient/update', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const Users_Type = userData?.Users_Type;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (Users_Type?.toLowerCase() !== 'patient') {
    return res.status(403).json({ message: "Permission denied. Only patients can perform this action.", status: false });
  }

  let { Patient_FirstName, Patient_LastName, Patient_Phone, Patient_Gender, Patient_MedicalHistory } = req.body || {};

  if (Patient_FirstName && (typeof Patient_FirstName !== "string" || Patient_FirstName.length > 100)) {
    return res.status(400).json({ message: "Invalid first name (must be a string and <= 100 characters).", status: false });
  }

  if (Patient_LastName && (typeof Patient_LastName !== "string" || Patient_LastName.length > 100)) {
    return res.status(400).json({ message: "Invalid last name (must be a string and <= 100 characters).", status: false });
  }

  if (Patient_Phone) {
    if (!validator.isMobilePhone(Patient_Phone, 'th-TH', { strictMode: false })) {
      return res.status(400).json({ message: "Invalid Thai phone number format.", status: false });
    }
    if (Patient_Phone.length > 20 || Patient_Phone.length < 8) {
      return res.status(400).json({ message: "Phone number length must be between 8 and 20 digits.", status: false });
    }
    if (!/^\d+$/.test(Patient_Phone)) {
      return res.status(400).json({ message: "Phone number must contain only digits.", status: false });
    }
  }

  const allowedGenders = ["male", "female"];
  if (Patient_Gender && !allowedGenders.includes(Patient_Gender.toLowerCase())) {
    return res.status(400).json({ message: "Invalid gender value.", status: false });
  }

  if (Patient_MedicalHistory && Patient_MedicalHistory.length > 1023) {
    return res.status(400).json({ message: "Medical history text too long (max 1023 characters).", status: false });
  }

  const allowedFields = { Patient_FirstName, Patient_LastName, Patient_Phone, Patient_Gender, Patient_MedicalHistory };
  const fieldsToUpdate = [];
  const values = [];

  for (const [key, value] of Object.entries(allowedFields)) {
    if (value !== undefined) {
      fieldsToUpdate.push(`${key} = ?`);
      values.push(value);
    }
  }

  if (fieldsToUpdate.length === 0) {
    return res.status(400).json({ message: "No fields provided for update.", status: false });
  }

  const sqlCheck = "SELECT Patient_ID FROM patient WHERE Users_ID = ?";
  db.query(sqlCheck, [Users_ID], (err, result) => {
    if (err) {
      console.error("Database error (patient check)", err);
      return res.status(500).json({ message: "Database error occurred.", status: false });
    }

    if (result.length === 0) {
      return res.status(404).json({ message: "Patient profile not found.", status: false });
    }

    const Patient_ID = result[0].Patient_ID;
    const sqlUpdate = `UPDATE patient SET ${fieldsToUpdate.join(", ")} WHERE Patient_ID = ?`;
    values.push(Patient_ID);

    db.query(sqlUpdate, values, (err, updateResult) => {
      if (err) {
        console.error("Database error (patient update)", err);
        return res.status(500).json({ message: "Database error occurred.", status: false });
      }

      if (updateResult.affectedRows > 0) {
        return res.status(200).json({ message: "Patient profile updated successfully.", status: true });
      } else {
        return res.status(404).json({ message: "No changes made or patient not found.", status: false });
      }
    });
  });
});

////////////////////////////////// DOCTOR API ///////////////////////////////////////
// API get Doctor by Specialty_Name
app.get('/api/doctor/specialty/get/:Specialty_Name', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const { Specialty_Name } = req.params;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (!Specialty_Name || typeof Specialty_Name !== 'string' || Specialty_Name.length > 100) {
    return res.status(400).json({ message: "Invalid Specialty parameter.", status: false });
  }

  try {
    const sql = `
      SELECT d.Doctor_ID, d.Doctor_FirstName, d.Doctor_LastName, d.Doctor_Phone, 
             s.Specialty_Name 
      FROM doctor d 
      INNER JOIN specialty s ON d.Specialty_ID = s.Specialty_ID 
      INNER JOIN users u ON d.Users_ID = u.Users_ID 
      WHERE s.Specialty_Name LIKE ? AND u.Users_IsActive = 1
    `;

    const searchParam = `%${Specialty_Name}%`;

    db.query(sql, [searchParam], (err, result) => {
      if (err) {
        console.error('Database error (get by Specialty_Name)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        return res.status(200).json({ data: result, message: 'Specialty retrieved successfully.', status: true });
      } else {
        return res.status(404).json({ message: 'No doctors found for this specialty.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error (get by Specialty_Name)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// API get Doctor by doctorName
app.get('/api/doctor/name/get/:doctorName', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, async (req, res) => {
  const userData = req.user;
  const Users_ID = userData?.Users_ID;
  const { doctorName } = req.params;

  if (!Users_ID || typeof Users_ID !== 'number') {
    return res.status(400).json({ message: "Missing or invalid Users_ID from token.", status: false });
  }

  if (!doctorName || typeof doctorName !== 'string' || doctorName.length > 100) {
    return res.status(400).json({ message: "Invalid doctorName parameter.", status: false });
  }

  try {
    const sql = `
      SELECT d.Doctor_ID, d.Doctor_FirstName, d.Doctor_LastName, d.Doctor_Phone, 
             s.Specialty_Name 
      FROM doctor d 
      INNER JOIN specialty s ON d.Specialty_ID = s.Specialty_ID 
      INNER JOIN users u ON d.Users_ID = u.Users_ID 
      WHERE (d.Doctor_FirstName LIKE ? OR d.Doctor_LastName LIKE ?) 
        AND u.Users_IsActive = 1
    `;

    const searchParam = `%${doctorName}%`;

    db.query(sql, [searchParam, searchParam], (err, result) => {
      if (err) {
        console.error('Database error (get by doctorName)', err);
        return res.status(500).json({ message: 'An error occurred on the server.', status: false });
      }

      if (result.length > 0) {
        return res.status(200).json({ data: result, message: 'Doctors retrieved successfully.', status: true });
      } else {
        return res.status(404).json({ message: 'No doctors found with this name.', status: false });
      }
    });
  } catch (error) {
    console.error('Catch error (get by doctorName)', error);
    res.status(500).json({ message: 'An unexpected error occurred.', status: false });
  }
});

// POST /api/appointment/create
app.post('/api/appointment/create', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, (req, res) => {
  const Users_ID = req.user?.Users_ID;
  const { doctorId, availabilityId } = req.body;

  if (!Users_ID || !doctorId || !availabilityId) {
    return res.status(400).json({ message: "Missing required fields", status: false });
  }

  const sqlGetPatient = `SELECT Patient_ID FROM patient WHERE Users_ID = ? LIMIT 1`;
  db.query(sqlGetPatient, [Users_ID], (err, patientRes) => {
    if (err || patientRes.length === 0) {
      return res.status(500).json({ message: "Patient not found", status: false });
    }

    const Patient_ID = patientRes[0].Patient_ID;

    const sqlCheckAvailability = `
            SELECT Availability_IsBooked FROM availability 
            WHERE Availability_ID = ? AND Doctor_ID = ?
            LIMIT 1
        `;
    db.query(sqlCheckAvailability, [availabilityId, doctorId], (err, availRes) => {
      if (err || availRes.length === 0) {
        return res.status(400).json({ message: "Availability not found", status: false });
      }

      if (availRes[0].Availability_IsBooked) {
        return res.status(400).json({ message: "เวลานี้ถูกจองแล้ว", status: false });
      }

      const sqlGetStatus = `SELECT AppointmentStatus_ID FROM appointmentstatus WHERE AppointmentStatus_Name = 'Pending' LIMIT 1`;
      db.query(sqlGetStatus, (err, statusRes) => {
        if (err || statusRes.length === 0) {
          return res.status(500).json({ message: "Appointment status not found", status: false });
        }

        const AppointmentStatus_ID = statusRes[0].AppointmentStatus_ID;
        const sqlInsert = `
                    INSERT INTO appointment (Doctor_ID, Patient_ID, Availability_ID, AppointmentStatus_ID)
                    VALUES (?, ?, ?, ?)
                `;
        db.query(sqlInsert, [doctorId, Patient_ID, availabilityId, AppointmentStatus_ID], (err, insertRes) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ message: "Database error", status: false });
          }

          const sqlUpdateAvailability = `UPDATE availability SET Availability_IsBooked = 1 WHERE Availability_ID = ?`;
          db.query(sqlUpdateAvailability, [availabilityId], (err) => {
            if (err) console.error('Update availability error', err);
            res.status(201).json({ message: "Appointment created successfully", status: true });
          });
        });
      });
    });
  });
});

// API Get Availability by doctorId
app.get('/api/doctor/:doctorId/availability', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, (req, res) => {
  const { doctorId } = req.params;

  if (!doctorId || isNaN(doctorId)) {
    return res.status(400).json({ message: 'Invalid doctorId parameter.', status: false });
  }

  const sql = `
    SELECT Availability_ID, Availability_Date, Availability_StartTime, Availability_EndTime
    FROM availability
    WHERE Doctor_ID = ? AND Availability_IsBooked = 0
    ORDER BY Availability_Date ASC, Availability_StartTime ASC
  `;

  db.query(sql, [doctorId], (err, result) => {
    if (err) {
      console.error('Database error (get availability)', err);
      return res.status(500).json({ message: 'Database error.', status: false });
    }

    res.status(200).json({ data: result, message: 'Availability retrieved successfully.', status: true });
  });
});

// API Get Doctor's Availability
app.get('/api/doctor/availability', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, (req, res) => {
  const Users_ID = req.user?.Users_ID;
  if (!Users_ID) return res.status(400).json({ message: 'Invalid user', status: false });

  const sqlGetDoctorId = `SELECT Doctor_ID FROM doctor WHERE Users_ID = ? LIMIT 1`;
  db.query(sqlGetDoctorId, [Users_ID], (err, doctorRes) => {
    if (err || doctorRes.length === 0) return res.status(500).json({ message: 'Doctor not found', status: false });
    const Doctor_ID = doctorRes[0].Doctor_ID;

    const sql = `
    SELECT Availability_ID, Availability_Date, Availability_StartTime, Availability_EndTime
      FROM availability
      WHERE Doctor_ID = ? AND Availability_IsBooked = 0
      ORDER BY Availability_Date ASC, Availability_StartTime ASC
    `;

    db.query(sql, [Doctor_ID], (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error', status: false });
      res.status(200).json(result);
    });
  });
});

// API Add Availability
app.post('/api/doctor/availability', RateLimiter(0.5 * 60 * 1000, 12), VerifyTokens, (req, res) => {
  const Users_ID = req.user?.Users_ID;
  const { date, startTime, endTime } = req.body || {};
  if (!Users_ID || !date || !startTime || !endTime) return res.status(400).json({ message: 'Missing fields', status: false });

  const sqlGetDoctorId = `SELECT Doctor_ID FROM doctor WHERE Users_ID = ? LIMIT 1`;
  db.query(sqlGetDoctorId, [Users_ID], (err, doctorRes) => {
    if (err || doctorRes.length === 0) return res.status(500).json({ message: 'Doctor not found', status: false });
    const Doctor_ID = doctorRes[0].Doctor_ID;

    const sqlInsert = `
      INSERT INTO availability (Doctor_ID, Availability_Date, Availability_StartTime, Availability_EndTime)
      VALUES (?, ?, ?, ?)
    `;
    db.query(sqlInsert, [Doctor_ID, date, startTime, endTime], (err, insertRes) => {
      if (err) return res.status(500).json({ message: 'Database error', status: false });
      res.status(201).json({ message: 'Availability added successfully', status: true });
    });
  });
});

// GET /api/patient/appointment
app.get('/api/patient/appointment', VerifyTokens, (req, res) => {
  const Users_ID = req.user?.Users_ID;

  const sqlGetPatient = `SELECT Patient_ID FROM patient WHERE Users_ID = ? LIMIT 1`;
  db.query(sqlGetPatient, [Users_ID], (err, patientRes) => {
    if (err || patientRes.length === 0) {
      return res.status(500).json({ message: 'Patient not found', status: false });
    }

    const Patient_ID = patientRes[0].Patient_ID;
    const sqlAppointments = `
      SELECT a.Appointment_ID, a.Appointment_RegisTime,
             d.Doctor_FirstName, d.Doctor_LastName, s.Specialty_Name,
             av.Availability_Date, av.Availability_StartTime, av.Availability_EndTime,
             ast.AppointmentStatus_Name, ast.AppointmentStatus_Description
      FROM appointment a
      INNER JOIN doctor d ON a.Doctor_ID = d.Doctor_ID
      INNER JOIN specialty s ON d.Specialty_ID = s.Specialty_ID
      INNER JOIN availability av ON a.Availability_ID = av.Availability_ID
      INNER JOIN appointmentstatus ast ON a.AppointmentStatus_ID = ast.AppointmentStatus_ID
      WHERE a.Patient_ID = ?
      ORDER BY a.Appointment_RegisTime DESC
    `;
    db.query(sqlAppointments, [Patient_ID], (err, result) => {
      if (err) return res.status(500).json({ message: 'Database error', status: false });
      res.status(200).json({ data: result, status: true });
    });
  });
});

// GET /api/doctor/appointments/pending**
app.get('/api/doctor/appointments/pending', VerifyTokens, (req, res) => {
  const Users_ID = req.user?.Users_ID;

  const sqlGetDoctor = `SELECT Doctor_ID FROM doctor WHERE Users_ID = ? LIMIT 1`;
  db.query(sqlGetDoctor, [Users_ID], (err, doctorRes) => {
    if (err || doctorRes.length === 0) return res.status(500).json({ status: false, message: 'Doctor not found' });
    const Doctor_ID = doctorRes[0].Doctor_ID;

    const sql = `
      SELECT a.Appointment_ID, a.Appointment_RegisTime, a.Patient_ID,
             p.Patient_FirstName, p.Patient_LastName,
             av.Availability_Date, av.Availability_StartTime, av.Availability_EndTime,
             ast.AppointmentStatus_Name AS status, ast.AppointmentStatus_Description
      FROM appointment a
      INNER JOIN patient p ON a.Patient_ID = p.Patient_ID
      INNER JOIN availability av ON a.Availability_ID = av.Availability_ID
      INNER JOIN appointmentstatus ast ON a.AppointmentStatus_ID = ast.AppointmentStatus_ID
      WHERE a.Doctor_ID = ? AND ast.AppointmentStatus_Name = 'Pending'
      ORDER BY a.Appointment_RegisTime DESC
    `;
    db.query(sql, [Doctor_ID], (err, result) => {
      if (err) return res.status(500).json({ status: false, message: 'Database error' });
      res.status(200).json({ status: true, data: result });
    });
  });
});

// POST /api/doctor/appointments/action
app.post('/api/doctor/appointments/action', VerifyTokens, (req, res) => {
  const Users_ID = req.user?.Users_ID;
  const { appointmentId, action } = req.body;

  if (!appointmentId || !['Confirmed', 'Cancelled'].includes(action)) {
    return res.status(400).json({ status: false, message: 'ข้อมูลไม่ถูกต้อง' });
  }

  const sqlGetDoctor = `SELECT Doctor_ID FROM doctor WHERE Users_ID = ? LIMIT 1`;
  db.query(sqlGetDoctor, [Users_ID], (err, doctorRes) => {
    if (err || doctorRes.length === 0) return res.status(500).json({ status: false, message: 'Doctor not found' });
    const Doctor_ID = doctorRes[0].Doctor_ID;

    const sqlGetStatus = `SELECT AppointmentStatus_ID FROM appointmentstatus WHERE AppointmentStatus_Name = ? LIMIT 1`;
    db.query(sqlGetStatus, [action], (err, statusRes) => {
      if (err || statusRes.length === 0) return res.status(500).json({ status: false, message: 'Status not found' });
      const AppointmentStatus_ID = statusRes[0].AppointmentStatus_ID;

      const sqlUpdate = `UPDATE appointment SET AppointmentStatus_ID = ? WHERE Appointment_ID = ? AND Doctor_ID = ?`;
      db.query(sqlUpdate, [AppointmentStatus_ID, appointmentId, Doctor_ID], (err) => {
        if (err) return res.status(500).json({ status: false, message: 'Database error' });
        res.status(200).json({ status: true, message: 'Update successful' });
      });
    });
  });
});

// GET /api/doctor/appointments/schedule
app.get('/api/doctor/appointments/schedule', VerifyTokens, (req, res) => {
    const Users_ID = req.user?.Users_ID;
    if (!Users_ID) return res.status(400).json({ status: false, message: 'Invalid user' });

    const sqlGetDoctorId = `SELECT Doctor_ID FROM doctor WHERE Users_ID = ? LIMIT 1`;
    db.query(sqlGetDoctorId, [Users_ID], (err, doctorRes) => {
        if (err || doctorRes.length === 0) 
            return res.status(500).json({ status: false, message: 'Doctor not found' });

        const Doctor_ID = doctorRes[0].Doctor_ID;

        const sqlAppointments = `
            SELECT a.Appointment_ID, a.Appointment_RegisTime,
                   p.Patient_FirstName, p.Patient_LastName, p.Patient_Phone,
                   s.Specialty_Name,
                   av.Availability_Date, av.Availability_StartTime, av.Availability_EndTime,
                   ast.AppointmentStatus_Name AS status, ast.AppointmentStatus_Description
            FROM appointment a
            INNER JOIN patient p ON a.Patient_ID = p.Patient_ID
            INNER JOIN doctor d ON a.Doctor_ID = d.Doctor_ID
            INNER JOIN specialty s ON d.Specialty_ID = s.Specialty_ID
            INNER JOIN availability av ON a.Availability_ID = av.Availability_ID
            INNER JOIN appointmentstatus ast ON a.AppointmentStatus_ID = ast.AppointmentStatus_ID
            WHERE a.Doctor_ID = ?
            ORDER BY av.Availability_Date ASC, av.Availability_StartTime ASC
        `;
        db.query(sqlAppointments, [Doctor_ID], (err, result) => {
            if (err) return res.status(500).json({ status: false, message: 'Database error' });
            if (!result || result.length === 0) 
                return res.status(200).json({ status: true, data: [], message: 'No appointments found' });

            res.status(200).json({ status: true, data: result, message: 'Appointments retrieved successfully' });
        });
    });
});

/////////////////////////////////////////////////////////////////////////////////////

app.listen(process.env.SERVER_PORT, () => {
  console.log(`Example app listening on port ${process.env.SERVER_PORT}`)
});