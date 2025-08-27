const mysql = require('mysql2');
require('dotenv').config();

const db = mysql.createPool({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  password: process.env.DATABASE_PASS,
  database: process.env.DATABASE_NAME,
  port: process.env.DATABASE_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false
  }
});

db.getConnection((err) => {
  if (err) {
    console.error('Database connection error:', err.code);
    return;
  }
  console.log('Database connected successfully with SSL');
});

module.exports = db;
