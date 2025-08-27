const e = require('cors');
const jwt = require('jsonwebtoken');

// Generator Token
function Tokens_Generator(Users_ID, Users_Email, Users_Username, UsersType_ID, Users_Type, Login_Type) {
  if (!Users_ID || !Users_Email || !Users_Username || !UsersType_ID || !Users_Type || !Login_Type) {
    return 0;
  } else {
    if (Login_Type === 'website' || Login_Type === 'application') {
      const Token = jwt.sign(
      {
        Users_ID: Users_ID,
        Users_Email: Users_Email,
        Users_Username: Users_Username,
        UsersType_ID: UsersType_ID,
        Users_Type: Users_Type,
        Login_Type: Login_Type
      },
      process.env.PRIVATE_TOKEN_KEY, 
      { expiresIn: '24h' }
    );
    return Token;
    }else {
      return 0;
    }
  }
}

module.exports = Tokens_Generator;
