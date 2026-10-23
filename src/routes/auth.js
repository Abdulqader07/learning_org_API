const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db');
const authenticationToken = require('../middleware/auth');
const authorizeRole = require('../middleware/roles');
const tokenStore = require('../lib/tokenStore');

const router = express.Router();

router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      message: "There's Data Missing! Please Make Sure You Filled All Data."
    });
  }
  const stmt = db.prepare(`SELECT COUNT(*) FROM users WHERE username = ?`);
  const userExsits = stmt.get(username);

  if (userExsits['COUNT(*)'] > 0) {
    const getUserStmt = db.prepare(`SELECT * FROM users WHERE username = ?`);
    const userName = getUserStmt.get(username);

    if (password === userName.password) {
      const token = jwt.sign(
        { userid: userName.userid, role: 'user' },
        process.env.SECRET_KEY,
        { expiresIn: '1h' }
      );

      const refreshToken = jwt.sign(
        { userid: userName.userid, role: 'user' },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '1d' }
      );

      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax'
      });

      res.status(200).json({
        message: `Welcome Back ${username}!`,
        token: token
      });
    } else {
      return res.status(400).json({ message: 'Password Is Invalid.' });
    }
  }
  return res.status(404).json({ message: `There's No User Called ${username}.` });
});

router.post('/signup', (req, res) => {
  const { username, email, password, passwordConfirmation } = req.body;

  if (!username || !email || !password || !passwordConfirmation) {
    return res.status(400).json({
      message: "There's Data Missing! Please Make Sure You Filled All Data."
    });
  }

  const stmt = db.prepare(`SELECT COUNT(*) FROM users WHERE username = ? or email = ?`);
  const userExsits = stmt.get(username, email);

  if (userExsits['COUNT(*)'] > 0) {
    return res.status(409).json({ message: 'This User Already Exsits.' });
  }

  if (password === passwordConfirmation) {
    const addUserStmt = db.prepare(`INSERT INTO users (username, email, password) VALUES (?, ?, ?)`);
    addUserStmt.run(username, email, password);

    return res.status(201).json({
      message: 'User Created Successfully.',
      user: { username: username, email: email, password: password }
    });
  } else {
    return res.status(400).json({ message: 'Please Check If The Password Is Correct.' });
  }
});

router.delete('/logout', authenticationToken, authorizeRole('user', 'admin'), (req, res) => {
  const userHeader = req.headers['authorization'];
  const userToken = userHeader && userHeader.split(' ')[1];

  if (!userToken) {
    return res.status(400).json({ message: 'User Is Already Logged Out.' });
  }

  jwt.verify(userToken, process.env.SECRET_KEY, (error, user) => {
    if (error) {
      return res.status(400).json({ message: 'Missing Token' });
    }
    tokenStore.add(userToken);
    res.cookie('token', '', { maxAge: 1 });
  });
});

router.post('/refresh', (req, res) => {
  const cookieJwt = req.cookies.refreshToken;

  if (!cookieJwt) {
    return res.status(403).json({ message: 'Unauthorized' });
  }
  jwt.verify(cookieJwt, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
    if (error) {
      return res.status(400).json({ message: 'Unauthorized' });
    }

    const token = jwt.sign(
      { userid: req.user.userid, role: req.user.role },
      process.env.SECRET_KEY,
      { expiresIn: '10m' }
    );

    return res.status(201).json({
      message: 'New Token Generated.',
      token: token
    });
  });
  return res.status(400).json({ message: 'Unauthorized' });
});

router.put('/profile', authenticationToken, authorizeRole('user', 'admin'), (req, res) => {
  const userId = req.user.userid;
  const { username, email } = req.body;

  if (email || username) {
    const stmt = db.prepare(`SELECT COUNT(*) FROM resources WHERE email = ? AND userId != ?`);
    const stmtUser = db.prepare(`SELECT COUNT(*) FROM resources WHERE username = ? AND userId != ?`);
    const getStmtEmail = stmt.get(email, userId);
    const getStmtUsername = stmtUser.get(username, userId);

    if (getStmtEmail['COUNT(*)'] === 0) {
      const stmtUpdateEmail = db.prepare(`UPDATE resources SET email = ? WHERE userId = ?`);
      stmtUpdateEmail.run(email, userId);
    } else {
      res.status(400).json({ message: 'This Email Is Already Taken' });
    }
    if (getStmtUsername['COUNT(*)'] === 0) {
      const stmtUpdateUsername = db.prepare(`UPDATE resources SET username = ? WHERE userId = ?`);
      stmtUpdateUsername.run(username, userId);
    } else {
      res.status(400).json({ message: 'This Username Is Already Taken.' });
    }

    return res.json({
      update: { username: username, email: email }
    });
  }
  return res.status(400).json({
    message: 'Something Went Wrong Please Check Your Date You Sent'
  });
});

module.exports = router;