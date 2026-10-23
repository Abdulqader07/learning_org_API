const jwt = require('jsonwebtoken');
const tokenStore = require('../lib/tokenStore');

function authenticationToken(req, res, next) {
  const headerAuth = req.headers['authorization'];
  const token = headerAuth && headerAuth.split(' ')[1];
  if (!token || tokenStore.has(token)) {
    return res.status(401).json({ message: 'The Token Is Missing.' });
  }
  jwt.verify(token, process.env.SECRET_KEY, (error, user) => {
    if (error) return res.status(403).json({ message: 'Invalid or Expired Token.' });
    req.user = user;
    next();
  });
}

module.exports = authenticationToken;