function authorizeRole(...AllowdRoles) {
  return (req, res, next) => {
    if (!req.user || !AllowdRoles.includes(req.user.role)) {
      return res.status(403).json({ message: "You're Not Allowed From This Premission." });
    }
    next();
  };
}

module.exports = authorizeRole;