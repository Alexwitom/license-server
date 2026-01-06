module.exports = function (req, res, next) {
  const key = req.headers["x-admin-key"];
  if (key !== process.env.ADMIN_KEY) {
    return res.status(403).json({ ok: false });
  }
  next();
};
