
const jwt = require("jsonwebtoken");

const requireAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;

  const match = authHeader?.match(/^Bearer ([^\s]+)$/);

  if (!match) {
    return res.status(401).json({
      error: {
        code: "AUTH_REQUIRED",
        message: "Authentication required",
      },
    });
  }

  try {
    const token = match[1];

    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
    });

    req.user = decoded;

    return next();
  } catch (error) {
    return res.status(401).json({
      error: {
        code: "AUTH_REQUIRED",
        message: "Authentication required",
      },
    });
  }
};

module.exports = requireAuth;
