const jwt = require("jsonwebtoken");

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-this-in-production";

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({
      success: false,
      error: "인증 토큰이 필요합니다.",
      data: {
        authenticated: false,
      },
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: "유효하지 않은 토큰입니다.",
        data: {
          authenticated: false,
          expired: err.name === "TokenExpiredError",
        },
      });
    }

    req.user = user; // 토큰에서 추출한 사용자 정보
    next();
  });
};

module.exports = { authenticateToken };
