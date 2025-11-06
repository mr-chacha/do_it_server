const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 4000;

// CORS 설정
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// JSON 파싱을 위한 미들웨어
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// 라우트 연결
app.use("/api/auth", require("./routes/auth"));
app.use("/api/connect", require("./routes/couple"));
app.use("/api/verifications", require("./routes/verification"));
app.use("/api/finance", require("./routes/finance"));
app.use("/api/schedule", require("./routes/schedule"));

// 루트 경로
app.get("/", (req, res) => {
  res.send("🚀 Express server is running!");
});

app.listen(PORT, () => {
  console.log(`✅ Server is running on http://localhost:${PORT}`);
});
