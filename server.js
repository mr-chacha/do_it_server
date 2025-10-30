const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const app = express();
const PORT = 4000;

// CORS 설정
app.use(
  cors({
    origin: "http://localhost:3000", // 프론트엔드 주소
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
// JSON 파싱을 위한 미들웨어
app.use(express.json());

//  이메일 인증 API

// 이메일 발송을 위한 transporter 설정
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "hoitchac@gmail.com",
    pass: "yizvzyyrxjjcheox",
  },
});

// 인증번호 저장소 (실제 운영 환경에서는 Redis 등을 사용)
const verificationCodes = new Map();

// 인증번호 생성 함수 (6자리 랜덤 숫자)
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 만료 시간 10분
const EXPIRATION_TIME = 10 * 60 * 1000;

// 1.이메일 인증번호 발송 
app.post("/api/signup/verifications", async (req, res) => {
  try {
    const { email } = req.body;

    // 입력값 검증
    if (!email) {
      return res.status(400).json({
        success: false,
        error: "이메일 주소를 입력해주세요.",
      });
    }

    // 이메일 형식 검증
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: "올바른 이메일 형식이 아닙니다.",
      });
    }

    // 기존 인증번호 확인
    const existing = verificationCodes.get(email);
    const isResend = !!existing; // 재발송 여부 확인

    // 인증번호 생성
    const code = generateVerificationCode();
    const expiresAt = Date.now() + EXPIRATION_TIME;

    // 인증번호 저장
    verificationCodes.set(email, {
      code,
      expiresAt,
      attempts: 0,
      maxAttempts: 5,
    });

    console.log(`📧 인증번호 ${isResend ? '재발송' : '발송'}: ${code} (대상: ${email})`);

    // 이메일 발송
    const mailOptions = {
      from: "hoitchac@gmail.com",
      to: email,
      subject: isResend ? "[재발송] 이메일 인증번호" : "이메일 인증번호",
      text: `안녕하세요!\n\n인증번호${isResend ? '가 재발송되었습니다' : '는'} ${code} 입니다.\n\n유효 시간: 10분`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2 style="color: #333;">
            이메일 인증번호 ${isResend ? '재발송' : ''}
          </h2>
          <p>안녕하세요!</p>
          <p>인증번호${isResend ? '가 재발송되었습니다. 새로운 ' : '는 아래와 같습니다'}:</p>
          <div style="background: #f4f4f4; padding: 15px; margin: 20px 0; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px;">
            ${code}
          </div>
          <p style="color: #666; font-size: 14px;">유효 시간: 10분</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    // 성공 응답
    res.status(isResend ? 200 : 201).json({  // 생성은 201, 재발송은 200
      success: true,
      message: `인증번호가 ${isResend ? '재' : ''}발송되었습니다.`,
      data: {
        email,
        expiresIn: "10분",
        isResend,  // 재발송 여부 포함
      },
    });
  } catch (error) {
    console.error("인증번호 발송 실패:", error);
    res.status(500).json({
      success: false,
      error: "인증번호 발송 중 오류가 발생했습니다.",
      details: error.message,
    });
  }
});


// 2. 이메일로 발송된 인증번호 확인
app.post("/api/signup/verifications/validation", async (req, res) => {
  try {
    const { email, code } = req.body;

    // 입력값 검증
    if (!email || !code) {
      return res.status(400).json({
        success: false,
        error: "이메일과 인증번호를 모두 입력해주세요.",
      });
    }

    // 저장된 인증번호 확인
    const stored = verificationCodes.get(email);

    if (!stored) {
      return res.status(404).json({
        success: false,
        error: "인증번호가 발송되지 않았거나 만료되었습니다.",
      });
    }

    // 만료 시간 확인
    if (Date.now() > stored.expiresAt) {
      verificationCodes.delete(email); // 만료된 정보 삭제
      return res.status(400).json({
        success: false,
        error: "인증번호가 만료되었습니다. 다시 발송해주세요.",
      });
    }

    // 시도 횟수 확인
    if (stored.attempts >= stored.maxAttempts) {
      verificationCodes.delete(email);
      return res.status(400).json({
        success: false,
        error: "인증번호 입력 시도 횟수를 초과했습니다. 다시 발송해주세요.",
      });
    }

    // 시도 횟수 증가
    stored.attempts += 1;

    // 인증번호 검증
    if (stored.code !== code) {
      return res.status(400).json({
        success: false,
        error: "인증번호가 올바르지 않습니다.",
        data: {
          remainingAttempts: stored.maxAttempts - stored.attempts,
        },
      });
    }

    // 인증 성공
    verificationCodes.delete(email); // 인증 완료 후 삭제

    console.log(`✅ 인증 성공: ${email}`);

    res.json({
      success: true,
      message: "이메일 인증이 완료되었습니다.",
      data: {
        email,
        verified: true,
        verifiedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("인증번호 검증 실패:", error);
    res.status(500).json({
      success: false,
      error: "인증번호 검증 중 오류가 발생했습니다.",
      details: error.message,
    });
  }
});


app.get("/", (req, res) => {
  res.send("🚀 Express server is running!");
});

app.get("/api/hello", (req, res) => {
  res.json({ message: "Hello from Express API!" });
});

app.listen(PORT, () => {
  console.log(`✅ Server is running on http://localhost:${PORT}`);
});
