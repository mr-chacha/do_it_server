const express = require("express");
const nodemailer = require("nodemailer");
const app = express();
const PORT = 3000;

// JSON 파싱을 위한 미들웨어
app.use(express.json());

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
const EXPIRATION_TIME = 10 * 60 * 1000; // 10분

// 기존 이메일 발송 함수 (서버 시작 시)
async function sendEmail() {
  try {
    console.log("📧 이메일 발송 중...");

    const mailOptions = {
      from: "hoitchac@gmail.com",
      to: "c9926@naver.com",
      subject: "서버 시작 알림",
      text: "서버가 시작되었습니다! 🚀",
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("✅ 이메일 발송 완료! ID:", info.messageId);
  } catch (error) {
    console.error("❌ 이메일 발송 실패:", error.message);
  }
}

// ============================================
// RESTful 이메일 인증 API
// ============================================

// 1. POST /api/emails/send-code - 이메일 인증번호 발송
app.post("/api/emails/send-code", async (req, res) => {
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

    // 인증번호 생성
    const code = generateVerificationCode();
    const expiresAt = Date.now() + EXPIRATION_TIME;

    // 인증번호 저장 (이메일을 키로 사용)
    verificationCodes.set(email, {
      code,
      expiresAt,
      attempts: 0, // 시도 횟수
      maxAttempts: 5,
    });

    console.log(`📧 인증번호 생성: ${code} (발송 대상: ${email})`);

    // 이메일 발송
    const mailOptions = {
      from: "hoitchac@gmail.com",
      to: email,
      subject: "이메일 인증번호",
      text: `안녕하세요!\n\n인증번호는 ${code} 입니다.\n\n유효 시간: 10분\n\n이 메일은 자동 발송된 메일입니다.`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2 style="color: #333;">이메일 인증번호</h2>
          <p>안녕하세요!</p>
          <p>인증번호는 아래와 같습니다:</p>
          <div style="background: #f4f4f4; padding: 15px; margin: 20px 0; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px;">
            ${code}
          </div>
          <p style="color: #666; font-size: 14px;">유효 시간: 10분</p>
          <p style="color: #999; font-size: 12px;">이 메일은 자동 발송된 메일입니다.</p>
        </div>
      `,
    };

    const info = await transporter.sendMail(mailOptions);

    // 성공 응답
    res.status(200).json({
      success: true,
      message: "인증번호가 이메일로 발송되었습니다.",
      data: {
        email,
        expiresIn: "10분",
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

// 2. POST /api/emails/verify - 인증번호 검증
app.post("/api/emails/verify", async (req, res) => {
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

    // 인증번호 증가
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

// 3. GET /api/emails/status - 인증 상태 확인 (선택사항)
app.get("/api/emails/status", (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({
      success: false,
      error: "이메일 주소를 입력해주세요.",
    });
  }

  const stored = verificationCodes.get(email);

  if (!stored) {
    return res.json({
      success: true,
      data: {
        status: "not_sent",
        message: "인증번호가 발송되지 않았습니다.",
      },
    });
  }

  const remainingTime = Math.max(0, stored.expiresAt - Date.now());
  const minutes = Math.floor(remainingTime / 60000);
  const seconds = Math.floor((remainingTime % 60000) / 1000);

  res.json({
    success: true,
    data: {
      status: "pending",
      email,
      remainingTime: `${minutes}분 ${seconds}초`,
      attempts: stored.attempts,
      maxAttempts: stored.maxAttempts,
    },
  });
});

// ============================================
// 기존 엔드포인트들
// ============================================

app.get("/", (req, res) => {
  res.send("🚀 Express server is running!");
});

app.get("/api/hello", (req, res) => {
  res.json({ message: "Hello from Express API!" });
});

app.listen(PORT, () => {
  console.log(`✅ Server is running on http://localhost:${PORT}`);
  sendEmail();
});
