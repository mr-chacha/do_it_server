const express = require("express");
const {
  transporter,
  verificationCodes,
  verifiedEmails,
  generateVerificationCode,
  EXPIRATION_TIME,
} = require("../utils/email");
const { db } = require("../firebase/firebase");

const router = express.Router();

// 1.이메일 인증번호 발송
router.post("/", async (req, res) => {
  try {
    const { email } = req.body;

    // 입력값 검증
    if (!email) {
      return res.status(400).json({
        status: 400,
        error: "이메일 주소를 입력해주세요.",
        data: {
          field: "email",
          empty: true,
        },
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        status: 400,
        error: "올바른 이메일 형식이 아닙니다.",
        data: {
          field: "email",
          invalidFormat: true,
        },
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    // ============================================
    // 데이터베이스에서 이미 등록된 이메일인지 확인
    // ============================================
    const usersRef = db.collection("users");
    const userSnapshot = await usersRef
      .where("email", "==", normalizedEmail)
      .limit(1)
      .get();

    if (!userSnapshot.empty) {
      return res.status(400).json({
        status: 400,
        error: "이미 등록된 유저입니다.",
        data: {
          field: "email",
          alreadyRegistered: true,
        },
      });
    }

    // 기존 인증번호 확인
    const existing = verificationCodes.get(normalizedEmail);
    const isResend = !!existing; // 재발송 여부 확인

    // 인증번호 생성
    const code = generateVerificationCode();
    const expiresAt = Date.now() + EXPIRATION_TIME;

    // 인증번호 저장
    verificationCodes.set(normalizedEmail, {
      code,
      expiresAt,
      attempts: 0,
      maxAttempts: 5,
    });

    console.log(
      `📧 인증번호 ${
        isResend ? "재발송" : "발송"
      }: ${code} (대상: ${normalizedEmail})`
    );

    // 이메일 발송
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: normalizedEmail,
      subject: isResend ? "[재발송] 이메일 인증번호" : "이메일 인증번호",
      text: `안녕하세요!\n\n인증번호${
        isResend ? "가 재발송되었습니다" : "는"
      } ${code} 입니다.\n\n유효 시간: 10분`,
      html: `
        <div style="font-family: Arial, sans-serif; padding: 20px;">
          <h2 style="color: #333;">
            이메일 인증번호 ${isResend ? "재발송" : ""}
          </h2>
          <p>안녕하세요!</p>
          <p>인증번호${
            isResend ? "가 재발송되었습니다. 새로운 " : "는 아래와 같습니다"
          }:</p>
          <div style="background: #f4f4f4; padding: 15px; margin: 20px 0; font-size: 24px; font-weight: bold; text-align: center; letter-spacing: 5px;">
            ${code}
          </div>
          <p style="color: #666; font-size: 14px;">유효 시간: 10분</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    // 성공 응답
    res.status(isResend ? 200 : 201).json({
      status: isResend ? 200 : 201,
      message: `인증번호가 ${isResend ? "재" : ""}발송되었습니다.`,
      data: {
        email: normalizedEmail,
        expiresIn: "10분",
        isResend,
        sentAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("인증번호 발송 실패:", error);
    res.status(500).json({
      status: 500,
      error: "인증번호 발송 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 2. 이메일로 발송된 인증번호 확인
router.post("/validation", async (req, res) => {
  try {
    const { email, code } = req.body;

    // 입력값 검증
    if (!email || !code) {
      return res.status(400).json({
        status: 400,
        error: "이메일과 인증번호를 모두 입력해주세요.",
        data: {
          missingFields: [!email && "email", !code && "code"].filter(Boolean),
        },
      });
    }

    const stored = verificationCodes.get(email.toLowerCase().trim());

    if (!stored) {
      return res.status(400).json({
        status: 400,
        error: "인증번호가 발송되지 않았거나 만료되었습니다.",
        data: {
          field: "code",
          notFound: true,
          expired: true,
        },
      });
    }

    // 만료 시간 확인
    if (Date.now() > stored.expiresAt) {
      verificationCodes.delete(email.toLowerCase().trim());
      return res.status(400).json({
        status: 400,
        error: "인증번호가 만료되었습니다. 다시 발송해주세요.",
        data: {
          field: "code",
          expired: true,
          expiredAt: new Date(stored.expiresAt).toISOString(),
        },
      });
    }

    if (stored.attempts >= stored.maxAttempts) {
      verificationCodes.delete(email.toLowerCase().trim());
      return res.status(400).json({
        status: 400,
        error: "인증번호 입력 시도 횟수를 초과했습니다. 다시 발송해주세요.",
        data: {
          field: "code",
          maxAttemptsExceeded: true,
          maxAttempts: stored.maxAttempts,
        },
      });
    }

    // 시도 횟수 증가
    stored.attempts += 1;

    // 인증번호 검증
    if (stored.code !== code) {
      return res.status(400).json({
        status: 400,
        error: "인증번호가 올바르지 않습니다.",
        data: {
          field: "code",
          invalid: true,
          remainingAttempts: stored.maxAttempts - stored.attempts,
        },
      });
    }

    // 인증 성공
    verificationCodes.delete(email.toLowerCase().trim());
    verifiedEmails.add(email.toLowerCase().trim());

    console.log(`✅ 인증 성공: ${email}`);

    res.status(200).json({
      status: 200,
      message: "이메일 인증이 완료되었습니다.",
      data: {
        email: email.toLowerCase().trim(),
        verified: true,
        verifiedAt: new Date().toISOString(),
        canSignup: true,
      },
    });
  } catch (error) {
    console.error("인증번호 검증 실패:", error);
    res.status(500).json({
      status: 500,
      error: "인증번호 검증 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

module.exports = router;
