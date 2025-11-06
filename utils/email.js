const nodemailer = require("nodemailer");

// 이메일 발송을 위한 transporter 설정
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// 인증번호 저장소 (실제 운영 환경에서는 Redis 등을 사용)
const verificationCodes = new Map();
const verifiedEmails = new Set();

// 인증번호 생성 함수 (6자리 랜덤 숫자)
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 만료 시간 10분
const EXPIRATION_TIME = 10 * 60 * 1000;

module.exports = {
  transporter,
  verificationCodes,
  verifiedEmails,
  generateVerificationCode,
  EXPIRATION_TIME,
};
