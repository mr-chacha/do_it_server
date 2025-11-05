const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { db, admin, bucket } = require("./firebase/firebase");

const app = express();
const PORT = process.env.PORT || 4000;
require("dotenv").config();

// JWT 시크릿 키 (환경변수로 관리 권장)
const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-this-in-production";

// CORS 설정
app.use(
  cors({
    origin: true, // 모든 origin 허용 (개발 환경용)
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// JSON 파싱을 위한 미들웨어 (이미지 업로드를 위해 크기 제한 증가)
app.use(express.json({ limit: "10mb" })); // 기본 100kb에서 10MB로 증가
app.use(express.urlencoded({ extended: true, limit: "10mb" })); // URL 인코딩도 증가

// JWT 미들웨어 (인증 확인)
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

// 이메일 인증 완료 여부 저장소
const verifiedEmails = new Set();

// 회원가입 API
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    // ============================================
    // 1. 최소 검증 (프론트에서 처리하지만 기본 검증)
    // ============================================
    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({
        status: 400,
        error: "모든 필드를 입력해주세요.",
        data: {
          missingFields: [
            !name && "name",
            !email && "email",
            !password && "password",
            !confirmPassword && "confirmPassword",
          ].filter(Boolean),
        },
      });
    }

    // 이메일 인증 여부 확인
    if (!verifiedEmails.has(email.toLowerCase().trim())) {
      return res.status(400).json({
        status: 400,
        error: "이메일 인증을 완료해주세요.",
        data: {
          field: "email",
          verified: false,
        },
      });
    }

    // ============================================
    // 2. Firestore users 컬렉션에서 이메일 중복 확인
    // ============================================
    const usersRef = db.collection("users");
    const userSnapshot = await usersRef
      .where("email", "==", email.toLowerCase().trim())
      .limit(1)
      .get();

    //  Firestore에서 확인
    if (!userSnapshot.empty) {
      return res.status(400).json({
        status: 400,
        error: "이미 가입된 이메일입니다.",
        data: {
          field: "email",
          duplicate: true,
        },
      });
    }

    // ============================================
    // 3. 사용자 데이터 생성 및 Firestore에 저장
    // ============================================
    const userId = usersRef.doc().id; // Firestore 자동 ID 생성
    const userData = {
      id: userId,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: password, // ⚠️ 실제로는 bcrypt로 해시화 필요
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      verified: true,
      coupleId: null,
      partnerEmail: null,
    };

    // Firestore에 저장
    await usersRef.doc(userId).set(userData);

    // 인증 완료된 이메일에서 제거
    verifiedEmails.delete(email.toLowerCase().trim());

    // ============================================
    // 4. JWT 토큰 발급
    // ============================================
    const token = jwt.sign(
      {
        userId: userId,
        email: userData.email,
        name: userData.name,
      },
      JWT_SECRET,
      { expiresIn: "7d" } // 7일 유효
    );

    console.log(`✅ 회원가입 성공: ${email} (${name})`);

    // ============================================
    // 5. 성공 응답 (200)
    // ============================================
    res.status(200).json({
      status: 200,
      message: "회원가입이 완료되었습니다.",
      data: {
        user: {
          id: userData.id,
          name: userData.name,
          email: userData.email,
        },
        token: token, // ⭐ JWT 토큰 반환
      },
    });
  } catch (error) {
    console.error("회원가입 실패:", error);
    res.status(500).json({
      status: 500,
      error: "회원가입 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 로그인 API
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // ============================================
    // 1. 입력값 검증 (400 에러)
    // ============================================
    if (!email || !password) {
      return res.status(400).json({
        status: 400,
        error: "이메일과 비밀번호를 입력해주세요.",
        data: {
          missingFields: [!email && "email", !password && "password"].filter(
            Boolean
          ),
        },
      });
    }

    // ============================================
    // 2. Firestore users 컬렉션에서 사용자 조회
    // ============================================
    const usersRef = db.collection("users");
    const userSnapshot = await usersRef
      .where("email", "==", email.toLowerCase().trim())
      .limit(1)
      .get();

    // 사용자가 없음 (404 또는 400)
    if (userSnapshot.empty) {
      return res.status(400).json({
        status: 400,
        error: "이메일 또는 비밀번호가 올바르지 않습니다.",
        data: {
          field: "credentials",
          invalid: true,
        },
      });
    }

    // 사용자 데이터 가져오기
    const userDoc = userSnapshot.docs[0];
    const userData = userDoc.data();

    // ============================================
    // 3. 비밀번호 확인 (실제로는 bcrypt.compare 사용)
    // ============================================
    if (userData.password !== password) {
      return res.status(400).json({
        status: 400,
        error: "이메일 또는 비밀번호가 올바르지 않습니다.",
        data: {
          field: "credentials",
          invalid: true,
        },
      });
    }

    // ============================================
    // 4. JWT 토큰 발급
    // ============================================
    const token = jwt.sign(
      {
        userId: userData.id,
        email: userData.email,
        name: userData.name,
      },
      JWT_SECRET,
      { expiresIn: "7d" } // 7일 유효
    );

    console.log(`✅ 로그인 성공: ${email}`);

    // ============================================
    // 5. 성공 응답 (200)
    // ============================================
    res.status(200).json({
      status: 200,
      message: "로그인 성공",
      data: {
        user: {
          id: userData.id,
          name: userData.name,
          email: userData.email,
          coupleId: userData.coupleId,
          partnerEmail: userData.partnerEmail,
        },
        token: token, // ⭐ JWT 토큰 반환
      },
    });
  } catch (error) {
    console.error("로그인 실패:", error);
    res.status(500).json({
      status: 500,
      error: "로그인 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 로그아웃 API
app.post("/api/logout", async (req, res) => {});

// 상대방 연결 API (인증 필요)
app.post("/api/connect", authenticateToken, async (req, res) => {
  try {
    // 로그인한 사용자 정보 (JWT에서 추출)
    const { email: senderEmail, userId: senderUserId } = req.user;

    // 요청 본문에서 상대방 이메일 받기
    const { partnerEmail } = req.body;

    // ============================================
    // 1. 입력값 검증 (400 에러)
    // ============================================
    if (!partnerEmail) {
      return res.status(400).json({
        status: 400,
        error: "상대방 이메일을 입력해주세요.",
        data: {
          field: "partnerEmail",
          empty: true,
        },
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(partnerEmail)) {
      return res.status(400).json({
        status: 400,
        error: "올바른 이메일 형식이 아닙니다.",
        data: {
          field: "partnerEmail",
          invalidFormat: true,
        },
      });
    }

    const normalizedPartnerEmail = partnerEmail.toLowerCase().trim();
    const normalizedSenderEmail = senderEmail.toLowerCase().trim();

    // 자기 자신에게 연결 시도 방지
    if (normalizedSenderEmail === normalizedPartnerEmail) {
      return res.status(400).json({
        status: 400,
        error: "자기 자신에게 연결할 수 없습니다.",
        data: {
          field: "partnerEmail",
          sameEmail: true,
        },
      });
    }

    // ============================================
    // 2. 상대방 이메일이 DB에 있는지 확인
    // ============================================
    const usersRef = db.collection("users");
    const partnerSnapshot = await usersRef
      .where("email", "==", normalizedPartnerEmail)
      .limit(1)
      .get();

    if (partnerSnapshot.empty) {
      return res.status(400).json({
        status: 400,
        error: "등록된 이메일이 없습니다.",
        data: {
          field: "partnerEmail",
          notFound: true,
        },
      });
    }

    // 발신자가 이미 연결되어 있는지 확인
    const senderDoc = await usersRef.doc(senderUserId).get();
    if (!senderDoc.exists) {
      return res.status(400).json({
        status: 400,
        error: "발신자 정보를 찾을 수 없습니다.",
        data: {
          notFound: true,
        },
      });
    }

    const senderData = senderDoc.data();
    if (senderData.partnerEmail) {
      return res.status(400).json({
        status: 400,
        error: "이미 연결된 상대방이 있습니다.",
        data: {
          alreadyConnected: true,
        },
      });
    }

    // 수신자가 이미 연결되어 있는지 확인
    const partnerData = partnerSnapshot.docs[0].data();
    if (partnerData.partnerEmail) {
      return res.status(400).json({
        status: 400,
        error: "상대방이 이미 다른 사용자와 연결되어 있습니다.",
        data: {
          partnerAlreadyConnected: true,
        },
      });
    }

    // ============================================
    // 3. 초대 토큰 생성 및 저장
    // ============================================
    const invitationToken = jwt.sign(
      {
        senderEmail: normalizedSenderEmail,
        senderUserId,
        receiverEmail: normalizedPartnerEmail,
        receiverUserId: partnerSnapshot.docs[0].id,
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    // invitations 컬렉션에 초대 정보 저장
    const invitationsRef = db.collection("invitations");
    await invitationsRef.doc(invitationToken).set({
      senderEmail: normalizedSenderEmail,
      senderUserId,
      receiverEmail: normalizedPartnerEmail,
      receiverUserId: partnerSnapshot.docs[0].id,
      status: "pending", // pending, accepted, rejected, expired
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromDate(
        new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      ), // 7일
    });

    // ============================================
    // 4. 초대장 이메일 발송
    // ============================================
    const acceptUrl = `http://localhost:3000/connect/accept?token=${invitationToken}`;

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: normalizedPartnerEmail,
      subject: "💕 커플 연결 초대장",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2563eb;">커플 연결 초대장</h2>
          <p>안녕하세요! <strong>${
            senderData.name || normalizedSenderEmail
          }</strong>님께서 커플 연결을 요청하셨습니다.</p>
          <p>아래 버튼을 클릭하여 연결을 수락해주세요.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${acceptUrl}" 
               style="display: inline-block; background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
              연결 수락하기
            </a>
          </div>
          <p style="color: #666; font-size: 12px;">이 링크는 7일간 유효합니다.</p>
          <p style="color: #666; font-size: 12px;">만약 본인이 요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    console.log(
      `✅ 초대장 발송: ${normalizedSenderEmail} -> ${normalizedPartnerEmail}`
    );

    // ============================================
    // 5. 성공 응답 (200)
    // ============================================
    res.status(200).json({
      status: 200,
      message: "초대장이 발송되었습니다.",
      data: {
        partnerEmail: normalizedPartnerEmail,
        sentAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("초대장 발송 실패:", error);
    res.status(500).json({
      status: 500,
      error: "초대장 발송 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 초대장 정보 조회 API (인증 불필요, 토큰으로 확인)
app.get("/api/connect/accept/info", async (req, res) => {
  try {
    const { token } = req.query;

    // ============================================
    // 1. 토큰 검증
    // ============================================
    if (!token) {
      return res.status(400).json({
        status: 400,
        error: "초대 토큰이 필요합니다.",
        data: {
          missingToken: true,
        },
      });
    }

    // invitations 컬렉션에서 초대 정보 조회
    const invitationsRef = db.collection("invitations");
    const invitationDoc = await invitationsRef.doc(token).get();

    if (!invitationDoc.exists) {
      return res.status(400).json({
        status: 400,
        error: "유효하지 않은 초대장입니다.",
        data: {
          invalidToken: true,
        },
      });
    }

    const invitationData = invitationDoc.data();

    // 이미 처리된 초대장인지 확인
    if (invitationData.status !== "pending") {
      return res.status(400).json({
        status: 400,
        error:
          invitationData.status === "accepted"
            ? "이미 수락된 초대장입니다."
            : "유효하지 않은 초대장입니다.",
        data: {
          status: invitationData.status,
        },
      });
    }

    // 만료 확인
    if (
      invitationData.expiresAt &&
      invitationData.expiresAt.toDate() < new Date()
    ) {
      await invitationsRef.doc(token).update({
        status: "expired",
      });
      return res.status(400).json({
        status: 400,
        error: "만료된 초대장입니다.",
        data: {
          expired: true,
        },
      });
    }

    // ============================================
    // 2. 발신자 정보 조회
    // ============================================
    const usersRef = db.collection("users");
    const senderDoc = await usersRef.doc(invitationData.senderUserId).get();

    if (!senderDoc.exists) {
      return res.status(400).json({
        status: 400,
        error: "발신자 정보를 찾을 수 없습니다.",
        data: {
          userNotFound: true,
        },
      });
    }

    const senderData = senderDoc.data();

    // 성공 응답 (발신자 정보 반환)
    res.status(200).json({
      status: 200,
      message: "초대장 정보 조회 성공",
      data: {
        senderName: senderData.name || invitationData.senderEmail,
        senderEmail: invitationData.senderEmail,
        token: token,
      },
    });
  } catch (error) {
    console.error("초대장 정보 조회 실패:", error);
    res.status(500).json({
      status: 500,
      error: "초대장 정보 조회 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
      },
    });
  }
});

// 초대장 수락 API (인증 불필요, 토큰으로 인증)
app.post("/api/connect/accept", async (req, res) => {
  try {
    const { token } = req.body;

    // ============================================
    // 1. 토큰 검증
    // ============================================
    if (!token) {
      return res.status(400).json({
        status: 400,
        error: "초대 토큰이 필요합니다.",
        data: {
          missingToken: true,
        },
      });
    }

    // invitations 컬렉션에서 초대 정보 조회
    const invitationsRef = db.collection("invitations");
    const invitationDoc = await invitationsRef.doc(token).get();

    if (!invitationDoc.exists) {
      return res.status(400).json({
        status: 400,
        error: "유효하지 않은 초대장입니다.",
        data: {
          invalidToken: true,
        },
      });
    }

    const invitationData = invitationDoc.data();

    // 이미 처리된 초대장인지 확인
    if (invitationData.status !== "pending") {
      return res.status(400).json({
        status: 400,
        error:
          invitationData.status === "accepted"
            ? "이미 수락된 초대장입니다."
            : "유효하지 않은 초대장입니다.",
        data: {
          status: invitationData.status,
        },
      });
    }

    // 만료 확인
    if (
      invitationData.expiresAt &&
      invitationData.expiresAt.toDate() < new Date()
    ) {
      await invitationsRef.doc(token).update({
        status: "expired",
      });
      return res.status(400).json({
        status: 400,
        error: "만료된 초대장입니다.",
        data: {
          expired: true,
        },
      });
    }

    // ============================================
    // 2. 두 사용자 연결 처리
    // ============================================
    const usersRef = db.collection("users");
    const senderDoc = await usersRef.doc(invitationData.senderUserId).get();
    const receiverDoc = await usersRef.doc(invitationData.receiverUserId).get();

    if (!senderDoc.exists || !receiverDoc.exists) {
      return res.status(400).json({
        status: 400,
        error: "사용자 정보를 찾을 수 없습니다.",
        data: {
          userNotFound: true,
        },
      });
    }

    const senderData = senderDoc.data();
    const receiverData = receiverDoc.data();

    // 이미 연결되어 있는지 확인
    if (senderData.partnerEmail || receiverData.partnerEmail) {
      return res.status(400).json({
        status: 400,
        error: "이미 연결된 상태입니다.",
        data: {
          alreadyConnected: true,
        },
      });
    }

    // coupleId 생성 (발신자의 ID를 coupleId로 사용)
    const coupleId = invitationData.senderUserId;

    // Firestore batch write로 두 사용자 동시 업데이트
    const batch = db.batch();

    // 발신자 업데이트
    batch.update(usersRef.doc(invitationData.senderUserId), {
      coupleId,
      partnerEmail: invitationData.receiverEmail,
      partnerName: receiverData.name || null, // 파트너 이름 추가
      partnerNickname: receiverData.nickname || null, // 파트너 닉네임 추가
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // 수신자 업데이트
    batch.update(usersRef.doc(invitationData.receiverUserId), {
      coupleId,
      partnerEmail: invitationData.senderEmail,
      partnerName: senderData.name || null, // 파트너 이름 추가
      partnerNickname: senderData.nickname || null, // 파트너 닉네임 추가
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // 초대장 상태를 'accepted'로 변경
    batch.update(invitationsRef.doc(token), {
      status: "accepted",
      acceptedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await batch.commit();

    console.log(
      `✅ 커플 연결 완료: ${invitationData.senderEmail} <-> ${invitationData.receiverEmail}`
    );

    // ============================================
    // 3. 성공 응답 (200)
    // ============================================
    res.status(200).json({
      status: 200,
      message: "커플 연결이 완료되었습니다.",
      data: {
        partnerEmail: invitationData.senderEmail,
        partnerName: senderData.name || invitationData.senderEmail,
        partnerNickname: senderData.nickname || null,
      },
    });
  } catch (error) {
    console.error("초대장 수락 실패:", error);
    res.status(500).json({
      status: 500,
      error: "초대장 수락 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 초대장 재발송 API (인증 필요)
app.post("/api/connect/resend", authenticateToken, async (req, res) => {
  try {
    const { email: senderEmail, userId: senderUserId } = req.user;

    // 기존 pending 상태의 초대장 찾기
    const invitationsRef = db.collection("invitations");
    const existingInvitations = await invitationsRef
      .where("senderUserId", "==", senderUserId)
      .where("status", "==", "pending")
      .orderBy("createdAt", "desc")
      .limit(1)
      .get();

    if (existingInvitations.empty) {
      return res.status(400).json({
        status: 400,
        error: "재발송할 초대장이 없습니다.",
        data: {
          noInvitation: true,
        },
      });
    }

    const invitationDoc = existingInvitations.docs[0];
    const invitationData = invitationDoc.data();

    // 만료 확인
    if (
      invitationData.expiresAt &&
      invitationData.expiresAt.toDate() < new Date()
    ) {
      return res.status(400).json({
        status: 400,
        error: "만료된 초대장입니다. 새로운 초대장을 발송해주세요.",
        data: {
          expired: true,
        },
      });
    }

    // 초대장 이메일 재발송
    const acceptUrl = `http://localhost:3001/connect/accept?token=${invitationDoc.id}`;

    const senderDoc = await db.collection("users").doc(senderUserId).get();
    const senderData = senderDoc.data();

    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: invitationData.receiverEmail,
      subject: "💕 커플 연결 초대장 (재발송)",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2563eb;">커플 연결 초대장 (재발송)</h2>
          <p>안녕하세요! <strong>${
            senderData.name || senderEmail
          }</strong>님께서 커플 연결을 요청하셨습니다.</p>
          <p>아래 버튼을 클릭하여 연결을 수락해주세요.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${acceptUrl}" 
               style="display: inline-block; background-color: #2563eb; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
              연결 수락하기
            </a>
          </div>
          <p style="color: #666; font-size: 12px;">이 링크는 7일간 유효합니다.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);

    console.log(
      `✅ 초대장 재발송: ${senderEmail} -> ${invitationData.receiverEmail}`
    );

    res.status(200).json({
      status: 200,
      message: "초대장이 재발송되었습니다.",
      data: {
        partnerEmail: invitationData.receiverEmail,
        sentAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("초대장 재발송 실패:", error);
    res.status(500).json({
      status: 500,
      error: "초대장 재발송 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
      },
    });
  }
});

// 상대방 연결 확인 API
app.post("/api/connect/check", async (req, res) => {});

// 상대방 연결 취소 API
app.post("/api/connect/cancel", async (req, res) => {});

//  이메일 인증 API
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

// 인증번호 생성 함수 (6자리 랜덤 숫자)
function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 만료 시간 10분
const EXPIRATION_TIME = 10 * 60 * 1000;

// 1.이메일 인증번호 발송
app.post("/api/verifications", async (req, res) => {
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
app.post("/api/verifications/validation", async (req, res) => {
  try {
    const { email, code } = req.body;

    // 입력값 검증
    if (!email || !code) {
      return res.status(400).json({
        status: 400, // ⭐
        error: "이메일과 인증번호를 모두 입력해주세요.",
        data: {
          missingFields: [!email && "email", !code && "code"].filter(Boolean),
        },
      });
    }

    const stored = verificationCodes.get(email.toLowerCase().trim());

    if (!stored) {
      return res.status(400).json({
        status: 400, // ⭐
        error: "인증번호가 발송되지 않았거나 만료되었습니다.",
        data: {
          field: "code",
          notFound: true,
          expired: true,
        },
      });
    }

    // 만료 시간 확인
    if (!stored) {
      return res.status(400).json({
        status: 400, // ⭐
        error: "인증번호가 발송되지 않았거나 만료되었습니다.",
        data: {
          field: "code",
          notFound: true,
          expired: true,
        },
      });
    }

    if (Date.now() > stored.expiresAt) {
      verificationCodes.delete(email.toLowerCase().trim());
      return res.status(400).json({
        status: 400, // ⭐
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
        status: 400, // ⭐
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
        status: 400, // ⭐
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
      status: 200, // ⭐
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
      status: 500, // ⭐
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

// 가계부 거래 등록 API (인증 필요)
app.post("/api/finance/transactions", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { type, title, amount, category, description, date } = req.body;

    // 입력값 검증
    if (!type || !title || !amount || !category) {
      return res.status(400).json({
        status: 400,
        error: "필수 필드를 입력해주세요.",
        data: {
          missingFields: [
            !type && "type",
            !title && "title",
            !amount && "amount",
            !category && "category",
          ].filter(Boolean),
        },
      });
    }

    // 연결 상태 확인
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        status: 404,
        error: "사용자를 찾을 수 없습니다.",
      });
    }

    const userData = userDoc.data();
    if (!userData.coupleId) {
      return res.status(400).json({
        status: 400,
        error: "커플 연결이 필요합니다.",
      });
    }

    // 거래 데이터 생성
    const transactionData = {
      type: type, // income, expense, savings
      title: title,
      amount: parseInt(amount),
      category: category,
      description: description || "",
      date: date
        ? admin.firestore.Timestamp.fromDate(new Date(date))
        : admin.firestore.FieldValue.serverTimestamp(),
      createdBy: userId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Firestore에 저장
    const transactionsRef = db
      .collection("couples")
      .doc(userData.coupleId)
      .collection("transactions");
    const transactionDoc = await transactionsRef.add(transactionData);

    console.log(`✅ 거래 등록 성공: ${userId}`);

    res.status(201).json({
      status: 201,
      message: "거래가 등록되었습니다.",
      data: {
        transaction: {
          id: transactionDoc.id,
          ...transactionData,
        },
      },
    });
  } catch (error) {
    console.error("거래 등록 실패:", error);
    res.status(500).json({
      status: 500,
      error: "거래 등록 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
      },
    });
  }
});

// 가계부 거래 조회 API (인증 필요)
app.get("/api/finance/transactions", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { year, month, type } = req.query;

    // 연결 상태 확인
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        status: 404,
        error: "사용자를 찾을 수 없습니다.",
      });
    }

    const userData = userDoc.data();
    if (!userData.coupleId) {
      return res.status(400).json({
        status: 400,
        error: "커플 연결이 필요합니다.",
      });
    }

    // 쿼리 구성
    let query = db
      .collection("couples")
      .doc(userData.coupleId)
      .collection("transactions");

    // 날짜 필터링
    if (year && month) {
      const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
      const endDate = new Date(parseInt(year), parseInt(month), 0, 23, 59, 59);

      query = query
        .where("date", ">=", admin.firestore.Timestamp.fromDate(startDate))
        .where("date", "<=", admin.firestore.Timestamp.fromDate(endDate));
    }

    // 타입 필터링
    if (type) {
      query = query.where("type", "==", type);
    }

    // 최신순 정렬 및 조회
    const snapshot = await query.orderBy("date", "desc").get();

    const transactions = [];
    snapshot.forEach((doc) => {
      const data = doc.data();
      transactions.push({
        id: doc.id,
        type: data.type,
        title: data.title,
        amount: data.amount,
        category: data.category,
        description: data.description,
        date: data.date.toDate().toISOString(),
        createdBy: data.createdBy,
        createdAt: data.createdAt?.toDate()?.toISOString(),
        updatedAt: data.updatedAt?.toDate()?.toISOString(),
      });
    });

    res.status(200).json({
      status: 200,
      message: "거래 내역 조회 성공",
      data: {
        transactions,
        count: transactions.length,
      },
    });
  } catch (error) {
    console.error("거래 조회 실패:", error);
    res.status(500).json({
      status: 500,
      error: "거래 조회 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
      },
    });
  }
});

// 가계부 거래 수정 API (인증 필요)
app.put(
  "/api/finance/transactions/:transactionId",
  authenticateToken,
  async (req, res) => {
    try {
      const { userId } = req.user;
      const { transactionId } = req.params;
      const { type, title, amount, category, description, date } = req.body;

      // 입력값 검증
      if (!type || !title || !amount || !category) {
        return res.status(400).json({
          status: 400,
          error: "필수 필드를 입력해주세요.",
          data: {
            missingFields: [
              !type && "type",
              !title && "title",
              !amount && "amount",
              !category && "category",
            ].filter(Boolean),
          },
        });
      }

      // 연결 상태 확인
      const userDoc = await db.collection("users").doc(userId).get();
      if (!userDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "사용자를 찾을 수 없습니다.",
        });
      }

      const userData = userDoc.data();
      if (!userData.coupleId) {
        return res.status(400).json({
          status: 400,
          error: "커플 연결이 필요합니다.",
        });
      }

      // 거래 존재 및 권한 확인
      const transactionRef = db
        .collection("couples")
        .doc(userData.coupleId)
        .collection("transactions")
        .doc(transactionId);

      const transactionDoc = await transactionRef.get();

      if (!transactionDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "거래를 찾을 수 없습니다.",
          data: {
            transactionId,
          },
        });
      }

      const transactionData = transactionDoc.data();

      // 본인이 작성한 거래만 수정 가능
      if (transactionData.createdBy !== userId) {
        return res.status(403).json({
          status: 403,
          error: "본인이 작성한 거래만 수정할 수 있습니다.",
          data: {
            transactionId,
            createdBy: transactionData.createdBy,
          },
        });
      }

      // 수정 데이터 구성
      const updateData = {
        type: type,
        title: title,
        amount: parseInt(amount),
        category: category,
        description: description || "",
        date: date
          ? admin.firestore.Timestamp.fromDate(new Date(date))
          : transactionData.date, // 날짜 미입력 시 기존 날짜 유지
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      // Firestore에 업데이트
      await transactionRef.update(updateData);

      console.log(`✅ 거래 수정 성공: ${userId} - ${transactionId}`);

      res.status(200).json({
        status: 200,
        message: "거래가 수정되었습니다.",
        data: {
          transaction: {
            id: transactionId,
            ...updateData,
            createdBy: transactionData.createdBy,
            createdAt: transactionData.createdAt?.toDate()?.toISOString(),
          },
        },
      });
    } catch (error) {
      console.error("거래 수정 실패:", error);
      res.status(500).json({
        status: 500,
        error: "거래 수정 중 오류가 발생했습니다.",
        data: {
          timestamp: new Date().toISOString(),
          code: error.code || "UNKNOWN_ERROR",
          details:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        },
      });
    }
  }
);

// 가계부 거래 삭제 API (인증 필요)
app.delete(
  "/api/finance/transactions/:transactionId",
  authenticateToken,
  async (req, res) => {
    try {
      const { userId } = req.user;
      const { transactionId } = req.params;

      // 연결 상태 확인
      const userDoc = await db.collection("users").doc(userId).get();
      if (!userDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "사용자를 찾을 수 없습니다.",
        });
      }

      const userData = userDoc.data();
      if (!userData.coupleId) {
        return res.status(400).json({
          status: 400,
          error: "커플 연결이 필요합니다.",
        });
      }

      // 거래 존재 및 권한 확인
      const transactionRef = db
        .collection("couples")
        .doc(userData.coupleId)
        .collection("transactions")
        .doc(transactionId);

      const transactionDoc = await transactionRef.get();

      if (!transactionDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "거래를 찾을 수 없습니다.",
          data: {
            transactionId,
          },
        });
      }

      const transactionData = transactionDoc.data();

      // 본인이 작성한 거래만 삭제 가능
      if (transactionData.createdBy !== userId) {
        return res.status(403).json({
          status: 403,
          error: "본인이 작성한 거래만 삭제할 수 있습니다.",
          data: {
            transactionId,
            createdBy: transactionData.createdBy,
          },
        });
      }

      // Firestore에서 삭제
      await transactionRef.delete();

      console.log(`✅ 거래 삭제 성공: ${userId} - ${transactionId}`);

      res.status(200).json({
        status: 200,
        message: "거래가 삭제되었습니다.",
        data: {
          transactionId,
          deletedAt: new Date().toISOString(),
        },
      });
    } catch (error) {
      console.error("거래 삭제 실패:", error);
      res.status(500).json({
        status: 500,
        error: "거래 삭제 중 오류가 발생했습니다.",
        data: {
          timestamp: new Date().toISOString(),
          code: error.code || "UNKNOWN_ERROR",
          details:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        },
      });
    }
  }
);

// 일정 등록 API (인증 필요)
app.post("/api/schedule/events", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const {
      title,
      description,
      startDate,
      endDate,
      author,
      repeatType,
      repeatEndDate,
    } = req.body;

    // 입력값 검증
    if (!title || !startDate || !endDate) {
      return res.status(400).json({
        status: 400,
        error: "필수 필드를 입력해주세요.",
        data: {
          missingFields: [
            !title && "title",
            !startDate && "startDate",
            !endDate && "endDate",
          ].filter(Boolean),
        },
      });
    }

    // 연결 상태 확인
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        status: 404,
        error: "사용자를 찾을 수 없습니다.",
      });
    }

    const userData = userDoc.data();
    if (!userData.coupleId) {
      return res.status(400).json({
        status: 400,
        error: "커플 연결이 필요합니다.",
      });
    }

    // 일정 등록 API에서도 상대방 찾기 수정
    let authorId = null;
    if (author === "me") {
      authorId = userId; // 로그인한 사용자의 userId
    } else if (author === "partner") {
      // ⭐ 상대방의 userId 찾기 (인덱스 없이 작동)
      const allUsersSnapshot = await db
        .collection("users")
        .where("coupleId", "==", userData.coupleId)
        .get();

      // 현재 사용자가 아닌 사용자 찾기
      let foundPartnerId = null;
      allUsersSnapshot.forEach((doc) => {
        if (doc.id !== userId) {
          foundPartnerId = doc.id;
        }
      });

      if (!foundPartnerId) {
        return res.status(400).json({
          status: 400,
          error: "상대방 정보를 찾을 수 없습니다.",
        });
      }
      authorId = foundPartnerId;
    } else if (author === "us") {
      authorId = userData.coupleId; // coupleId 사용
    } else {
      return res.status(400).json({
        status: 400,
        error: "유효하지 않은 작성자입니다.",
      });
    }

    // 일정 데이터 생성
    const eventData = {
      title: title.trim(),
      description: description || "",
      startDate: admin.firestore.Timestamp.fromDate(new Date(startDate)),
      endDate: admin.firestore.Timestamp.fromDate(new Date(endDate)),
      author: authorId, // ⭐ userId 또는 coupleId로 저장
      authorType: author, // ⭐ 원본 타입 저장 (me, partner, us)
      repeatType: repeatType || "none",
      repeatEndDate: repeatEndDate
        ? admin.firestore.Timestamp.fromDate(new Date(repeatEndDate))
        : null,
      createdBy: userId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // Firestore에 저장
    const eventsRef = db
      .collection("couples")
      .doc(userData.coupleId)
      .collection("events");
    const eventDoc = await eventsRef.add(eventData);

    console.log(`✅ 일정 등록 성공: ${userId} - ${eventDoc.id}`);

    res.status(201).json({
      status: 201,
      message: "일정이 등록되었습니다.",
      data: {
        event: {
          id: eventDoc.id,
          ...eventData,
          startDate: eventData.startDate.toDate().toISOString(),
          endDate: eventData.endDate.toDate().toISOString(),
          repeatEndDate:
            eventData.repeatEndDate?.toDate()?.toISOString() || null,
        },
      },
    });
  } catch (error) {
    console.error("일정 등록 실패:", error);
    res.status(500).json({
      status: 500,
      error: "일정 등록 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 일정 조회 API (인증 필요)
app.get("/api/schedule/events", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { year, month, startDate, endDate } = req.query;

    // 연결 상태 확인
    const userDoc = await db.collection("users").doc(userId).get();
    if (!userDoc.exists) {
      return res.status(404).json({
        status: 404,
        error: "사용자를 찾을 수 없습니다.",
      });
    }

    const userData = userDoc.data();
    if (!userData.coupleId) {
      return res.status(400).json({
        status: 400,
        error: "커플 연결이 필요합니다.",
      });
    }

    // ⭐ 상대방 userId 가져오기 (인덱스 없이 작동하도록 수정)
    const allUsersSnapshot = await db
      .collection("users")
      .where("coupleId", "==", userData.coupleId)
      .get();

    // 현재 사용자가 아닌 사용자 찾기
    let partnerUserId = null;
    allUsersSnapshot.forEach((doc) => {
      if (doc.id !== userId) {
        partnerUserId = doc.id;
      }
    });

    // 필터 날짜 범위 계산 (먼저 계산)
    let filterStartDate, filterEndDate;
    if (year && month) {
      filterStartDate = new Date(parseInt(year), parseInt(month) - 1, 1);
      filterEndDate = new Date(parseInt(year), parseInt(month), 0, 23, 59, 59);
    } else if (startDate && endDate) {
      filterStartDate = new Date(startDate);
      filterEndDate = new Date(endDate);
    } else {
      // 필터가 없으면 현재 달 기준
      const now = new Date();
      filterStartDate = new Date(now.getFullYear(), now.getMonth(), 1);
      filterEndDate = new Date(
        now.getFullYear(),
        now.getMonth() + 1,
        0,
        23,
        59,
        59
      );
    }

    // 쿼리 구성
    let query = db
      .collection("couples")
      .doc(userData.coupleId)
      .collection("events");

    // 반복 일정을 위해 쿼리 범위를 조정
    // 반복 일정이 필터 범위와 겹칠 수 있도록 더 넓은 범위로 조회
    // 하지만 반복 없는 일정은 필터 범위 내에 있는 것만 조회
    if (year && month) {
      // 년월로 필터링
      const startDateFilter = new Date(parseInt(year), parseInt(month) - 1, 1);
      const endDateFilter = new Date(
        parseInt(year),
        parseInt(month),
        0,
        23,
        59,
        59
      );

      // 반복 일정을 위해 시작일이 필터 종료일 이전인 일정도 조회
      // 하지만 반복 없는 일정은 필터 범위 내에 있는 것만 포함됨
      query = query
        .where(
          "startDate",
          "<=",
          admin.firestore.Timestamp.fromDate(endDateFilter)
        )
        .orderBy("startDate", "asc");
    } else if (startDate && endDate) {
      // 시작일/종료일로 필터링
      const startDateFilter = new Date(startDate);
      const endDateFilter = new Date(endDate);

      // 반복 일정을 위해 조회 범위를 더 넓게 설정
      query = query
        .where(
          "startDate",
          "<=",
          admin.firestore.Timestamp.fromDate(endDateFilter)
        )
        .orderBy("startDate", "asc");
    } else {
      // 필터가 없으면 현재 달 기준
      query = query.orderBy("startDate", "asc");
    }

    // 최신순 정렬 및 조회
    const snapshot = await query.get();

    // 반복 일정 확장 함수 (반복 있는 일정만 처리)
    const expandRecurringEvents = (event, filterStartDate, filterEndDate) => {
      const events = [];

      // Date 객체로 안전하게 변환하는 헬퍼 함수
      const toDate = (dateValue) => {
        if (!dateValue) return null;
        // 이미 Date 객체인 경우
        if (dateValue instanceof Date) {
          return dateValue;
        }
        // Firestore Timestamp인 경우
        if (dateValue && typeof dateValue.toDate === "function") {
          return dateValue.toDate();
        }
        // 문자열인 경우
        if (typeof dateValue === "string") {
          return new Date(dateValue);
        }
        // 그 외의 경우
        return new Date(dateValue);
      };

      const originalStartDate = toDate(event.startDate);
      const originalEndDate = toDate(event.endDate);

      // 유효하지 않은 날짜 체크
      if (!originalStartDate || isNaN(originalStartDate.getTime())) {
        console.error("Invalid startDate:", event.startDate);
        return [];
      }
      if (!originalEndDate || isNaN(originalEndDate.getTime())) {
        console.error("Invalid endDate:", event.endDate);
        return [];
      }

      const duration = originalEndDate.getTime() - originalStartDate.getTime(); // 일정 지속 시간

      // 예외 일정 날짜 목록 (삭제된 일정)
      const exceptions = (event.exceptions || [])
        .map((ex) => {
          const exDate = toDate(ex);
          if (!exDate) return null;
          // 날짜만 추출 (시간 정보 제거)
          const dateOnly = new Date(
            exDate.getFullYear(),
            exDate.getMonth(),
            exDate.getDate()
          );
          return {
            year: exDate.getFullYear(),
            month: exDate.getMonth() + 1,
            day: exDate.getDate(),
            timestamp: dateOnly.getTime(), // 비교를 위한 타임스탬프
          };
        })
        .filter(Boolean);

      // 반복 종료일 설정
      const repeatEndDate = event.repeatEndDate
        ? toDate(event.repeatEndDate)
        : new Date(filterEndDate.getTime() + 365 * 24 * 60 * 60 * 1000); // 1년 후

      if (!repeatEndDate || isNaN(repeatEndDate.getTime())) {
        console.error("Invalid repeatEndDate:", event.repeatEndDate);
        return events;
      }

      let currentDate = new Date(originalStartDate);
      let iteration = 0;
      const maxIterations = 1000; // 무한 루프 방지

      while (currentDate <= repeatEndDate && iteration < maxIterations) {
        const currentEndDate = new Date(currentDate.getTime() + duration);

        // 예외 일정인지 확인 (삭제된 일정) - 날짜만 비교
        const currentDateOnly = new Date(
          currentDate.getFullYear(),
          currentDate.getMonth(),
          currentDate.getDate()
        );

        const isException = exceptions.some((ex) => {
          return currentDateOnly.getTime() === ex.timestamp;
        });

        // 예외가 아니고 필터 범위와 겹치는 경우에만 추가
        if (
          !isException &&
          currentEndDate >= filterStartDate &&
          currentDate <= filterEndDate
        ) {
          events.push({
            ...event,
            id: `${event.id}_${iteration}`, // 반복 인스턴스에 고유 ID 부여
            startDate: currentDate.toISOString(),
            endDate: currentEndDate.toISOString(),
            originalEventId: event.id, // 원본 일정 ID
            isRecurring: true,
            recurrenceIndex: iteration,
          });
        }

        // 다음 반복 날짜 계산
        switch (event.repeatType) {
          case "daily":
            currentDate.setDate(currentDate.getDate() + 1);
            break;
          case "weekly":
            currentDate.setDate(currentDate.getDate() + 7);
            break;
          case "monthly":
            currentDate.setMonth(currentDate.getMonth() + 1);
            break;
          case "yearly":
            currentDate.setFullYear(currentDate.getFullYear() + 1);
            break;
          default:
            return events; // 알 수 없는 반복 타입은 중단
        }

        iteration++;
      }

      return events;
    };

    const events = [];
    snapshot.forEach((doc) => {
      const data = doc.data();

      // ⭐ authorType을 우선적으로 사용 (저장된 원본 타입)
      let displayAuthor = "me"; // 기본값

      if (data.authorType) {
        // authorType이 있으면 그것을 사용 (가장 정확)
        displayAuthor = data.authorType;
      } else {
        // authorType이 없으면 기존 로직 사용 (하위 호환성)
        // author가 coupleId인 경우 (우리)
        if (String(data.author) === String(userData.coupleId)) {
          displayAuthor = "us";
        }
        // createdBy가 현재 사용자인 경우 (나)
        else if (String(data.createdBy) === String(userId)) {
          displayAuthor = "me";
        }
        // createdBy가 상대방인 경우 (상대방)
        else if (
          partnerUserId &&
          String(data.createdBy) === String(partnerUserId)
        ) {
          displayAuthor = "partner";
        }
        // author가 상대방 userId인 경우도 체크 (이전 데이터 호환성)
        else if (
          partnerUserId &&
          String(data.author) === String(partnerUserId)
        ) {
          displayAuthor = "partner";
        }
      }

      const eventData = {
        id: doc.id,
        title: data.title,
        description: data.description,
        startDate: data.startDate.toDate(),
        endDate: data.endDate.toDate(),
        author: displayAuthor, // ⭐ 변환된 author
        authorType: data.authorType || null, // 원본 authorType도 포함
        repeatType: data.repeatType || "none",
        repeatEndDate: data.repeatEndDate ? data.repeatEndDate.toDate() : null,
        exceptions: data.exceptions || [], // ⭐ 예외 일정 배열 추가
        createdBy: data.createdBy,
        createdAt: data.createdAt?.toDate()?.toISOString(),
        updatedAt: data.updatedAt?.toDate()?.toISOString(),
      };

      // ⭐ 반복 없는 일정은 바로 처리 (확장 함수 호출 안 함)
      const repeatType = eventData.repeatType || "none";
      if (repeatType === "none" || !repeatType) {
        // 반복 없는 일정은 필터 범위 내에 있는지 확인 후 추가
        const eventStartDate = eventData.startDate;
        if (
          eventStartDate >= filterStartDate &&
          eventStartDate <= filterEndDate
        ) {
          events.push({
            ...eventData,
            startDate: eventStartDate.toISOString(),
            endDate: eventData.endDate.toISOString(),
            isRecurring: false,
          });
        }
      } else {
        // 반복 있는 일정만 확장 함수 사용
        const expandedEvents = expandRecurringEvents(
          eventData,
          filterStartDate,
          filterEndDate
        );
        events.push(...expandedEvents);
      }
    });

    // 날짜순 정렬
    events.sort((a, b) => {
      const dateA = new Date(a.startDate);
      const dateB = new Date(b.startDate);
      return dateA - dateB;
    });

    // ISO 문자열로 변환
    const formattedEvents = events.map((event) => ({
      ...event,
      startDate:
        typeof event.startDate === "string"
          ? event.startDate
          : event.startDate.toISOString(),
      endDate:
        typeof event.endDate === "string"
          ? event.endDate
          : event.endDate.toISOString(),
      repeatEndDate: event.repeatEndDate
        ? event.repeatEndDate.toISOString()
        : null,
    }));

    res.status(200).json({
      status: 200,
      message: "일정 조회 성공",
      data: {
        events: formattedEvents,
        count: formattedEvents.length,
      },
    });
  } catch (error) {
    console.error("일정 조회 실패:", error);
    res.status(500).json({
      status: 500,
      error: "일정 조회 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 일정 수정 API (인증 필요)
app.put(
  "/api/schedule/events/:eventId",
  authenticateToken,
  async (req, res) => {
    try {
      const { userId } = req.user;
      const { eventId } = req.params;
      const {
        title,
        description,
        startDate,
        endDate,
        author,
        repeatType,
        repeatEndDate,
      } = req.body;

      // 입력값 검증
      if (!title || !startDate || !endDate) {
        return res.status(400).json({
          status: 400,
          error: "필수 필드를 입력해주세요.",
          data: {
            missingFields: [
              !title && "title",
              !startDate && "startDate",
              !endDate && "endDate",
            ].filter(Boolean),
          },
        });
      }

      // 연결 상태 확인
      const userDoc = await db.collection("users").doc(userId).get();
      if (!userDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "사용자를 찾을 수 없습니다.",
        });
      }

      const userData = userDoc.data();
      if (!userData.coupleId) {
        return res.status(400).json({
          status: 400,
          error: "커플 연결이 필요합니다.",
        });
      }

      // 일정 존재 및 권한 확인
      const eventRef = db
        .collection("couples")
        .doc(userData.coupleId)
        .collection("events")
        .doc(eventId);

      const eventDoc = await eventRef.get();

      if (!eventDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "일정을 찾을 수 없습니다.",
          data: {
            eventId,
          },
        });
      }

      const eventData = eventDoc.data();

      // 본인이 작성한 일정만 수정 가능
      if (eventData.createdBy !== userId) {
        return res.status(403).json({
          status: 403,
          error: "본인이 작성한 일정만 수정할 수 있습니다.",
          data: {
            eventId,
            createdBy: eventData.createdBy,
          },
        });
      }

      // 수정 데이터 구성
      const updateData = {
        title: title.trim(),
        description: description || "",
        startDate: admin.firestore.Timestamp.fromDate(new Date(startDate)),
        endDate: admin.firestore.Timestamp.fromDate(new Date(endDate)),
        author: author || eventData.author,
        repeatType: repeatType || eventData.repeatType || "none",
        repeatEndDate: repeatEndDate
          ? admin.firestore.Timestamp.fromDate(new Date(repeatEndDate))
          : eventData.repeatEndDate,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      // Firestore에 업데이트
      await eventRef.update(updateData);

      console.log(`✅ 일정 수정 성공: ${userId} - ${eventId}`);

      res.status(200).json({
        status: 200,
        message: "일정이 수정되었습니다.",
        data: {
          event: {
            id: eventId,
            ...updateData,
            startDate: updateData.startDate.toDate().toISOString(),
            endDate: updateData.endDate.toDate().toISOString(),
            repeatEndDate:
              updateData.repeatEndDate?.toDate()?.toISOString() || null,
            createdBy: eventData.createdBy,
            createdAt: eventData.createdAt?.toDate()?.toISOString(),
          },
        },
      });
    } catch (error) {
      console.error("일정 수정 실패:", error);
      res.status(500).json({
        status: 500,
        error: "일정 수정 중 오류가 발생했습니다.",
        data: {
          timestamp: new Date().toISOString(),
          code: error.code || "UNKNOWN_ERROR",
          details:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        },
      });
    }
  }
);

// 일정 삭제 API (인증 필요)
app.delete(
  "/api/schedule/events/:eventId",
  authenticateToken,
  async (req, res) => {
    try {
      const { userId } = req.user;
      const { eventId } = req.params;
      const { deleteType = "all", targetDate } = req.query; // 쿼리 파라미터로 받기

      // 연결 상태 확인
      const userDoc = await db.collection("users").doc(userId).get();
      if (!userDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "사용자를 찾을 수 없습니다.",
        });
      }

      const userData = userDoc.data();
      if (!userData.coupleId) {
        return res.status(400).json({
          status: 400,
          error: "커플 연결이 필요합니다.",
        });
      }

      // 일정 존재 및 권한 확인
      const eventRef = db
        .collection("couples")
        .doc(userData.coupleId)
        .collection("events")
        .doc(eventId);

      const eventDoc = await eventRef.get();

      if (!eventDoc.exists) {
        return res.status(404).json({
          status: 404,
          error: "일정을 찾을 수 없습니다.",
          data: {
            eventId,
          },
        });
      }

      const eventData = eventDoc.data();

      // ⭐ "우리" 일정이면 둘 다 삭제 가능, 그 외에는 본인만 삭제 가능
      const isUsEvent = eventData.author === userData.coupleId;
      const isCreatedByMe = eventData.createdBy === userId;

      if (!isUsEvent && !isCreatedByMe) {
        // "우리"가 아니고 본인이 작성하지 않은 경우 삭제 불가
        return res.status(403).json({
          status: 403,
          error: "본인이 작성한 일정만 삭제할 수 있습니다.",
          data: {
            eventId,
            createdBy: eventData.createdBy,
          },
        });
      }

      // 삭제 타입에 따라 처리
      const isRecurring =
        eventData.repeatType && eventData.repeatType !== "none";

      if (isRecurring && deleteType === "single") {
        // 반복 일정에서 특정 일정만 삭제하는 경우
        // 예외 일정으로 저장 (나중에 조회 시 제외)

        const targetDateTime = targetDate ? new Date(targetDate) : new Date();

        // 날짜만 추출 (시간 제거)
        const exceptionDateOnly = new Date(
          targetDateTime.getFullYear(),
          targetDateTime.getMonth(),
          targetDateTime.getDate()
        );

        const exceptionDate =
          admin.firestore.Timestamp.fromDate(exceptionDateOnly);

        // 기존 exceptions 배열 가져오기
        const currentExceptions = eventData.exceptions || [];

        // 이미 예외로 등록된 날짜인지 확인
        const isAlreadyException = currentExceptions.some((ex) => {
          const exDate = ex.toDate();
          const exDateOnly = new Date(
            exDate.getFullYear(),
            exDate.getMonth(),
            exDate.getDate()
          );
          return exDateOnly.getTime() === exceptionDateOnly.getTime();
        });

        if (!isAlreadyException) {
          await eventRef.update({
            exceptions: admin.firestore.FieldValue.arrayUnion(exceptionDate),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          });

          console.log(
            `✅ 반복 일정 예외 추가: ${userId} - ${eventId} - ${exceptionDateOnly.toISOString()}`
          );

          return res.status(200).json({
            status: 200,
            message: "일정이 삭제되었습니다.",
            data: {
              eventId,
              deleteType: "single",
              deletedAt: new Date().toISOString(),
            },
          });
        } else {
          return res.status(400).json({
            status: 400,
            error: "이미 삭제된 일정입니다.",
          });
        }
      } else if (isRecurring && deleteType === "future") {
        // 이후 모든 반복 일정 삭제하는 경우
        // repeatEndDate를 선택한 날짜 이전으로 설정
        const targetDateTime = targetDate ? new Date(targetDate) : new Date();

        // 하루 전날로 설정하여 선택한 날짜는 포함하지 않음
        const newRepeatEndDate = new Date(targetDateTime);
        newRepeatEndDate.setDate(newRepeatEndDate.getDate() - 1);
        newRepeatEndDate.setHours(23, 59, 59, 999);

        await eventRef.update({
          repeatEndDate: admin.firestore.Timestamp.fromDate(newRepeatEndDate),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log(
          `✅ 반복 일정 종료일 변경: ${userId} - ${eventId} - ${newRepeatEndDate.toISOString()}`
        );

        return res.status(200).json({
          status: 200,
          message: "이후의 모든 반복 일정이 삭제되었습니다.",
          data: {
            eventId,
            deleteType: "future",
            newRepeatEndDate: newRepeatEndDate.toISOString(),
            deletedAt: new Date().toISOString(),
          },
        });
      } else {
        // 일반 삭제 (반복 없는 일정 또는 전체 삭제)
        await eventRef.delete();

        console.log(`✅ 일정 삭제 성공: ${userId} - ${eventId}`);

        return res.status(200).json({
          status: 200,
          message: "일정이 삭제되었습니다.",
          data: {
            eventId,
            deleteType: "all",
            deletedAt: new Date().toISOString(),
          },
        });
      }
    } catch (error) {
      console.error("일정 삭제 실패:", error);
      res.status(500).json({
        status: 500,
        error: "일정 삭제 중 오류가 발생했습니다.",
        data: {
          timestamp: new Date().toISOString(),
          code: error.code || "UNKNOWN_ERROR",
          details:
            process.env.NODE_ENV === "development" ? error.message : undefined,
        },
      });
    }
  }
);

// 현재 사용자 정보 조회 API (인증 필요)
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    // req.user는 authenticateToken 미들웨어에서 설정됨
    const { userId } = req.user;

    // Firestore에서 최신 사용자 정보 조회
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({
        status: 400,
        error: "사용자를 찾을 수 없습니다.",
        data: {
          userId,
          notFound: true,
        },
      });
    }

    const userData = userDoc.data();
    const { password, ...userWithoutPassword } = userData; // 비밀번호 제외

    // 파트너 정보 조회
    let partnerInfo = null;
    if (userData.coupleId) {
      // 같은 coupleId를 가진 다른 사용자 찾기
      const allUsersSnapshot = await db
        .collection("users")
        .where("coupleId", "==", userData.coupleId)
        .get();

      allUsersSnapshot.forEach((doc) => {
        if (doc.id !== userId) {
          const partnerData = doc.data();
          partnerInfo = {
            userId: doc.id,
            name: partnerData.name,
            email: partnerData.email,
            nickname: partnerData.nickname || null,
          };
        }
      });
    }

    res.status(200).json({
      status: 200,
      message: "사용자 정보 조회 성공",
      data: {
        user: userWithoutPassword,
        partner: partnerInfo, // 파트너 정보 추가
      },
    });
  } catch (error) {
    console.error("사용자 정보 조회 실패:", error);
    res.status(500).json({
      status: 500,
      error: "사용자 정보 조회 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
      },
    });
  }
});

// 개인정보 수정 API (인증 필요)
app.put("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;
    const { nickname, profileImage } = req.body;

    // 사용자 존재 확인
    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({
        status: 404,
        error: "사용자를 찾을 수 없습니다.",
        data: {
          userId,
          notFound: true,
        },
      });
    }

    // 업데이트할 데이터 구성
    const updateData = {
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    // 닉네임이 제공된 경우 업데이트
    if (nickname !== undefined) {
      updateData.nickname = nickname.trim() || null;
    }

    // 프로필 이미지가 제공된 경우 Firebase Storage에 업로드
    if (profileImage !== undefined) {
      if (profileImage) {
        // Base64 문자열인지 확인
        if (profileImage.startsWith("data:image")) {
          try {
            // Base64 데이터 파싱
            const matches = profileImage.match(
              /^data:image\/(\w+);base64,(.+)$/
            );
            if (!matches) {
              return res.status(400).json({
                status: 400,
                error: "올바른 이미지 형식이 아닙니다.",
              });
            }

            const imageType = matches[1]; // jpeg, png, gif 등
            const base64Data = matches[2];

            // 이미지 버퍼 생성
            const imageBuffer = Buffer.from(base64Data, "base64");

            // 파일명 생성 (userId_timestamp.확장자)
            const fileName = `profiles/${userId}_${Date.now()}.${imageType}`;

            // Firebase Storage에 업로드
            const file = bucket.file(fileName);
            await file.save(imageBuffer, {
              metadata: {
                contentType: `image/${imageType}`,
                metadata: {
                  uploadedBy: userId,
                  uploadedAt: new Date().toISOString(),
                },
              },
            });

            // 공개 URL 생성 (읽기 권한 설정 필요)
            // 또는 signed URL 생성
            await file.makePublic(); // 공개 접근 허용 (또는 signed URL 사용)

            const imageUrl = `https://storage.googleapis.com/${bucket.name}/${fileName}`;
            updateData.profileImage = imageUrl;

            // 기존 이미지가 있으면 삭제 (선택사항)
            const userData = userDoc.data();
            if (
              userData.profileImage &&
              userData.profileImage.includes("storage.googleapis.com")
            ) {
              try {
                const oldFileName = userData.profileImage.split(
                  `${bucket.name}/`
                )[1];
                if (oldFileName) {
                  const oldFile = bucket.file(oldFileName);
                  await oldFile.delete();
                }
              } catch (deleteError) {
                console.error("기존 이미지 삭제 실패:", deleteError);
                // 삭제 실패해도 계속 진행
              }
            }
          } catch (uploadError) {
            console.error("이미지 업로드 실패:", uploadError);
            return res.status(500).json({
              status: 500,
              error: "이미지 업로드 중 오류가 발생했습니다.",
            });
          }
        } else {
          // 이미 URL인 경우 (기존 이미지 유지)
          updateData.profileImage = profileImage;
        }
      } else {
        // null인 경우 이미지 삭제
        const userData = userDoc.data();
        if (
          userData.profileImage &&
          userData.profileImage.includes("storage.googleapis.com")
        ) {
          try {
            const oldFileName = userData.profileImage.split(
              `${bucket.name}/`
            )[1];
            if (oldFileName) {
              const oldFile = bucket.file(oldFileName);
              await oldFile.delete();
            }
          } catch (deleteError) {
            console.error("이미지 삭제 실패:", deleteError);
          }
        }
        updateData.profileImage = null;
      }
    }

    // Firestore 업데이트
    await db.collection("users").doc(userId).update(updateData);

    // 업데이트된 사용자 정보 조회
    const updatedUserDoc = await db.collection("users").doc(userId).get();
    const updatedUserData = updatedUserDoc.data();
    const { password, ...userWithoutPassword } = updatedUserData;

    console.log(`✅ 개인정보 수정 성공: ${userId}`);

    res.status(200).json({
      status: 200,
      message: "개인정보가 수정되었습니다.",
      data: {
        user: userWithoutPassword,
      },
    });
  } catch (error) {
    console.error("개인정보 수정 실패:", error);
    res.status(500).json({
      status: 500,
      error: "개인정보 수정 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

app.get("/", (req, res) => {
  res.send("🚀 Express server is running!");
});

app.listen(PORT, () => {
  console.log(`✅ Server is running on http://localhost:${PORT}`);
});
