const express = require("express");
const jwt = require("jsonwebtoken");
const { db, admin } = require("../firebase/firebase");
const { authenticateToken } = require("../middleware/auth");
const { transporter } = require("../utils/email");

const router = express.Router();

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-this-in-production";

// 커플 연결 API (인증 필요)
router.post("/connect", authenticateToken, async (req, res) => {
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

// 커플 연결 끊기 API (인증 필요)
router.post("/disconnect", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;

    // ============================================
    // 1. 현재 사용자 정보 조회
    // ============================================
    const usersRef = db.collection("users");
    const userDoc = await usersRef.doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({
        status: 404,
        error: "사용자 정보를 찾을 수 없습니다.",
        data: {
          userNotFound: true,
        },
      });
    }

    const userData = userDoc.data();

    // 연결되어 있지 않은 경우
    if (!userData.coupleId || !userData.partnerEmail) {
      return res.status(400).json({
        status: 400,
        error: "연결된 상대방이 없습니다.",
        data: {
          notConnected: true,
        },
      });
    }

    const coupleId = userData.coupleId;
    const partnerEmail = userData.partnerEmail;

    // ============================================
    // 2. 상대방 찾기 (coupleId로 같은 커플의 모든 사용자 찾기)
    // ============================================
    const partnerSnapshot = await usersRef
      .where("coupleId", "==", coupleId)
      .get();

    // Firestore batch write로 두 사용자 동시 업데이트
    const batch = db.batch();

    // 현재 사용자 연결 해제
    batch.update(usersRef.doc(userId), {
      coupleId: admin.firestore.FieldValue.delete(),
      partnerEmail: admin.firestore.FieldValue.delete(),
      partnerName: admin.firestore.FieldValue.delete(),
      partnerNickname: admin.firestore.FieldValue.delete(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // 상대방도 연결 해제
    partnerSnapshot.forEach((doc) => {
      if (doc.id !== userId) {
        batch.update(doc.ref, {
          coupleId: admin.firestore.FieldValue.delete(),
          partnerEmail: admin.firestore.FieldValue.delete(),
          partnerName: admin.firestore.FieldValue.delete(),
          partnerNickname: admin.firestore.FieldValue.delete(),
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }
    });

    // ============================================
    // 3. 관련된 pending 상태의 초대장들을 expired로 변경 (선택사항)
    // ============================================
    const invitationsRef = db.collection("invitations");
    const relatedInvitations = await invitationsRef
      .where("status", "==", "pending")
      .where("receiverEmail", "==", partnerEmail)
      .get();

    relatedInvitations.forEach((doc) => {
      const invitationData = doc.data();
      // 현재 사용자와 관련된 초대장만 만료 처리
      if (
        invitationData.senderUserId === userId ||
        invitationData.receiverUserId === userId
      ) {
        batch.update(doc.ref, {
          status: "expired",
          expiredAt: admin.firestore.FieldValue.serverTimestamp(),
        });
      }
    });

    await batch.commit();

    console.log(`✅ 커플 연결 해제 완료: ${userId} (coupleId: ${coupleId})`);

    // ============================================
    // 4. 성공 응답 (200)
    // ============================================
    res.status(200).json({
      status: 200,
      message: "커플 연결이 해제되었습니다.",
      data: {
        disconnectedAt: new Date().toISOString(),
      },
    });
  } catch (error) {
    console.error("커플 연결 해제 실패:", error);
    res.status(500).json({
      status: 500,
      error: "커플 연결 해제 중 오류가 발생했습니다.",
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
router.get("/accept/info", async (req, res) => {
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
router.post("/accept", async (req, res) => {
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
router.post("/resend", authenticateToken, async (req, res) => {
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

module.exports = router;
