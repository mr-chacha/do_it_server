const express = require("express");
const jwt = require("jsonwebtoken");
const { db, admin, bucket } = require("../firebase/firebase");
const { authenticateToken } = require("../middleware/auth");
const { verifiedEmails } = require("../utils/email");

const { OAuth2Client } = require("google-auth-library");
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const router = express.Router();

const JWT_SECRET =
  process.env.JWT_SECRET || "your-secret-key-change-this-in-production";

// 소셜 회원가입/로그인 (통합)
// ============================================
router.post("/social", async (req, res) => {
  try {
    const { provider, accessToken, email, name, profileImage } = req.body;

    // 입력값 검증
    if (!provider || !email || !name) {
      return res.status(400).json({
        status: 400,
        error: "필수 정보가 누락되었습니다.",
        data: {
          missingFields: [
            !provider && "provider",
            !email && "email",
            !name && "name",
          ].filter(Boolean),
        },
      });
    }

    // 지원하는 provider 확인
    if (!["google", "kakao"].includes(provider)) {
      return res.status(400).json({
        status: 400,
        error: "지원하지 않는 소셜 로그인 방식입니다.",
      });
    }

    const usersRef = db.collection("users");
    const normalizedEmail = email.toLowerCase().trim();

    // ============================================
    // 1. 기존 사용자 확인
    // ============================================
    const userSnapshot = await usersRef
      .where("email", "==", normalizedEmail)
      .limit(1)
      .get();

    let userData;
    let userId;
    let isNewUser = false;

    if (userSnapshot.empty) {
      // ============================================
      // 2. 신규 사용자 → 자동 회원가입
      // ============================================
      isNewUser = true;
      userId = usersRef.doc().id;

      userData = {
        id: userId,
        name: name.trim(),
        email: normalizedEmail,
        provider: provider, // "google" or "kakao"
        profileImage: profileImage || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        verified: true, // 소셜 로그인은 이메일 인증 완료로 간주
        coupleId: null,
        partnerEmail: null,
      };

      await usersRef.doc(userId).set(userData);

      console.log(`✅ 소셜 회원가입 성공: ${email} (${provider})`);
    } else {
      // ============================================
      // 3. 기존 사용자 → 로그인
      // ============================================
      const userDoc = userSnapshot.docs[0];
      userId = userDoc.id;
      userData = userDoc.data();

      // 일반 회원가입 → 소셜 로그인 시도 시 provider 추가
      if (!userData.provider) {
        await usersRef.doc(userId).update({
          provider: provider,
          profileImage: profileImage || userData.profileImage,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        userData.provider = provider;
      }

      console.log(`✅ 소셜 로그인 성공: ${email} (${provider})`);
    }

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
      { expiresIn: "7d" }
    );

    // ============================================
    // 5. 성공 응답
    // ============================================
    res.status(200).json({
      status: 200,
      message: isNewUser ? "회원가입이 완료되었습니다." : "로그인 성공",
      data: {
        user: {
          id: userData.id,
          name: userData.name,
          email: userData.email,
          coupleId: userData.coupleId,
          partnerEmail: userData.partnerEmail,
          provider: userData.provider,
          profileImage: userData.profileImage,
          nickname: userData.nickname || null,
        },
        token: token,
        isNewUser: isNewUser, // ⭐ 신규 회원인지 여부
      },
    });
  } catch (error) {
    console.error("소셜 인증 실패:", error);
    res.status(500).json({
      status: 500,
      error: "소셜 인증 중 오류가 발생했습니다.",
      data: {
        timestamp: new Date().toISOString(),
        code: error.code || "UNKNOWN_ERROR",
        details:
          process.env.NODE_ENV === "development" ? error.message : undefined,
      },
    });
  }
});

// 회원가입 API
router.post("/signup", async (req, res) => {
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

// 회원탈퇴 API (인증 필요)
router.delete("/me", authenticateToken, async (req, res) => {
  try {
    const { userId } = req.user;

    // ============================================
    // 1. 사용자 정보 조회
    // ============================================
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

    const userData = userDoc.data();

    // ============================================
    // 2. 커플 연결 상태 확인
    // ============================================
    if (userData.coupleId || userData.partnerEmail) {
      return res.status(400).json({
        status: 400,
        error: "커플 연결을 먼저 해제해주세요.",
        data: {
          field: "coupleId",
          connected: true,
          message: "커플 연결 상태에서는 회원탈퇴를 할 수 없습니다.",
        },
      });
    }

    // ============================================
    // 3. 프로필 이미지 삭제 (Firebase Storage)
    // ============================================
    if (
      userData.profileImage &&
      userData.profileImage.includes("storage.googleapis.com")
    ) {
      try {
        const fileName = userData.profileImage.split(`${bucket.name}/`)[1];
        if (fileName) {
          const file = bucket.file(fileName);
          await file.delete();
          console.log(`🗑️ 프로필 이미지 삭제: ${fileName}`);
        }
      } catch (deleteError) {
        console.error("프로필 이미지 삭제 실패:", deleteError);
        // 이미지 삭제 실패해도 계속 진행
      }
    }

    // ============================================
    // 4. 관련 초대장 데이터 정리 (선택사항)
    // ============================================
    try {
      const invitationsRef = db.collection("invitations");

      // 발신자로서 보낸 초대장들
      const sentInvitations = await invitationsRef
        .where("senderUserId", "==", userId)
        .get();

      // 수신자로서 받은 초대장들
      const receivedInvitations = await invitationsRef
        .where("receiverUserId", "==", userId)
        .get();

      const batch = db.batch();

      sentInvitations.forEach((doc) => {
        batch.delete(doc.ref);
      });

      receivedInvitations.forEach((doc) => {
        batch.delete(doc.ref);
      });

      await batch.commit();
      console.log(`🗑️ 초대장 데이터 삭제 완료`);
    } catch (invitationError) {
      console.error("초대장 삭제 실패:", invitationError);
      // 초대장 삭제 실패해도 계속 진행
    }

    // ============================================
    // 5. 사용자 데이터 삭제 (Firestore)
    // ============================================
    await db.collection("users").doc(userId).delete();

    console.log(`✅ 회원탈퇴 완료: ${userData.email} (${userId})`);

    // ============================================
    // 6. 성공 응답 (200)
    // ============================================
    res.status(200).json({
      status: 200,
      message: "회원탈퇴가 완료되었습니다.",
      data: {
        deletedAt: new Date().toISOString(),
        email: userData.email,
      },
    });
  } catch (error) {
    console.error("회원탈퇴 실패:", error);
    res.status(500).json({
      status: 500,
      error: "회원탈퇴 중 오류가 발생했습니다.",
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
router.post("/login", async (req, res) => {
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
router.post("/logout", authenticateToken, async (req, res) => {
  try {
    // JWT 토큰 기반 인증이므로, 클라이언트에서 토큰을 삭제하면
    // 자동으로 로그아웃됩니다. 여기서는 성공 응답만 보내면 됩니다.
    // 필요하다면 나중에 토큰 블랙리스트를 추가할 수 있습니다.

    res.status(200).json({
      success: true,
      message: "로그아웃되었습니다.",
    });
  } catch (error) {
    console.error("로그아웃 실패:", error);
    res.status(500).json({
      success: false,
      error: "로그아웃 처리 중 오류가 발생했습니다.",
    });
  }
});

// 현재 사용자 정보 조회 API (인증 필요)
router.get("/me", authenticateToken, async (req, res) => {
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
router.put("/me", authenticateToken, async (req, res) => {
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

module.exports = router;
