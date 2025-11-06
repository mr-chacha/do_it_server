const express = require("express");
const { db, admin } = require("../firebase/firebase");
const { authenticateToken } = require("../middleware/auth");

const router = express.Router();

// 가계부 거래 등록 API (인증 필요)
router.post("/transactions", authenticateToken, async (req, res) => {
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
      createdByName: userData.nickname || userData.name || "알 수 없음", // 닉네임 또는 이름 저장
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
router.get("/transactions", authenticateToken, async (req, res) => {
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

    // 모든 사용자 정보를 한 번에 조회 (성능 최적화)
    const userIds = new Set();
    snapshot.forEach((doc) => {
      const data = doc.data();
      if (data.createdBy) {
        userIds.add(data.createdBy);
      }
    });

    // 사용자 정보 일괄 조회
    const usersMap = {};
    if (userIds.size > 0) {
      const usersPromises = Array.from(userIds).map(async (uid) => {
        const userDoc = await db.collection("users").doc(uid).get();
        if (userDoc.exists) {
          const userData = userDoc.data();
          return {
            id: uid,
            name: userData.name,
            nickname: userData.nickname || userData.name || "알 수 없음",
          };
        }
        return null;
      });
      const users = await Promise.all(usersPromises);
      users.forEach((user) => {
        if (user) {
          usersMap[user.id] = user;
        }
      });
    }

    const transactions = [];
    snapshot.forEach((doc) => {
      const data = doc.data();
      const creatorInfo = usersMap[data.createdBy] || null;

      transactions.push({
        id: doc.id,
        type: data.type,
        title: data.title,
        amount: data.amount,
        category: data.category,
        description: data.description,
        date: data.date.toDate().toISOString(),
        createdBy: data.createdBy,
        createdByName:
          data.createdByName ||
          creatorInfo?.nickname ||
          creatorInfo?.name ||
          "알 수 없음", // 닉네임 포함
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
router.put(
  "/transactions/:transactionId",
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
router.delete(
  "/transactions/:transactionId",
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

module.exports = router;
