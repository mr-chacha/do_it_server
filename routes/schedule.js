const express = require("express");
const { db, admin } = require("../firebase/firebase");
const { authenticateToken } = require("../middleware/auth");

const router = express.Router();

// 일정 등록 API (인증 필요)
router.post("/events", authenticateToken, async (req, res) => {
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
router.get("/events", authenticateToken, async (req, res) => {
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
router.put("/events/:eventId", authenticateToken, async (req, res) => {
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
      updateType, // "single", "future", "all"
      targetDate, // 반복 일정의 특정 날짜 (single일 때 필요)
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

    // 작성자 ID 변환 (등록 API와 동일한 로직)
    let authorId = eventData.author; // 기본값: 기존 값 유지
    let authorType = eventData.authorType || "me"; // 기본값: 기존 값 유지

    if (author) {
      if (author === "me") {
        authorId = userId;
        authorType = "me";
      } else if (author === "partner") {
        // 상대방의 userId 찾기
        const allUsersSnapshot = await db
          .collection("users")
          .where("coupleId", "==", userData.coupleId)
          .get();

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
        authorType = "partner";
      } else if (author === "us") {
        authorId = userData.coupleId;
        authorType = "us";
      } else {
        return res.status(400).json({
          status: 400,
          error: "유효하지 않은 작성자입니다.",
        });
      }
    }

    // 반복 일정 수정 처리
    const isRecurring = eventData.repeatType && eventData.repeatType !== "none";
    const updateTypeValue = updateType || (isRecurring ? "single" : "all");

    if (isRecurring && updateTypeValue === "single") {
      // 이 일정만 수정: 예외 일정으로 추가
      if (!targetDate) {
        return res.status(400).json({
          status: 400,
          error: "targetDate가 필요합니다.",
        });
      }

      // 예외 일정 목록에 추가
      const exceptions = eventData.exceptions || [];
      const targetDateTimestamp = admin.firestore.Timestamp.fromDate(
        new Date(targetDate)
      );

      // 중복 체크
      const isAlreadyException = exceptions.some((ex) => {
        const exDate = ex.toDate ? ex.toDate() : new Date(ex);
        const targetDateObj = targetDateTimestamp.toDate();
        return (
          exDate.getFullYear() === targetDateObj.getFullYear() &&
          exDate.getMonth() === targetDateObj.getMonth() &&
          exDate.getDate() === targetDateObj.getDate()
        );
      });

      if (!isAlreadyException) {
        exceptions.push(targetDateTimestamp);
      }

      // 새로운 일정 생성 (수정된 일정)
      const newEventData = {
        title: title.trim(),
        description: description || "",
        startDate: admin.firestore.Timestamp.fromDate(new Date(startDate)),
        endDate: admin.firestore.Timestamp.fromDate(new Date(endDate)),
        author: authorId,
        authorType: authorType,
        repeatType: "none", // 예외 일정은 반복 없음
        createdBy: userId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        parentEventId: eventId, // 원본 일정 ID
      };

      const eventsRef = db
        .collection("couples")
        .doc(userData.coupleId)
        .collection("events");
      const newEventDoc = await eventsRef.add(newEventData);

      // 원본 일정의 예외 목록 업데이트
      await eventRef.update({
        exceptions: exceptions,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      console.log(`✅ 일정 수정 성공 (single): ${userId} - ${eventId}`);

      return res.status(200).json({
        status: 200,
        message: "일정이 수정되었습니다.",
        data: {
          event: {
            id: newEventDoc.id,
            ...newEventData,
            startDate: newEventData.startDate.toDate().toISOString(),
            endDate: newEventData.endDate.toDate().toISOString(),
          },
        },
      });
    } else if (isRecurring && updateTypeValue === "future") {
      // 이후 모든 반복 일정 수정: 원본 일정의 repeatEndDate를 targetDate로 변경 후 새 일정 생성
      if (!targetDate) {
        return res.status(400).json({
          status: 400,
          error: "targetDate가 필요합니다.",
        });
      }

      // 원본 일정의 repeatEndDate를 targetDate 이전으로 변경
      const targetDateTimestamp = admin.firestore.Timestamp.fromDate(
        new Date(targetDate)
      );
      const oneDayBefore = new Date(targetDate);
      oneDayBefore.setDate(oneDayBefore.getDate() - 1);

      await eventRef.update({
        repeatEndDate: admin.firestore.Timestamp.fromDate(oneDayBefore),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      // 새로운 반복 일정 생성 (수정된 내용)
      const newEventData = {
        title: title.trim(),
        description: description || "",
        startDate: admin.firestore.Timestamp.fromDate(new Date(startDate)),
        endDate: admin.firestore.Timestamp.fromDate(new Date(endDate)),
        author: authorId,
        authorType: authorType,
        repeatType: repeatType || eventData.repeatType || "none",
        repeatEndDate: repeatEndDate
          ? admin.firestore.Timestamp.fromDate(new Date(repeatEndDate))
          : eventData.repeatEndDate,
        createdBy: userId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      const eventsRef = db
        .collection("couples")
        .doc(userData.coupleId)
        .collection("events");
      const newEventDoc = await eventsRef.add(newEventData);

      console.log(`✅ 일정 수정 성공 (future): ${userId} - ${eventId}`);

      return res.status(200).json({
        status: 200,
        message: "일정이 수정되었습니다.",
        data: {
          event: {
            id: newEventDoc.id,
            ...newEventData,
            startDate: newEventData.startDate.toDate().toISOString(),
            endDate: newEventData.endDate.toDate().toISOString(),
            repeatEndDate:
              newEventData.repeatEndDate?.toDate()?.toISOString() || null,
          },
        },
      });
    } else {
      // 전체 수정 (all 또는 반복 없는 일정)
      const updateData = {
        title: title.trim(),
        description: description || "",
        startDate: admin.firestore.Timestamp.fromDate(new Date(startDate)),
        endDate: admin.firestore.Timestamp.fromDate(new Date(endDate)),
        author: authorId,
        authorType: authorType,
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
    }
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
});

// 일정 삭제 API (인증 필요)
router.delete("/events/:eventId", authenticateToken, async (req, res) => {
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
    const isRecurring = eventData.repeatType && eventData.repeatType !== "none";

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
});

module.exports = router;
