const admin = require("firebase-admin");

// 환경변수에서 Firebase 설정 읽기
const serviceAccount = process.env.FIREBASE_PRIVATE_KEY
  ? {
      type: "service_account",
      project_id: process.env.FIREBASE_PROJECT_ID,
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
    }
  : require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: `${
    process.env.FIREBASE_PROJECT_ID || "doit-15c63"
  }.appspot.com`,
});

const db = admin.firestore();
const bucket = admin.storage().bucket();

module.exports = { db, admin, bucket };
