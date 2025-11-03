const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccountKey.json");

// Firebase Admin 초기화
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`,
  // Storage Bucket - 실제 버킷 이름 사용
  storageBucket: "doit-15c63.firebasestorage.app",
});

// Firestore 인스턴스
const db = admin.firestore();

// Firebase Storage 인스턴스 - 실제 버킷 이름 사용
const bucket = admin.storage().bucket("doit-15c63.firebasestorage.app");

module.exports = { admin, db, bucket };
