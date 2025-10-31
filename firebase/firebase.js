const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json');  

// Firebase Admin 초기화
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`
});

// Firestore 인스턴스
const db = admin.firestore();

module.exports = { admin, db };