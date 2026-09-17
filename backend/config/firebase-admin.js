const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");
const path = require("path");

const serviceAccount = require(
    path.join(__dirname, "../../firebase-service-account.json")
);

initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();
const auth = getAuth();

console.log("Firebase Admin SDK connected");

module.exports = {
    db,
    auth
};