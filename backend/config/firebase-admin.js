const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");
const fs = require("fs");
const path = require("path");

function loadServiceAccount() {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
    }

    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
        return JSON.parse(
            Buffer
                .from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, "base64")
                .toString("utf8")
        );
    }

    const serviceAccountPaths = [
        path.join(__dirname, "../../firebase-service-account.json"),
        path.join(__dirname, "../../firebase-service-account.json.json")
    ];

    const serviceAccountPath =
        serviceAccountPaths.find(candidate => fs.existsSync(candidate));

    if (!serviceAccountPath) {
        throw new Error(
            "Firebase service account credentials are missing. Set FIREBASE_SERVICE_ACCOUNT_JSON in Vercel."
        );
    }

    return require(serviceAccountPath);
}

const serviceAccount =
    loadServiceAccount();

const firebaseApp =
    getApps()[0] ||
    initializeApp({
        credential: cert(serviceAccount)
    });

const db = getFirestore(firebaseApp);
const auth = getAuth(firebaseApp);

console.log("Firebase Admin SDK connected");

module.exports = {
    db,
    auth
};
