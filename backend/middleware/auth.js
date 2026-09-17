const { auth, db } = require("../config/firebase-admin");

async function verifyToken(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                success: false,
                message: "Authentication token required"
            });
        }

        const idToken = authHeader.split("Bearer ")[1];

        const decodedToken = await auth.verifyIdToken(idToken);

        const userDoc = await db
            .collection("users")
            .doc(decodedToken.uid)
            .get();

        if (!userDoc.exists) {
            return res.status(403).json({
                success: false,
                message: "User profile not found"
            });
        }

        const userData = userDoc.data();

        req.user = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            role: userData.role
        };

        next();

    } catch (error) {
        console.error("Authentication error:", error.message);

        return res.status(401).json({
            success: false,
            message: "Invalid or expired authentication token"
        });
    }
}

module.exports = {
    verifyToken
};