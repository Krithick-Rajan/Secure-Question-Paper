"use strict";

const { auth, db } = require("../config/firebase-admin");

// Fast in-memory token verification cache: token -> { user, expiresAt }
const tokenCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes cache

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
        if (!idToken) {
            return res.status(401).json({
                success: false,
                message: "Authentication token required"
            });
        }

        // Check in-memory cache first (0.01ms latency)
        const cached = tokenCache.get(idToken);
        const now = Date.now();
        if (cached && cached.expiresAt > now) {
            req.user = cached.user;
            return next();
        }

        const decodedToken = await auth.verifyIdToken(idToken);

        // Fast path: Role is cryptographically signed in JWT custom claims!
        let userRole = decodedToken.role || null;

        // Fallback to Firestore only if custom claim was not set
        if (!userRole) {
            try {
                const userDoc = await db.collection("users").doc(decodedToken.uid).get();
                if (userDoc.exists) {
                    const userData = userDoc.data();
                    userRole = userData.role;
                }
            } catch (_dbError) {
                console.warn("Could not fetch user profile from Firestore:", _dbError.message);
            }
        }

        if (!userRole) {
            return res.status(403).json({
                success: false,
                message: "User profile not found. Please contact an administrator."
            });
        }

        req.user = {
            uid: decodedToken.uid,
            email: decodedToken.email,
            role: userRole
        };

        // Store in fast cache
        tokenCache.set(idToken, {
            user: req.user,
            expiresAt: now + CACHE_TTL_MS
        });

        // Prune stale cache entries if map grows
        if (tokenCache.size > 200) {
            for (const [k, v] of tokenCache.entries()) {
                if (v.expiresAt <= now) tokenCache.delete(k);
            }
        }

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