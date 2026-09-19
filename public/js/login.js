import { initializeApp } from "https://www.gstatic.com/firebasejs/12.0.0/firebase-app.js";

import {
    getAuth,
    signInWithEmailAndPassword
} from "https://www.gstatic.com/firebasejs/12.0.0/firebase-auth.js";

const firebaseConfig = {
    apiKey: "AIzaSyAVavVTFdNXgu0QUtWNJ_kElcuwrkh3-mE",
    authDomain: "question-paper-e9c27.firebaseapp.com",
    projectId: "question-paper-e9c27",
    storageBucket: "question-paper-e9c27.firebasestorage.app",
    messagingSenderId: "1058724585397",
    appId: "1:1058724585397:web:3f84fd79b2c7d5a03ec3fc"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

const loginForm = document.getElementById("loginForm");
const message = document.getElementById("message");

const ROLE_REDIRECTS = {
    "admin":          "/overview.html",
    "setter":         "/setter.html",
    "custodian":      "/custodian-portal.html",
    "print-operator": "/print-operator.html"
};

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const submitBtn = loginForm.querySelector("button[type='submit']") || loginForm.querySelector("button");
    const email    = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.style.opacity = "0.7";
    }
    message.textContent = "Signing in...";

    try {
        const userCredential = await signInWithEmailAndPassword(
            auth,
            email,
            password
        );

        const user = userCredential.user;

        // Instant in-memory token result (0ms network cost)
        const tokenResult = await user.getIdTokenResult(false);
        let role = tokenResult.claims?.role;

        // Fallback to /api/me only if custom claim was not found in JWT
        if (!role) {
            const idToken = await user.getIdToken(false);
            const response = await fetch("/api/me", {
                method: "GET",
                headers: { "Authorization": `Bearer ${idToken}` }
            });
            const result = await response.json();
            role = result.user?.role;
        }

        const destination = ROLE_REDIRECTS[role];

        if (destination) {
            sessionStorage.setItem("sqp_user_role", role);
            sessionStorage.setItem("sqp_user_email", email);
            sessionStorage.setItem("sqp_user_uid", user.uid);
            message.textContent = "Redirecting...";
            window.location.href = destination;
        } else {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.style.opacity = "1";
            }
            throw new Error("This account does not have a recognised role. Contact your administrator.");
        }

    } catch (error) {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.style.opacity = "1";
        }
        if (error.code) {
            message.textContent = getLoginErrorMessage(error.code);
        } else {
            message.textContent = error.message;
        }
    }
});

function getLoginErrorMessage(errorCode) {

    switch (errorCode) {

        case "auth/invalid-credential":
            return "Invalid email or password.";

        case "auth/invalid-email":
            return "Invalid email address.";

        case "auth/user-disabled":
            return "This account has been disabled.";

        case "auth/too-many-requests":
            return "Too many login attempts. Try again later.";

        case "auth/network-request-failed":
            return "Network error. Check your internet connection.";

        default:
            return "Firebase login failed.";
    }

}
