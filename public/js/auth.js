import {
    initializeApp
} from "https://www.gstatic.com/firebasejs/12.0.0/firebase-app.js";

import {
    getAuth,
    onAuthStateChanged,
    signOut
} from "https://www.gstatic.com/firebasejs/12.0.0/firebase-auth.js";

const firebaseConfig = {
    apiKey: "AIzaSyAVavVTFdNXgu0QUtWNJ_kElcuwrkh3-mE",
    authDomain: "question-paper-e9c27.firebaseapp.com",
    projectId: "question-paper-e9c27",
    storageBucket: "question-paper-e9c27.firebasestorage.app",
    messagingSenderId: "1058724585397",
    appId: "1:1058724585397:web:3f84fd79b2c7d5a03ec3fc"
};

const app =
    initializeApp(firebaseConfig);

const auth =
    getAuth(app);

window.firebaseAuth = auth;

window.getAuthToken = async function () {
    if (auth.currentUser) {
        return await auth.currentUser.getIdToken();
    }
    return new Promise((resolve) => {
        const unsubscribe = onAuthStateChanged(auth, async (user) => {
            unsubscribe();
            if (user) resolve(await user.getIdToken());
            else resolve(null);
        });
    });
};

const ADMIN_PAGES =
    new Set([
        "overview",
        "exams",
        "fragments",
        "custodians",
        "release",
        "security",
        "audit",
        "users"
    ]);

const PAGE_ROLES = {
    setter: "setter",
    custodian: "custodian",
    "print-operator": "print-operator"
};

const ROLE_REDIRECTS = {
    admin: "/overview.html",
    setter: "/setter.html",
    custodian: "/custodian-portal.html",
    "print-operator": "/print-operator.html"
};

function getRequiredRole() {
    const page =
        document.body?.dataset?.page || "";

    if (
        ADMIN_PAGES.has(page)
    ) {
        return "admin";
    }

    return PAGE_ROLES[page] || null;
}

function getRoleDestination(role) {
    return ROLE_REDIRECTS[role] || "/";
}

let resolveAuthReady;
let isAuthResolved = false;

window.authReady =
    new Promise(resolve => {
        resolveAuthReady = (val) => {
            if (!isAuthResolved) {
                isAuthResolved = true;
                resolve(val);
            }
        };
    });

// Instant optimistic resolution from active session (0ms page navigation)
const cachedRole = sessionStorage.getItem("sqp_user_role");
const cachedEmail = sessionStorage.getItem("sqp_user_email");
const cachedUid = sessionStorage.getItem("sqp_user_uid");

if (cachedRole) {
    const reqRole = getRequiredRole();
    if (reqRole && cachedRole !== reqRole) {
        window.location.href = getRoleDestination(cachedRole);
    } else {
        window.currentUserProfile = {
            role: cachedRole,
            email: cachedEmail || "",
            uid: cachedUid || ""
        };
        if (cachedRole === "admin") {
            window.currentAdmin = window.currentUserProfile;
        }
        resolveAuthReady({
            authenticated: true,
            authorized: true,
            admin: cachedRole === "admin",
            user: window.currentUserProfile
        });
    }
}

onAuthStateChanged(
    auth,
    async user => {

        if (!user) {
            sessionStorage.removeItem("sqp_user_role");
            sessionStorage.removeItem("sqp_user_email");
            sessionStorage.removeItem("sqp_user_uid");

            resolveAuthReady({
                authenticated: false,
                admin: false
            });

            window.location.href = "/";

            return;
        }

        try {
            const requiredRole =
                getRequiredRole();

            const token =
                await user.getIdToken();

            const response =
                await fetch(
                    "/api/me",
                    {
                        method: "GET",
                        headers: {
                            "Authorization":
                                `Bearer ${token}`
                        }
                    }
                );

            if (!response.ok) {
                if (response.status === 401) {
                    sessionStorage.removeItem("sqp_user_role");
                    sessionStorage.removeItem("sqp_user_email");
                    sessionStorage.removeItem("sqp_user_uid");

                    resolveAuthReady({
                        authenticated: false,
                        authorized: false
                    });

                    await signOut(auth);
                    window.location.href = "/";
                    return;
                }
                throw new Error("Profile verification failed");
            }

            const result =
                await response.json();

            if (
                !result.success ||
                !result.user
            ) {
                sessionStorage.removeItem("sqp_user_role");
                sessionStorage.removeItem("sqp_user_email");
                sessionStorage.removeItem("sqp_user_uid");

                resolveAuthReady({
                    authenticated: false,
                    authorized: false
                });

                await signOut(auth);
                window.location.href = "/";
                return;
            }

            const role =
                result.user.role;

            sessionStorage.setItem("sqp_user_role", role);
            sessionStorage.setItem("sqp_user_email", result.user.email || "");
            sessionStorage.setItem("sqp_user_uid", result.user.uid || "");

            if (
                requiredRole &&
                role !== requiredRole
            ) {

                resolveAuthReady({
                    authenticated: true,
                    authorized: false,
                    user: result.user
                });

                window.location.href =
                    getRoleDestination(role);

                return;
            }

            window.currentUserProfile =
                result.user;

            if (
                role === "admin"
            ) {
                window.currentAdmin =
                    result.user;
            }

            resolveAuthReady({
                authenticated: true,
                authorized: true,
                admin: role === "admin",
                user: result.user
            });

        } catch (_error) {

            const cachedRole =
                sessionStorage.getItem("sqp_user_role");

            const requiredRole =
                getRequiredRole();

            if (
                cachedRole &&
                (!requiredRole || cachedRole === requiredRole || cachedRole === "admin")
            ) {
                resolveAuthReady({
                    authenticated: true,
                    authorized: true,
                    admin: cachedRole === "admin",
                    user: {
                        uid: user.uid,
                        email: user.email,
                        role: cachedRole
                    }
                });
                return;
            }

            resolveAuthReady({
                authenticated: true,
                authorized: false
            });

        }

    }
);

window.logout = async function () {
    try {
        sessionStorage.removeItem("sqp_user_role");
        sessionStorage.removeItem("sqp_user_email");
        sessionStorage.removeItem("sqp_user_uid");
        await signOut(auth);
    } catch (_err) {

    }
    window.location.href = "/";
};
