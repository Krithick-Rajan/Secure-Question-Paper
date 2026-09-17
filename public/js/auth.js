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

window.authReady =
    new Promise(resolve => {
        resolveAuthReady = resolve;
    });


onAuthStateChanged(
    auth,
    async user => {

        if (!user) {

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
                    "/api/admin-test",
                    {
                        method: "GET",

                        headers: {
                            "Authorization":
                                `Bearer ${token}`
                        }
                    }
                );


            if (!response.ok) {
                resolveAuthReady({
                    authenticated: false,
                    authorized: false
                });

                await signOut(auth);

                window.location.href = "/";

                return;
            }


            const result =
                await response.json();


            if (
                !result.success ||
                !result.user
            ) {

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


            resolveAuthReady({
                authenticated: false,
                admin: false
            });


            await signOut(auth);

            window.location.href = "/";

        }

    }
);
