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
                    admin: false
                });

                await signOut(auth);

                window.location.href = "/";

                return;
            }


            const result =
                await response.json();


            if (
                !result.success ||
                !result.user ||
                result.user.role !== "admin"
            ) {

                resolveAuthReady({
                    authenticated: false,
                    admin: false
                });

                await signOut(auth);

                window.location.href = "/";

                return;
            }


            window.currentAdmin =
                result.user;


            resolveAuthReady({
                authenticated: true,
                admin: true,
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