"use strict";

const form = document.getElementById("registerForm");
const msgEl = document.getElementById("regMessage");
const submitBtn = document.getElementById("regSubmitButton");

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const displayName = document.getElementById("regDisplayName")?.value?.trim();
    const email = document.getElementById("regEmail")?.value?.trim();
    const password = document.getElementById("regPassword")?.value;
    const role = document.getElementById("regRole")?.value;

    if (!email || !password || !role) {
        showMessage("Please fill in all required fields.", "error");
        return;
    }

    if (password.length < 6) {
        showMessage("Password must be at least 6 characters long.", "error");
        return;
    }

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.querySelector("span").textContent = "Registering user...";
    }
    showMessage("Creating user credentials and setting security role...", "loading");

    try {
        const headers = { "Content-Type": "application/json" };

        // If an administrator is currently logged in, attach token
        try {
            const token = window.sessionStorage.getItem("sqp_admin_token") ||
                          window.sessionStorage.getItem("sqp_id_token");
            if (token) {
                headers["Authorization"] = `Bearer ${token}`;
            }
        } catch (_e) {}

        const res = await fetch("/api/register", {
            method: "POST",
            headers,
            body: JSON.stringify({ email, password, displayName, role })
        });

        const data = await res.json();

        if (!res.ok || !data.success) {
            throw new Error(data.message || "Registration failed.");
        }

        showMessage(`✓ Account created successfully for ${data.user.email} (${data.user.role})! Redirecting to sign in...`, "success");

        document.getElementById("regDisplayName").value = "";
        document.getElementById("regEmail").value = "";
        document.getElementById("regPassword").value = "";

        setTimeout(() => {
            window.location.href = "/login.html";
        }, 2200);

    } catch (err) {
        showMessage(err.message || "Registration encountered an error.", "error");
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.querySelector("span").textContent = "Register account";
        }
    }
});

function showMessage(text, type) {
    if (!msgEl) return;
    msgEl.textContent = text;
    msgEl.className = `login-message ${type}`;
    if (type === "success") {
        msgEl.style.color = "#57c6b1";
    } else if (type === "error") {
        msgEl.style.color = "#db6b61";
    } else {
        msgEl.style.color = "#e5c67f";
    }
}
