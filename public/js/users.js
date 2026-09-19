"use strict";

let usersToken = null;
let allUsers = [];

async function initUsersPage() {
    try {
        await window.authReady;
        const token = typeof window.getAuthToken === "function"
            ? await window.getAuthToken()
            : await window.firebaseAuth?.currentUser?.getIdToken();
        if (!token) { return; }
        usersToken = token;
        await Promise.all([loadAllUsers(), loadExamsForAssign()]);
        wireUsersEvents();
    } catch (_error) {
        showUsersError("Unable to load users page: " + _error.message);
    }
}

function waitForUsersToken() {
    return new Promise((resolve, reject) => {
        window.firebaseAuth.currentUser
            .getIdToken()
            .then(t => { usersToken = t; resolve(); })
            .catch(reject);
    });
}

function waitForUsersAuth() {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(
            () => reject(new Error("Authentication timeout.")),
            12000
        );

        function resolveWithToken() {
            if (window.firebaseAuth && window.firebaseAuth.currentUser) {
                clearTimeout(timeout);
                window.firebaseAuth.currentUser
                    .getIdToken()
                    .then(t => { usersToken = t; resolve(); })
                    .catch(reject);
            } else {
                clearTimeout(timeout);
                reject(new Error("Not authenticated. Please log in."));
            }
        }

        if (
            window.authReady &&
            typeof window.authReady.then === "function"
        ) {
            window.authReady
                .then(result => {
                    if (result && result.authenticated === false) {
                        clearTimeout(timeout);
                        reject(new Error("Authentication required."));
                        return;
                    }
                    resolveWithToken();
                })
                .catch(err => {
                    clearTimeout(timeout);
                    reject(err);
                });
        } else {
            let attempts = 0;
            const poll = setInterval(() => {
                attempts++;
                if (window.firebaseAuth && window.firebaseAuth.currentUser) {
                    clearInterval(poll);
                    resolveWithToken();
                } else if (attempts >= 80) {
                    clearInterval(poll);
                    clearTimeout(timeout);
                    reject(new Error("Authentication timeout."));
                }
            }, 150);
        }
    });
}

async function loadAllUsers() {
    const bodyEl = document.getElementById("usersListBody");
    try {
        const res  = await fetch("/api/admin/users", { headers: { Authorization: `Bearer ${usersToken}` } });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);
        allUsers = data.users || [];
        renderUsersList(allUsers);
        populateAssignUserSelect(allUsers);
    } catch (_err) {
        if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty portal-error">Failed to load users: ${escUHtml(_err.message)}</div>`;
    }
}

function renderUsersList(users) {
    const bodyEl = document.getElementById("usersListBody");
    if (!bodyEl) return;
    if (!users.length) {
        bodyEl.innerHTML = `<div class="portal-empty">No users found.</div>`;
        return;
    }
    const ROLE_BADGE = {
        admin: "badge-admin",
        setter: "badge-setter",
        custodian: "badge-custodian",
        "print-operator": "badge-print-operator"
    };
    bodyEl.innerHTML = users.map(u => `
        <div class="user-row">
            <div class="user-row-avatar">${escUHtml((u.email || "?")[0].toUpperCase())}</div>
            <div class="user-row-info">
                <strong>${escUHtml(u.displayName || u.email)}</strong>
                <span>${escUHtml(u.email)}</span>
            </div>
            <span class="security-module-badge ${ROLE_BADGE[u.role] || "badge-neutral"}">${escUHtml(u.role)}</span>
            <button class="share-download-btn delete-user-btn" data-uid="${escUHtml(u.uid)}" type="button">Delete</button>
        </div>
    `).join("");

    bodyEl.querySelectorAll(".delete-user-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            const uid = btn.dataset.uid;
            if (!uid) return;
            btn.disabled = true;
            btn.textContent = "Deleting...";
            try {
                const res  = await fetch(`/api/admin/users/${uid}`, { method: "DELETE", headers: { Authorization: `Bearer ${usersToken}` } });
                const data = await res.json();
                if (!data.success) throw new Error(data.message);
                await loadAllUsers();
            } catch (_err) {
                btn.disabled = false;
                btn.textContent = "Delete";
                showUsersError(_err.message);
            }
        });
    });
}

async function loadExamsForAssign() {
    const sel = document.getElementById("assignExamSelect");
    try {
        const res  = await fetch("/api/examinations", { headers: { Authorization: `Bearer ${usersToken}` } });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);
        if (sel) {
            sel.innerHTML = `<option value="">Select examination</option>` +
                (data.examinations || []).map(e =>
                    `<option value="${escUHtml(e.id)}">${escUHtml(e.code || e.id)} — ${escUHtml(e.name || e.title || "")}</option>`
                ).join("");
        }
    } catch (_err) {
        if (sel) sel.innerHTML = `<option value="">Failed to load exams</option>`;
    }
}

function populateAssignUserSelect(users) {
    const sel = document.getElementById("assignUserSelect");
    if (!sel) return;
    sel.innerHTML = `<option value="">Select user</option>` +
        users.filter(u => u.role !== "admin").map(u =>
            `<option value="${escUHtml(u.uid)}" data-role="${escUHtml(u.role)}">${escUHtml(u.displayName || u.email)} (${escUHtml(u.role)})</option>`
        ).join("");
}

function wireUsersEvents() {
    document.getElementById("createUserButton")?.addEventListener("click", handleCreateUser);
    document.getElementById("refreshUsersButton")?.addEventListener("click", loadAllUsers);
    document.getElementById("assignButton")?.addEventListener("click", handleAssign);

    document.getElementById("assignUserSelect")?.addEventListener("change", () => {
        const sel     = document.getElementById("assignUserSelect");
        const opt     = sel?.selectedOptions[0];
        const role    = opt?.dataset.role || "";
        const shareF  = document.getElementById("shareNumberField");
        if (shareF) shareF.style.display = role === "custodian" ? "" : "none";
    });
}

async function handleCreateUser() {
    const email       = document.getElementById("newUserEmail")?.value?.trim();
    const password    = document.getElementById("newUserPassword")?.value;
    const displayName = document.getElementById("newUserDisplayName")?.value?.trim();
    const role        = document.getElementById("newUserRole")?.value;
    const msgEl       = document.getElementById("createUserMessage");
    const btn         = document.getElementById("createUserButton");

    if (!email || !password || !role) {
        if (msgEl) { msgEl.textContent = "Email, password, and role are required."; msgEl.className = "form-message error"; }
        return;
    }

    if (btn) { btn.disabled = true; btn.querySelector("span").textContent = "Creating..."; }
    if (msgEl) { msgEl.textContent = "Creating user..."; msgEl.className = "form-message loading"; }

    try {
        const res  = await fetch("/api/admin/users/create", {
            method:  "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${usersToken}` },
            body:    JSON.stringify({ email, password, displayName, role })
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || "Failed to create user.");

        if (msgEl) { msgEl.textContent = `\u2713 User created: ${data.user.email} (${data.user.role})`; msgEl.className = "form-message success"; }
        const emailInput = document.getElementById("newUserEmail");
        const passwordInput = document.getElementById("newUserPassword");
        const nameInput = document.getElementById("newUserDisplayName");
        if (emailInput) emailInput.value = "";
        if (passwordInput) passwordInput.value = "";
        if (nameInput) nameInput.value = "";

        await loadAllUsers();
    } catch (_err) {
        if (msgEl) { msgEl.textContent = _err.message; msgEl.className = "form-message error"; }
    } finally {
        if (btn) { btn.disabled = false; btn.querySelector("span").textContent = "Create user"; }
    }
}

async function handleAssign() {
    const examId      = document.getElementById("assignExamSelect")?.value;
    const userSel     = document.getElementById("assignUserSelect");
    const uid         = userSel?.value;
    const role        = userSel?.selectedOptions[0]?.dataset.role || "";
    const shareNumber = document.getElementById("assignShareNumber")?.value;
    const msgEl       = document.getElementById("assignMessage");
    const btn         = document.getElementById("assignButton");

    if (!examId || !uid) {
        if (msgEl) { msgEl.textContent = "Select both an examination and a user."; msgEl.className = "form-message error"; }
        return;
    }

    if (btn) { btn.disabled = true; btn.querySelector("span").textContent = "Assigning..."; }
    if (msgEl) { msgEl.textContent = "Assigning..."; msgEl.className = "form-message loading"; }

    try {
        let endpoint = "";
        let body = { examinationId: examId };

        if (role === "setter")              { endpoint = "/api/admin/assign-setter";          body.setterUid    = uid; }
        else if (role === "custodian")      { endpoint = "/api/admin/assign-custodian";       body.custodianUid = uid; body.shareNumber = Number(shareNumber); }
        else if (role === "print-operator") { endpoint = "/api/admin/assign-print-operator";  body.operatorUid  = uid; }
        else { throw new Error("Cannot assign this role type."); }

        const res  = await fetch(endpoint, {
            method:  "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${usersToken}` },
            body:    JSON.stringify(body)
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || "Assignment failed.");

        if (msgEl) { msgEl.textContent = `\u2713 ${data.message}`; msgEl.className = "form-message success"; }
    } catch (_err) {
        if (msgEl) { msgEl.textContent = _err.message; msgEl.className = "form-message error"; }
    } finally {
        if (btn) { btn.disabled = false; btn.querySelector("span").textContent = "Assign to exam"; }
    }
}

function showUsersError(msg) {
    const bodyEl = document.getElementById("usersListBody");
    if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty portal-error">${escUHtml(msg)}</div>`;
}

function escUHtml(v) {
    return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

initUsersPage();
