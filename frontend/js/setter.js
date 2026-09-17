"use strict";

let setterToken = null;
let setterSelectedExamId = null;
let setterSelectedExamCode = "";
let setterUploadWired = false;


async function initSetterPage() {
    try {
        await window.authReady;
        if (!window.firebaseAuth?.currentUser) { return; }
        setterToken = await window.firebaseAuth.currentUser.getIdToken();
        const user = window.firebaseAuth.currentUser;
        const a = document.getElementById('setterAvatar');
        const n = document.getElementById('setterName');
        const e = document.getElementById('setterEmail');
        if (a && user.email) a.textContent = user.email[0].toUpperCase();
        if (n) n.textContent = user.displayName || 'Question Setter';
        if (e) e.textContent = user.email || '';
        await loadSetterExams();
    } catch (_error) {
        showSetterMsg('Unable to load setter portal: ' + _error.message, 'error');
    }
}


function waitForSetterAuth() {

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
                    .then(token => {
                        setterToken = token;
                        const user = window.firebaseAuth.currentUser;
                        const avatarEl = document.getElementById("setterAvatar");
                        const nameEl   = document.getElementById("setterName");
                        const emailEl  = document.getElementById("setterEmail");
                        if (avatarEl && user.email) avatarEl.textContent = user.email[0].toUpperCase();
                        if (nameEl)  nameEl.textContent  = user.displayName || "Question Setter";
                        if (emailEl) emailEl.textContent = user.email || "";
                        resolve();
                    })
                    .catch(reject);
            } else {
                clearTimeout(timeout);
                reject(new Error("Not authenticated."));
            }
        }

        if (window.authReady && typeof window.authReady.then === "function") {
            window.authReady
                .then(result => {
                    if (result && result.authenticated === false) {
                        clearTimeout(timeout);
                        reject(new Error("Authentication required."));
                        return;
                    }
                    resolveWithToken();
                })
                .catch(err => { clearTimeout(timeout); reject(err); });
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


async function loadSetterExams() {

    const listEl = document.getElementById("setterExamList");

    try {

        const res = await fetch("/api/setter/my-exams", {
            headers: {
                Authorization: `Bearer ${setterToken}`
            }
        });

        const data = await res.json();

        if (!data.success) {
            throw new Error(
                data.message || "Failed to load examinations."
            );
        }

        const exams = data.examinations || [];

        if (!exams.length) {
            if (listEl) {
                listEl.innerHTML = `
                    <div class="portal-empty">
                        No examinations have been assigned to your account yet.
                        Contact your administrator.
                    </div>
                `;
            }
            return;
        }

        if (listEl) {
            listEl.innerHTML = exams.map(exam => `
                <div
                    class="exam-assignment-row"
                    data-id="${esc(exam.id)}"
                    data-code="${esc(exam.code || "")}"
                    onclick="selectSetterExam(
                        '${esc(exam.id)}',
                        '${esc(exam.code || "")}',
                        '${esc(exam.name || "")}'
                    )"
                >

                    <div class="exam-assignment-info">
                        <strong>${esc(exam.code || exam.id)}</strong>
                        <span>${esc(exam.name || "")}</span>
                    </div>

                    <div class="exam-assignment-status">
                        <span class="security-module-badge badge-neutral">
                            ${esc(exam.status || "active")}
                        </span>
                        <b>&#8250;</b>
                    </div>

                </div>
            `).join("");
        }

    } catch (_err) {
        if (listEl) {
            listEl.innerHTML = `
                <div class="portal-empty portal-error">
                    Failed to load examinations.
                </div>
            `;
        }
    }
}


function selectSetterExam(examId, examCode, examName) {

    setterSelectedExamId = examId;
    setterSelectedExamCode = examCode;

    document.querySelectorAll(".exam-assignment-row")
        .forEach(r => r.classList.remove("selected"));

    const row = document.querySelector(
        `.exam-assignment-row[data-id="${examId}"]`
    );
    if (row) {
        row.classList.add("selected");
    }

    const uploadPanel =
        document.getElementById("setterUploadPanel");
    const historyPanel =
        document.getElementById("setterFragmentHistory");
    const labelEl =
        document.getElementById("setterUploadLabel");
    const badgeEl =
        document.getElementById("setterUploadBadge");

    if (uploadPanel) uploadPanel.style.display = "";
    if (historyPanel) historyPanel.style.display = "";

    if (labelEl) {
        labelEl.textContent = `UPLOAD FRAGMENT — ${examCode}`;
    }

    if (badgeEl) {
        badgeEl.textContent = examCode;
        badgeEl.className = "security-module-badge badge-warn";
    }

    if (!setterUploadWired) {
        document.getElementById("setterUploadButton")
            ?.addEventListener("click", handleSetterUpload);
        setterUploadWired = true;
    }

    loadSetterFragments();
}

window.selectSetterExam = selectSetterExam;


async function handleSetterUpload() {

    const titleEl   = document.getElementById("setterFragmentTitle");
    const contentEl = document.getElementById("setterFragmentContent");
    const msgEl     = document.getElementById("setterUploadMessage");
    const btn       = document.getElementById("setterUploadButton");

    const title   = titleEl?.value?.trim();
    const content = contentEl?.value?.trim();

    if (!title || !content) {
        showSetterMsg("Enter both a title and content.", "error");
        return;
    }

    if (!setterSelectedExamId) {
        showSetterMsg("Select an examination first.", "error");
        return;
    }

    if (btn) {
        btn.disabled = true;
        btn.querySelector("span").textContent =
            "Encrypting and uploading...";
    }

    showSetterMsg("Encrypting fragment...", "loading");

    try {

        const res = await fetch("/api/fragments", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${setterToken}`
            },
            body: JSON.stringify({
                examinationId: setterSelectedExamId,
                title,
                content,
                isDecoy: false
            })
        });

        const data = await res.json();

        if (!res.ok || !data.success) {
            throw new Error(data.message || "Upload failed.");
        }

        showSetterMsg(
            "\u2713 Fragment encrypted and uploaded successfully.",
            "success"
        );

        if (titleEl)   titleEl.value   = "";
        if (contentEl) contentEl.value = "";

        await loadSetterFragments();

    } catch (_err) {
        showSetterMsg(_err.message, "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.querySelector("span").textContent =
                "Encrypt and upload fragment";
        }
    }
}


async function loadSetterFragments() {

    if (!setterSelectedExamId) {
        return;
    }

    const listEl  = document.getElementById("setterFragmentList");
    const countEl = document.getElementById("setterFragmentCount");

    try {

        const res = await fetch(
            `/api/fragments?examinationId=${encodeURIComponent(setterSelectedExamId)}`,
            {
                headers: {
                    Authorization: `Bearer ${setterToken}`
                }
            }
        );

        const data = await res.json();

        if (!data.success) {
            throw new Error(data.message);
        }

        const frags = (data.fragments || []).filter(f => !f.isDecoy);

        if (countEl) {
            countEl.textContent =
                `${frags.length} fragment${frags.length !== 1 ? "s" : ""}`;
        }

        if (!frags.length) {
            if (listEl) {
                listEl.innerHTML = `
                    <div class="portal-empty">
                        No fragments uploaded yet for this examination.
                    </div>
                `;
            }
            return;
        }

        if (listEl) {
            listEl.innerHTML = frags.map((f, i) => {

                const createdAt = f.createdAt
                    ? new Date(
                        f.createdAt._seconds
                            ? f.createdAt._seconds * 1000
                            : f.createdAt
                    ).toLocaleString()
                    : "";

                return `
                    <div class="setter-fragment-row">

                        <div class="setter-fragment-num">
                            ${i + 1}
                        </div>

                        <div class="setter-fragment-info">
                            <strong>${esc(f.title || "Untitled")}</strong>
                            <span>
                                ${esc(f.encryptionAlgorithm || "AES-256-GCM")}
                                &bull; ${esc(createdAt)}
                            </span>
                        </div>

                        <span class="security-module-badge badge-pass">
                            ENCRYPTED
                        </span>

                    </div>
                `;
            }).join("");
        }

    } catch (_err) {
        if (listEl) {
            listEl.innerHTML = `
                <div class="portal-empty portal-error">
                    Failed to load fragments.
                </div>
            `;
        }
    }
}


function showSetterMsg(msg, type) {
    const el = document.getElementById("setterUploadMessage");
    if (el) {
        el.textContent = msg;
        el.className = `form-message ${type}`;
    }
}


function esc(v) {
    return String(v ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


initSetterPage();

