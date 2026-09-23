"use strict";

let securityPageExaminations = [];
let securitySelectedId = null;
let securityPollTimer = null;
let securityPageInitialized = false;

initializeSecurityPage();

async function initializeSecurityPage() {
    if (securityPageInitialized) {
        return;
    }

    try {
        await waitForAuth();
        await loadSecurityExaminations();
        renderSecurityPage();
        securityPageInitialized = true;
    } catch (_error) {
        renderSecurityError(
            "Unable to initialize security dashboard."
        );
    }
}

function waitForAuth() {
    return new Promise(
        (resolve, reject) => {
            const timeout =
                setTimeout(
                    () => {
                        reject(
                            new Error(
                                "Authentication service did not initialize."
                            )
                        );
                    },
                    10000
                );

            if (
                window.authReady &&
                typeof window.authReady.then === "function"
            ) {
                window.authReady
                    .then(
                        result => {
                            clearTimeout(timeout);

                            if (
                                result &&
                                result.authenticated === false
                            ) {
                                reject(
                                    new Error(
                                        "Authentication required."
                                    )
                                );
                                return;
                            }

                            resolve();
                        }
                    )
                    .catch(
                        error => {
                            clearTimeout(timeout);
                            reject(error);
                        }
                    );
                return;
            }

            let attempts = 0;

            const check = setInterval(
                () => {
                    attempts++;

                    if (
                        window.firebaseAuth &&
                        window.firebaseAuth.currentUser
                    ) {
                        clearTimeout(timeout);
                        clearInterval(check);
                        resolve();
                        return;
                    }

                    if (attempts >= 50) {
                        clearInterval(check);
                        clearTimeout(timeout);
                        reject(
                            new Error(
                                "Authenticated user is required."
                            )
                        );
                    }
                },
                200
            );
        }
    );
}

async function getAuthToken() {
    if (typeof window.getAuthToken === "function") {
        const t = await window.getAuthToken();
        if (t) return t;
    }
    const user =
        window.firebaseAuth?.currentUser;

    if (user) {
        return await user.getIdToken();
    }

    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error("Authenticated user is required.")), 6000);
        const check = setInterval(async () => {
            if (window.firebaseAuth?.currentUser) {
                clearInterval(check);
                clearTimeout(timeout);
                try {
                    resolve(await window.firebaseAuth.currentUser.getIdToken());
                } catch (e) {
                    reject(e);
                }
            }
        }, 50);
    });
}

async function securityApiRequest(url) {
    const token = await getAuthToken();

    const response = await fetch(url, {
        headers: {
            Authorization: `Bearer ${token}`
        }
    });

    const data = await parseSecurityJson(response);

    if (!response.ok) {
        throw new Error(
            data.message || "Request failed."
        );
    }

    return data;
}

async function parseSecurityJson(response) {
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
        return response.json();
    }

    const text = await response.text();
    const message = text.includes("<!DOCTYPE")
        ? "Server returned an HTML error page. Check deployment environment variables and API routing."
        : text.slice(0, 300);

    throw new Error(message || "Server returned a non-JSON response.");
}

async function loadSecurityExaminations() {
    const data = await securityApiRequest(
        "/api/examinations"
    );

    securityPageExaminations =
        Array.isArray(data.examinations)
            ? data.examinations
            : [];

    if (securityPageExaminations.length > 0) {
        securitySelectedId =
            securityPageExaminations[0].id;
    }
}

function renderSecurityPage() {
    const container =
        document.getElementById(
            "security-live-panel"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `

        <div class="security-exam-selector" style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <label for="securityExamSelect">
                    Examination
                </label>
                <select id="securityExamSelect">
                    <option value="">Select examination</option>
                </select>
            </div>
            <button id="initializeSecurityBtn" class="secondary-button" style="padding: 8px 16px; font-size: 13px;">
                Initialize Security (MPC & VDF)
            </button>
        </div>

        <div
            class="canary-alert-banner"
            id="canaryAlertBanner"
            hidden
        >

            <div class="canary-alert-icon">
                ⚠
            </div>

            <div>

                <strong>
                    CANARY TRIGGERED — RELEASE BLOCKED
                </strong>

                <span id="canaryAlertDetail">
                    A decoy fragment was accessed outside the authorized release path.
                    The examination release has been blocked and a security alert has been logged.
                </span>

            </div>

        </div>

        <div
            class="security-live-grid"
            id="securityLiveGrid"
        >

            <div class="security-module-card">

                <div class="security-module-header">

                    <span class="card-label">
                        MPC VERIFICATION
                    </span>

                    <span
                        class="security-module-badge"
                        id="mpcBadge"
                    >
                        CHECKING
                    </span>

                </div>

                <div class="security-module-body">

                    <div class="security-module-row">

                        <span>Protocol</span>

                        <strong>
                            Additive Secret-Sharing MPC
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Status</span>

                        <strong id="mpcStatus">
                            —
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Manifest hash</span>

                        <strong
                            class="security-module-hash"
                            id="mpcHash"
                        >
                            —
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Fragments covered</span>

                        <strong id="mpcFragments">
                            —
                        </strong>

                    </div>

                </div>

            </div>

            <div class="security-module-card">

                <div class="security-module-header">

                    <span class="card-label">
                        VDF TIME-LOCK
                    </span>

                    <span
                        class="security-module-badge"
                        id="vdfBadge"
                    >
                        CHECKING
                    </span>

                </div>

                <div class="security-module-body">

                    <div class="security-module-row">

                        <span>Algorithm</span>

                        <strong id="vdfAlgorithm">
                            Wesolowski RSA VDF
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>RSA modulus</span>

                        <strong id="vdfNid">
                            RSA-2048-challenge
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Squarings (T)</span>

                        <strong id="vdfIterations">
                            —
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Proof (π prefix)</span>

                        <strong
                            class="security-module-hash"
                            id="vdfProof"
                        >
                            —
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Verify time</span>

                        <strong id="vdfVerifyMs">
                            —
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Release time</span>

                        <strong id="vdfReleaseTime">
                            —
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Time gate</span>

                        <strong id="vdfTimeGate">
                            —
                        </strong>

                    </div>

                </div>

            </div>

            <div class="security-module-card">

                <div class="security-module-header">

                    <span class="card-label">
                        CANARY DETECTION
                    </span>

                    <span
                        class="security-module-badge"
                        id="canaryBadge"
                    >
                        CHECKING
                    </span>

                </div>

                <div class="security-module-body">

                    <div class="security-module-row">

                        <span>Detection status</span>

                        <strong id="canaryStatus">
                            —
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Trigger action</span>

                        <strong>
                            Block release + audit log
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Canary ID</span>

                        <strong
                            class="security-module-hash"
                            id="canaryId"
                        >
                            —
                        </strong>

                    </div>

                </div>

            </div>

            <div class="security-module-card">

                <div class="security-module-header">

                    <span class="card-label">
                        THRESHOLD CUSTODY
                    </span>

                    <span
                        class="security-module-badge"
                        id="custodyBadge"
                    >
                        CHECKING
                    </span>

                </div>

                <div class="security-module-body">

                    <div class="security-module-row">

                        <span>Algorithm</span>

                        <strong>
                            Shamir Secret Sharing
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Threshold</span>

                        <strong>
                            3 of 5 shares
                        </strong>

                    </div>

                    <div class="security-module-row">

                        <span>Fingerprint</span>

                        <strong id="custodyFingerprint">
                            —
                        </strong>

                    </div>

                </div>

            </div>

        </div>

        <div
            class="security-empty-state"
            id="securityEmptyState"
            hidden
        >

            <p>
                Select an examination to load its security status.
            </p>

        </div>

    `;

    populateSecurityExamSelect();

    const select =
        document.getElementById(
            "securityExamSelect"
        );

    if (select) {
        select.addEventListener(
            "change",
            async event => {
                securitySelectedId =
                    event.target.value || null;

                stopSecurityPoll();

                if (!securitySelectedId) {
                    clearSecurityPanel();
                    return;
                }

                await loadSecurityStatus();
                startSecurityPoll();
            }
        );
    }

    const initBtn = document.getElementById("initializeSecurityBtn");
    if (initBtn) {
        initBtn.addEventListener("click", async () => {
            if (!securitySelectedId) {
                alert("Please select an examination first.");
                return;
            }
            initBtn.disabled = true;
            initBtn.textContent = "Initializing MPC & VDF...";
            try {
                const token = await getAuthToken();
                const response = await fetch("/api/security/initialize", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + token
                    },
                    body: JSON.stringify({ examinationId: securitySelectedId })
                });
                const data = await parseSecurityJson(response);
                if (data.success) {
                    alert("Cryptographic security initialized successfully! MPC manifest and VDF time-lock verified.");
                    await loadSecurityStatus();
                } else {
                    alert(data.message || "Security initialization failed.");
                }
            } catch (err) {
                alert("Error: " + err.message);
            } finally {
                initBtn.disabled = false;
                initBtn.textContent = "Initialize Security (MPC & VDF)";
            }
        });
    }

    if (securitySelectedId) {
        if (select) {
            select.value = securitySelectedId;
        }

        loadSecurityStatus();
        startSecurityPoll();
    } else {
        clearSecurityPanel();
    }
}

function populateSecurityExamSelect() {
    const select =
        document.getElementById(
            "securityExamSelect"
        );

    if (!select) {
        return;
    }

    select.innerHTML =
        `<option value="">Select examination</option>`;

    securityPageExaminations.forEach(
        exam => {
            const option =
                document.createElement("option");

            option.value = exam.id;

            option.textContent =
                `${exam.code || "EXAM"} — ${exam.title || "Examination"}`;

            select.appendChild(option);
        }
    );
}

async function loadSecurityStatus() {
    if (!securitySelectedId) {
        return;
    }

    try {
        const data = await securityApiRequest(
            `/api/security/status/${encodeURIComponent(securitySelectedId)}`
        );

        renderSecurityStatus(
            data.security || {}
        );

    } catch (_error) {
        clearSecurityPanel();
    }
}

function renderSecurityStatus(security) {
    const mpc =
        security.mpc || {};

    const vdf =
        security.vdf || {};

    const canary =
        security.canary || {};

    const custody =
        security.custody || {};

    const fragments =
        security.fragments || {};

    const canaryTriggered =
        canary.status === "TRIGGERED";

    const banner =
        document.getElementById(
            "canaryAlertBanner"
        );

    if (banner) {
        banner.hidden = !canaryTriggered;
    }

    const mpcConfigured = mpc.configured === true;
    const mpcVerified = mpc.verified === true;

    setBadge(
        "mpcBadge",
        mpcVerified
            ? "VERIFIED"
            : mpcConfigured
                ? "PENDING"
                : "NOT CONFIGURED",
        mpcVerified
            ? "badge-pass"
            : mpcConfigured
                ? "badge-warn"
                : "badge-fail"
    );

    setText(
        "mpcStatus",
        mpcVerified
            ? "Verified"
            : mpcConfigured
                ? "Computed — awaiting re-verify"
                : "Not initialized"
    );

    setText(
        "mpcHash",
        mpc.manifestHash
            ? truncateHash(mpc.manifestHash)
            : "—"
    );

    setText(
        "mpcFragments",
        fragments.total !== undefined
            ? `${fragments.total} fragments covered`
            : "—"
    );

    const vdfConfigured = vdf.configured === true;
    const vdfVerified = vdf.verified === true;
    const timeGateOpen = vdf.timeGateOpen === true;

    setBadge(
        "vdfBadge",
        vdfVerified
            ? "WESOLOWSKI — VERIFIED"
            : vdfConfigured
                ? timeGateOpen
                    ? "TIME GATE OPEN"
                    : "LOCKED"
                : "NOT CONFIGURED",
        vdfVerified
            ? "badge-pass"
            : vdfConfigured
                ? "badge-warn"
                : "badge-fail"
    );

    setText(
        "vdfAlgorithm",
        vdf.algorithm || "Wesolowski RSA VDF"
    );

    setText(
        "vdfNid",
        vdf.N_id || "RSA-2048-challenge"
    );

    setText(
        "vdfIterations",
        vdf.iterations
            ? Number(vdf.iterations).toLocaleString("en-IN") + " squarings"
            : "—"
    );

    setText(
        "vdfProof",
        vdf.proof
            ? vdf.proof + "…"
            : "—"
    );

    setText(
        "vdfVerifyMs",
        vdf.verifyMs !== undefined
            ? `${vdf.verifyMs} ms`
            : "—"
    );

    setText(
        "vdfReleaseTime",
        vdf.releaseTime
            ? formatDateTime(new Date(vdf.releaseTime))
            : "—"
    );

    setText(
        "vdfTimeGate",
        vdfConfigured
            ? timeGateOpen
                ? "OPEN"
                : "LOCKED"
            : "—"
    );

    setBadge(
        "canaryBadge",
        canaryTriggered
            ? "TRIGGERED"
            : "CLEAR",
        canaryTriggered
            ? "badge-alert"
            : "badge-pass"
    );

    setText(
        "canaryStatus",
        canaryTriggered
            ? "TRIGGERED — release blocked"
            : "CLEAR — no unauthorized access"
    );

    const examination =
        securityPageExaminations.find(
            e => e.id === securitySelectedId
        );

    const lastCanaryId =
        examination?.security?.lastCanaryId ||
        null;

    setText(
        "canaryId",
        canaryTriggered && lastCanaryId
            ? truncateHash(lastCanaryId)
            : canaryTriggered
                ? "See audit log"
                : "—"
    );

    const custodyVerified =
        custody.verified === true;

    setBadge(
        "custodyBadge",
        custodyVerified
            ? "VERIFIED"
            : "PENDING",
        custodyVerified
            ? "badge-pass"
            : "badge-warn"
    );

    setText(
        "custodyFingerprint",
        custodyVerified
            ? "Fingerprint verified"
            : "Not yet verified"
    );
}

function clearSecurityPanel() {
    const ids = [
        "mpcBadge",
        "vdfBadge",
        "canaryBadge",
        "custodyBadge"
    ];

    ids.forEach(id => {
        setBadge(id, "—", "badge-neutral");
    });

    const textIds = [
        "mpcStatus",
        "mpcHash",
        "mpcFragments",
        "vdfAlgorithm",
        "vdfNid",
        "vdfIterations",
        "vdfProof",
        "vdfVerifyMs",
        "vdfReleaseTime",
        "vdfTimeGate",
        "canaryStatus",
        "canaryId",
        "custodyFingerprint"
    ];

    textIds.forEach(id => {
        setText(id, "—");
    });

    const banner =
        document.getElementById(
            "canaryAlertBanner"
        );

    if (banner) {
        banner.hidden = true;
    }
}

function renderSecurityError(message) {
    const container =
        document.getElementById(
            "security-live-panel"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="release-result release-result-error">

            <div class="release-result-icon">
                ×
            </div>

            <div>

                <strong>
                    Security dashboard unavailable
                </strong>

                <span>
                    ${escapeHtml(message)}
                </span>

            </div>

        </div>
    `;
}

function startSecurityPoll() {
    stopSecurityPoll();

    securityPollTimer = setInterval(
        () => {
            if (securitySelectedId) {
                loadSecurityStatus();
            }
        },
        30000
    );
}

function stopSecurityPoll() {
    if (securityPollTimer) {
        clearInterval(securityPollTimer);
        securityPollTimer = null;
    }
}

function setBadge(id, text, className) {
    const el = document.getElementById(id);

    if (!el) {
        return;
    }

    el.textContent = text;

    el.className = `security-module-badge ${className || ""}`.trim();
}

function setText(id, value) {
    const el = document.getElementById(id);

    if (el) {
        el.textContent = value;
    }
}

function truncateHash(hash) {
    if (!hash || hash.length <= 16) {
        return hash || "—";
    }

    return `${hash.slice(0, 8)}…${hash.slice(-8)}`;
}

function formatDateTime(date) {
    if (
        !(date instanceof Date) ||
        Number.isNaN(date.getTime())
    ) {
        return "—";
    }

    return date.toLocaleString(
        "en-IN",
        {
            dateStyle: "medium",
            timeStyle: "short"
        }
    );
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
