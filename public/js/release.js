"use strict";

let examinations = [];
let selectedExaminationId = null;
let releaseStatus = null;
let releaseTimer = null;
let releasePageInitialized = false;

initializeReleasePage();

async function initializeReleasePage() {
    if (releasePageInitialized) {
        return;
    }

    try {
        await waitForShell();
        await waitForAuthentication();
        await loadExaminations();
        renderReleasePage();

        releasePageInitialized = true;

    } catch (error) {

        showPageError(
            error.message ||
            "Unable to initialize secure release."
        );
    }
}

function waitForShell() {
    return new Promise(
        resolve => {
            const existing =
                document.getElementById(
                    "rendered-content"
                );

            if (existing) {
                resolve();
                return;
            }

            document.addEventListener(
                "secureCustodyShellReady",
                () => {
                    resolve();
                },
                {
                    once: true
                }
            );

            setTimeout(
                () => {
                    const container =
                        document.getElementById(
                            "rendered-content"
                        );

                    if (container) {
                        resolve();
                    }
                },
                3000
            );
        }
    );
}

function waitForAuthentication() {
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
                typeof window.authReady.then ===
                    "function"
            ) {
                window.authReady
                    .then(
                        result => {
                            clearTimeout(
                                timeout
                            );

                            if (
                                result &&
                                result.authenticated ===
                                    false
                            ) {
                                reject(
                                    new Error(
                                        "Administrator authentication is required."
                                    )
                                );

                                return;
                            }

                            if (
                                !window.firebaseAuth ||
                                !window.firebaseAuth.currentUser
                            ) {
                                reject(
                                    new Error(
                                        "Authenticated Firebase user is required."
                                    )
                                );

                                return;
                            }

                            resolve();
                        }
                    )
                    .catch(
                        error => {
                            clearTimeout(
                                timeout
                            );

                            reject(
                                error
                            );
                        }
                    );

                return;
            }

            let attempts = 0;

            const checkAuth =
                setInterval(
                    () => {
                        attempts++;

                        if (
                            window.firebaseAuth &&
                            window.firebaseAuth.currentUser
                        ) {
                            clearTimeout(
                                timeout
                            );

                            clearInterval(
                                checkAuth
                            );

                            resolve();

                            return;
                        }

                        if (
                            attempts >=
                            50
                        ) {
                            clearInterval(
                                checkAuth
                            );

                            clearTimeout(
                                timeout
                            );

                            reject(
                                new Error(
                                    "Authenticated Firebase user is required."
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
    const user =
        window.firebaseAuth?.currentUser;

    if (!user) {
        throw new Error(
            "Authenticated Firebase user is required."
        );
    }

    return await user.getIdToken(
        true
    );
}

async function apiRequest(
    url,
    options = {}
) {
    const token =
        await getAuthToken();

    const headers = {
        Authorization:
            `Bearer ${token}`,

        ...(options.body
            ? {
                "Content-Type":
                    "application/json"
            }
            : {}),

        ...(options.headers || {})
    };

    const response =
        await fetch(
            url,
            {
                ...options,
                headers
            }
        );

    let data;

    try {
        data =
            await response.json();

    } catch {
        throw new Error(
            "Server returned an invalid response."
        );
    }

    if (!response.ok) {
        throw new Error(
            data.message ||
            "Request failed."
        );
    }

    return data;
}

async function loadExaminations() {
    const data =
        await apiRequest(
            "/api/examinations"
        );

    examinations =
        Array.isArray(
            data.examinations
        )
            ? data.examinations
            : [];

    if (
        examinations.length >
        0
    ) {
        selectedExaminationId =
            examinations[0].id;
    }
}

function renderReleasePage() {
    const container =
        document.getElementById(
            "rendered-content"
        );

    if (!container) {
        throw new Error(
            "Release content container was not found."
        );
    }

    container.innerHTML = `
        <div class="page">

            <section class="page-intro">

                <div>

                    <div class="eyebrow">
                        CONTROLLED RELEASE
                    </div>

                    <h1>
                        Secure Release
                    </h1>

                    <p>
                        Release protected examination fragments only after the
                        configured time gate and threshold custody requirements are satisfied.
                    </p>

                </div>

            </section>

            <section class="large-panel release-panel">

                <div class="panel-header">

                    <div>

                        <div class="eyebrow">
                            RELEASE CONTROL
                        </div>

                        <h2>
                            Time-gated examination release
                        </h2>

                        <p>
                            The protected question paper remains encrypted until
                            the controlled release process is authorized.
                        </p>

                    </div>

                    <div
                        class="release-state"
                        id="releaseState"
                    >

                        <span class="state-dot"></span>

                        <span id="releaseStateText">
                            LOCKED
                        </span>

                    </div>

                </div>

                <div class="panel-body release-panel-content">

                    <div class="release-examination">

                        <label for="releaseExamination">
                            Examination
                        </label>

                        <select id="releaseExamination">
                            <option value="">
                                Select examination
                            </option>
                        </select>

                    </div>

                    <div id="releaseResult"></div>

                    <div class="release-details">

                        <div class="release-time-card">

                            <div class="release-label">
                                RELEASE TIME
                            </div>

                            <div
                                class="release-value"
                                id="releaseTime"
                            >
                                NOT CONFIGURED
                            </div>

                        </div>

                        <div class="release-time-card">

                            <div class="release-label">
                                CURRENT TIME
                            </div>

                            <div
                                class="release-value"
                                id="currentTime"
                            >
                                —
                            </div>

                        </div>

                        <div class="release-time-card">

                            <div class="release-label">
                                TIME GATE
                            </div>

                            <div
                                class="release-value"
                                id="timeGate"
                            >
                                LOCKED
                            </div>

                        </div>

                    </div>

                    <div class="release-security-grid">

                        <div class="release-security-item">

                            <span class="security-label">
                                THRESHOLD CUSTODY
                            </span>

                            <strong id="custodyStatus">
                                CHECKING
                            </strong>

                            <small>
                                3 of 5 required
                            </small>

                        </div>

                        <div class="release-security-item">

                            <span class="security-label">
                                ENCRYPTED FRAGMENTS
                            </span>

                            <strong id="fragmentStatus">
                                CHECKING
                            </strong>

                            <small>
                                Protected question fragments
                            </small>

                        </div>

                        <div class="release-security-item">

                            <span class="security-label">
                                PLAINTEXT
                            </span>

                            <strong id="plaintextStatus">
                                NONE
                            </strong>

                            <small>
                                No plaintext persisted
                            </small>

                        </div>

                        <div class="release-security-item">

                            <span class="security-label">
                                RELEASE STATUS
                            </span>

                            <strong id="authorizationStatus">
                                REQUIRED
                            </strong>

                            <small>
                                Controlled release execution
                            </small>

                        </div>

                    </div>

                    <div class="release-action-row">

                        <div>

                            <div class="release-action-label">
                                CONTROLLED RELEASE
                            </div>

                            <p id="releaseMessage">
                                Select an examination to inspect its release state.
                            </p>

                        </div>

                        <button
                            id="authorizeReleaseButton"
                            class="primary-button"
                            type="button"
                            disabled
                        >
                            Release Locked
                        </button>

                    </div>

                </div>

            </section>

            <section class="large-panel release-audit-panel">

                <div class="panel-header">

                    <div>

                        <div class="eyebrow">
                            SECURITY RECORD
                        </div>

                        <h2>
                            Release conditions
                        </h2>

                        <p>
                            Every condition must pass before the protected
                            question paper can enter the controlled release path.
                        </p>

                    </div>

                </div>

                <div class="panel-body release-panel-content">

                    <div class="release-condition-list">

                        <div class="release-condition">

                            <span class="condition-number">
                                01
                            </span>

                            <div>

                                <strong>
                                    Time gate
                                </strong>

                                <span>
                                    The configured examination release time must be reached.
                                </span>

                            </div>

                            <b id="conditionTime">
                                LOCKED
                            </b>

                        </div>

                        <div class="release-condition">

                            <span class="condition-number">
                                02
                            </span>

                            <div>

                                <strong>
                                    Threshold custody
                                </strong>

                                <span>
                                    At least 3 of the 5 protected shares must reconstruct
                                    the registered AES-256 key.
                                </span>

                            </div>

                            <b id="conditionCustody">
                                PENDING
                            </b>

                        </div>

                        <div class="release-condition">

                            <span class="condition-number">
                                03
                            </span>

                            <div>

                                <strong>
                                    Encrypted fragments
                                </strong>

                                <span>
                                    All protected fragments must use the examination custody key.
                                </span>

                            </div>

                            <b id="conditionFragments">
                                PENDING
                            </b>

                        </div>

                        <div class="release-condition">

                            <span class="condition-number">
                                04
                            </span>

                            <div>

                                <strong>
                                    Controlled execution
                                </strong>

                                <span>
                                    The release agent reconstructs and decrypts the
                                    paper only in memory.
                                </span>

                            </div>

                            <b id="conditionAuthorization">
                                REQUIRED
                            </b>

                        </div>

                        <div class="release-condition">

                            <span class="condition-number">
                                05
                            </span>

                            <div>

                                <strong>
                                    MPC manifest verified
                                </strong>

                                <span>
                                    The additive secret-sharing MPC manifest must be
                                    computed and verified over all encrypted fragments.
                                </span>

                            </div>

                            <b id="conditionMpc">
                                PENDING
                            </b>

                        </div>

                        <div class="release-condition">

                            <span class="condition-number">
                                06
                            </span>

                            <div>

                                <strong>
                                    VDF proof verified
                                </strong>

                                <span>
                                    The sequential SHA-256 VDF commitment must be
                                    verified and the time gate must be satisfied.
                                </span>

                            </div>

                            <b id="conditionVdf">
                                PENDING
                            </b>

                        </div>

                        <div class="release-condition">

                            <span class="condition-number">
                                07
                            </span>

                            <div>

                                <strong>
                                    Canary status clear
                                </strong>

                                <span>
                                    No canary decoy fragment may have been triggered.
                                    A triggered canary permanently blocks the release.
                                </span>

                            </div>

                            <b id="conditionCanary">
                                CHECKING
                            </b>

                        </div>

                    </div>

                </div>

            </section>

        </div>
    `;

    populateExaminations();

    const examinationSelect =
        document.getElementById(
            "releaseExamination"
        );

    if (examinationSelect) {

        examinationSelect.addEventListener(
            "change",
            async event => {

                selectedExaminationId =
                    event.target.value ||
                    null;

                stopReleaseTimer();

                if (
                    !selectedExaminationId
                ) {
                    resetReleaseState();
                    return;
                }

                await inspectReleaseState();
            }
        );
    }

    const releaseButton =
        document.getElementById(
            "authorizeReleaseButton"
        );

    if (releaseButton) {

        releaseButton.addEventListener(
            "click",
            executeControlledRelease
        );
    }

    if (
        selectedExaminationId
    ) {

        if (examinationSelect) {
            examinationSelect.value =
                selectedExaminationId;
        }

        inspectReleaseState();

    } else {

        resetReleaseState();
    }
}

function populateExaminations() {
    const select =
        document.getElementById(
            "releaseExamination"
        );

    if (!select) {
        return;
    }

    select.innerHTML = `
        <option value="">
            Select examination
        </option>
    `;

    examinations.forEach(
        examination => {

            const option =
                document.createElement(
                    "option"
                );

            option.value =
                examination.id;

            option.textContent =
                `${examination.code || "EXAM"} — ${examination.title || "Examination"}`;

            select.appendChild(
                option
            );
        }
    );
}

async function inspectReleaseState() {
    if (
        !selectedExaminationId
    ) {
        return;
    }

    try {

        setLoadingState();

        const data =
            await apiRequest(
                `/api/release/status/${encodeURIComponent(
                    selectedExaminationId
                )}`
            );

        releaseStatus =
            data.release ||
            data.data ||
            data;

        updateReleaseUI(
            releaseStatus
        );

        startReleaseTimer();

    } catch (error) {

        showReleaseError(
            error.message
        );
    }
}

function updateReleaseUI(
    status
) {
    status =
        status || {};

    const releaseTime =
        status.releaseTime
            ? new Date(
                status.releaseTime
            )
            : null;

    const currentTime =
        status.currentTime
            ? new Date(
                status.currentTime
            )
            : new Date();

    const timeGateOpen =
        Boolean(
            status.timeGateOpen
        );

    const custodyVerified =
        Boolean(
            status.custodyVerified
        );

    const fragmentsReady =
        Boolean(
            status.fragmentsReady
        );

    const mpcVerified =
        Boolean(
            status.mpcVerified
        );

    const vdfVerified =
        Boolean(
            status.vdfVerified
        );

    const canaryClear =
        status.canaryClear !== false;

    const authorized =
        Boolean(
            status.authorized
        );

    const released =
        Boolean(
            status.released
        );

    setText(
        "releaseTime",
        releaseTime
            ? formatDateTime(
                releaseTime
            )
            : "NOT CONFIGURED"
    );

    setText(
        "currentTime",
        formatDateTime(
            currentTime
        )
    );

    setText(
        "timeGate",
        timeGateOpen
            ? "OPEN"
            : "LOCKED"
    );

    setText(
        "custodyStatus",
        custodyVerified
            ? "VERIFIED"
            : "PENDING"
    );

    setText(
        "fragmentStatus",
        fragmentsReady
            ? `${status.encryptedFragments || 0} / ${status.totalFragments || 0} READY`
            : `${status.encryptedFragments || 0} / ${status.totalFragments || 0} PENDING`
    );

    setText(
        "plaintextStatus",
        released
            ? "RELEASED"
            : "NONE"
    );

    setText(
        "authorizationStatus",
        released
            ? "COMPLETED"
            : authorized
                ? "AUTHORIZED"
                : "REQUIRED"
    );

    setCondition(
        "conditionTime",
        timeGateOpen
            ? "OPEN"
            : "LOCKED",
        timeGateOpen
    );

    setCondition(
        "conditionCustody",
        custodyVerified
            ? "VERIFIED"
            : "PENDING",
        custodyVerified
    );

    setCondition(
        "conditionFragments",
        fragmentsReady
            ? "READY"
            : "PENDING",
        fragmentsReady
    );

    setCondition(
        "conditionAuthorization",
        released
            ? "COMPLETED"
            : authorized
                ? "AUTHORIZED"
                : "REQUIRED",
        released || authorized
    );

    setCondition(
        "conditionMpc",
        mpcVerified
            ? "VERIFIED"
            : "PENDING",
        mpcVerified
    );

    setCondition(
        "conditionVdf",
        vdfVerified
            ? "VERIFIED"
            : "PENDING",
        vdfVerified
    );

    setCondition(
        "conditionCanary",
        canaryClear
            ? "CLEAR"
            : "BLOCKED",
        canaryClear
    );

    const allConditionsPassed =
        timeGateOpen &&
        custodyVerified &&
        fragmentsReady &&
        mpcVerified &&
        vdfVerified &&
        canaryClear;

    const stateText =
        released
            ? "RELEASED"
            : allConditionsPassed
                ? "READY"
                : "LOCKED";

    setText(
        "releaseStateText",
        stateText
    );

    const stateElement =
        document.getElementById(
            "releaseState"
        );

    if (stateElement) {

        stateElement.classList.toggle(
            "is-open",
            allConditionsPassed
        );

        stateElement.classList.toggle(
            "is-released",
            released
        );
    }

    const button =
        document.getElementById(
            "authorizeReleaseButton"
        );

    const canRelease =
        allConditionsPassed &&
        !released;

    if (button) {

        button.disabled =
            !canRelease;

        if (released) {

            button.textContent =
                "Release Completed";

        } else if (!canaryClear) {

            button.textContent =
                "Canary Blocked";

        } else if (canRelease) {

            button.textContent =
                "Execute Secure Release";

        } else {

            button.textContent =
                "Release Locked";
        }
    }

    const message =
        released
            ? "The controlled release has been completed. The plaintext paper was processed in memory and was not persisted."
            : !canaryClear
                ? "A canary decoy fragment was triggered. The release has been permanently blocked. See the audit log for details."
                : !timeGateOpen
                    ? "The examination remains locked until the configured release time."
                    : !custodyVerified
                        ? "Threshold custody verification is required before release."
                        : !fragmentsReady
                            ? "Protected fragments are not ready for controlled release."
                            : !mpcVerified
                                ? "MPC manifest verification is required before release."
                                : !vdfVerified
                                    ? "VDF proof verification is required before release."
                                    : "All release conditions are satisfied. Secure release execution is available.";

    setText(
        "releaseMessage",
        message
    );

    if (released) {

        showReleaseResult(
            "success",
            "Controlled release completed",
            `Release agent ${status.releaseAgent || "OFFLINE-AGENT"} completed the in-memory release simulation. No plaintext was persisted.`
        );

    } else if (!canaryClear) {

        showReleaseResult(
            "error",
            "Canary triggered — release blocked",
            "A decoy fragment was accessed outside the authorized release path. The release is permanently blocked."
        );

    } else if (allConditionsPassed) {

        showReleaseResult(
            "ready",
            "Controlled release available",
            "All security conditions have passed. The secure release agent can now execute."
        );

    } else {

        showReleaseResult(
            "locked",
            "Release locked",
            message
        );
    }
}

function setLoadingState() {
    setText(
        "releaseStateText",
        "CHECKING"
    );

    setText(
        "releaseTime",
        "CHECKING"
    );

    setText(
        "currentTime",
        "CHECKING"
    );

    setText(
        "timeGate",
        "CHECKING"
    );

    setText(
        "custodyStatus",
        "CHECKING"
    );

    setText(
        "fragmentStatus",
        "CHECKING"
    );

    setText(
        "plaintextStatus",
        "NONE"
    );

    setText(
        "authorizationStatus",
        "REQUIRED"
    );

    setText(
        "releaseMessage",
        "Checking release conditions..."
    );

    const button =
        document.getElementById(
            "authorizeReleaseButton"
        );

    if (button) {

        button.disabled =
            true;

        button.textContent =
            "Checking";
    }
}

async function executeControlledRelease() {
    if (
        !selectedExaminationId
    ) {
        return;
    }

    const button =
        document.getElementById(
            "authorizeReleaseButton"
        );

    if (button) {

        button.disabled =
            true;

        button.textContent =
            "Executing...";
    }

    showReleaseResult(
        "ready",
        "Controlled release in progress",
        "Verifying the time gate, reconstructing threshold custody, decrypting protected fragments in memory, and completing the release simulation."
    );

    try {

        const data =
            await apiRequest(
                "/api/release/execute",
                {
                    method:
                        "POST",

                    body:
                        JSON.stringify({
                            examinationId:
                                selectedExaminationId
                        })
                }
            );

        const result =
            data.release ||
            {};

        showReleaseResult(
            "success",
            "Controlled release completed",
            `Release agent ${result.releaseAgent || "OFFLINE-AGENT"} completed the in-memory release simulation. ${result.fragmentCount || 0} encrypted fragments were processed. Plaintext was not persisted.`
        );

        await inspectReleaseState();

    } catch (error) {

        showReleaseResult(
            "error",
            "Controlled release failed",
            error.message
        );

        await inspectReleaseState();
    }
}

function startReleaseTimer() {
    stopReleaseTimer();

    releaseTimer =
        setInterval(
            () => {

                if (
                    selectedExaminationId
                ) {
                    inspectReleaseState();
                }

            },
            15000
        );
}

function stopReleaseTimer() {
    if (releaseTimer) {

        clearInterval(
            releaseTimer
        );

        releaseTimer =
            null;
    }
}

function resetReleaseState() {
    setText(
        "releaseStateText",
        "LOCKED"
    );

    setText(
        "releaseTime",
        "NOT CONFIGURED"
    );

    setText(
        "currentTime",
        "—"
    );

    setText(
        "timeGate",
        "LOCKED"
    );

    setText(
        "custodyStatus",
        "CHECKING"
    );

    setText(
        "fragmentStatus",
        "CHECKING"
    );

    setText(
        "plaintextStatus",
        "NONE"
    );

    setText(
        "authorizationStatus",
        "REQUIRED"
    );

    setText(
        "releaseMessage",
        "Select an examination to inspect its release state."
    );

    const button =
        document.getElementById(
            "authorizeReleaseButton"
        );

    if (button) {

        button.disabled =
            true;

        button.textContent =
            "Release Locked";
    }

    showReleaseResult(
        "locked",
        "Release locked",
        "Select an examination to inspect the release conditions."
    );
}

function showReleaseResult(
    type,
    title,
    message
) {
    const container =
        document.getElementById(
            "releaseResult"
        );

    if (!container) {
        return;
    }

    const icon =
        type === "success"
            ? "✓"
            : type === "error"
                ? "×"
                : type === "ready"
                    ? "→"
                    : "•";

    container.innerHTML = `
        <div class="release-result release-result-${type}">

            <div class="release-result-icon">
                ${icon}
            </div>

            <div>

                <strong>
                    ${escapeHtml(title)}
                </strong>

                <span>
                    ${escapeHtml(message)}
                </span>

            </div>

        </div>
    `;
}

function showReleaseError(
    message
) {
    setText(
        "releaseStateText",
        "ERROR"
    );

    setText(
        "releaseMessage",
        message
    );

    const button =
        document.getElementById(
            "authorizeReleaseButton"
        );

    if (button) {

        button.disabled =
            true;

        button.textContent =
            "Release Locked";
    }

    showReleaseResult(
        "error",
        "Release request failed",
        message
    );
}

function showPageError(
    message
) {
    const container =
        document.getElementById(
            "rendered-content"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="page">

            <section class="large-panel">

                <div class="panel-body">

                    <div class="release-result release-result-error">

                        <div class="release-result-icon">
                            ×
                        </div>

                        <div>

                            <strong>
                                Release initialization failed
                            </strong>

                            <span>
                                ${escapeHtml(message)}
                            </span>

                        </div>

                    </div>

                </div>

            </section>

        </div>
    `;
}

function setText(
    id,
    value
) {
    const element =
        document.getElementById(
            id
        );

    if (element) {
        element.textContent =
            value;
    }
}

function setCondition(
    id,
    value,
    active
) {
    const element =
        document.getElementById(
            id
        );

    if (!element) {
        return;
    }

    element.textContent =
        value;

    element.classList.toggle(
        "is-active",
        active
    );
}

function formatDateTime(
    date
) {
    if (
        !(date instanceof Date) ||
        Number.isNaN(
            date.getTime()
        )
    ) {
        return "—";
    }

    return date.toLocaleString(
        "en-IN",
        {
            dateStyle:
                "medium",

            timeStyle:
                "short"
        }
    );
}

function escapeHtml(
    value
) {
    return String(
        value ?? ""
    )
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}