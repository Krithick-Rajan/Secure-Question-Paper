"use strict";

let auditLogs = [];

async function initializeAuditPage() {
    try {
        await waitForAuthentication();
        await loadAuditLogs();
    } catch (error) {

        showAuditError(
            error.message ||
            "Unable to load audit activity."
        );
    }
}

async function waitForAuthentication() {
    if (
        window.authReady &&
        typeof window.authReady.then ===
            "function"
    ) {
        const authState =
            await window.authReady;

        if (
            !authState ||
            !authState.authenticated ||
            !authState.admin
        ) {
            throw new Error(
                "Administrator authentication is required."
            );
        }

        return;
    }

    if (
        window.firebaseAuth &&
        window.firebaseAuth.currentUser
    ) {
        return;
    }

    await new Promise(
        (resolve, reject) => {
            const timeout =
                setTimeout(
                    () => {
                        reject(
                            new Error(
                                "Authentication service is not ready."
                            )
                        );
                    },
                    10000
                );

            const check =
                setInterval(
                    () => {
                        if (
                            window.firebaseAuth &&
                            window.firebaseAuth.currentUser
                        ) {
                            clearInterval(
                                check
                            );

                            clearTimeout(
                                timeout
                            );

                            resolve();
                        }
                    },
                    100
                );
        }
    );
}

async function getAuthToken() {
    if (
        !window.firebaseAuth
    ) {
        throw new Error(
            "Firebase authentication is unavailable."
        );
    }

    const user =
        window.firebaseAuth.currentUser;

    if (!user) {
        throw new Error(
            "Administrator session has expired."
        );
    }

    return await user.getIdToken();
}

async function loadAuditLogs() {
    const token =
        await getAuthToken();

    const response =
        await fetch(
            "/api/audit-logs",
            {
                method:
                    "GET",

                headers: {
                    "Authorization":
                        `Bearer ${token}`,

                    "Content-Type":
                        "application/json"
                }
            }
        );

    let result;

    try {
        result =
            await response.json();
    } catch {
        throw new Error(
            "The audit service returned an invalid response."
        );
    }

    if (
        !response.ok ||
        !result.success
    ) {
        throw new Error(
            result.message ||
            "Unable to retrieve audit logs."
        );
    }

    auditLogs =
        Array.isArray(
            result.logs
        )
            ? result.logs
            : [];

    renderAuditPage(
        result.summary ||
        {}
    );
}

function renderAuditPage(
    summary
) {
    updateSummaryCards(
        summary
    );

    renderAuditEvents(
        auditLogs
    );
}

function updateSummaryCards(
    summary
) {
    const stats =
        document.querySelectorAll(
            ".stats .stat"
        );

    if (
        stats.length < 4
    ) {
        return;
    }

    const total =
        Number(
            summary.total ??
            auditLogs.length
        );

    const alerts =
        Number(
            summary.alerts ??
            auditLogs.filter(
                log =>
                    log.severity ===
                    "ALERT"
            ).length
        );

    const access =
        Number(
            summary.access ??
            0
        );

    const alertStatus =
        alerts > 0
            ? `${formatCount(alerts)} Alert${alerts === 1 ? "" : "s"}`
            : "Clear";

    const statusDescription =
        alerts > 0
            ? "Security events require review"
            : "No active alerts";

    const totalNumber =
        stats[0].querySelector(
            ".stat-number"
        );

    const alertNumber =
        stats[1].querySelector(
            ".stat-number"
        );

    const accessNumber =
        stats[2].querySelector(
            ".stat-number"
        );

    const statusNumber =
        stats[3].querySelector(
            ".stat-number"
        );

    const statusBottom =
        stats[3].querySelector(
            ".stat-bottom"
        );

    if (totalNumber) {
        totalNumber.textContent =
            formatCount(
                total
            );
    }

    if (alertNumber) {
        alertNumber.textContent =
            formatCount(
                alerts
            );
    }

    if (accessNumber) {
        accessNumber.textContent =
            formatCount(
                access
            );
    }

    if (statusNumber) {
        statusNumber.textContent =
            alertStatus;
    }

    if (statusBottom) {
        statusBottom.textContent =
            statusDescription;
    }

    const panelHeader =
        document.querySelector(
            ".large-panel .panel-header"
        );

    if (panelHeader) {
        const pill =
            panelHeader.querySelector(
                ".ready-pill"
            );

        if (pill) {
            pill.textContent =
                alerts > 0
                    ? `${formatCount(alerts)} Alert${alerts === 1 ? "" : "s"}`
                    : "Clear";

            pill.classList.toggle(
                "audit-alert-pill",
                alerts > 0
            );
        }
    }
}

function renderAuditEvents(
    logs
) {
    const panelBody =
        document.querySelector(
            ".large-panel .panel-body"
        );

    if (!panelBody) {
        return;
    }

    if (!logs.length) {
        panelBody.innerHTML =
            createEmptyState();

        return;
    }

    panelBody.innerHTML =
        `
        <div class="audit-event-list">
            ${logs
                .map(
                    (
                        log,
                        index
                    ) =>
                        createAuditEvent(
                            log,
                            index
                        )
                )
                .join("")}
        </div>
        `;
}

function createAuditEvent(
    log,
    index
) {
    const alert =
        log.severity ===
        "ALERT";

    const eventTitle =
        formatEventName(
            log.action ||
            log.event
        );

    const description =
        log.description ||
        getEventDescription(
            log.action ||
            log.event
        );

    const examination =
        log.examinationCode ||
        "SYSTEM";

    const timestamp =
        formatDateTime(
            log.timestamp
        );

    const eventClass =
        alert
            ? " audit-event-alert"
            : "";

    return `
        <article
            class="audit-event${eventClass}"
            data-event-index="${index}"
        >

            <div class="audit-event-marker">
                <span></span>
            </div>

            <div class="audit-event-main">

                <div class="audit-event-header">

                    <div>

                        <div class="audit-event-type">
                            ${escapeHtml(
                                eventTitle
                            )}
                        </div>

                        <div class="audit-event-examination">
                            ${escapeHtml(
                                examination
                            )}
                        </div>

                    </div>

                    <div class="audit-event-time">
                        ${escapeHtml(
                            timestamp
                        )}
                    </div>

                </div>

                <div class="audit-event-description">
                    ${escapeHtml(
                        description
                    )}
                </div>

                ${createAuditDetails(
                    log
                )}

            </div>

        </article>
    `;
}

function createAuditDetails(
    log
) {
    const details = [];

    if (
        log.actorEmail
    ) {
        details.push(
            createDetail(
                "ACTOR",
                log.actorEmail
            )
        );
    }

    if (
        log.role
    ) {
        details.push(
            createDetail(
                "ROLE",
                log.role
            )
        );
    }

    if (
        log.threshold
    ) {
        details.push(
            createDetail(
                "THRESHOLD",
                log.threshold
            )
        );
    }

    if (
        Array.isArray(
            log.sharesUsed
        ) &&
        log.sharesUsed.length
    ) {
        details.push(
            createDetail(
                "SHARES",
                log.sharesUsed.join(
                    ", "
                )
            )
        );
    }

    if (
        log.fragmentNumber !==
        null &&
        log.fragmentNumber !==
            undefined
    ) {
        details.push(
            createDetail(
                "FRAGMENT",
                String(
                    log.fragmentNumber
                )
            )
        );
    }

    if (
        log.fragmentCount !==
        null &&
        log.fragmentCount !==
            undefined
    ) {
        details.push(
            createDetail(
                "FRAGMENTS",
                String(
                    log.fragmentCount
                )
            )
        );
    }

    if (
        log.encryptionAlgorithm
    ) {
        details.push(
            createDetail(
                "ENCRYPTION",
                log.encryptionAlgorithm
            )
        );
    }

    if (
        log.keyAlgorithm
    ) {
        details.push(
            createDetail(
                "KEY",
                log.keyAlgorithm
            )
        );
    }

    if (
        log.executionMode
    ) {
        details.push(
            createDetail(
                "MODE",
                log.executionMode
            )
        );
    }

    if (
        log.releaseAgent
    ) {
        details.push(
            createDetail(
                "RELEASE AGENT",
                log.releaseAgent
            )
        );
    }

    if (
        log.plaintextPersisted !==
        null &&
        log.plaintextPersisted !==
            undefined
    ) {
        details.push(
            createDetail(
                "PLAINTEXT PERSISTED",
                log.plaintextPersisted
                    ? "Yes"
                    : "No",
                log.plaintextPersisted
                    ? "negative"
                    : "positive"
            )
        );
    }

    if (
        log.plaintextWrittenToDisk !==
        null &&
        log.plaintextWrittenToDisk !==
            undefined
    ) {
        details.push(
            createDetail(
                "WRITTEN TO DISK",
                log.plaintextWrittenToDisk
                    ? "Yes"
                    : "No",
                log.plaintextWrittenToDisk
                    ? "negative"
                    : "positive"
            )
        );
    }

    if (!details.length) {
        return "";
    }

    return `
        <div class="audit-event-details">
            ${details.join("")}
        </div>
    `;
}

function createDetail(
    label,
    value,
    stateClass = ""
) {
    return `
        <div class="audit-detail">

            <span class="audit-detail-label">
                ${escapeHtml(
                    label
                )}
            </span>

            <strong
                class="audit-detail-value ${stateClass}"
            >
                ${escapeHtml(
                    String(
                        value
                    )
                )}
            </strong>

        </div>
    `;
}

function createEmptyState() {
    return `
        <div class="audit-empty">

            <div class="control-symbol">

                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    aria-hidden="true"
                >

                    <path d="M7 3h8l3 3v15H7z"/>

                    <path d="M15 3v4h4"/>

                    <path d="M10 12h5"/>

                    <path d="M10 16h5"/>

                </svg>

            </div>

            <h3>
                No audit events
            </h3>

            <p>
                Activity will be recorded when the system is used.
            </p>

        </div>
    `;
}

function showAuditError(
    message
) {
    const panelBody =
        document.querySelector(
            ".large-panel .panel-body"
        );

    if (!panelBody) {
        return;
    }

    panelBody.innerHTML =
        `
        <div class="audit-empty audit-error-state">

            <div class="control-symbol">

                <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    aria-hidden="true"
                >

                    <circle
                        cx="12"
                        cy="12"
                        r="9"
                    />

                    <path d="M12 7v6"/>

                    <path d="M12 16h.01"/>

                </svg>

            </div>

            <h3>
                Audit service unavailable
            </h3>

            <p>
                ${escapeHtml(
                    message
                )}
            </p>

        </div>
        `;
}

function formatEventName(
    event
) {
    if (!event) {
        return "Security Event";
    }

    const eventNames = {
        SECURE_RELEASE_EXECUTED:
            "Secure Release Executed",

        SECURE_RELEASE_EXECUTION_REJECTED:
            "Secure Release Execution Rejected",

        EXAMINATION_RELEASE_AUTHORIZED:
            "Examination Release Authorized",

        EXAMINATION_RELEASE_REJECTED:
            "Examination Release Rejected",

        EXAMINATION_CREATED:
            "Examination Created",

        CUSTODY_INITIALIZED:
            "Custody Initialized",

        CUSTODY_RECONSTRUCTION_VERIFIED:
            "Custody Reconstruction Verified",

        CUSTODY_RECONSTRUCTION_SUCCESS:
            "Custody Reconstruction Success",

        CUSTODY_RECONSTRUCTION_REJECTED:
            "Custody Reconstruction Rejected",

        FRAGMENT_ENCRYPTED:
            "Fragment Encrypted",

        FRAGMENT_ENCRYPTION:
            "Fragment Encrypted"
    };

    if (
        eventNames[event]
    ) {
        return eventNames[event];
    }

    return String(
        event
    )
        .replace(
            /_/g,
            " "
        )
        .toLowerCase()
        .replace(
            /\b\w/g,
            character =>
                character.toUpperCase()
        );
}

function getEventDescription(
    event
) {
    const descriptions = {
        SECURE_RELEASE_EXECUTED:
            "The protected examination was released through the controlled in-memory release path.",

        SECURE_RELEASE_EXECUTION_REJECTED:
            "Controlled release execution was rejected because one or more release conditions were not satisfied.",

        EXAMINATION_RELEASE_AUTHORIZED:
            "The examination release was authorized after the required security conditions were verified.",

        EXAMINATION_RELEASE_REJECTED:
            "The examination release attempt was rejected because the required release conditions were not satisfied.",

        EXAMINATION_CREATED:
            "A new examination was registered in the secure custody system.",

        CUSTODY_INITIALIZED:
            "A new AES-256 custody key was generated and divided into five protected shares using a 3-of-5 threshold.",

        CUSTODY_RECONSTRUCTION_VERIFIED:
            "The protected AES-256 key was successfully reconstructed and verified using the supplied threshold shares.",

        CUSTODY_RECONSTRUCTION_SUCCESS:
            "The protected AES-256 key was successfully reconstructed and verified using the supplied threshold shares.",

        CUSTODY_RECONSTRUCTION_REJECTED:
            "Key reconstruction was rejected because the required threshold conditions were not satisfied.",

        FRAGMENT_ENCRYPTED:
            "A question fragment was encrypted and stored as protected ciphertext.",

        FRAGMENT_ENCRYPTION:
            "A question fragment was encrypted and stored as protected ciphertext."
    };

    return (
        descriptions[event] ||
        "A security event was recorded by the secure custody system."
    );
}

function formatDateTime(
    value
) {
    if (!value) {
        return "Time unavailable";
    }

    const date =
        new Date(
            value
        );

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(
            value
        );
    }

    return date.toLocaleString(
        "en-IN",
        {
            day:
                "2-digit",

            month:
                "short",

            year:
                "numeric",

            hour:
                "2-digit",

            minute:
                "2-digit",

            second:
                "2-digit",

            hour12:
                true
        }
    );
}

function formatCount(
    value
) {
    const number =
        Number(
            value
        ) || 0;

    return String(
        number
    ).padStart(
        2,
        "0"
    );
}

function escapeHtml(
    value
) {
    return String(
        value ??
        ""
    )
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}

function injectAuditStyles() {
    if (
        document.getElementById(
            "audit-log-styles"
        )
    ) {
        return;
    }

    const style =
        document.createElement(
            "style"
        );

    style.id =
        "audit-log-styles";

    style.textContent = `
        .audit-event-list {
            width: 100%;
            display: flex;
            flex-direction: column;
        }

        .audit-event {
            position: relative;
            display: grid;
            grid-template-columns: 34px minmax(0, 1fr);
            gap: 18px;
            padding: 28px 26px;
            border-bottom: 1px solid var(--border);
        }

        .audit-event:last-child {
            border-bottom: 0;
        }

        .audit-event-marker {
            width: 34px;
            height: 34px;
            display: grid;
            place-items: center;
            border: 1px solid var(--border);
            background: var(--surface-soft);
        }

        .audit-event-marker span {
            width: 7px;
            height: 7px;
            display: block;
            border-radius: 50%;
            background: var(--green);
            box-shadow: 0 0 12px rgba(80, 201, 191, 0.35);
        }

        .audit-event-alert .audit-event-marker span {
            background: var(--red);
            box-shadow: 0 0 12px rgba(223, 104, 91, 0.35);
        }

        .audit-event-main {
            min-width: 0;
        }

        .audit-event-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 24px;
        }

        .audit-event-type {
            color: var(--text);
            font-size: 16px;
            line-height: 1.3;
            font-weight: 600;
        }

        .audit-event-examination {
            margin-top: 5px;
            color: var(--gold);
            font-family: var(--font-mono);
            font-size: 9px;
            letter-spacing: 0.08em;
        }

        .audit-event-time {
            flex: 0 0 auto;
            color: var(--text-dim);
            font-family: var(--font-mono);
            font-size: 9px;
            line-height: 1.5;
            text-align: right;
        }

        .audit-event-description {
            max-width: 900px;
            margin-top: 14px;
            color: var(--text-muted);
            font-size: 12px;
            line-height: 1.7;
        }

        .audit-event-details {
            display: grid;
            grid-template-columns: repeat(4, minmax(130px, 1fr));
            gap: 10px;
            margin-top: 20px;
        }

        .audit-detail {
            min-width: 0;
            padding: 12px 13px;
            border: 1px solid var(--border);
            background: rgba(255, 255, 255, 0.012);
        }

        .audit-detail-label {
            display: block;
            color: var(--text-dim);
            font-family: var(--font-mono);
            font-size: 8px;
            letter-spacing: 0.08em;
            line-height: 1.3;
        }

        .audit-detail-value {
            display: block;
            margin-top: 7px;
            color: var(--text-soft);
            font-family: var(--font-mono);
            font-size: 10px;
            line-height: 1.5;
            font-weight: 500;
            overflow-wrap: anywhere;
        }

        .audit-detail-value.positive {
            color: var(--green);
        }

        .audit-detail-value.negative {
            color: var(--red);
        }

        .audit-alert-pill {
            color: var(--red) !important;
            border-color: rgba(223, 104, 91, 0.35) !important;
        }

        @media (max-width: 1000px) {
            .audit-event-details {
                grid-template-columns: repeat(2, minmax(130px, 1fr));
            }
        }

        @media (max-width: 700px) {
            .audit-event {
                grid-template-columns: 1fr;
                gap: 14px;
                padding: 22px 18px;
            }

            .audit-event-header {
                flex-direction: column;
                gap: 10px;
            }

            .audit-event-time {
                text-align: left;
            }

            .audit-event-details {
                grid-template-columns: 1fr;
            }
        }
    `;

    document.head.appendChild(
        style
    );
}

function startAuditPage() {
    injectAuditStyles();

    initializeAuditPage();
}

if (
    document.readyState ===
    "loading"
) {
    document.addEventListener(
        "DOMContentLoaded",
        startAuditPage
    );
} else {
    startAuditPage();
}