"use strict";

async function initializeCustodyPage() {
    try {
        if (!window.authReady) {
            throw new Error(
                "Authentication service is not initialized."
            );
        }

        await window.authReady;

        if (!window.firebaseAuth) {
            throw new Error(
                "Firebase Authentication is not available."
            );
        }

        const user =
            window.firebaseAuth.currentUser;

        if (!user) {
            window.location.href =
                "/login.html";
            return;
        }

        if (
            typeof user.getIdToken !==
            "function"
        ) {
            throw new Error(
                "Firebase authenticated user is unavailable."
            );
        }

        const token =
            await user.getIdToken();

        const examinationsResponse =
            await fetch(
                "/api/examinations",
                {
                    headers: {
                        Authorization:
                            `Bearer ${token}`
                    }
                }
            );

        const examinationsData =
            await examinationsResponse.json();

        if (
            !examinationsResponse.ok ||
            !examinationsData.success
        ) {
            throw new Error(
                examinationsData.message ||
                "Failed to load examinations."
            );
        }

        const examinationSelect =
            document.getElementById(
                "custodyExamination"
            );

        if (!examinationSelect) {
            throw new Error(
                "Examination selector was not found."
            );
        }

        examinationSelect.innerHTML = `
            <option value="">
                Select examination
            </option>

            ${(
                examinationsData.examinations ||
                []
            ).map(
                examination => `
                    <option value="${escapeHtml(
                        examination.id
                    )}">
                        ${escapeHtml(
                            examination.code ||
                            examination.examCode ||
                            ""
                        )}
                        —
                        ${escapeHtml(
                            examination.name ||
                            examination.title ||
                            ""
                        )}
                    </option>
                `
            ).join("")}
        `;

        examinationSelect.addEventListener(
            "change",
            async () => {
                const examinationId =
                    examinationSelect.value;

                if (!examinationId) {
                    resetCustodyStatus();
                    return;
                }

                await loadCustodyStatus(
                    examinationId,
                    token
                );
            }
        );

    } catch (error) {

        showCustodyError(
            error.message
        );
    }
}

async function loadCustodyStatus(
    examinationId,
    token
) {
    const resultElement =
        document.getElementById(
            "custodyResult"
        );

    const subtitleElement =
        document.getElementById(
            "custodyPanelSubtitle"
        );

    if (resultElement) {
        resultElement.className =
            "custody-result-container";

        resultElement.innerHTML =
            "";
    }

    if (subtitleElement) {
        subtitleElement.textContent =
            "Loading protected custody status...";
    }

    try {
        const response =
            await fetch(
                `/api/custody/status/${encodeURIComponent(
                    examinationId
                )}`,
                {
                    headers: {
                        Authorization:
                            `Bearer ${token}`
                    }
                }
            );

        const data =
            await response.json();

        if (
            !response.ok ||
            !data.success
        ) {
            throw new Error(
                data.message ||
                "Failed to load custody status."
            );
        }

        const custody =
            normalizeCustodyData(
                data.custody
            );

        if (
            custody.status ===
            "initialized"
        ) {
            renderInitializedCustody(
                examinationId,
                token,
                custody
            );

            // Show the submit-share panel so custodians can submit at release time
            renderSubmitShareSection(examinationId, token);

        } else {
            renderUninitializedCustody(
                examinationId,
                token
            );
        }

    } catch (error) {

        showCustodyError(
            error.message
        );
    }
}

function normalizeCustodyData(
    custody
) {
    const source =
        custody || {};

    const thresholdRequired =
        Number(
            source.thresholdRequired ??
            source.threshold ??
            source.requiredShares ??
            source.thresholdCount ??
            3
        );

    const totalShares =
        Number(
            source.totalShares ??
            source.shareCount ??
            source.total ??
            source.shares ??
            5
        );

    const sharesAssigned =
        Number(
            source.sharesAssigned ??
            source.assignedShares ??
            source.assigned ??
            source.numberOfShares ??
            totalShares
        );

    return {
        ...source,

        status:
            source.status ||
            "uninitialized",

        thresholdRequired:
            Number.isFinite(
                thresholdRequired
            )
                ? thresholdRequired
                : 3,

        totalShares:
            Number.isFinite(
                totalShares
            )
                ? totalShares
                : 5,

        sharesAssigned:
            Number.isFinite(
                sharesAssigned
            )
                ? sharesAssigned
                : 0
    };
}

function renderInitializedCustody(
    examinationId,
    token,
    custody
) {
    const resultElement =
        document.getElementById(
            "custodyResult"
        );

    const subtitleElement =
        document.getElementById(
            "custodyPanelSubtitle"
        );

    const threshold =
        custody.thresholdRequired;

    const total =
        custody.totalShares;

    const assigned =
        custody.sharesAssigned;

    if (resultElement) {
        resultElement.className =
            "custody-result-container";
    }

    if (subtitleElement) {
        subtitleElement.textContent =
            `${threshold} of ${total} shares are required for key reconstruction.`;
    }

    if (!resultElement) {
        return;
    }

    resultElement.innerHTML = `
        <div class="custody-result custody-success">

            <div class="custody-result-icon">

                <svg
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                >
                    <path d="M12 3l7 3v5c0 4.7-3 8.8-7 10-4-1.2-7-5.3-7-10V6l7-3z"></path>
                    <path d="M9 12l2 2 4-4"></path>
                </svg>

            </div>

            <div>

                <strong>
                    Threshold custody initialized
                </strong>

                <span>
                    ${assigned} of ${total}
                    protected shares are assigned.
                </span>

            </div>

        </div>

        <section class="custody-verification">

            <div class="verification-header">

                <div class="verification-heading">

                    <span class="verification-kicker">
                        THRESHOLD VERIFICATION
                    </span>

                    <h3>
                        Verify protected key reconstruction
                    </h3>

                    <p>
                        Select custody shares to verify that the
                        ${threshold}-of-${total}
                        threshold is enforced. Share values and the
                        reconstructed key remain hidden.
                    </p>

                </div>

                <div class="verification-required">

                    <span>
                        REQUIRED
                    </span>

                    <strong>
                        ${String(
                            threshold
                        ).padStart(2, "0")}
                    </strong>

                    <small>
                        OF ${String(
                            total
                        ).padStart(2, "0")}
                    </small>

                </div>

            </div>

            <div class="verification-shares">

                ${createShareCard(1)}
                ${createShareCard(2)}
                ${createShareCard(3)}
                ${createShareCard(4)}
                ${createShareCard(5)}

            </div>

            <div class="verification-footer">

                <div class="verification-summary">

                    <div class="verification-count">

                        <span>
                            SELECTED
                        </span>

                        <strong id="selectedShareCount">
                            0 / ${total}
                        </strong>

                    </div>

                    <div class="verification-threshold-status">

                        <span>
                            THRESHOLD
                        </span>

                        <strong id="thresholdStatus">
                            Select shares
                        </strong>

                    </div>

                </div>

                <button
                    type="button"
                    id="verifyThresholdButton"
                    class="verification-button"
                    disabled
                >
                    Verify Threshold
                </button>

            </div>

            <div id="verificationResult"></div>

        </section>
    `;

    setupVerificationControls(
        examinationId,
        token,
        threshold,
        total
    );

    updateCustodyPositionRows(
        assigned
    );
}

function createShareCard(
    shareId
) {
    const formattedId =
        String(
            shareId
        ).padStart(
            2,
            "0"
        );

    return `
        <label
            class="verification-share-card"
            data-share-id="${shareId}"
        >

            <input
                type="checkbox"
                class="verification-share-checkbox"
                value="${shareId}"
            >

            <span class="verification-checkbox">

                <svg
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                >
                    <path d="M5 12l4 4L19 6"></path>
                </svg>

            </span>

            <span class="verification-share-content">

                <strong>
                    Custodian ${formattedId}
                </strong>

                <small>
                    Protected share ${formattedId}
                </small>

                <em>
                    READY
                </em>

            </span>

        </label>
    `;
}

function setupVerificationControls(
    examinationId,
    token,
    thresholdRequired,
    totalShares
) {
    const checkboxes =
        Array.from(
            document.querySelectorAll(
                ".verification-share-checkbox"
            )
        );

    const verifyButton =
        document.getElementById(
            "verifyThresholdButton"
        );

    const selectedCountElement =
        document.getElementById(
            "selectedShareCount"
        );

    const thresholdStatusElement =
        document.getElementById(
            "thresholdStatus"
        );

    checkboxes.forEach(
        checkbox => {
            checkbox.addEventListener(
                "change",
                () => {
                    updateVerificationState(
                        checkboxes,
                        verifyButton,
                        selectedCountElement,
                        thresholdStatusElement,
                        thresholdRequired,
                        totalShares
                    );
                }
            );
        }
    );

    if (verifyButton) {
        verifyButton.addEventListener(
            "click",
            async () => {
                await verifyThreshold(
                    examinationId,
                    token,
                    thresholdRequired,
                    totalShares
                );
            }
        );
    }

    updateVerificationState(
        checkboxes,
        verifyButton,
        selectedCountElement,
        thresholdStatusElement,
        thresholdRequired,
        totalShares
    );
}

function updateVerificationState(
    checkboxes,
    verifyButton,
    selectedCountElement,
    thresholdStatusElement,
    thresholdRequired,
    totalShares
) {
    const selectedCount =
        checkboxes.filter(
            checkbox =>
                checkbox.checked
        ).length;

    if (selectedCountElement) {
        selectedCountElement.textContent =
            `${selectedCount} / ${totalShares}`;
    }

    if (thresholdStatusElement) {
        thresholdStatusElement.classList.remove(
            "satisfied",
            "insufficient"
        );

        if (selectedCount === 0) {
            thresholdStatusElement.textContent =
                "Select shares";

            thresholdStatusElement.classList.add(
                "insufficient"
            );
        } else if (
            selectedCount <
            thresholdRequired
        ) {
            thresholdStatusElement.textContent =
                `${thresholdRequired - selectedCount} more required`;

            thresholdStatusElement.classList.add(
                "insufficient"
            );
        } else {
            thresholdStatusElement.textContent =
                "Threshold satisfied";

            thresholdStatusElement.classList.add(
                "satisfied"
            );
        }
    }

    if (verifyButton) {
        verifyButton.disabled =
            selectedCount <
            thresholdRequired;
    }

    document
        .querySelectorAll(
            ".verification-share-card"
        )
        .forEach(
            card => {
                const checkbox =
                    card.querySelector(
                        ".verification-share-checkbox"
                    );

                if (!checkbox) {
                    return;
                }

                card.classList.toggle(
                    "selected",
                    checkbox.checked
                );
            }
        );
}

async function verifyThreshold(
    examinationId,
    token,
    thresholdRequired,
    totalShares
) {
    const verifyButton =
        document.getElementById(
            "verifyThresholdButton"
        );

    const checkboxes =
        Array.from(
            document.querySelectorAll(
                ".verification-share-checkbox"
            )
        );

    const selectedShareIds =
        checkboxes
            .filter(
                checkbox =>
                    checkbox.checked
            )
            .map(
                checkbox =>
                    Number(
                        checkbox.value
                    )
            );

    if (
        selectedShareIds.length <
        thresholdRequired
    ) {
        showVerificationResult(
            "error",
            "Threshold not satisfied",
            `At least ${thresholdRequired} of ${totalShares} shares are required.`
        );

        return;
    }

    if (verifyButton) {
        verifyButton.disabled =
            true;

        verifyButton.textContent =
            "Verifying...";
    }

    try {
        const response =
            await fetch(
                "/api/custody/reconstruct-test",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",

                        Authorization:
                            `Bearer ${token}`
                    },

                    body: JSON.stringify({
                        examinationId,

                        shareIds:
                            selectedShareIds
                    })
                }
            );

        const data =
            await response.json();

        if (
            response.ok &&
            data.success === true &&
            data.verification &&
            data.verification.fingerprintVerified === true
        ) {
            const sharesUsed =
                Array.isArray(
                    data.verification.sharesUsed
                )
                    ? data.verification.sharesUsed.length
                    : Number(
                        data.verification.sharesUsed ||
                        selectedShareIds.length
                    );

            const verificationTotal =
                Number(
                    data.verification.totalShares ||
                    totalShares
                );

            showVerificationResult(
                "success",
                "Threshold verified",
                `${sharesUsed} of ${verificationTotal} protected shares successfully reconstructed and verified the AES-256 key fingerprint.`
            );

            if (verifyButton) {
                verifyButton.textContent =
                    "Threshold Verified";

                verifyButton.disabled =
                    true;
            }

            updateCustodyLockState(
                "verified"
            );

            return;
        }

        showVerificationResult(
            "error",
            "Verification failed",
            data.message ||
            "The protected key could not be verified."
        );

        if (verifyButton) {
            verifyButton.disabled =
                false;

            verifyButton.textContent =
                "Verify Threshold";
        }

    } catch (_error) {

        showVerificationResult(
            "error",
            "Verification failed",
            "Unable to complete the threshold verification request."
        );

        if (verifyButton) {
            verifyButton.disabled =
                false;

            verifyButton.textContent =
                "Verify Threshold";
        }
    }
}

function showVerificationResult(
    type,
    title,
    message
) {
    const resultElement =
        document.getElementById(
            "verificationResult"
        );

    if (!resultElement) {
        return;
    }

    const isSuccess =
        type === "success";

    resultElement.innerHTML = `
        <div class="custody-result ${
            isSuccess
                ? "custody-success"
                : "custody-error"
        }">

            <div class="custody-result-icon">

                ${
                    isSuccess
                        ? `
                            <svg
                                viewBox="0 0 24 24"
                                aria-hidden="true"
                            >
                                <path d="M12 3l7 3v5c0 4.7-3 8.8-7 10-4-1.2-7-5.3-7-10V6l7-3z"></path>
                                <path d="M9 12l2 2 4-4"></path>
                            </svg>
                        `
                        : `
                            <svg
                                viewBox="0 0 24 24"
                                aria-hidden="true"
                            >
                                <path d="M7 7l10 10"></path>
                                <path d="M17 7L7 17"></path>
                            </svg>
                        `
                }

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

function updateCustodyLockState(
    state
) {
    const custodyCards =
        document.querySelectorAll(
            ".stat"
        );

    custodyCards.forEach(
        card => {
            const label =
                card.querySelector(
                    ".stat-top > span"
                );

            if (!label) {
                return;
            }

            if (
                label.textContent
                    .trim()
                    .toUpperCase() ===
                "CUSTODY"
            ) {
                const value =
                    card.querySelector(
                        ".stat-number"
                    );

                const description =
                    card.querySelector(
                        ".stat-bottom"
                    );

                if (value) {
                    value.textContent =
                        state === "verified"
                            ? "Verified"
                            : "Locked";
                }

                if (description) {
                    description.textContent =
                        state === "verified"
                            ? "Threshold reconstruction verified"
                            : "Threshold custody protected";
                }
            }
        }
    );
}

function renderUninitializedCustody(
    examinationId,
    token
) {
    const resultElement =
        document.getElementById(
            "custodyResult"
        );

    const subtitleElement =
        document.getElementById(
            "custodyPanelSubtitle"
        );

    if (resultElement) {
        resultElement.className =
            "custody-result-container";
    }

    if (subtitleElement) {
        subtitleElement.textContent =
            "Initialize distributed custody for this examination.";
    }

    if (!resultElement) {
        return;
    }

    resultElement.innerHTML = `
        <div class="custody-result custody-pending">

            <div class="custody-result-icon">

                <svg
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                >
                    <path d="M12 3l7 3v5c0 4.7-3 8.8-7 10-4-1.2-7-5.3-7-10V6l7-3z"></path>
                    <path d="M12 8v5"></path>
                    <path d="M12 16h.01"></path>
                </svg>

            </div>

            <div>

                <strong>
                    Threshold custody not initialized
                </strong>

                <span>
                    No protected shares have been assigned for this examination.
                </span>

            </div>

            <button
                type="button"
                id="initializeCustodyButton"
                class="verification-button"
            >
                Initialize 3-of-5 Custody
            </button>

        </div>
    `;

    const initializeButton =
        document.getElementById(
            "initializeCustodyButton"
        );

    if (initializeButton) {
        initializeButton.addEventListener(
            "click",
            async () => {
                await initializeCustody(
                    examinationId,
                    token
                );
            }
        );
    }

    updateCustodyPositionRows(
        0
    );
}

async function initializeCustody(
    examinationId,
    token
) {
    const button =
        document.getElementById(
            "initializeCustodyButton"
        );

    if (button) {
        button.disabled = true;
        button.textContent = "Initializing...";
    }

    try {
        const response =
            await fetch(
                "/api/custody/initialize",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${token}`
                    },

                    body: JSON.stringify({ examinationId })
                }
            );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(
                data.message || "Failed to initialize custody."
            );
        }

        // ── One-time share disclosure ─────────────────────────────────
        // data.shares contains all 5 share values — shown ONCE, then gone.
        // ─────────────────────────────────────────────────────────────────
        if (data.shares && data.shares.length > 0) {
            renderShareDisclosure(
                data.shares,
                examinationId,
                token,
                data.custody?.examinationCode || ""
            );
        } else {
            await loadCustodyStatus(examinationId, token);
        }

    } catch (error) {

        showCustodyError(error.message);

        if (button) {
            button.disabled = false;
            button.textContent = "Initialize 3-of-5 Custody";
        }
    }
}

function renderShareDisclosure(
    shares,
    examinationId,
    token,
    examCode
) {
    const resultElement =
        document.getElementById("custodyResult");

    if (!resultElement) return;

    resultElement.className = "custody-result-container";

    resultElement.innerHTML = `

        <div class="share-disclosure-panel">

            <div class="share-disclosure-header">

                <div class="share-disclosure-icon">⚠</div>

                <div>

                    <strong>
                        CRITICAL — Save all 5 shares now
                    </strong>

                    <span>
                        These share values will <b>never</b> be shown again.
                        The server has already deleted them.
                        Distribute one share to each of the 5 custodians immediately.
                        You will need any 3 of these 5 shares to release the exam.
                    </span>

                </div>

            </div>


            <div class="share-disclosure-grid">

                ${shares.map(
                    share => `

                        <div class="share-card">

                            <div class="share-card-header">

                                <span class="share-card-label">
                                    CUSTODIAN SHARE ${escapeHtml(share.shareId)}
                                </span>

                                <button
                                    class="share-download-btn"
                                    onclick="downloadShare(${escapeHtml(share.shareId)}, '${escapeHtml(share.value)}', '${escapeHtml(examCode)}')"
                                    type="button"
                                >
                                    ↓ Download
                                </button>

                            </div>

                            <div class="share-card-value">
                                <code id="shareValue${escapeHtml(share.shareId)}">${escapeHtml(share.value)}</code>
                            </div>

                        </div>

                    `
                ).join("")}

            </div>


            <div class="share-disclosure-actions">

                <button
                    class="primary-button share-confirm-btn"
                    id="confirmSharesSaved"
                    type="button"
                >
                    <span>I have saved all 5 shares securely</span>
                    <b>→</b>
                </button>

            </div>

        </div>

    `;

    document
        .getElementById("confirmSharesSaved")
        ?.addEventListener(
            "click",
            async () => {
                await loadCustodyStatus(examinationId, token);
                renderSubmitShareSection(examinationId, token);
            }
        );
}

function downloadShare(shareId, shareValue, examCode) {
    const content = [
        `SECURE QUESTION PAPER — CUSTODIAN SHARE`,
        `Examination: ${examCode}`,
        `Share ID: ${shareId}`,
        `Share Value: ${shareValue}`,
        ``,
        `IMPORTANT:`,
        `- Keep this share confidential.`,
        `- This is 1 of 5 shares. Any 3 of 5 are required to release the exam.`,
        `- Submit this value via the Custody page when asked to release.`,
        `- Do NOT share this file with anyone except the designated custodian.`
    ].join("\n");

    const blob = new Blob([content], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");

    a.href     = url;
    a.download = `custody-share-${shareId}-${examCode || "exam"}.txt`;
    a.click();

    URL.revokeObjectURL(url);
}

// Make downloadShare accessible from onclick attributes
window.downloadShare = downloadShare;

function renderSubmitShareSection(examinationId, token) {
    const resultElement =
        document.getElementById("custodyResult");

    if (!resultElement) return;

    // Append submit-share panel below the custody status
    const existing =
        document.getElementById("submitSharePanel");

    if (existing) return;

    const panel = document.createElement("div");
    panel.id = "submitSharePanel";
    panel.className = "submit-share-panel";

    panel.innerHTML = `

        <div class="submit-share-header">

            <span class="card-label">
                SUBMIT CUSTODIAN SHARE
            </span>

            <span id="shareCountBadge" class="share-count-badge">
                0 of 3 submitted
            </span>

        </div>


        <p class="submit-share-desc">
            To release this examination, 3 of the 5 custodians must submit
            their share here. Each custodian pastes the share value they
            received at initialization.
        </p>


        <div class="submit-share-form">

            <div class="form-field">

                <label for="submitShareId">
                    Share ID (1–5)
                </label>

                <input
                    type="number"
                    id="submitShareId"
                    min="1"
                    max="5"
                    placeholder="e.g. 3"
                >

            </div>

            <div class="form-field form-field-wide">

                <label for="submitShareValue">
                    Share value
                </label>

                <textarea
                    id="submitShareValue"
                    rows="4"
                    placeholder="Paste the hex share value here..."
                ></textarea>

            </div>

            <div id="submitShareMessage" class="form-message"></div>

            <button
                class="primary-button"
                id="submitShareButton"
                type="button"
            >
                <span>Submit share</span>
                <b>→</b>
            </button>

        </div>

    `;

    resultElement.appendChild(panel);

    // Wire up the submit button
    document
        .getElementById("submitShareButton")
        ?.addEventListener(
            "click",
            async () => {
                await handleShareSubmit(examinationId, token);
            }
        );

    // Load current share count
    refreshShareCount(examinationId, token);
}

async function refreshShareCount(examinationId, token) {
    try {
        const response = await fetch(
            `/api/custody/session-shares/${encodeURIComponent(examinationId)}`,
            { headers: { Authorization: `Bearer ${token}` } }
        );

        const data = await response.json();

        if (!data.success) return;

        const badge =
            document.getElementById("shareCountBadge");

        if (badge) {
            badge.textContent =
                `${data.submittedCount} of 3 submitted`;

            badge.className =
                `share-count-badge ${data.thresholdMet ? "threshold-met" : ""}`;
        }

    } catch (_error) {
        /* non-fatal */
    }
}

async function handleShareSubmit(examinationId, token) {
    const shareIdInput    = document.getElementById("submitShareId");
    const shareValueInput = document.getElementById("submitShareValue");
    const messageEl       = document.getElementById("submitShareMessage");
    const submitBtn       = document.getElementById("submitShareButton");

    const shareId    = shareIdInput?.value?.trim();
    const shareValue = shareValueInput?.value?.trim();

    if (!shareId || !shareValue) {
        if (messageEl) {
            messageEl.textContent = "Enter both share ID and share value.";
            messageEl.className = "form-message error";
        }
        return;
    }

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.querySelector("span").textContent = "Submitting...";
    }

    if (messageEl) {
        messageEl.textContent = "Submitting share...";
        messageEl.className = "form-message loading";
    }

    try {
        const response = await fetch(
            "/api/custody/submit-share",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${token}`
                },
                body: JSON.stringify({
                    examinationId,
                    shareId: Number(shareId),
                    shareValue
                })
            }
        );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.message || "Share submission failed.");
        }

        if (messageEl) {
            messageEl.textContent =
                data.thresholdMet
                    ? `✓ Share ${shareId} submitted. Threshold met — 3 of 3 shares received.`
                    : `✓ Share ${shareId} submitted. ${data.submittedCount} of 3 shares received.`;
            messageEl.className = "form-message success";
        }

        if (shareIdInput)    shareIdInput.value    = "";
        if (shareValueInput) shareValueInput.value = "";

        await refreshShareCount(examinationId, token);

    } catch (error) {

        if (messageEl) {
            messageEl.textContent = error.message;
            messageEl.className = "form-message error";
        }

    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.querySelector("span").textContent = "Submit share";
        }
    }
}


function updateCustodyPositionRows(
    assignedCount
) {
    const rows =
        document.querySelectorAll(
            ".custodian-row"
        );

    rows.forEach(
        (row, index) => {
            const assigned =
                index <
                assignedCount;

            const status =
                row.querySelector(
                    ".custodian-status"
                );

            if (status) {
                status.textContent =
                    assigned
                        ? "ASSIGNED"
                        : "PENDING";
            }

            row.classList.toggle(
                "assigned",
                assigned
            );
        }
    );
}

function resetCustodyStatus() {
    const resultElement =
        document.getElementById(
            "custodyResult"
        );

    const subtitleElement =
        document.getElementById(
            "custodyPanelSubtitle"
        );

    if (resultElement) {
        resultElement.className =
            "custody-result-container";

        resultElement.innerHTML =
            "";
    }

    if (subtitleElement) {
        subtitleElement.textContent =
            "Select an examination to view custody status.";
    }
}

function showCustodyError(
    message
) {
    const resultElement =
        document.getElementById(
            "custodyResult"
        );

    if (!resultElement) {
        return;
    }

    resultElement.className =
        "custody-result-container";

    resultElement.innerHTML = `
        <div class="custody-result custody-error">

            <div class="custody-result-icon">

                <svg
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                >
                    <path d="M7 7l10 10"></path>
                    <path d="M17 7L7 17"></path>
                </svg>

            </div>

            <div>

                <strong>
                    Custody request failed
                </strong>

                <span>
                    ${escapeHtml(message)}
                </span>

            </div>

        </div>
    `;
}

function escapeHtml(
    value
) {
    return String(
        value ?? ""
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

if (
    document.readyState ===
    "loading"
) {
    document.addEventListener(
        "DOMContentLoaded",
        initializeCustodyPage
    );
} else {
    initializeCustodyPage();
}