"use strict";

let createButtons = document.querySelectorAll(".create-examination-button");
let modal = document.getElementById("examModal");
let closeButton = document.getElementById("closeExamModal");
let cancelButton = document.getElementById("cancelExam");
let examForm = document.getElementById("examForm");
let formMessage = document.getElementById("examFormMessage");
let examName = document.getElementById("examName");
let examCode = document.getElementById("examCode");
let examSubject = document.getElementById("examSubject");
let examDate = document.getElementById("examDate");
let examTime = document.getElementById("examTime");
let releaseTime = document.getElementById("releaseTime");
let submitButton = document.getElementById("createExamSubmit");
let examEmptyState = document.getElementById("examEmptyState");
let examList = document.getElementById("examList");
let registeredCount = document.getElementById("registeredCount");
let activeCount = document.getElementById("activeCount");
let registerTitle = document.getElementById("registerTitle");
let registerStatus = document.getElementById("registerStatus");

function openModal() {
    if (!modal) {
        return;
    }

    modal.classList.add("open");
    modal.setAttribute("aria-hidden", "false");
    document.body.classList.add("modal-open");

    setTimeout(() => {
        if (examName) {
            examName.focus();
        }
    }, 100);
}

function closeModal() {
    if (!modal) {
        return;
    }

    modal.classList.remove("open");
    modal.setAttribute("aria-hidden", "true");
    document.body.classList.remove("modal-open");

    if (examForm) {
        examForm.reset();
    }

    showMessage("", "");
}

createButtons.forEach(button => {
    button.addEventListener("click", openModal);
});

closeButton?.addEventListener("click", closeModal);

cancelButton?.addEventListener("click", closeModal);

modal?.addEventListener("click", event => {
    if (event.target === modal) {
        closeModal();
    }
});

document.addEventListener("keydown", event => {
    if (
        event.key === "Escape" &&
        modal?.classList.contains("open")
    ) {
        closeModal();
    }
});

examCode?.addEventListener("input", () => {
    examCode.value =
        examCode.value
            .toUpperCase()
            .replace(/\s+/g, "");
});

examForm?.addEventListener("submit", async event => {
    event.preventDefault();

    const name =
        examName.value.trim();

    const code =
        examCode.value.trim().toUpperCase();

    const subject =
        examSubject.value.trim();

    const examDateValue =
        examDate.value;

    const startTime =
        examTime.value;

    const releaseTimeValue =
        releaseTime.value;

    if (
        !name ||
        !code ||
        !subject ||
        !examDateValue ||
        !startTime ||
        !releaseTimeValue
    ) {
        showMessage(
            "Please complete all examination fields.",
            "error"
        );

        return;
    }

    if (
        releaseTimeValue < startTime
    ) {
        showMessage(
            "Secure release time cannot be earlier than the examination start time.",
            "error"
        );

        return;
    }

    try {
        setSubmitting(true);

        showMessage(
            "Creating examination...",
            "loading"
        );

        const auth =
            window.firebaseAuth;

        if (!auth) {
            throw new Error(
                "Authentication service is not available."
            );
        }

        const user =
            auth.currentUser;

        if (!user) {
            throw new Error(
                "Your login session has expired. Please sign in again."
            );
        }

        const idToken =
            await user.getIdToken(true);

        const releaseDateTime =
            `${examDateValue}T${releaseTimeValue}:00`;

        const response =
            await fetch(
                "/api/examinations",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json",
                        "Authorization":
                            `Bearer ${idToken}`
                    },
                    body: JSON.stringify({
                        name,
                        title: name,
                        code,
                        subject,
                        examDate:
                            examDateValue,
                        startTime,
                        releaseTime:
                            releaseDateTime
                    })
                }
            );

        const contentType =
            response.headers.get(
                "content-type"
            ) || "";

        if (
            !contentType.includes(
                "application/json"
            )
        ) {
            throw new Error(
                "The server returned an unexpected response."
            );
        }

        const result =
            await response.json();

        if (!response.ok) {
            throw new Error(
                result.message ||
                "Failed to create examination."
            );
        }

        showMessage(
            "Examination created successfully.",
            "success"
        );

        setTimeout(
            async () => {
                closeModal();
                await loadExaminations();
            },
            700
        );
    } catch (error) {

        showMessage(
            error.message ||
            "Unable to create examination.",
            "error"
        );
    } finally {
        setSubmitting(false);
    }
});

function showMessage(
    message,
    type
) {
    if (!formMessage) {
        return;
    }

    formMessage.textContent =
        message;

    formMessage.className =
        "form-message";

    if (type) {
        formMessage.classList.add(
            type
        );
    }
}

function setSubmitting(
    submitting
) {
    if (!submitButton) {
        return;
    }

    submitButton.disabled =
        submitting;

    if (submitting) {
        submitButton.innerHTML = `
            <span>
                Creating...
            </span>

            <b>
                ...
            </b>
        `;
    } else {
        submitButton.innerHTML = `
            <span>
                Create examination
            </span>

            <b>
                →
            </b>
        `;
    }
}

async function loadExaminations() {
    try {
        const auth =
            window.firebaseAuth;

        if (!auth) {
            return;
        }

        const user =
            auth.currentUser;

        if (!user) {
            return;
        }

        const idToken =
            await user.getIdToken();

        const response =
            await fetch(
                "/api/examinations",
                {
                    method: "GET",
                    headers: {
                        "Authorization":
                            `Bearer ${idToken}`
                    }
                }
            );

        if (!response.ok) {
            return;
        }

        const result =
            await response.json();

        if (!result.success) {
            return;
        }

        renderExaminations(
            result.examinations || []
        );
    } catch (_error) {
        /* silently swallow load error */
    }
}

function renderExaminations(
    examinations
) {
    const total =
        examinations.length;

    const active =
        examinations.filter(
            examination =>
                examination.status ===
                "active"
        ).length;

    if (registeredCount) {
        registeredCount.textContent =
            String(total).padStart(
                2,
                "0"
            );
    }

    if (activeCount) {
        activeCount.textContent =
            String(active).padStart(
                2,
                "0"
            );
    }

    if (!examList) {
        return;
    }

    if (total === 0) {
        if (examEmptyState) {
            examEmptyState.hidden =
                false;
        }

        examList.hidden =
            true;

        if (registerTitle) {
            registerTitle.textContent =
                "No examinations configured";
        }

        if (registerStatus) {
            registerStatus.textContent =
                "Ready";
        }

        return;
    }

    if (examEmptyState) {
        examEmptyState.hidden =
            true;
    }

    examList.hidden =
        false;

    if (registerTitle) {
        registerTitle.textContent =
            "Registered examinations";
    }

    if (registerStatus) {
        registerStatus.textContent =
            `${total} registered`;
    }

    examList.innerHTML =
        examinations
            .map(
                examination =>
                    createExamItem(
                        examination
                    )
            )
            .join("");
}

function createExamItem(
    examination
) {
    const status =
        examination.status ||
        "draft";

    const statusText =
        status
            .replace(
                /_/g,
                " "
            )
            .toUpperCase();

    const date =
        formatExamDate(
            examination.examDate
        );

    const examinationName =
        examination.title ||
        examination.name ||
        "Examination";

    const examinationCode =
        examination.code ||
        examination.examCode ||
        "—";

    const subject =
        examination.subject ||
        "—";

    const startTime =
        examination.startTime ||
        "—";

    const configuredReleaseTime =
        examination.releaseTime
            ? formatReleaseTime(
                examination.releaseTime
            )
            : "Not configured";

    return `
        <div class="exam-list-item">

            <div class="exam-list-main">

                <div class="exam-list-icon">

                    <svg
                        viewBox="0 0 24 24"
                        fill="none"
                    >

                        <rect
                            x="6"
                            y="3"
                            width="12"
                            height="18"
                            rx="2"
                        />

                        <path d="M9 7h6"/>
                        <path d="M9 11h6"/>
                        <path d="M9 15h4"/>

                    </svg>

                </div>

                <div class="exam-list-details">

                    <strong>
                        ${escapeHtml(
                            examinationName
                        )}
                    </strong>

                    <span>
                        ${escapeHtml(
                            examinationCode
                        )}
                        ·
                        ${escapeHtml(
                            subject
                        )}
                    </span>

                </div>

            </div>

            <div class="exam-list-meta">

                <span>
                    ${date}
                </span>

                <span>
                    ${escapeHtml(
                        startTime
                    )}
                </span>

                <strong>
                    ${statusText}
                </strong>

                <small>
                    Release:
                    ${escapeHtml(
                        configuredReleaseTime
                    )}
                </small>

            </div>

        </div>
    `;
}

function formatExamDate(
    value
) {
    if (!value) {
        return "Date not set";
    }

    const date =
        new Date(
            `${value}T00:00:00`
        );

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return value;
    }

    return date.toLocaleDateString(
        "en-GB",
        {
            day: "2-digit",
            month: "short",
            year: "numeric"
        }
    );
}

function formatReleaseTime(
    value
) {
    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleString(
        "en-IN",
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
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

function initializeExaminations() {
    let attempts = 0;

    const maxAttempts =
        50;

    const waitForAuth =
        setInterval(
            async () => {
                attempts++;

                if (
                    window.firebaseAuth?.currentUser
                ) {
                    clearInterval(
                        waitForAuth
                    );

                    await loadExaminations();

                    return;
                }

                if (
                    attempts >=
                    maxAttempts
                ) {
                    clearInterval(
                        waitForAuth
                    );
                }
            },
            200
        );
}

initializeExaminations();