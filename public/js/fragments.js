"use strict";

const createButtons =
    document.querySelectorAll(
        ".create-fragment-button"
    );

const modal =
    document.getElementById("fragmentModal");

const closeButton =
    document.getElementById("closeFragmentModal");

const cancelButton =
    document.getElementById("cancelFragment");

const fragmentForm =
    document.getElementById("fragmentForm");

const formMessage =
    document.getElementById("fragmentFormMessage");

const fragmentExam =
    document.getElementById("fragmentExam");

const fragmentNumber =
    document.getElementById("fragmentNumber");

const fragmentLabel =
    document.getElementById("fragmentLabel");

const fragmentText =
    document.getElementById("fragmentText");

const fragmentIsDecoy =
    document.getElementById("fragmentIsDecoy");

const submitButton =
    document.getElementById("createFragmentSubmit");

const fragmentEmptyState =
    document.getElementById("fragmentEmptyState");

const fragmentList =
    document.getElementById("fragmentList");

const protectedCount =
    document.getElementById("protectedCount");

const decoyCount =
    document.getElementById("decoyCount");

const fragmentRegisterTitle =
    document.getElementById("fragmentRegisterTitle");

const fragmentRegisterStatus =
    document.getElementById("fragmentRegisterStatus");

let examinations = [];

function openModal() {
    if (!modal) {
        return;
    }

    modal.classList.add("open");

    modal.setAttribute(
        "aria-hidden",
        "false"
    );

    document.body.classList.add(
        "modal-open"
    );

    loadExaminations();

    setTimeout(() => {
        fragmentExam?.focus();
    }, 100);
}

function closeModal() {
    if (!modal) {
        return;
    }

    modal.classList.remove("open");

    modal.setAttribute(
        "aria-hidden",
        "true"
    );

    document.body.classList.remove(
        "modal-open"
    );

    fragmentForm?.reset();

    showMessage("", "");
}

createButtons.forEach(button => {
    button.addEventListener(
        "click",
        openModal
    );
});

closeButton?.addEventListener(
    "click",
    closeModal
);

cancelButton?.addEventListener(
    "click",
    closeModal
);

modal?.addEventListener(
    "click",
    event => {
        if (
            event.target === modal
        ) {
            closeModal();
        }
    }
);

document.addEventListener(
    "keydown",
    event => {
        if (
            event.key === "Escape" &&
            modal?.classList.contains("open")
        ) {
            closeModal();
        }
    }
);

async function getAuthToken() {
    if (typeof window.getAuthToken === "function") {
        const t = await window.getAuthToken();
        if (t) return t;
    }
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

    return await user.getIdToken();
}

async function loadExaminations() {
    try {
        const token =
            await getAuthToken();

        const response =
            await fetch(
                "/api/examinations",
                {
                    method: "GET",
                    headers: {
                        "Authorization":
                            `Bearer ${token}`
                    }
                }
            );

        const result =
            await response.json();

        if (!response.ok) {
            throw new Error(
                result.message ||
                "Unable to load examinations."
            );
        }

        examinations =
            result.examinations || [];

        renderExaminationOptions();

    } catch (error) {
        showMessage(
            error.message,
            "error"
        );
    }
}

function renderExaminationOptions() {
    if (!fragmentExam) {
        return;
    }

    fragmentExam.innerHTML = `
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
                `${examination.code} — ${examination.title || "Untitled examination"}`;

            fragmentExam.appendChild(
                option
            );
        }
    );

    if (
        examinations.length === 0
    ) {
        fragmentExam.innerHTML = `
            <option value="">
                No examinations available
            </option>
        `;
    }
}

fragmentForm?.addEventListener(
    "submit",
    async event => {
        event.preventDefault();

        const examinationId =
            fragmentExam.value;

        const number =
            Number(
                fragmentNumber.value
            );

        const label =
            fragmentLabel.value.trim();

        const questionText =
            fragmentText.value.trim();

        const isDecoy =
            fragmentIsDecoy?.checked === true;

        if (
            !examinationId ||
            !Number.isInteger(number) ||
            number < 1 ||
            !label ||
            !questionText
        ) {
            showMessage(
                "Please complete all fragment fields.",
                "error"
            );

            return;
        }

        try {
            setSubmitting(true);

            showMessage(
                isDecoy
                    ? "Creating canary fragment..."
                    : "Encrypting fragment...",
                "loading"
            );

            const token =
                await getAuthToken();

            const response =
                await fetch(
                    "/api/fragments",
                    {
                        method: "POST",
                        headers: {
                            "Content-Type":
                                "application/json",
                            "Authorization":
                                `Bearer ${token}`
                        },
                        body: JSON.stringify({
                            examinationId,
                            fragmentNumber:
                                number,
                            fragmentLabel:
                                label,
                            questionText,
                            isDecoy
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
                    "Failed to protect fragment."
                );
            }

            showMessage(
                isDecoy
                    ? "Canary fragment created and encrypted successfully."
                    : "Fragment encrypted and protected successfully.",
                "success"
            );

            setTimeout(
                async () => {
                    closeModal();
                    await loadFragments();
                },
                700
            );

        } catch (error) {
            showMessage(
                error.message ||
                "Unable to protect fragment.",
                "error"
            );

        } finally {
            setSubmitting(false);
        }
    }
);

async function loadFragments() {
    try {
        const token =
            await getAuthToken();

        const response =
            await fetch(
                "/api/fragments",
                {
                    method: "GET",
                    headers: {
                        "Authorization":
                            `Bearer ${token}`
                    }
                }
            );

        if (!response.ok) {
            throw new Error(
                "Unable to load protected fragments."
            );
        }

        const result =
            await response.json();

        if (!result.success) {
            throw new Error(
                result.message ||
                "Unable to load protected fragments."
            );
        }

        renderFragments(
            result.fragments || []
        );

    } catch (_error) {

    }
}

function renderFragments(
    fragments
) {
    const real =
        fragments.filter(
            f => !f.isDecoy
        );

    const decoys =
        fragments.filter(
            f => f.isDecoy
        );

    if (protectedCount) {
        protectedCount.textContent =
            String(real.length).padStart(2, "0");
    }

    if (decoyCount) {
        decoyCount.textContent =
            String(decoys.length).padStart(2, "0");
    }

    if (!fragmentList) {
        return;
    }

    const total =
        fragments.length;

    if (total === 0) {
        if (fragmentEmptyState) {
            fragmentEmptyState.hidden =
                false;
        }

        fragmentList.hidden =
            true;

        if (fragmentRegisterTitle) {
            fragmentRegisterTitle.textContent =
                "No fragments loaded";
        }

        if (fragmentRegisterStatus) {
            fragmentRegisterStatus.textContent =
                "Protected";
        }

        return;
    }

    if (fragmentEmptyState) {
        fragmentEmptyState.hidden =
            true;
    }

    fragmentList.hidden =
        false;

    if (fragmentRegisterTitle) {
        fragmentRegisterTitle.textContent =
            "Encrypted fragment register";
    }

    if (fragmentRegisterStatus) {
        fragmentRegisterStatus.textContent =
            `${total} protected`;
    }

    fragmentList.innerHTML =
        fragments
            .map(
                fragment =>
                    createFragmentItem(
                        fragment
                    )
            )
            .join("");
}

function createFragmentItem(
    fragment
) {
    const date =
        fragment.createdAt
            ? formatDate(
                fragment.createdAt
            )
            : "Protected";

    const examinationCode =
        fragment.examinationCode ||
        "EXAM";

    const label =
        fragment.fragmentLabel ||
        "Protected Fragment";

    const number =
        fragment.fragmentNumber ||
        1;

    const isDecoy =
        fragment.isDecoy === true;

    const decoyBadge =
        isDecoy
            ? `<span class="canary-badge">CANARY</span>`
            : "";

    const statusLabel =
        isDecoy
            ? "CANARY ENCRYPTED"
            : "ENCRYPTED";

    return `
        <div class="fragment-list-item${isDecoy ? " fragment-list-item--canary" : ""}">

            <div class="fragment-list-main">

                <div class="fragment-list-icon${isDecoy ? " fragment-list-icon--canary" : ""}">

                    <svg
                        viewBox="0 0 24 24"
                        fill="none"
                    >

                        <rect
                            x="5"
                            y="7"
                            width="14"
                            height="13"
                            rx="2"
                        />

                        <path d="M8 7V4h8v3"/>
                        <path d="M8 12h8"/>
                        <path d="M8 16h5"/>

                    </svg>

                </div>

                <div class="fragment-list-details">

                    <strong>
                        Fragment ${escapeHtml(number)}
                        ·
                        ${escapeHtml(label)}
                        ${decoyBadge}
                    </strong>

                    <span>
                        ${escapeHtml(examinationCode)}
                        ·
                        AES-256-GCM
                    </span>

                </div>

            </div>

            <div class="fragment-list-meta">

                <span>
                    ${date}
                </span>

                <strong>
                    ${statusLabel}
                </strong>

            </div>

        </div>
    `;
}

function formatDate(
    value
) {
    let date;

    if (
        value &&
        typeof value === "object" &&
        typeof value._seconds === "number"
    ) {
        date =
            new Date(
                value._seconds * 1000
            );
    } else {
        date =
            new Date(value);
    }

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return "Protected";
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
                Encrypting...
            </span>

            <b>
                ...
            </b>
        `;
    } else {
        submitButton.innerHTML = `
            <span>
                Encrypt &amp; protect
            </span>

            <b>
                →
            </b>
        `;
    }
}

async function initializeFragments() {
    try {
        await window.authReady;
        const token = typeof window.getAuthToken === "function"
            ? await window.getAuthToken()
            : await window.firebaseAuth?.currentUser?.getIdToken();
        if (!token) {
            return;
        }

        await loadExaminations();

        await loadFragments();

    } catch (_error) {}
}

initializeFragments();