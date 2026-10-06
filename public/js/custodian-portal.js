"use strict";

let custodianToken = null;
let custodianAssignment = null;

async function initCustodianPage() {
    try {
        await window.authReady;
        const token = typeof window.getAuthToken === "function"
            ? await window.getAuthToken()
            : await window.firebaseAuth?.currentUser?.getIdToken();
        if (!token) { return; }
        custodianToken = token;
        let user = window.firebaseAuth?.currentUser || window.currentUserProfile;
        if (!user || !user.email) {
            const meRes = await fetch("/api/me", { headers: { Authorization: "Bearer " + token } }).then(r => r.json()).catch(() => ({}));
            if (meRes && meRes.user) user = meRes.user;
        }
        const a = document.getElementById('custodianAvatar');
        const n = document.getElementById('custodianName');
        const e = document.getElementById('custodianEmail');
        if (a && user && user.email) a.textContent = user.email[0].toUpperCase();
        if (n && user) n.textContent = user.displayName || user.name || 'Custodian';
        if (e && user) e.textContent = user.email || '';
        await loadCustodianAssignment();
    } catch (_error) {
        showCustodianError('Unable to load custodian portal: ' + _error.message);
    }
}

async function loadCustodianAssignment(targetExamId = null) {
    const bodyEl = document.getElementById("custodianAssignmentBody");
    const badgeEl = document.getElementById("custodianStatusBadge");
    const submitPanel = document.getElementById("custodianSubmitPanel");
    const donePanel   = document.getElementById("custodianDonePanel");

    if (submitPanel) submitPanel.style.display = "none";
    if (donePanel) donePanel.style.display = "none";

    try {
        const url = targetExamId
            ? `/api/custodian/my-assignment?examinationId=${encodeURIComponent(targetExamId)}`
            : "/api/custodian/my-assignment";
        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${custodianToken}` }
        });
        const data = await res.json();

        if (!data.success) throw new Error(data.message);

        if (!data.assignment) {
            if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty">No custody assignment found. Contact the administrator.</div>`;
            if (badgeEl) { badgeEl.textContent = "UNASSIGNED"; badgeEl.className = "security-module-badge badge-fail"; }
            return;
        }

        custodianAssignment = data.assignment;

        const { examinationCode, examinationName, shareNumber, shareValue, custodyStatus, shareSubmitted, releaseTime } = data.assignment;

        const allAssignments = data.assignments || [data.assignment];
        let selectorHtml = "";
        if (allAssignments.length > 1) {
            selectorHtml = `
                <div class="portal-info-row" style="margin-bottom: 14px; padding-bottom: 12px; border-bottom: 1px solid var(--border, rgba(255,255,255,0.08));">
                    <span style="font-weight: 600; color: var(--gold-bright, #d0aa60);">Switch Examination</span>
                    <select id="custodianExamSelector" style="background: rgba(0,0,0,0.5); color: #fff; border: 1px solid rgba(255,255,255,0.2); border-radius: 6px; padding: 6px 12px; font-size: 13px; outline: none; cursor: pointer;">
                        ${allAssignments.map(a => `<option value="${a.examinationId}" ${a.examinationId === custodianAssignment.examinationId ? "selected" : ""}>${escCHtml(a.examinationCode)} — ${escCHtml(a.examinationName || "")} (${a.shareSubmitted ? "Submitted" : "Pending"})</option>`).join("")}
                    </select>
                </div>
            `;
        }

        if (bodyEl) {
            bodyEl.innerHTML = `
                ${selectorHtml}
                <div class="portal-info-grid">
                    <div class="portal-info-row">
                        <span>Examination</span>
                        <strong>${escCHtml(examinationCode)} — ${escCHtml(examinationName || "")}</strong>
                    </div>
                    <div class="portal-info-row">
                        <span>Your share number</span>
                        <strong class="share-card-label">SHARE #${escCHtml(shareNumber)}</strong>
                    </div>
                    ${shareValue ? `
                    <div class="portal-info-row">
                        <span>Your assigned share value</span>
                        <code style="font-family: monospace; font-size: 11px; word-break: break-all; color: var(--accent);">${escCHtml(shareValue)}</code>
                    </div>
                    ` : ""}
                    <div class="portal-info-row">
                        <span>Custody status</span>
                        <strong>${escCHtml(custodyStatus)}</strong>
                    </div>
                    <div class="portal-info-row">
                        <span>Release time</span>
                        <strong>${releaseTime ? new Date(releaseTime._seconds ? releaseTime._seconds * 1000 : releaseTime).toLocaleString() : "Not set"}</strong>
                    </div>
                    <div class="portal-info-row">
                        <span>Share submission</span>
                        <strong>${shareSubmitted ? "✓ Submitted" : "Not yet submitted"}</strong>
                    </div>
                </div>
            `;
        }

        if (allAssignments.length > 1) {
            document.getElementById("custodianExamSelector")?.addEventListener("change", (e) => loadCustodianAssignment(e.target.value));
        }

        if (badgeEl) {
            badgeEl.textContent = custodyStatus === "initialized" ? "INITIALIZED" : "PENDING";
            badgeEl.className = `security-module-badge ${custodyStatus === "initialized" ? "badge-warn" : "badge-neutral"}`;
        }

        const numLabel = document.getElementById("custodianShareNumLabel");
        if (numLabel) numLabel.textContent = shareNumber;

        const valInput = document.getElementById("custodianShareValue");
        if (valInput && shareValue) {
            valInput.value = shareValue;
        }

        if (custodyStatus === "initialized") {
            if (shareSubmitted) {
                if (submitPanel) submitPanel.style.display = "none";
                if (donePanel) donePanel.style.display = "";
            } else {
                if (donePanel) donePanel.style.display = "none";
                if (submitPanel) submitPanel.style.display = "";
                document.getElementById("custodianSubmitButton")?.addEventListener("click", handleCustodianSubmit);
                await refreshCustodianShareCount();
            }
        }

    } catch (_err) {
        if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty portal-error">Failed to load assignment: ${escCHtml(_err.message)}</div>`;
    }
}

async function refreshCustodianShareCount() {
    if (!custodianAssignment) return;
    try {
        const res = await fetch(`/api/custody/session-shares/${encodeURIComponent(custodianAssignment.examinationId)}`, {
            headers: { Authorization: `Bearer ${custodianToken}` }
        });
        const data = await res.json();
        const badge = document.getElementById("custodianShareCount");
        if (badge && data.success) {
            badge.textContent = `${data.submittedCount} of 3 submitted`;
            badge.className = `share-count-badge${data.thresholdMet ? " threshold-met" : ""}`;
        }
    } catch (_err) {  }
}

async function handleCustodianSubmit() {
    const valueEl = document.getElementById("custodianShareValue");
    const msgEl   = document.getElementById("custodianSubmitMessage");
    const btn     = document.getElementById("custodianSubmitButton");
    const shareValue = valueEl?.value?.trim();

    if (!shareValue) {
        if (msgEl) { msgEl.textContent = "Paste your share value."; msgEl.className = "form-message error"; }
        return;
    }

    if (btn) { btn.disabled = true; btn.querySelector("span").textContent = "Submitting..."; }
    if (msgEl) { msgEl.textContent = "Submitting share..."; msgEl.className = "form-message loading"; }

    try {
        const res = await fetch("/api/custodian/submit-share", {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${custodianToken}` },
            body: JSON.stringify({
                shareValue,
                examinationId: custodianAssignment?.examinationId
            })
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || "Submission failed.");

        const submitPanel = document.getElementById("custodianSubmitPanel");
        const donePanel   = document.getElementById("custodianDonePanel");
        if (submitPanel) submitPanel.style.display = "none";
        if (donePanel)   donePanel.style.display = "";

    } catch (_err) {
        if (msgEl) { msgEl.textContent = _err.message; msgEl.className = "form-message error"; }
        if (btn) { btn.disabled = false; btn.querySelector("span").textContent = "Submit my share"; }
    }
}

function showCustodianError(msg) {
    const bodyEl = document.getElementById("custodianAssignmentBody");
    if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty portal-error">${escCHtml(msg)}</div>`;
}

function escCHtml(v) {
    return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

initCustodianPage();
