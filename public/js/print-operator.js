"use strict";

let printToken = null;
let printAssignment = null;

async function initPrintPage() {
    try {
        await window.authReady;
        const token = typeof window.getAuthToken === "function"
            ? await window.getAuthToken()
            : await window.firebaseAuth?.currentUser?.getIdToken();
        if (!token) { return; }
        printToken = token;
        let user = window.firebaseAuth?.currentUser || window.currentUserProfile;
        if (!user || !user.email) {
            const meRes = await fetch("/api/me", { headers: { Authorization: "Bearer " + token } }).then(r => r.json()).catch(() => ({}));
            if (meRes && meRes.user) user = meRes.user;
        }
        const a = document.getElementById('printAvatar');
        const n = document.getElementById('printName');
        const e = document.getElementById('printEmail');
        if (a && user && user.email) a.textContent = user.email[0].toUpperCase();
        if (n && user) n.textContent = user.displayName || user.name || 'Print Operator';
        if (e && user) e.textContent = user.email || '';
        await loadPrintAssignment();
    } catch (_error) {
        showPrintError('Unable to load print portal: ' + _error.message);
    }
}

async function loadPrintAssignment() {
    const bodyEl  = document.getElementById("printAssignmentBody");
    const badgeEl = document.getElementById("printStatusBadge");

    try {
        const res  = await fetch("/api/print-operator/my-assignment", {
            headers: { Authorization: `Bearer ${printToken}` }
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.message);

        if (!data.assignment) {
            if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty">No print assignment found. Contact the administrator.</div>`;
            if (badgeEl) { badgeEl.textContent = "UNASSIGNED"; badgeEl.className = "security-module-badge badge-fail"; }
            return;
        }

        printAssignment = data.assignment;
        const { examinationCode, examinationName, releaseStatus, releaseTime, releaseExecuted, printConfirmed } = data.assignment;

        if (bodyEl) {
            bodyEl.innerHTML = `
                <div class="portal-info-grid">
                    <div class="portal-info-row">
                        <span>Examination</span>
                        <strong>${escPHtml(examinationCode)} — ${escPHtml(examinationName || "")}</strong>
                    </div>
                    <div class="portal-info-row">
                        <span>Release time</span>
                        <strong>${releaseTime ? new Date(releaseTime._seconds ? releaseTime._seconds * 1000 : releaseTime).toLocaleString() : "Not set"}</strong>
                    </div>
                    <div class="portal-info-row">
                        <span>Release status</span>
                        <strong>${escPHtml(releaseStatus || "pending")}</strong>
                    </div>
                    <div class="portal-info-row">
                        <span>Print confirmed</span>
                        <strong>${printConfirmed ? "\u2713 Confirmed" : "Not yet confirmed"}</strong>
                    </div>
                </div>
            `;
        }

        if (badgeEl) {
            badgeEl.textContent = releaseExecuted ? "RELEASED" : "PENDING";
            badgeEl.className = `security-module-badge ${releaseExecuted ? "badge-pass" : "badge-warn"}`;
        }

        if (printConfirmed) {
            const donePanel = document.getElementById("printDonePanel");
            if (donePanel) donePanel.style.display = "";
            return;
        }

        const actionPanel = document.getElementById("printActionPanel");
        if (actionPanel) actionPanel.style.display = "";

        const dlBtn = document.getElementById("downloadPacketButton");
        if (releaseExecuted && dlBtn) {
            dlBtn.disabled = false;
            dlBtn.addEventListener("click", handleDownloadPacket);
        } else if (dlBtn) {
            dlBtn.title = "Release has not been executed yet.";
        }

        const confirmRow = document.getElementById("confirmPrintRow");
        if (releaseExecuted && confirmRow) {
            confirmRow.style.display = "";
            document.getElementById("confirmPrintButton")?.addEventListener("click", handleConfirmPrint);
        }

    } catch (_err) {
        if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty portal-error">Failed to load: ${escPHtml(_err.message)}</div>`;
    }
}

async function handleDownloadPacket() {
    const msgEl = document.getElementById("printDownloadMessage");
    const btn   = document.getElementById("downloadPacketButton");

    if (btn) { btn.disabled = true; btn.querySelector("span").textContent = "Downloading..."; }
    if (msgEl) { msgEl.textContent = "Fetching release packet..."; msgEl.className = "form-message loading"; }

    try {
        const res  = await fetch(`/api/print-operator/release-packet/${encodeURIComponent(printAssignment.examinationId)}`, {
            headers: { Authorization: `Bearer ${printToken}` }
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || "Download failed.");

        const packet  = data.releasePacket;
        const content = typeof packet === "object" ? JSON.stringify(packet, null, 2) : String(packet);
        const blob    = new Blob([content], { type: "application/octet-stream" });
        const url     = URL.createObjectURL(blob);
        const a       = document.createElement("a");
        a.href        = url;
        a.download    = `release-packet-${escPHtml(data.examinationCode || printAssignment.examinationId)}.bin`;
        a.click();
        URL.revokeObjectURL(url);

        if (msgEl) { msgEl.textContent = "\u2713 Release packet downloaded. Transfer to air-gapped terminal."; msgEl.className = "form-message success"; }
        if (btn) { btn.querySelector("span").textContent = "Download packet"; }

    } catch (_err) {
        if (msgEl) { msgEl.textContent = _err.message; msgEl.className = "form-message error"; }
        if (btn) { btn.disabled = false; btn.querySelector("span").textContent = "Download packet"; }
    }
}

async function handleConfirmPrint() {
    const msgEl = document.getElementById("printConfirmMessage");
    const btn   = document.getElementById("confirmPrintButton");

    if (btn) { btn.disabled = true; btn.querySelector("span").textContent = "Confirming..."; }
    if (msgEl) { msgEl.textContent = "Recording confirmation..."; msgEl.className = "form-message loading"; }

    try {
        const res  = await fetch("/api/print-operator/confirm-print", {
            method:  "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${printToken}` },
            body:    JSON.stringify({ examinationId: printAssignment.examinationId })
        });
        const data = await res.json();
        if (!res.ok || !data.success) throw new Error(data.message || "Confirmation failed.");

        const actionPanel = document.getElementById("printActionPanel");
        const donePanel   = document.getElementById("printDonePanel");
        if (actionPanel) actionPanel.style.display = "none";
        if (donePanel)   donePanel.style.display = "";

    } catch (_err) {
        if (msgEl) { msgEl.textContent = _err.message; msgEl.className = "form-message error"; }
        if (btn) { btn.disabled = false; btn.querySelector("span").textContent = "Confirm print"; }
    }
}

function showPrintError(msg) {
    const bodyEl = document.getElementById("printAssignmentBody");
    if (bodyEl) bodyEl.innerHTML = `<div class="portal-empty portal-error">${escPHtml(msg)}</div>`;
}

function escPHtml(v) {
    return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

initPrintPage();
