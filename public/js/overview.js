"use strict";

function esc(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

async function loadOverview() {
    try {
        if (window.authReady && typeof window.authReady.then === "function") {
            await window.authReady;
        }

        const token = typeof window.getAuthToken === "function"
            ? await window.getAuthToken()
            : await window.firebaseAuth?.currentUser?.getIdToken();

        if (!token) {
            return;
        }

        const headers = { "Authorization": "Bearer " + token };

        const [metricsRes, examsRes, fragmentsRes, logsRes] = await Promise.all([
            fetch("/api/overview/metrics", { headers }).then(r => r.json()).catch(() => ({})),
            fetch("/api/examinations", { headers }).then(r => r.json()).catch(() => ({})),
            fetch("/api/fragments", { headers }).then(r => r.json()).catch(() => ({})),
            fetch("/api/audit-logs", { headers }).then(r => r.json()).catch(() => ({}))
        ]);

        const metrics = metricsRes.metrics || {};
        const exams = examsRes.examinations || [];
        const fragments = fragmentsRes.fragments || [];
        const logs = logsRes.logs || [];

        const totalExams = exams.length || metrics.totalExams || 0;
        const totalFragments = fragments.length || metrics.totalFragments || 0;

        const examsEl = document.getElementById("overview-active-exams");
        const examsBottomEl = document.getElementById("overview-active-exams-bottom");
        const fragsEl = document.getElementById("overview-fragments");
        const fragsBottomEl = document.getElementById("overview-fragments-bottom");

        if (examsEl) {
            examsEl.textContent = String(totalExams).padStart(2, "0");
        }
        if (examsBottomEl) {
            examsBottomEl.textContent = totalExams === 1 ? "1 active examination" : `${totalExams} active examinations`;
        }
        if (fragsEl) {
            fragsEl.textContent = String(totalFragments).padStart(2, "0");
        }
        if (fragsBottomEl) {
            fragsBottomEl.textContent = totalFragments === 1 ? "1 encrypted fragment" : `${totalFragments} encrypted fragments`;
        }

        const controlBody = document.getElementById("overviewControlBody");
        if (controlBody && exams.length > 0) {
            const activeExam = exams[0];
            const examFrags = fragments.filter(f => f.examinationId === activeExam.id || f.examinationCode === activeExam.code);
            const fragCount = examFrags.length;
            const isInit = activeExam.custodyStatus === "initialized" || activeExam.custodyStatus === "verified";
            controlBody.className = "control-content";
            controlBody.innerHTML = `
                <div>
                    <div class="control-header-row">
                        <div class="control-code-wrap">
                            <span class="exam-code-tag">${esc(activeExam.code || "EXAM")}</span>
                            <span class="control-status-badge ${isInit ? 'status-initialized' : 'status-pending'}">${esc((activeExam.custodyStatus || "active").toUpperCase())}</span>
                        </div>
                        <span class="ready-pill">${esc((activeExam.status || "READY").toUpperCase())}</span>
                    </div>
                    <h3 class="control-exam-title">${esc(activeExam.title || activeExam.name || "Active Examination")}</h3>
                    <p class="control-exam-subject">${esc(activeExam.subject || "Protected examination workflow")}</p>
                    <div class="control-meta-grid">
                        <div class="control-meta-item">
                            <span class="control-meta-label">FRAGMENTS</span>
                            <strong class="control-meta-val">${fragCount > 0 ? fragCount + " ENCRYPTED" : "AWAITING UPLOAD"}</strong>
                        </div>
                        <div class="control-meta-item">
                            <span class="control-meta-label">CUSTODY THRESHOLD</span>
                            <strong class="control-meta-val">3 OF 5 SHARES</strong>
                        </div>
                        <div class="control-meta-item">
                            <span class="control-meta-label">VDF TIME GATE</span>
                            <strong class="control-meta-val">${esc(activeExam.examDate || "SCHEDULED")}</strong>
                        </div>
                    </div>
                </div>
                <div class="control-actions">
                    <a href="/exams.html" class="control-btn-secondary">Manage exams</a>
                    <a href="/security.html" class="control-btn-secondary">Security controls</a>
                    <a href="/release.html" class="control-btn-primary"><span>Release workflow</span><b>→</b></a>
                </div>
            `;
        }

        const pipelineSteps = document.querySelectorAll(".pipeline-step");
        if (pipelineSteps.length >= 5) {
            if (exams.length > 0) {
                pipelineSteps[0].classList.add("active");
            }
            if (totalFragments > 0) {
                pipelineSteps[1].classList.add("active");
            }
            if (exams.some(e => e.custodyStatus === "initialized" || e.custodyStatus === "verified")) {
                pipelineSteps[2].classList.add("active");
            }
            if (exams.some(e => e.security && e.security.status === "verified")) {
                pipelineSteps[3].classList.add("active");
            }
            if (exams.some(e => e.releaseStatus === "released")) {
                pipelineSteps[4].classList.add("active");
            }
        }

        const secBody = document.getElementById("overviewSecurityEventsBody");
        if (secBody && logs.length > 0) {
            secBody.innerHTML = `
                <div style="width: 100%; display: flex; flex-direction: column; gap: 8px;">
                    ${logs.slice(0, 3).map(l => `
                        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--border-soft);">
                            <strong style="color: var(--text);">${esc(l.action || "SECURITY_EVENT")}</strong>
                            <span style="color: var(--text-muted); font-family: var(--font-mono); font-size: 10px;">${esc(l.timestamp ? new Date(l.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : "Recorded")}</span>
                        </div>
                    `).join("")}
                </div>
            `;
        }

        const fragBody = document.getElementById("overviewFragmentStatusBody");
        if (fragBody && fragments.length > 0) {
            fragBody.innerHTML = `
                <div style="width: 100%; display: flex; flex-direction: column; gap: 8px;">
                    ${fragments.slice(0, 3).map(f => `
                        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px; padding: 4px 0; border-bottom: 1px solid var(--border-soft);">
                            <div>
                                <strong style="color: var(--text);">${esc(f.title || f.fragmentLabel || "Protected Fragment")}</strong>
                                <span style="color: var(--text-dim); margin-left: 6px;">${esc(f.examinationCode || "")}</span>
                            </div>
                            <span class="ready-pill" style="font-size: 9px;">AES-256-GCM</span>
                        </div>
                    `).join("")}
                </div>
            `;
        }

    } catch (_err) {}
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadOverview);
} else {
    loadOverview();
}
