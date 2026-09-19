"use strict";

function createPrintSidebar() {
    const sidebar = document.createElement("aside");
    sidebar.className = "sidebar";
    sidebar.innerHTML = `
        <div class="brand">
            <div class="brand-mark"><span></span></div>
            <div class="brand-text">
                <div class="brand-name">SECURE QUESTION PAPER</div>
                <div class="brand-caption">PRINT TERMINAL</div>
            </div>
        </div>
        <nav class="navigation">
            <div class="navigation-heading">Workspace</div>
            <a class="navigation-item active" href="/print-operator.html"><span>Release Terminal</span></a>
        </nav>
        <div class="sidebar-bottom">
            <div class="administrator">
                <div class="administrator-avatar" id="printAvatar">P</div>
                <div class="administrator-info">
                    <strong id="printName">Print Operator</strong>
                    <span id="printEmail">operator@exam.com</span>
                    <a href="javascript:void(0)" onclick="window.logout()" style="color: #ff5252; text-decoration: none; font-size: 11px;">Sign out</a>
                </div>
                <div class="administrator-status"></div>
            </div>
        </div>
    `;
    return sidebar;
}

function initPrintShell() {
    const existing = document.getElementById("page-content");
    if (!existing) return;
    const wrapper = document.createElement("div");
    wrapper.className = "page-content-wrapper";
    while (existing.firstChild) wrapper.appendChild(existing.firstChild);
    existing.remove();
    const app = document.createElement("div");
    app.className = "app";
    const main = document.createElement("main");
    main.className = "main";
    const topbar = document.createElement("header");
    topbar.className = "topbar";
    topbar.innerHTML = `
        <div class="breadcrumb"><span>Secure Question Paper</span><b>/</b><strong>Print Terminal</strong></div>
        <div class="topbar-right">
            <div class="live-status"><span></span>System operational</div>
            <div class="topbar-divider"></div>
            <div class="date">${new Date().toLocaleDateString("en-GB", { day:"2-digit", month:"short", year:"numeric" })}</div>
        </div>
    `;
    const content = document.createElement("div");
    content.className = "content";
    content.id = "rendered-content";
    content.appendChild(wrapper);
    main.appendChild(topbar);
    main.appendChild(content);
    app.appendChild(createPrintSidebar());
    app.appendChild(main);
    document.body.appendChild(app);
    document.dispatchEvent(new CustomEvent("secureCustodyShellReady"));
}

if (document.getElementById("page-content")) {
    initPrintShell();
} else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPrintShell, { once: true });
} else {
    initPrintShell();
}
