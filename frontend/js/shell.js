"use strict";

const page =
    document.body.dataset.page || "overview";

const pages = {
    overview: {
        title: "Overview",
        href: "/overview.html"
    },

    exams: {
        title: "Examinations",
        href: "/exams.html"
    },

    fragments: {
        title: "Fragments",
        href: "/fragments.html"
    },

    custodians: {
        title: "Custody",
        href: "/custodians.html"
    },

    release: {
        title: "Release",
        href: "/release.html"
    },

    security: {
        title: "Security",
        href: "/security.html"
    },

    audit: {
        title: "Audit log",
        href: "/audit.html"
    },

    users: {
        title: "Users",
        href: "/users.html"
    }
};

function createNavigationItem(key) {
    const item =
        pages[key];

    if (!item) {
        return "";
    }

    const active =
        key === page
            ? "active"
            : "";

    return `
        <a
            class="navigation-item ${active}"
            href="${item.href}"
        >
            <span>${item.title}</span>
        </a>
    `;
}

function createSidebar() {
    const sidebar =
        document.createElement("aside");

    sidebar.className =
        "sidebar";

    sidebar.innerHTML = `
        <div class="brand">

            <div class="brand-mark">
                <span></span>
            </div>

            <div class="brand-text">

                <div class="brand-name">
                    SECURE CUSTODY
                </div>

                <div class="brand-caption">
                    EXAMINATION SECURITY
                </div>

            </div>

        </div>

        <nav class="navigation">

            <div class="navigation-heading">
                Workspace
            </div>

            ${createNavigationItem("overview")}
            ${createNavigationItem("exams")}
            ${createNavigationItem("custodians")}
            ${createNavigationItem("fragments")}
            ${createNavigationItem("release")}

            <div class="navigation-heading second">
                Security
            </div>

            ${createNavigationItem("security")}
            ${createNavigationItem("audit")}
            ${createNavigationItem("users")}

        </nav>

        <div class="sidebar-bottom">

            <div class="administrator">

                <div class="administrator-avatar">
                    A
                </div>

                <div class="administrator-info">

                    <strong>
                        Administrator
                    </strong>

                    <span>
                        System access
                    </span>

                </div>

                <div class="administrator-status"></div>

            </div>

        </div>
    `;

    return sidebar;
}

function createTopbar() {
    const topbar =
        document.createElement("header");

    topbar.className =
        "topbar";

    const pageTitle =
        pages[page]
            ? pages[page].title
            : "Overview";

    topbar.innerHTML = `
        <div class="breadcrumb">

            <span>
                Secure Custody
            </span>

            <b>/</b>

            <strong>
                ${pageTitle}
            </strong>

        </div>

        <div class="topbar-right">

            <div class="live-status">

                <span></span>

                System operational

            </div>

            <div class="topbar-divider"></div>

            <div
                class="date"
                id="current-date"
            >
                ${getCurrentDate()}
            </div>

        </div>
    `;

    return topbar;
}

function createMain(content) {
    const main =
        document.createElement("main");

    main.className =
        "main";

    const topbar =
        createTopbar();

    const contentWrapper =
        document.createElement("div");

    contentWrapper.className =
        "content";

    contentWrapper.id =
        "rendered-content";

    contentWrapper.appendChild(
        content
    );

    main.appendChild(
        topbar
    );

    main.appendChild(
        contentWrapper
    );

    return main;
}

function createApplication() {
    const existingContent =
        document.getElementById(
            "page-content"
        );

    if (!existingContent) {
        return;
    }

    const pageContent =
        document.createElement("div");

    pageContent.className =
        "page-content-wrapper";

    while (
        existingContent.firstChild
    ) {
        pageContent.appendChild(
            existingContent.firstChild
        );
    }

    existingContent.remove();

    const app =
        document.createElement("div");

    app.className =
        "app";

    const sidebar =
        createSidebar();

    const main =
        createMain(
            pageContent
        );

    app.appendChild(
        sidebar
    );

    app.appendChild(
        main
    );

    document.body.appendChild(
        app
    );

    updatePageTitle();

    initializeNavigation();

    document.dispatchEvent(
        new CustomEvent(
            "secureCustodyShellReady"
        )
    );
}

function updatePageTitle() {
    const currentPage =
        pages[page];

    if (!currentPage) {
        return;
    }

    document.title =
        `${currentPage.title} | Secure Custody`;
}

function initializeNavigation() {
    const links =
        document.querySelectorAll(
            ".navigation-item"
        );

    links.forEach(
        link => {

            link.addEventListener(
                "click",
                event => {

                    const href =
                        link.getAttribute(
                            "href"
                        );

                    if (!href) {
                        return;
                    }

                    if (
                        href ===
                        window.location.pathname
                    ) {
                        event.preventDefault();
                    }

                }
            );

        }
    );
}

function getCurrentDate() {
    const date =
        new Date();

    return date.toLocaleDateString(
        "en-GB",
        {
            day: "2-digit",
            month: "short",
            year: "numeric"
        }
    );
}

function initializeShell() {
    if (
        document.readyState ===
        "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            createApplication,
            {
                once: true
            }
        );

    } else {

        createApplication();

    }
}

initializeShell();