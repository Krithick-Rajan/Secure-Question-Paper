(function () {
    "use strict";

    const root = document.documentElement;

    let hasMoved = false;

    // Start with cursor off-screen and invisible so it NEVER appears in the middle of the webpage
    root.style.setProperty("--cursor-x", "-9999px");
    root.style.setProperty("--cursor-y", "-9999px");
    root.style.setProperty("--cursor-opacity", "0");

    function updateCursor(x, y) {
        if (typeof x !== "number" || typeof y !== "number" || Number.isNaN(x) || Number.isNaN(y)) return;

        // Direct 1:1 hardware-rate update for ZERO lag
        root.style.setProperty("--cursor-x", `${x}px`);
        root.style.setProperty("--cursor-y", `${y}px`);

        if (!hasMoved) {
            hasMoved = true;
            root.style.setProperty("--cursor-opacity", "1");
        }
    }

    function onPointerMove(event) {
        updateCursor(event.clientX, event.clientY);
    }

    function onTouchMove(event) {
        if (event.touches && event.touches[0]) {
            updateCursor(event.touches[0].clientX, event.touches[0].clientY);
        }
    }

    function onPointerEnter(event) {
        if (event.clientX && event.clientY) {
            updateCursor(event.clientX, event.clientY);
        }
        root.style.setProperty("--cursor-opacity", "1");
    }

    function onPointerLeave() {
        root.style.setProperty("--cursor-opacity", "0");
    }

    // Passive listeners for best browser scrolling performance
    window.addEventListener("pointermove", onPointerMove, { passive: true });
    window.addEventListener("mousemove", onPointerMove, { passive: true });
    window.addEventListener("touchmove", onTouchMove, { passive: true });
    window.addEventListener("pointerdown", onPointerMove, { passive: true });
    window.addEventListener("pointerenter", onPointerEnter, { passive: true });
    window.addEventListener("pointerleave", onPointerLeave, { passive: true });

    // Handle document visibility/focus
    window.addEventListener("blur", onPointerLeave);
    window.addEventListener("focus", () => {
        if (hasMoved) {
            root.style.setProperty("--cursor-opacity", "1");
        }
    });
})();