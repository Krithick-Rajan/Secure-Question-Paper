const root = document.documentElement;

let targetX = window.innerWidth * 0.5;
let targetY = window.innerHeight * 0.5;

let currentX = targetX;
let currentY = targetY;

const reducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
).matches;

if (!reducedMotion) {

    window.addEventListener(
        "pointermove",
        event => {

            targetX = event.clientX;
            targetY = event.clientY;

            root.style.setProperty(
                "--cursor-opacity",
                "1"
            );

        },
        {
            passive: true
        }
    );

    window.addEventListener(
        "pointerleave",
        () => {

            root.style.setProperty(
                "--cursor-opacity",
                "0"
            );

        }
    );

    window.addEventListener(
        "pointerenter",
        () => {

            root.style.setProperty(
                "--cursor-opacity",
                "1"
            );

        }
    );

    function animate() {

        currentX +=
            (targetX - currentX) * 0.1;

        currentY +=
            (targetY - currentY) * 0.1;

        root.style.setProperty(
            "--cursor-x",
            `${currentX}px`
        );

        root.style.setProperty(
            "--cursor-y",
            `${currentY}px`
        );

        requestAnimationFrame(animate);
    }

    animate();
}