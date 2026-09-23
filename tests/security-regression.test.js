const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const server = fs.readFileSync(path.join(root, "server.js"), "utf8");

function test(name, fn) {
    try {
        fn();
        console.log(`ok - ${name}`);
    } catch (error) {
        console.error(`not ok - ${name}`);
        throw error;
    }
}

test("Firestore diagnostic endpoint requires admin authentication", () => {
    assert.match(server, /app\.get\("\/api\/test-firestore",\s*verifyToken,\s*requireRole\("admin"\)/);
});

test("self-service registration is admin-only", () => {
    assert.match(server, /app\.post\("\/api\/register",\s*verifyToken,\s*requireRole\("admin"\)/);
});

test("CORS is restricted through an allow-list", () => {
    assert.doesNotMatch(server, /app\.use\(cors\(\)\)/);
    assert.match(server, /CORS_ORIGINS/);
});

test("release execution does not persist assembled plaintext paper", () => {
    const executeRoute = server.slice(
        server.indexOf('app.post("/api/release/execute"'),
        server.indexOf('app.get("/api/audit-logs"')
    );
    assert.doesNotMatch(executeRoute, /assembledPaper,\s*\n/);
    assert.match(executeRoute, /deliveryMode:\s*"on-demand-decrypt"/);
    assert.match(executeRoute, /"release\.plaintextPersisted":\s*false/);
});

test("print download generates plaintext only on demand", () => {
    const printRoute = server.slice(
        server.indexOf('app.get("/api/print-operator/release-packet/:examinationId"'),
        server.indexOf('app.post("/api/print-operator/confirm-print"')
    );
    assert.match(printRoute, /assembledPaper/);
    assert.match(printRoute, /deliveryMode:\s*"on-demand-decrypt"/);
    assert.match(printRoute, /plaintextPersisted:\s*false/);
});

test("release execution requires a verified VDF proof", () => {
    const releaseAgent = fs.readFileSync(path.join(root, "backend", "security", "release-agent.js"), "utf8");
    const executeRoute = server.slice(
        server.indexOf('app.post("/api/release/execute"'),
        server.indexOf('app.get("/api/audit-logs"')
    );
    assert.match(releaseAgent, /vdfProof:\s*Boolean\(vdfVerified\)/);
    assert.match(executeRoute, /const vdfVerified = vdfState\.verified === true/);
    assert.match(executeRoute, /vdfVerified,/);
});
