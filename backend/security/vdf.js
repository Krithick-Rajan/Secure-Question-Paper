"use strict";

const crypto = require("crypto");

const RSA_MODULUS = BigInt(
    "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357"
);

const RSA_MODULUS_ID = "RSA-2048-challenge";
const DEFAULT_ITERATIONS = 10000;

function modPow(base, exp, mod) {
    if (mod === 1n) return 0n;
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp & 1n) result = result * base % mod;
        exp >>= 1n;
        base = base * base % mod;
    }
    return result;
}

function millerRabinRound(n, d, r, a) {
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) return true;
    for (let i = 0n; i < r - 1n; i++) {
        x = x * x % n;
        if (x === n - 1n) return true;
    }
    return false;
}

function isProbablyPrime(n) {
    if (n < 2n) return false;
    if (n === 2n || n === 3n || n === 5n || n === 7n) return true;
    if (n % 2n === 0n) return false;

    let r = 0n;
    let d = n - 1n;
    while (d % 2n === 0n) { d /= 2n; r++; }

    const witnesses = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
    for (const a of witnesses) {
        if (a >= n) continue;
        if (!millerRabinRound(n, d, r, a)) return false;
    }
    return true;
}

function hashToPrime(x, y, T) {
    const seed = crypto
        .createHash("sha256")
        .update(x.toString(16))
        .update("|")
        .update(y.toString(16))
        .update("|")
        .update(String(T))
        .digest("hex");

    let candidate = BigInt("0x" + seed);
    if (candidate % 2n === 0n) candidate += 1n;
    while (!isProbablyPrime(candidate)) {
        candidate += 2n;
    }
    return candidate;
}

function inputToGroupElement(input) {
    const N = RSA_MODULUS;
    let raw;
    if (Buffer.isBuffer(input)) raw = input;
    else if (typeof input === "string") raw = Buffer.from(input, "utf8");
    else raw = Buffer.from(JSON.stringify(input), "utf8");
    const hash = crypto.createHash("sha256").update(raw).digest();
    return (BigInt("0x" + hash.toString("hex")) % (N - 4n)) + 2n;
}

function computeProof(x, T, N, l) {
    const bits = [];
    let remainder = 1n;
    bits.push(remainder >= l ? 1 : 0);
    if (remainder >= l) remainder -= l;

    for (let i = 0; i < T; i++) {
        remainder = 2n * remainder;
        if (remainder >= l) {
            bits.push(1);
            remainder -= l;
        } else {
            bits.push(0);
        }
    }

    let proof = 1n;
    for (const bit of bits) {
        proof = proof * proof % N;
        if (bit === 1) proof = proof * x % N;
    }
    return proof;
}

function computeWesolowskiVdf(input, T = DEFAULT_ITERATIONS) {
    const N = RSA_MODULUS;
    const startedAt = Date.now();
    const x = inputToGroupElement(input);

    let y = x;
    for (let i = 0; i < T; i++) {
        y = y * y % N;
    }

    const l = hashToPrime(x, y, T);
    const proof = computeProof(x, T, N, l);
    const computeMs = Date.now() - startedAt;

    return {
        algorithm: "wesolowski-rsa-vdf",
        x: x.toString(16),
        y: y.toString(16),
        proof: proof.toString(16),
        l: l.toString(),
        T,
        N_id: RSA_MODULUS_ID,
        computeMs
    };
}

function verifyWesolowskiVdf({ x, y, proof, l, T }) {
    const N = RSA_MODULUS;
    const startedAt = Date.now();

    if (!x || !y || !proof || !l || !T) {
        return {
            valid: false,
            reason: "Missing VDF fields (x, y, proof, l, T are all required)",
            verifyMs: 0
        };
    }

    try {
        const xBig = BigInt("0x" + x);
        const yBig = BigInt("0x" + y);
        const proofBig = BigInt("0x" + proof);
        const lBig = BigInt(l);
        const TBig = BigInt(T);

        const r = modPow(2n, TBig, lBig);
        const piL = modPow(proofBig, lBig, N);
        const xR = modPow(xBig, r, N);
        const expected = piL * xR % N;
        const valid = yBig === expected;
        const verifyMs = Date.now() - startedAt;

        return {
            valid,
            reason: valid ? "Wesolowski VDF proof verified" : "VDF proof check failed: y ≠ π^ℓ · x^r (mod N)",
            verifyMs
        };
    } catch (_err) {
        return {
            valid: false,
            reason: "VDF proof verification error: invalid field encoding",
            verifyMs: Date.now() - startedAt
        };
    }
}

function createReleaseTimeInput({ examinationId, releaseAt, mpcManifestHash, custodyFingerprint }) {
    if (!examinationId) throw new Error("Examination ID is required");
    if (!releaseAt) throw new Error("Release time is required");
    return [
        "SECURE-QUESTION-PAPER-VDF-WESOLOWSKI",
        examinationId,
        String(releaseAt),
        mpcManifestHash || "",
        custodyFingerprint || ""
    ].join("|");
}

function createVdfCommitment({ examinationId, releaseAt, mpcManifestHash, custodyFingerprint, iterations = DEFAULT_ITERATIONS }) {
    const input = createReleaseTimeInput({ examinationId, releaseAt, mpcManifestHash, custodyFingerprint });
    const result = computeWesolowskiVdf(input, iterations);
    const inputHash = crypto.createHash("sha256").update(input, "utf8").digest("hex");
    return {
        ...result,
        examinationId,
        releaseAt,
        inputHash,
        output: result.y,
        iterations: result.T
    };
}

function verifyVdfCommitment({ examinationId, releaseAt, mpcManifestHash, custodyFingerprint, storedVdf }) {
    if (!storedVdf || !storedVdf.proof) {
        return {
            valid: false,
            reason: "No Wesolowski proof found. Re-initialize VDF to upgrade.",
            verifyMs: 0
        };
    }

    const input = createReleaseTimeInput({ examinationId, releaseAt, mpcManifestHash, custodyFingerprint });
    const expectedX = inputToGroupElement(input);
    if (expectedX.toString(16) !== storedVdf.x) {
        return {
            valid: false,
            reason: "VDF input mismatch — commitment does not match current exam parameters",
            verifyMs: 0
        };
    }

    const inputHash = crypto.createHash("sha256").update(input, "utf8").digest("hex");
    const result = verifyWesolowskiVdf(storedVdf);
    return {
        ...result,
        examinationId,
        releaseAt,
        inputHash,
        computedOutput: storedVdf.y
    };
}

function isReleaseTimeReached(releaseAt) {
    const ts = new Date(releaseAt).getTime();
    if (Number.isNaN(ts)) throw new Error("Invalid release time");
    return Date.now() >= ts;
}

function getRemainingMilliseconds(releaseAt) {
    const ts = new Date(releaseAt).getTime();
    if (Number.isNaN(ts)) throw new Error("Invalid release time");
    return Math.max(0, ts - Date.now());
}

module.exports = {
    DEFAULT_ITERATIONS,
    RSA_MODULUS_ID,
    modPow,
    isProbablyPrime,
    hashToPrime,
    inputToGroupElement,
    computeProof,
    computeWesolowskiVdf,
    verifyWesolowskiVdf,
    createReleaseTimeInput,
    createVdfCommitment,
    verifyVdfCommitment,
    isReleaseTimeReached,
    getRemainingMilliseconds
};