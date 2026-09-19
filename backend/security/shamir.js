"use strict";

const crypto = require("crypto");

const FIELD_SIZE = 256;
const MAX_SHARES = 255;

function gfMultiply(a, b) {
    let result = 0;
    let x = a;
    let y = b;
    while (y > 0) {
        if (y & 1) result ^= x;
        const highBit = x & 0x80;
        x <<= 1;
        if (highBit) x ^= 0x11b;
        x &= 0xff;
        y >>= 1;
    }
    return result;
}

function gfPow(base, exponent) {
    let result = 1;
    let value = base;
    let power = exponent;
    while (power > 0) {
        if (power & 1) result = gfMultiply(result, value);
        value = gfMultiply(value, value);
        power = Math.floor(power / 2);
    }
    return result;
}

function gfInverse(value) {
    if (value === 0) throw new Error("Cannot calculate inverse of zero.");
    return gfPow(value, 254);
}

function evaluatePolynomial(coefficients, x) {
    let result = 0;
    for (let index = coefficients.length - 1; index >= 0; index--) {
        result = gfMultiply(result, x) ^ coefficients[index];
    }
    return result;
}

function validateSecret(secret) {
    if (!Buffer.isBuffer(secret)) throw new TypeError("Secret must be a Buffer.");
    if (secret.length === 0) throw new Error("Secret cannot be empty.");
}

function validateParameters(threshold, shareCount) {
    if (!Number.isInteger(threshold)) throw new TypeError("Threshold must be an integer.");
    if (!Number.isInteger(shareCount)) throw new TypeError("Share count must be an integer.");
    if (threshold < 2) throw new Error("Threshold must be at least 2.");
    if (threshold > shareCount) throw new Error("Threshold cannot be greater than share count.");
    if (shareCount > MAX_SHARES) throw new Error("Share count cannot exceed 255.");
}

function splitSecret(secret, threshold = 3, shareCount = 5) {
    validateSecret(secret);
    validateParameters(threshold, shareCount);

    const shares = [];
    for (let shareNumber = 1; shareNumber <= shareCount; shareNumber++) {
        shares.push({
            id: shareNumber,
            value: Buffer.alloc(secret.length)
        });
    }

    for (let byteIndex = 0; byteIndex < secret.length; byteIndex++) {
        const coefficients = new Array(threshold);
        coefficients[0] = secret[byteIndex];
        if (threshold > 1) {
            const randomCoefficients = crypto.randomBytes(threshold - 1);
            for (let index = 1; index < threshold; index++) {
                coefficients[index] = randomCoefficients[index - 1];
            }
        }
        for (const share of shares) {
            share.value[byteIndex] = evaluatePolynomial(coefficients, share.id);
        }
    }

    return shares.map(share => ({
        id: share.id,
        value: share.value.toString("base64")
    }));
}

function normalizeShare(share) {
    if (!share || typeof share !== "object") throw new Error("Invalid share.");
    const id = Number(share.id);
    if (!Number.isInteger(id) || id < 1 || id > MAX_SHARES) {
        throw new Error("Share ID must be an integer between 1 and 255.");
    }
    if (typeof share.value !== "string") throw new Error("Share value must be a Base64 string.");
    const value = Buffer.from(share.value, "base64");
    if (value.length === 0) throw new Error("Share value cannot be empty.");
    return { id, value };
}

function combineShares(inputShares) {
    if (!Array.isArray(inputShares)) throw new TypeError("Shares must be provided as an array.");
    if (inputShares.length < 2) throw new Error("At least two shares are required for reconstruction.");

    const shares = inputShares.map(normalizeShare);
    const uniqueIds = new Set(shares.map(share => share.id));
    if (uniqueIds.size !== shares.length) throw new Error("Duplicate share IDs are not allowed.");

    const secretLength = shares[0].value.length;
    for (const share of shares) {
        if (share.value.length !== secretLength) throw new Error("All shares must have the same length.");
    }

    const secret = Buffer.alloc(secretLength);
    for (let byteIndex = 0; byteIndex < secretLength; byteIndex++) {
        let recoveredByte = 0;
        for (let i = 0; i < shares.length; i++) {
            const xi = shares[i].id;
            let numerator = 1;
            let denominator = 1;
            for (let j = 0; j < shares.length; j++) {
                if (i === j) continue;
                const xj = shares[j].id;
                numerator = gfMultiply(numerator, xj);
                denominator = gfMultiply(denominator, xi ^ xj);
            }
            const inverse = gfInverse(denominator);
            const lagrangeCoefficient = gfMultiply(numerator, inverse);
            recoveredByte ^= gfMultiply(shares[i].value[byteIndex], lagrangeCoefficient);
        }
        secret[byteIndex] = recoveredByte;
    }

    return secret;
}

function validateShares(shares, expectedLength) {
    if (!Array.isArray(shares)) return false;
    try {
        const normalized = shares.map(normalizeShare);
        const ids = new Set(normalized.map(share => share.id));
        if (ids.size !== normalized.length) return false;
        if (expectedLength !== undefined) {
            return normalized.every(share => share.value.length === expectedLength);
        }
        return true;
    } catch {
        return false;
    }
}

module.exports = {
    splitSecret,
    combineShares,
    validateShares
};