"use strict";

const crypto = require("crypto");

const FIELD_PRIME = BigInt(
    "115792089237316195423570985008687907853269984665640564039457584007908834671663"
);

function normalizeField(value) {
    let result = BigInt(value) % FIELD_PRIME;
    if (result < 0n) result += FIELD_PRIME;
    return result;
}

function modAdd(a, b) {
    return normalizeField(normalizeField(a) + normalizeField(b));
}

function modSub(a, b) {
    return normalizeField(normalizeField(a) - normalizeField(b));
}

function modMultiply(a, b) {
    return normalizeField(normalizeField(a) * normalizeField(b));
}

function modPow(base, exponent) {
    let result = 1n;
    let current = normalizeField(base);
    let power = BigInt(exponent);
    while (power > 0n) {
        if (power & 1n) result = modMultiply(result, current);
        current = modMultiply(current, current);
        power >>= 1n;
    }
    return result;
}

function modInverse(value) {
    const normalized = normalizeField(value);
    if (normalized === 0n) throw new Error("Cannot invert zero in the MPC field.");
    return modPow(normalized, FIELD_PRIME - 2n);
}

function randomFieldElement() {
    while (true) {
        const bytes = crypto.randomBytes(32);
        let value = normalizeField(BigInt("0x" + bytes.toString("hex")));
        if (value !== 0n) return value;
    }
}

function bufferToField(buffer) {
    if (!Buffer.isBuffer(buffer)) throw new TypeError("MPC secret must be a Buffer.");
    if (buffer.length === 0) throw new Error("MPC secret cannot be empty.");
    return normalizeField(BigInt("0x" + buffer.toString("hex")));
}

function fieldToBuffer(value, length = 32) {
    const normalized = normalizeField(value);
    let hex = normalized.toString(16).padStart(length * 2, "0");
    if (hex.length > length * 2) hex = hex.slice(-length * 2);
    return Buffer.from(hex, "hex");
}

function createAdditiveShares(secret, participantCount = 3) {
    if (participantCount < 2) throw new Error("MPC requires at least two participants.");
    const secretField = bufferToField(secret);
    const shares = [];
    let accumulated = 0n;

    for (let index = 0; index < participantCount - 1; index++) {
        const share = randomFieldElement();
        shares.push(share);
        accumulated = modAdd(accumulated, share);
    }

    const finalShare = modSub(secretField, accumulated);
    shares.push(finalShare);

    return shares.map((value, index) => ({
        participantId: index + 1,
        share: value.toString(16)
    }));
}

function combineAdditiveShares(shares) {
    if (!Array.isArray(shares) || shares.length < 2) {
        throw new Error("At least two MPC shares are required.");
    }
    let result = 0n;
    for (const share of shares) {
        if (!share || share.share === undefined) throw new Error("Invalid MPC share.");
        result = modAdd(result, BigInt(`0x${share.share}`));
    }
    return result;
}

function createFragmentContribution(fragment) {
    if (!fragment) throw new Error("Fragment descriptor is required.");
    if (fragment.encrypted !== true) throw new Error("MPC only accepts encrypted fragments.");
    if (!fragment.ciphertext || !fragment.iv || !fragment.authTag) {
        throw new Error("Encrypted fragment is incomplete.");
    }

    const canonical = [
        String(fragment.examinationId || ""),
        String(fragment.fragmentNumber || ""),
        String(fragment.fragmentLabel || ""),
        String(fragment.ciphertext),
        String(fragment.iv),
        String(fragment.authTag)
    ].join("|");

    return crypto.createHash("sha256").update(canonical, "utf8").digest();
}

function createCustodianContribution(fragmentContribution, participantCount = 3) {
    return createAdditiveShares(fragmentContribution, participantCount);
}

function aggregateMpcShares(participantShares) {
    if (!Array.isArray(participantShares) || participantShares.length < 2) {
        throw new Error("At least two participant share sets are required.");
    }
    const participantCount = participantShares.length;
    const shareSets = participantShares.map(participant => {
        if (!Array.isArray(participant)) throw new Error("Invalid MPC participant share set.");
        return participant;
    });

    const values = [];
    for (let index = 0; index < participantCount; index++) {
        let sum = 0n;
        for (const shareSet of shareSets) {
            const share = shareSet.find(item => Number(item.participantId) === index + 1);
            if (!share) throw new Error("Missing participant share.");
            sum = modAdd(sum, BigInt(`0x${share.share}`));
        }
        values.push(sum);
    }

    let aggregate = 0n;
    for (const value of values) {
        aggregate = modAdd(aggregate, value);
    }
    return fieldToBuffer(aggregate);
}

function createEncryptedReleaseManifest(fragments) {
    if (!Array.isArray(fragments) || fragments.length === 0) {
        throw new Error("At least one encrypted fragment is required.");
    }

    const ordered = [...fragments].sort(
        (a, b) => Number(a.fragmentNumber) - Number(b.fragmentNumber)
    );

    for (const fragment of ordered) {
        if (fragment.encrypted !== true) {
            throw new Error("MPC release manifest cannot contain plaintext fragments.");
        }
        if (fragment.plaintextPersisted === true) {
            throw new Error("MPC release manifest rejected a persisted plaintext fragment.");
        }
    }

    const fragmentCommitments = ordered.map(fragment => createFragmentContribution(fragment));
    const manifestHash = crypto
        .createHash("sha256")
        .update(Buffer.concat(fragmentCommitments))
        .digest("hex");

    return {
        fragmentCount: ordered.length,
        fragmentNumbers: ordered.map(fragment => Number(fragment.fragmentNumber)),
        manifestHash,
        encryptionAlgorithm: "AES-256-GCM",
        plaintextPersisted: false,
        assembledRepresentation: "encrypted-fragment-manifest"
    };
}

function executeMpcManifestComputation(fragments, participantCount = 3) {
    const manifest = createEncryptedReleaseManifest(fragments);
    const allParticipantShares = [];

    for (const fragment of fragments) {
        const contribution = createFragmentContribution(fragment);
        const shares = createCustodianContribution(contribution, participantCount);
        allParticipantShares.push(shares);
    }

    const participantAggregates = [];
    for (let participantIndex = 0; participantIndex < participantCount; participantIndex++) {
        let aggregate = 0n;
        for (const shareSet of allParticipantShares) {
            const participantShare = shareSet[participantIndex];
            aggregate = modAdd(aggregate, BigInt(`0x${participantShare.share}`));
        }
        participantAggregates.push({
            participantId: participantIndex + 1,
            share: aggregate.toString(16)
        });
    }

    const mpcCommitment = crypto
        .createHash("sha256")
        .update(JSON.stringify(participantAggregates), "utf8")
        .digest("hex");

    return {
        success: true,
        protocol: "Additive Secret-Sharing MPC",
        participantCount,
        manifest,
        participantAggregates,
        mpcCommitment,
        plaintextExposed: false,
        plaintextPersisted: false
    };
}

function verifyMpcResult(result) {
    if (!result || result.success !== true) return false;
    if (result.plaintextExposed === true || result.plaintextPersisted === true) return false;
    if (result.protocol !== "Additive Secret-Sharing MPC") return false;
    if (!result.mpcCommitment || typeof result.mpcCommitment !== "string") return false;
    if (!Array.isArray(result.participantAggregates) || result.participantAggregates.length < 2) return false;

    const expected = crypto
        .createHash("sha256")
        .update(JSON.stringify(result.participantAggregates), "utf8")
        .digest("hex");

    return crypto.timingSafeEqual(
        Buffer.from(expected, "hex"),
        Buffer.from(result.mpcCommitment, "hex")
    );
}

module.exports = {
    FIELD_PRIME,
    createAdditiveShares,
    combineAdditiveShares,
    createFragmentContribution,
    createCustodianContribution,
    createEncryptedReleaseManifest,
    executeMpcManifestComputation,
    verifyMpcResult
};