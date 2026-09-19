"use strict";

const crypto = require("crypto");

const CANARY_PREFIX = "CANARY-FRAGMENT-V1";

function generateCanaryId() {
    return crypto.randomBytes(16).toString("hex");
}

function hashCanaryPayload(payload) {
    return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

function createCanaryFragment({ examinationId, examinationCode, fragmentNumber, createdBy }) {
    if (!examinationId) throw new Error("Examination ID is required");
    if (!examinationCode) throw new Error("Examination code is required");
    const canaryId = generateCanaryId();
    const payload = {
        marker: CANARY_PREFIX,
        canaryId,
        examinationId,
        examinationCode,
        fragmentNumber: Number(fragmentNumber),
        createdBy: createdBy || "system",
        createdAt: new Date().toISOString(),
        triggerOn: "DECRYPTION_ATTEMPT"
    };
    return {
        canaryId,
        isDecoy: true,
        payload,
        payloadHash: hashCanaryPayload(payload)
    };
}

function isCanaryPayload(plaintext) {
    if (!plaintext) return false;
    try {
        const parsed = typeof plaintext === "string" ? JSON.parse(plaintext) : plaintext;
        return Boolean(parsed && parsed.marker === CANARY_PREFIX && parsed.canaryId);
    } catch {
        return false;
    }
}

function validateCanaryPayload(plaintext) {
    if (!isCanaryPayload(plaintext)) {
        return { isCanary: false, valid: false };
    }
    try {
        const parsed = typeof plaintext === "string" ? JSON.parse(plaintext) : plaintext;
        const requiredFields = ["marker", "canaryId", "examinationId", "examinationCode", "fragmentNumber", "createdAt", "triggerOn"];
        const missingFields = requiredFields.filter(field => parsed[field] === undefined || parsed[field] === null);
        if (missingFields.length > 0) {
            return {
                isCanary: true,
                valid: false,
                canaryId: parsed.canaryId || null,
                reason: "Canary payload is missing required fields",
                missingFields
            };
        }
        return {
            isCanary: true,
            valid: true,
            canaryId: parsed.canaryId,
            examinationId: parsed.examinationId,
            examinationCode: parsed.examinationCode,
            fragmentNumber: parsed.fragmentNumber,
            triggerOn: parsed.triggerOn
        };
    } catch (error) {
        return { isCanary: true, valid: false, reason: error.message };
    }
}

function createCanaryAlert({ canary, examinationId, actor, action }) {
    const validation = validateCanaryPayload(canary);
    if (!validation.isCanary) throw new Error("Provided payload is not a valid canary");
    return {
        type: "CANARY_TRIGGERED",
        severity: "CRITICAL",
        alert: true,
        canaryId: validation.canaryId,
        examinationId: examinationId || validation.examinationId,
        actor: actor || "unknown",
        action: action || "UNAUTHORIZED_CANARY_ACCESS",
        detectedAt: new Date().toISOString(),
        message: "Decoy fragment access detected"
    };
}

function createCanaryDescriptor({ canaryId, examinationId, fragmentNumber }) {
    return {
        canaryId,
        examinationId,
        fragmentNumber: Number(fragmentNumber),
        type: "DECOY_FRAGMENT",
        status: "ACTIVE",
        createdAt: new Date().toISOString()
    };
}

function createCanaryAuditEvent({ alert, actor, actorRole }) {
    return {
        eventType: "CANARY_ACCESS_DETECTED",
        severity: "CRITICAL",
        actor: actor || "unknown",
        actorRole: actorRole || "unknown",
        canaryId: alert.canaryId,
        examinationId: alert.examinationId,
        action: alert.action,
        detectedAt: alert.detectedAt,
        alert: true,
        message: alert.message
    };
}

module.exports = {
    CANARY_PREFIX,
    generateCanaryId,
    createCanaryFragment,
    hashCanaryPayload,
    isCanaryPayload,
    validateCanaryPayload,
    createCanaryAlert,
    createCanaryDescriptor,
    createCanaryAuditEvent
};