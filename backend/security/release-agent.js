"use strict";

const crypto = require("crypto");

const AGENT_VERSION = "secure-release-agent-v1";

function generateAgentId() {
    const timestamp = Date.now().toString(36);
    const random = crypto.randomBytes(8).toString("hex");
    return `AGENT-${timestamp}-${random}`.toUpperCase();
}

function createReleaseAgent({ examinationId, examinationCode, releaseAt }) {
    if (!examinationId) throw new Error("Examination ID is required");
    if (!examinationCode) throw new Error("Examination code is required");
    if (!releaseAt) throw new Error("Release time is required");

    return {
        agentId: generateAgentId(),
        agentVersion: AGENT_VERSION,
        examinationId,
        examinationCode,
        releaseAt,
        executionMode: "offline-agent-simulation",
        networkMode: "one-way-release",
        plaintextPersisted: false,
        plaintextWrittenToDisk: false,
        status: "INITIALIZED",
        createdAt: new Date().toISOString()
    };
}

function validateReleaseAuthorization({ authorized, releaseTimeReached, custodyVerified, mpcVerified, fragmentsReady, canaryClear }) {
    const checks = {
        authorization: Boolean(authorized),
        timeGate: Boolean(releaseTimeReached),
        thresholdCustody: Boolean(custodyVerified),
        mpcManifest: Boolean(mpcVerified),
        encryptedFragments: Boolean(fragmentsReady),
        canaryStatus: Boolean(canaryClear)
    };

    const failedChecks = Object.entries(checks)
        .filter(([, value]) => value !== true)
        .map(([name]) => name);

    return {
        authorized: failedChecks.length === 0,
        checks,
        failedChecks
    };
}

function createReleasePackage({ examinationId, examinationCode, fragments, mpcResult, vdfResult, custodyFingerprint }) {
    if (!examinationId) throw new Error("Examination ID is required");
    if (!Array.isArray(fragments)) throw new Error("Fragments must be an array");

    return {
        packageType: "SECURE-QUESTION-PAPER-RELEASE",
        version: "1.0",
        examinationId,
        examinationCode,
        fragmentCount: fragments.length,
        fragmentNumbers: fragments.map(f => Number(f.fragmentNumber)).sort((a, b) => a - b),
        encryptedOnly: fragments.every(f => f.encrypted === true && f.plaintextPersisted === false),
        mpcManifestHash: mpcResult?.manifestHash || null,
        vdfOutput: vdfResult?.output || null,
        custodyFingerprint: custodyFingerprint || null,
        createdAt: new Date().toISOString()
    };
}

function createExecutionRecord({ agent, releasePackage, authorizedBy, fragmentCount }) {
    return {
        agentId: agent.agentId,
        agentVersion: agent.agentVersion,
        examinationId: agent.examinationId,
        examinationCode: agent.examinationCode,
        executionMode: agent.executionMode,
        authorizedBy: authorizedBy || null,
        fragmentCount: Number(fragmentCount || 0),
        mpcManifestHash: releasePackage.mpcManifestHash,
        vdfOutput: releasePackage.vdfOutput,
        plaintextPersisted: false,
        plaintextWrittenToDisk: false,
        networkInbound: false,
        executionStatus: "RELEASE_EXECUTED",
        executedAt: new Date().toISOString()
    };
}

function createPrintHandoff({ agent, examinationId, fragmentCount }) {
    return {
        handoffId: `PRINT-${crypto.randomBytes(10).toString("hex").toUpperCase()}`,
        agentId: agent.agentId,
        examinationId,
        fragmentCount: Number(fragmentCount || 0),
        transport: "one-way-release",
        source: "volatile-memory",
        destination: "printer-driver",
        plaintextFileCreated: false,
        plaintextFilePath: null,
        diskWrite: false,
        inboundNetwork: false,
        status: "HANDOFF_SIMULATED",
        createdAt: new Date().toISOString()
    };
}

function createAgentAuditEvent({ agent, executionRecord, printHandoff }) {
    return {
        eventType: "SECURE_RELEASE_EXECUTED",
        severity: "INFO",
        agentId: agent.agentId,
        agentVersion: agent.agentVersion,
        examinationId: agent.examinationId,
        examinationCode: agent.examinationCode,
        executionMode: executionRecord.executionMode,
        fragmentCount: executionRecord.fragmentCount,
        plaintextPersisted: false,
        plaintextWrittenToDisk: false,
        inboundNetwork: false,
        printHandoffId: printHandoff.handoffId,
        timestamp: executionRecord.executedAt,
        message: "Controlled release completed through simulated offline release agent"
    };
}

function sanitizeAgentResult({ agent, executionRecord, printHandoff }) {
    return {
        success: true,
        agent: {
            agentId: agent.agentId,
            agentVersion: agent.agentVersion,
            status: "COMPLETED"
        },
        execution: {
            examinationId: executionRecord.examinationId,
            examinationCode: executionRecord.examinationCode,
            fragmentCount: executionRecord.fragmentCount,
            executionMode: executionRecord.executionMode,
            plaintextPersisted: false,
            plaintextWrittenToDisk: false,
            inboundNetwork: false
        },
        printHandoff: {
            handoffId: printHandoff.handoffId,
            destination: printHandoff.destination,
            transport: printHandoff.transport,
            diskWrite: false
        }
    };
}

module.exports = {
    AGENT_VERSION,
    generateAgentId,
    createReleaseAgent,
    validateReleaseAuthorization,
    createReleasePackage,
    createExecutionRecord,
    createPrintHandoff,
    createAgentAuditEvent,
    sanitizeAgentResult
};