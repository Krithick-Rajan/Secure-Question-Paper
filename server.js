"use strict";

const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
require("dotenv").config();

const { db, auth: firebaseAuth } =
    require("./backend/config/firebase-admin");

const { verifyToken } =
    require("./backend/middleware/auth");

const { requireRole } =
    require("./backend/middleware/role");

const {
    splitSecret,
    combineShares,
    validateShares
} = require("./backend/security/shamir");

const {
    createEncryptedReleaseManifest,
    executeMpcManifestComputation,
    verifyMpcResult
} = require("./backend/security/mpc");

const {
    DEFAULT_ITERATIONS,
    createVdfCommitment,
    verifyVdfCommitment,
    isReleaseTimeReached
} = require("./backend/security/vdf");

const {
    createCanaryFragment,
    isCanaryPayload,
    validateCanaryPayload,
    createCanaryAlert,
    createCanaryAuditEvent
} = require("./backend/security/canary");

const {
    createReleaseAgent,
    validateReleaseAuthorization,
    createReleasePackage,
    createExecutionRecord,
    createPrintHandoff,
    createAgentAuditEvent,
    sanitizeAgentResult
} = require("./backend/security/release-agent");

const app = express();

const PORT =
    Number(process.env.PORT) || 5000;

app.use(
    cors()
);

app.use(
    express.json({
        limit: "2mb"
    })
);

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(
    express.static(
        path.join(
            __dirname,
            "frontend"
        )
    )
);

app.get(
    "/",
    (_req, res) => {
        res.sendFile(
            path.join(
                __dirname,
                "frontend",
                "login.html"
            )
        );
    }
);

function createFingerprint(value) {
    return crypto
        .createHash("sha256")
        .update(value)
        .digest("hex");
}

function constantTimeEqualHex(
    first,
    second
) {
    if (
        typeof first !== "string" ||
        typeof second !== "string"
    ) {
        return false;
    }

    if (
        first.length !==
        second.length
    ) {
        return false;
    }

    try {
        return crypto.timingSafeEqual(
            Buffer.from(
                first,
                "hex"
            ),
            Buffer.from(
                second,
                "hex"
            )
        );
    } catch {
        return false;
    }
}

function parseFirestoreDate(value) {
    if (!value) {
        return null;
    }

    if (
        value instanceof Date
    ) {
        return value;
    }

    if (
        typeof value.toDate ===
        "function"
    ) {
        return value.toDate();
    }

    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {
        const date =
            new Date(value);

        if (
            !Number.isNaN(
                date.getTime()
            )
        ) {
            return date;
        }
    }

    if (
        typeof value === "object" &&
        typeof value._seconds ===
            "number"
    ) {
        return new Date(
            value._seconds * 1000
        );
    }

    return null;
}

function safeString(value) {
    if (
        value === undefined ||
        value === null
    ) {
        return "";
    }

    return String(value);
}

async function getExamination(
    examinationId
) {
    if (!examinationId) {
        return null;
    }

    const snapshot =
        await db
            .collection(
                "examinations"
            )
            .doc(
                examinationId
            )
            .get();

    if (
        !snapshot.exists
    ) {
        return null;
    }

    return snapshot;
}

async function getCustodyShares(
    examinationId
) {
    const snapshot =
        await db
            .collection(
                "custody_shares"
            )
            .where(
                "examinationId",
                "==",
                examinationId
            )
            .get();

    return snapshot.docs.map(
        doc => {
            const data =
                doc.data();

            return {
                id:
                    doc.id,

                ...data,

                shareId:
                    Number(
                        data.shareId ??
                        data.id
                    ),

                value:
                    data.value ||
                    data.protectedShare
            };
        }
    );
}

async function reconstructExaminationKey(
    examinationId,
    minimumShares = 3
) {
    const examination =
        await getExamination(
            examinationId
        );

    if (!examination) {
        throw new Error(
            "Examination not found."
        );
    }

    const examinationData =
        examination.data();

    if (
        examinationData.custodyStatus !==
        "initialized"
    ) {
        throw new Error(
            "Threshold custody has not been initialized."
        );
    }

    const custody =
        examinationData.custody ||
        {};

    const threshold =
        Number(
            custody.thresholdRequired ||
            custody.threshold ||
            3
        );

    // Read from custody_session_shares (submitted by custodians at release time)
    const sessionSnapshot =
        await db
            .collection("custody_session_shares")
            .where("examinationId", "==", examinationId)
            .get();

    const sessionShares =
        sessionSnapshot.docs.map(
            doc => {
                const data = doc.data();
                return {
                    docId: doc.id,
                    shareId: Number(data.shareId),
                    value: data.value
                };
            }
        );

    if (sessionShares.length < minimumShares) {
        throw new Error(
            `Threshold not met: ${sessionShares.length} of ${threshold} required shares have been submitted. Ask custodians to submit their shares via the Custody page.`
        );
    }

    const usableShares =
        sessionShares
            .filter(
                share =>
                    share.value &&
                    share.shareId !== undefined
            )
            .sort(
                (a, b) => a.shareId - b.shareId
            )
            .slice(0, threshold);

    if (usableShares.length < threshold) {
        throw new Error(
            "Not enough valid custody shares are available."
        );
    }

    const normalizedShares =
        usableShares.map(
            share => ({
                id: share.shareId,
                value: share.value
            })
        );

    if (
        !validateShares(
            normalizedShares
        )
    ) {
        throw new Error(
            "Stored custody shares failed validation."
        );
    }

    const reconstructedKey =
        combineShares(
            normalizedShares
        );

    if (
        !Buffer.isBuffer(
            reconstructedKey
        )
    ) {
        throw new Error(
            "Custody key reconstruction returned an invalid key."
        );
    }

    if (
        reconstructedKey.length !==
        32
    ) {
        reconstructedKey.fill(
            0
        );

        throw new Error(
            "Reconstructed custody key is not 256 bits."
        );
    }

    const fingerprint =
        createFingerprint(
            reconstructedKey
        );

    const storedFingerprint =
        custody.keyFingerprint ||
        custody.fingerprint ||
        null;

    if (
        storedFingerprint &&
        !constantTimeEqualHex(
            fingerprint,
            storedFingerprint
        )
    ) {
        reconstructedKey.fill(
            0
        );

        throw new Error(
            "Reconstructed key fingerprint does not match the registered custody fingerprint."
        );
    }

    const result = {
        key:
            reconstructedKey,

        fingerprint,

        sharesUsed:
            normalizedShares.map(
                share => share.id
            ),

        threshold,

        totalShares:
            sessionShares.length
    };

    // Delete session shares immediately after reconstruction
    // (they should not persist on the server longer than necessary)
    try {
        const deleteBatch = db.batch();
        sessionSnapshot.docs.forEach(
            doc => deleteBatch.delete(doc.ref)
        );
        await deleteBatch.commit();
    } catch (_deleteErr) {
        // Non-fatal — key was already reconstructed successfully
    }

    return result;
}

function encryptFragment(
    plaintext,
    key
) {
    if (
        !Buffer.isBuffer(key) ||
        key.length !== 32
    ) {
        throw new Error(
            "A valid 256-bit encryption key is required."
        );
    }

    const iv =
        crypto.randomBytes(
            12
        );

    const cipher =
        crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

    const ciphertext =
        Buffer.concat([
            cipher.update(
                plaintext,
                "utf8"
            ),
            cipher.final()
        ]);

    const authTag =
        cipher.getAuthTag();

    return {
        ciphertext:
            ciphertext.toString(
                "base64"
            ),

        iv:
            iv.toString(
                "base64"
            ),

        authTag:
            authTag.toString(
                "base64"
            )
    };
}

function decryptFragment(
    encryptedData,
    key
) {
    if (
        !Buffer.isBuffer(key) ||
        key.length !== 32
    ) {
        throw new Error(
            "A valid 256-bit encryption key is required."
        );
    }

    const decipher =
        crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            Buffer.from(
                encryptedData.iv,
                "base64"
            )
        );

    decipher.setAuthTag(
        Buffer.from(
            encryptedData.authTag,
            "base64"
        )
    );

    const plaintext =
        Buffer.concat([
            decipher.update(
                Buffer.from(
                    encryptedData.ciphertext,
                    "base64"
                )
            ),
            decipher.final()
        ]);

    return plaintext.toString(
        "utf8"
    );
}

async function getFragments(
    examinationId
) {
    const snapshot =
        await db
            .collection(
                "fragments"
            )
            .where(
                "examinationId",
                "==",
                examinationId
            )
            .get();

    return snapshot.docs
        .map(
            doc => ({
                id:
                    doc.id,

                ...doc.data()
            })
        )
        .sort(
            (a, b) =>
                Number(
                    a.fragmentNumber
                ) -
                Number(
                    b.fragmentNumber
                )
        );
}

async function getFragmentState(
    examinationId
) {
    const fragments =
        await getFragments(
            examinationId
        );

    let encrypted =
        0;

    let plaintext =
        0;

    let decoys =
        0;

    fragments.forEach(
        fragment => {
            if (
                fragment.encrypted ===
                true
            ) {
                encrypted++;
            } else {
                plaintext++;
            }

            if (
                fragment.isDecoy ===
                true
            ) {
                decoys++;
            }
        }
    );

    return {
        total:
            fragments.length,

        encrypted,

        plaintext,

        decoys
    };
}

function buildMpcFragmentDescriptors(
    fragments
) {
    return fragments.map(
        fragment => ({
            id:
                fragment.id,

            examinationId:
                fragment.examinationId,

            fragmentNumber:
                Number(
                    fragment.fragmentNumber
                ),

            fragmentLabel:
                fragment.fragmentLabel ||
                "",

            ciphertext:
                fragment.ciphertext ||
                "",

            iv:
                fragment.iv ||
                "",

            authTag:
                fragment.authTag ||
                "",

            encrypted:
                fragment.encrypted ===
                true,

            status:
                fragment.status ||
                "encrypted",

            keySource:
                fragment.keySource ||
                null,

            isDecoy:
                fragment.isDecoy ===
                true
        })
    );
}

async function computeMpcForExamination(
    examinationId,
    fragments,
    custodyFingerprint
) {
    const descriptors =
        buildMpcFragmentDescriptors(
            fragments
        );

    const mpcInput = {
        examinationId,

        custodyFingerprint:
            custodyFingerprint ||
            "",

        fragmentCount:
            descriptors.length,

        fragments:
            descriptors
    };

    let result;

    try {
        result =
            executeMpcManifestComputation(
                mpcInput
            );
    } catch {
        try {
            const manifest =
                createEncryptedReleaseManifest(
                    mpcInput
                );

            result =
                executeMpcManifestComputation(
                    manifest
                );
        } catch (error) {
            throw new Error(
                `MPC manifest computation failed: ${error.message}`
            );
        }
    }

    if (!result) {
        throw new Error(
            "MPC computation returned no result."
        );
    }

    return result;
}

async function verifyStoredMpc(
    examinationData,
    examinationId,
    fragments
) {
    const security =
        examinationData.security ||
        {};

    const stored =
        security.mpc ||
        {};

    if (
        !stored.manifestHash
    ) {
        return {
            configured:
                false,

            verified:
                false,

            result:
                null
        };
    }

    const custodyFingerprint =
        examinationData.custody
            ?.keyFingerprint ||
        "";

    const result =
        await computeMpcForExamination(
            examinationId,
            fragments,
            custodyFingerprint
        );

    let verification;

    try {
        verification =
            verifyMpcResult(
                result,
                stored.manifestHash
            );
    } catch {
        verification =
            result.manifestHash ===
            stored.manifestHash;
    }

    return {
        configured:
            true,

        verified:
            verification === true ||
            verification?.valid ===
                true ||
            verification?.verified ===
                true,

        result
    };
}

async function registerMpcState(
    examinationId
) {
    const examination =
        await getExamination(
            examinationId
        );

    if (!examination) {
        throw new Error(
            "Examination not found."
        );
    }

    const examinationData =
        examination.data();

    const fragments =
        await getFragments(
            examinationId
        );

    if (
        fragments.length ===
        0
    ) {
        throw new Error(
            "At least one encrypted fragment is required before MPC registration."
        );
    }

    const invalid =
        fragments.some(
            fragment =>
                fragment.encrypted !==
                    true ||
                fragment.plaintextPersisted ===
                    true ||
                fragment.keySource !==
                    "examination-custody-key"
        );

    if (invalid) {
        throw new Error(
            "MPC registration requires all fragments to be encrypted using the examination custody key."
        );
    }

    const custodyFingerprint =
        examinationData.custody
            ?.keyFingerprint ||
        "";

    const result =
        await computeMpcForExamination(
            examinationId,
            fragments,
            custodyFingerprint
        );

    const manifestHash =
        result.manifestHash ||
        result.hash ||
        result.commitment ||
        null;

    if (!manifestHash) {
        throw new Error(
            "MPC computation did not produce a manifest hash."
        );
    }

    const mpcState = {
        algorithm:
            "software-mpc-encrypted-manifest",

        status:
            "verified",

        manifestHash,

        fragmentCount:
            fragments.length,

        custodyFingerprint,

        computedAt:
            new Date(),

        verifiedAt:
            new Date()
    };

    await db
        .collection(
            "examinations"
        )
        .doc(
            examinationId
        )
        .update({
            "security.mpc":
                mpcState
        });

    await db
        .collection(
            "audit_logs"
        )
        .add({
            action:
                "MPC_MANIFEST_COMPUTED",

            examinationId,

            examinationCode:
                examinationData.code ||
                null,

            actor:
                examinationData.createdBy ||
                "system",

            algorithm:
                "software-mpc-encrypted-manifest",

            manifestHash,

            fragmentCount:
                fragments.length,

            plaintextProcessed:
                false,

            timestamp:
                new Date()
        });

    return {
        ...mpcState,

        computedAt:
            mpcState.computedAt.toISOString(),

        verifiedAt:
            mpcState.verifiedAt.toISOString()
    };
}

async function registerVdfState(
    examinationId,
    mpcManifestHash
) {
    const examination =
        await getExamination(
            examinationId
        );

    if (!examination) {
        throw new Error(
            "Examination not found."
        );
    }

    const examinationData =
        examination.data();

    const release =
        examinationData.release ||
        {};

    const releaseTime =
        parseFirestoreDate(
            release.releaseTime ||
            examinationData.releaseTime
        );

    if (!releaseTime) {
        throw new Error(
            "A release time must be configured before creating the VDF commitment."
        );
    }

    const custodyFingerprint =
        examinationData.custody
            ?.keyFingerprint ||
        "";

    const commitment =
        createVdfCommitment({
            examinationId,

            releaseAt:
                releaseTime.toISOString(),

            mpcManifestHash:
                mpcManifestHash ||
                "",

            custodyFingerprint,

            iterations:
                Number(
                    process.env.VDF_ITERATIONS ||
                    DEFAULT_ITERATIONS
                )
        });

    const vdfState = {
        algorithm:
            "wesolowski-rsa-vdf",

        status:
            "committed",

        iterations:
            commitment.iterations,

        // Wesolowski VDF fields
        x:
            commitment.x,

        y:
            commitment.y,

        output:
            commitment.y,

        proof:
            commitment.proof,

        l:
            commitment.l,

        T:
            commitment.T,

        N_id:
            commitment.N_id,

        inputHash:
            commitment.inputHash,

        computeMs:
            commitment.computeMs,

        releaseAt:
            releaseTime,

        computedAt:
            new Date()
    };

    await db
        .collection(
            "examinations"
        )
        .doc(
            examinationId
        )
        .update({
            "security.vdf":
                vdfState
        });

    await db
        .collection(
            "audit_logs"
        )
        .add({
            action:
                "VDF_COMMITMENT_CREATED",

            examinationId,

            examinationCode:
                examinationData.code ||
                null,

            algorithm:
                "wesolowski-rsa-vdf",

            iterations:
                commitment.iterations,

            inputHash:
                commitment.inputHash,

            N_id:
                commitment.N_id,

            computeMs:
                commitment.computeMs,

            releaseTime,

            timestamp:
                new Date()
        });

    return {
        ...vdfState,

        releaseAt:
            releaseTime.toISOString(),

        computedAt:
            vdfState.computedAt.toISOString()
    };
}

async function verifyVdfState(
    examinationData,
    examinationId,
    mpcManifestHash
) {
    const security =
        examinationData.security ||
        {};

    const stored =
        security.vdf ||
        {};

    const release =
        examinationData.release ||
        {};

    const releaseTime =
        parseFirestoreDate(
            release.releaseTime ||
            examinationData.releaseTime
        );

    if (
        !releaseTime ||
        !stored.y
    ) {
        return {
            configured:
                false,

            verified:
                false,

            timeGateOpen:
                false
        };
    }

    const custodyFingerprint =
        examinationData.custody
            ?.keyFingerprint ||
        "";

    let cryptographicVerification;

    try {
        cryptographicVerification =
            verifyVdfCommitment({
                examinationId,

                releaseAt:
                    releaseTime.toISOString(),

                mpcManifestHash:
                    mpcManifestHash ||
                    "",

                custodyFingerprint,

                storedVdf: {
                    x:     stored.x,
                    y:     stored.y,
                    proof: stored.proof,
                    l:     stored.l,
                    T:     stored.T || stored.iterations
                }
            });
    } catch (error) {
        return {
            configured:
                true,

            verified:
                false,

            timeGateOpen:
                false,

            reason:
                error.message
        };
    }

    const timeGateOpen =
        isReleaseTimeReached(
            releaseTime
        );

    const verified =
        cryptographicVerification
            .valid === true &&
        timeGateOpen;

    return {
        configured:
            true,

        verified,

        timeGateOpen,

        releaseTime:
            releaseTime.toISOString(),

        iterations:
            stored.T || stored.iterations,

        algorithm:
            stored.algorithm || "wesolowski-rsa-vdf",

        N_id:
            stored.N_id || "RSA-2048-challenge",

        proof:
            stored.proof
                ? stored.proof.slice(0, 16) + "…"
                : null,

        verifyMs:
            cryptographicVerification.verifyMs,

        output:
            stored.y,

        inputHash:
            cryptographicVerification.inputHash
    };
}

async function recordCanaryAlert(
    examinationId,
    examinationData,
    plaintext,
    actor
) {
    if (
        !isCanaryPayload(
            plaintext
        )
    ) {
        return {
            triggered:
                false
        };
    }

    const validation =
        validateCanaryPayload(
            plaintext
        );

    const alert =
        createCanaryAlert({
            canary:
                plaintext,

            examinationId,

            actor:
                actor ||
                "unknown",

            action:
                "CANARY_DECRYPTION_DETECTED"
        });

    const audit =
        createCanaryAuditEvent({
            alert,

            actor:
                actor ||
                "unknown",

            actorRole:
                "admin"
        });

    await db
        .collection(
            "audit_logs"
        )
        .add({
            ...audit,

            examinationCode:
                examinationData.code ||
                null,

            validation,

            timestamp:
                new Date()
        });

    await db
        .collection(
            "examinations"
        )
        .doc(
            examinationId
        )
        .update({
            "security.canaryStatus":
                "TRIGGERED",

            "security.canaryTriggeredAt":
                new Date(),

            "security.lastCanaryId":
                validation.canaryId
        });

    return {
        triggered:
            true,

        alert,

        validation
    };
}

app.get(
    "/",
    (req, res) => {
        res.sendFile(
            path.join(
                __dirname,
                "frontend",
                "login.html"
            )
        );
    }
);

app.get(
    "/api/health",
    (req, res) => {
        res.json({
            success:
                true,

            service:
                "Secure Question Paper Backend",

            status:
                "operational",

            security: {
                aes:
                    "AES-256-GCM",

                custody:
                    "Shamir 3-of-5",

                mpc:
                    "Software MPC encrypted manifest",

                vdf:
                    "Sequential SHA-256 VDF prototype",

                canary:
                    "Enabled",

                releaseAgent:
                    "Enabled"
            }
        });
    }
);

app.get(
    "/api/test-firestore",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .collection(
                        "examinations"
                    )
                    .limit(10)
                    .get();

            return res.json({
                success:
                    true,

                count:
                    snapshot.size
            });
        } catch (error) {
            console.error(
                "Firestore test error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Firestore test failed."
            });
        }
    }
);

app.get(
    "/api/admin-test",
    verifyToken,
    requireRole("admin", "setter", "custodian", "print-operator"),
    (req, res) => {
        res.json({
            success:
                true,

            message:
                "Authorization successful.",

            user: {
                uid:
                    req.user.uid,

                email:
                    req.user.email,

                role:
                    req.user.role
            }
        });
    }
);

app.get(
    "/api/me",
    verifyToken,
    requireRole("admin", "setter", "custodian", "print-operator"),
    (req, res) => {
        res.json({
            success:
                true,

            user: {
                uid:
                    req.user.uid,

                email:
                    req.user.email,

                role:
                    req.user.role
            }
        });
    }
);

app.post(
    "/api/examinations",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                code,
                title,
                name,
                subject,
                examDate,
                startTime,
                releaseTime
            } = req.body;

            const examinationTitle =
                title ||
                name;

            if (
                !code ||
                !examinationTitle
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Examination code and title are required."
                });
            }

            let parsedReleaseTime =
                null;

            if (releaseTime) {
                parsedReleaseTime =
                    new Date(
                        releaseTime
                    );

                if (
                    Number.isNaN(
                        parsedReleaseTime.getTime()
                    )
                ) {
                    return res.status(
                        400
                    ).json({
                        success:
                            false,

                        message:
                            "Invalid release time."
                    });
                }
            }

            const examinationData = {
                code:
                    String(
                        code
                    ).trim(),

                title:
                    String(
                        examinationTitle
                    ).trim(),

                subject:
                    subject ||
                    null,

                examDate:
                    examDate ||
                    null,

                startTime:
                    startTime ||
                    null,

                custodyStatus:
                    "uninitialized",

                security: {
                    mpc: {
                        status:
                            "pending"
                    },

                    vdf: {
                        status:
                            "pending"
                    },

                    canaryStatus:
                        "CLEAR"
                },

                release: {
                    releaseTime:
                        parsedReleaseTime,

                    authorized:
                        false,

                    released:
                        false,

                    plaintextPersisted:
                        false
                },

                createdAt:
                    new Date(),

                createdBy:
                    req.user.uid
            };

            const reference =
                await db
                    .collection(
                        "examinations"
                    )
                    .add(
                        examinationData
                    );

            await db
                .collection(
                    "audit_logs"
                )
                .add({
                    action:
                        "EXAMINATION_CREATED",

                    examinationId:
                        reference.id,

                    examinationCode:
                        examinationData.code,

                    actor:
                        req.user.uid,

                    actorEmail:
                        req.user.email ||
                        null,

                    role:
                        req.user.role,

                    timestamp:
                        new Date()
                });

            return res.status(
                201
            ).json({
                success:
                    true,

                message:
                    "Examination created successfully.",

                examination: {
                    id:
                        reference.id,

                    ...examinationData,

                    releaseTime:
                        parsedReleaseTime
                            ? parsedReleaseTime.toISOString()
                            : null
                }
            });
        } catch (error) {
            console.error(
                "Create examination error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Failed to create examination."
            });
        }
    }
);

app.get(
    "/api/examinations",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .collection(
                        "examinations"
                    )
                    .orderBy(
                        "createdAt",
                        "desc"
                    )
                    .get();

            const examinations =
                snapshot.docs.map(
                    doc => {
                        const data =
                            doc.data();

                        const releaseTime =
                            parseFirestoreDate(
                                data.release?.releaseTime ||
                                data.releaseTime
                            );

                        return {
                            id:
                                doc.id,

                            code:
                                data.code ||
                                data.examCode ||
                                "",

                            title:
                                data.title ||
                                data.name ||
                                "",

                            name:
                                data.title ||
                                data.name ||
                                "",

                            subject:
                                data.subject ||
                                null,

                            examDate:
                                data.examDate ||
                                null,

                            startTime:
                                data.startTime ||
                                null,

                            custodyStatus:
                                data.custodyStatus ||
                                "uninitialized",

                            releaseTime:
                                releaseTime
                                    ? releaseTime.toISOString()
                                    : null,

                            security:
                                data.security ||
                                {},

                            release: {
                                ...(data.release ||
                                    {}),

                                releaseTime:
                                    releaseTime
                                        ? releaseTime.toISOString()
                                        : null
                            }
                        };
                    }
                );

            return res.json({
                success:
                    true,

                examinations
            });
        } catch (error) {
            console.error(
                "Get examinations error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Failed to load examinations."
            });
        }
    }
);

app.post(
    "/api/custody/initialize",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        let aesKey = null;

        try {
            const {
                examinationId
            } = req.body;

            if (!examinationId) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Examination ID is required."
                });
            }

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            const existingShares =
                await getCustodyShares(
                    examinationId
                );

            if (
                existingShares.length >=
                5
            ) {
                return res.status(
                    409
                ).json({
                    success:
                        false,

                    message:
                        "Threshold custody is already initialized."
                });
            }

            aesKey =
                crypto.randomBytes(
                    32
                );

            const fingerprint =
                createFingerprint(
                    aesKey
                );

            const shares =
                splitSecret(
                    aesKey,
                    3,
                    5
                );

            const batch =
                db.batch();

            shares.forEach(
                share => {
                    const shareReference =
                        db
                            .collection(
                                "custody_shares"
                            )
                            .doc();

                    batch.set(
                        shareReference,
                        {
                            examinationId,

                            examinationCode:
                                examinationData.code ||
                                null,

                            shareId:
                                Number(
                                    share.id
                                ),

                            value:
                                share.value,

                            protectedShare:
                                share.value,

                            threshold:
                                3,

                            totalShares:
                                5,

                            algorithm:
                                "Shamir Secret Sharing",

                            keyAlgorithm:
                                "AES-256",

                            keyLength:
                                256,

                            createdAt:
                                new Date()
                        }
                    );
                }
            );

            batch.update(
                db
                    .collection(
                        "examinations"
                    )
                    .doc(
                        examinationId
                    ),
                {
                    custodyStatus:
                        "initialized",

                    custody: {
                        thresholdRequired:
                            3,

                        totalShares:
                            5,

                        algorithm:
                            "Shamir Secret Sharing",

                        keyAlgorithm:
                            "AES-256",

                        keyLength:
                            256,

                        keyFingerprint:
                            fingerprint,

                        verificationStatus:
                            "pending",

                        fingerprintVerified:
                            false
                    },

                    "security.canaryStatus":
                        "CLEAR",

                    "security.mpc.status":
                        "pending",

                    "security.vdf.status":
                        "pending"
                }
            );

            const auditReference =
                db
                    .collection(
                        "audit_logs"
                    )
                    .doc();

            batch.set(
                auditReference,
                {
                    action:
                        "CUSTODY_INITIALIZED",

                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    actor:
                        req.user.uid,

                    actorEmail:
                        req.user.email ||
                        null,

                    role:
                        req.user.role,

                    threshold:
                        "3 OF 5",

                    shareCount:
                        5,

                    keyAlgorithm:
                        "AES-256",

                    secretSharing:
                        "Shamir Secret Sharing",

                    description:
                        "A new AES-256 custody key was generated and divided into five protected shares using a 3-of-5 threshold.",

                    timestamp:
                        new Date()
                }
            );

            await batch.commit();

            // ── True Shamir Distribution ─────────────────────────────────────
            // Shares are returned to the admin ONE TIME in this response, then
            // immediately deleted from Firestore.  The server will never hold
            // all shares simultaneously again.  Custodians must save their
            // share offline; they submit it back at release time.
            // ─────────────────────────────────────────────────────────────────

            const sharesToReturn =
                shares.map(
                    share => ({
                        shareId:
                            Number(share.id),

                        value:
                            share.value,

                        algorithm:
                            "Shamir-3-of-5",

                        examinationCode:
                            examinationData.code || null
                    })
                );

            // Delete all shares from Firestore immediately after commit
            const shareSnapshot =
                await db
                    .collection("custody_shares")
                    .where("examinationId", "==", examinationId)
                    .get();

            if (!shareSnapshot.empty) {
                const deleteBatch = db.batch();

                shareSnapshot.docs.forEach(
                    doc => deleteBatch.delete(doc.ref)
                );

                await deleteBatch.commit();
            }

            // Mark that shares are no longer stored server-side
            await db
                .collection("examinations")
                .doc(examinationId)
                .update({
                    "custody.sharesStoredOnServer": false,
                    "custody.sharesDistributed":   true,
                    "custody.distributedAt":        new Date()
                });

            return res.status(201).json({
                success:
                    true,

                message:
                    "Threshold custody initialized. Share each share value with its custodian immediately — they will NOT be shown again.",

                warning:
                    "CRITICAL: Save all 5 shares now. These values are permanently deleted from the server after this response.",

                custody: {
                    examinationId,

                    examinationCode:
                        examinationData.code,

                    thresholdRequired:
                        3,

                    totalShares:
                        5,

                    sharesAssigned:
                        5,

                    algorithm:
                        "Shamir Secret Sharing",

                    keyAlgorithm:
                        "AES-256",

                    keyLength:
                        256,

                    status:
                        "initialized",

                    sharesStoredOnServer:
                        false
                },

                // ★ One-time share disclosure ★
                shares:
                    sharesToReturn
            });

        } catch (error) {

            return res.status(500).json({
                success:
                    false,

                message:
                    "Failed to initialize threshold custody."
            });
        } finally {
            if (
                aesKey &&
                Buffer.isBuffer(aesKey)
            ) {
                aesKey.fill(0);
            }
        }
    }
);

// ── Custodian share submission ────────────────────────────────────────────────
// Each custodian submits their offline-stored share through this endpoint.
// When ≥ 3 valid shares are present in custody_session_shares, the
// reconstructExaminationKey() function can reconstruct the AES key in-memory.
// Session shares are deleted immediately after reconstruction.
// ─────────────────────────────────────────────────────────────────────────────

app.post(
    "/api/custody/submit-share",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                examinationId,
                shareId,
                shareValue
            } = req.body;

            if (!examinationId || !shareId || !shareValue) {
                return res.status(400).json({
                    success: false,
                    message: "examinationId, shareId, and shareValue are required."
                });
            }

            const shareIdNum = Number(shareId);
            if (
                !Number.isInteger(shareIdNum) ||
                shareIdNum < 1 ||
                shareIdNum > 5
            ) {
                return res.status(400).json({
                    success: false,
                    message: "shareId must be an integer between 1 and 5."
                });
            }

            const examination = await getExamination(examinationId);
            if (!examination) {
                return res.status(404).json({
                    success: false,
                    message: "Examination not found."
                });
            }

            const examinationData = examination.data();
            if (examinationData.custodyStatus !== "initialized") {
                return res.status(400).json({
                    success: false,
                    message: "Threshold custody has not been initialized for this examination."
                });
            }

            // Check if this shareId is already submitted for this session
            const existing = await db
                .collection("custody_session_shares")
                .where("examinationId", "==", examinationId)
                .where("shareId", "==", shareIdNum)
                .get();

            if (!existing.empty) {
                return res.status(409).json({
                    success: false,
                    message: `Share ${shareIdNum} has already been submitted for this examination.`
                });
            }

            // Store session share (temporary — deleted after key reconstruction)
            await db.collection("custody_session_shares").add({
                examinationId,
                examinationCode: examinationData.code || null,
                shareId: shareIdNum,
                value: shareValue,
                submittedBy: req.user.uid,
                submittedByEmail: req.user.email || null,
                submittedAt: new Date(),
                // TTL: auto-expire after 4 hours (Firestore TTL policy if configured)
                expiresAt: new Date(Date.now() + 4 * 60 * 60 * 1000)
            });

            // Count total submitted shares for this examination
            const allSubmitted = await db
                .collection("custody_session_shares")
                .where("examinationId", "==", examinationId)
                .get();

            const submittedCount = allSubmitted.size;

            await db.collection("audit_logs").add({
                action: "CUSTODY_SHARE_SUBMITTED",
                examinationId,
                examinationCode: examinationData.code || null,
                shareId: shareIdNum,
                actor: req.user.uid,
                actorEmail: req.user.email || null,
                submittedCount,
                thresholdRequired: 3,
                timestamp: new Date()
            });

            return res.json({
                success: true,
                message: `Share ${shareIdNum} submitted successfully.`,
                submittedCount,
                thresholdRequired: 3,
                thresholdMet: submittedCount >= 3
            });

        } catch (_error) {
            return res.status(500).json({
                success: false,
                message: "Failed to submit custody share."
            });
        }
    }
);

app.get(
    "/api/custody/session-shares/:examinationId",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { examinationId } = req.params;

            const snapshot = await db
                .collection("custody_session_shares")
                .where("examinationId", "==", examinationId)
                .get();

            const submitted = snapshot.docs.map(doc => ({
                shareId: doc.data().shareId,
                submittedAt: doc.data().submittedAt
            }));

            return res.json({
                success: true,
                submittedCount: submitted.length,
                thresholdRequired: 3,
                thresholdMet: submitted.length >= 3,
                submittedShareIds: submitted.map(s => s.shareId).sort((a, b) => a - b)
            });

        } catch (_error) {
            return res.status(500).json({
                success: false,
                message: "Failed to load session share status."
            });
        }
    }
);

app.get(
    "/api/custody/status/:examinationId",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                examinationId
            } = req.params;

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            const shares =
                await getCustodyShares(
                    examinationId
                );

            return res.json({
                success:
                    true,

                custody: {
                    examinationId,

                    examinationCode:
                        examinationData.code,

                    status:
                        examinationData.custodyStatus ||
                        "not_initialized",

                    thresholdRequired:
                        examinationData.custody
                            ?.thresholdRequired ||
                        3,

                    totalShares:
                        examinationData.custody
                            ?.totalShares ||
                        5,

                    sharesAssigned:
                        shares.length,

                    verificationStatus:
                        examinationData.custody
                            ?.verificationStatus ||
                        "pending",

                    fingerprintVerified:
                        examinationData.custody
                            ?.fingerprintVerified ||
                        false,

                    algorithm:
                        examinationData.custody
                            ?.algorithm ||
                        "Shamir Secret Sharing"
                }
            });
        } catch (error) {
            console.error(
                "Get custody status error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Failed to load custody status."
            });
        }
    }
);

app.post(
    "/api/custody/reconstruct-test",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        let reconstructedKey = null;

        try {
            const {
                examinationId,
                shareIds
            } = req.body;

            if (!examinationId) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Examination ID is required."
                });
            }

            if (
                !Array.isArray(
                    shareIds
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Share IDs must be provided as an array."
                });
            }

            const normalizedShareIds =
                shareIds.map(
                    id =>
                        Number(id)
                );

            const uniqueShareIds =
                [
                    ...new Set(
                        normalizedShareIds
                    )
                ];

            if (
                uniqueShareIds.length !==
                normalizedShareIds.length
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Duplicate share IDs are not allowed."
                });
            }

            if (
                uniqueShareIds.some(
                    id =>
                        !Number.isInteger(
                            id
                        ) ||
                        id < 1 ||
                        id > 5
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Share IDs must be integers from 1 to 5."
                });
            }

            if (
                uniqueShareIds.length <
                3
            ) {
                await db
                    .collection(
                        "audit_logs"
                    )
                    .add({
                        action:
                            "CUSTODY_RECONSTRUCTION_REJECTED",

                        examinationId,

                        actor:
                            req.user.uid,

                        actorEmail:
                            req.user.email ||
                            null,

                        role:
                            req.user.role,

                        sharesUsed:
                            uniqueShareIds,

                        reason:
                            "Threshold requires at least 3 shares.",

                        timestamp:
                            new Date()
                    });

                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "At least 3 shares are required for 3-of-5 reconstruction."
                });
            }

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            if (
                examinationData.custodyStatus !==
                "initialized"
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Threshold custody has not been initialized."
                });
            }

            const allShares =
                await getCustodyShares(
                    examinationId
                );

            const selectedShares =
                uniqueShareIds.map(
                    shareId =>
                        allShares.find(
                            share =>
                                Number(
                                    share.shareId
                                ) ===
                                shareId
                        )
                );

            if (
                selectedShares.some(
                    share =>
                        !share ||
                        !share.value
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "One or more selected protected shares were not found."
                });
            }

            const shamirShares =
                selectedShares.map(
                    share => ({
                        id:
                            Number(
                                share.shareId
                            ),

                        value:
                            share.value
                    })
                );

            if (
                !validateShares(
                    shamirShares
                )
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Selected protected shares failed validation."
                });
            }

            reconstructedKey =
                combineShares(
                    shamirShares
                );

            const fingerprint =
                createFingerprint(
                    reconstructedKey
                );

            const storedFingerprint =
                examinationData.custody
                    ?.keyFingerprint ||
                null;

            const fingerprintVerified =
                storedFingerprint
                    ? constantTimeEqualHex(
                        fingerprint,
                        storedFingerprint
                    )
                    : false;

            if (
                !fingerprintVerified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Reconstructed key fingerprint verification failed."
                });
            }

            await db
                .collection(
                    "examinations"
                )
                .doc(
                    examinationId
                )
                .update({
                    "custody.verificationStatus":
                        "verified",

                    "custody.fingerprintVerified":
                        true,

                    "custody.verifiedAt":
                        new Date(),

                    "custody.verifiedBy":
                        req.user.uid,

                    "custody.lastVerifiedShares":
                        uniqueShareIds
                });

            await db
                .collection(
                    "audit_logs"
                )
                .add({
                    action:
                        "CUSTODY_RECONSTRUCTION_VERIFIED",

                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    actor:
                        req.user.uid,

                    actorEmail:
                        req.user.email ||
                        null,

                    role:
                        req.user.role,

                    sharesUsed:
                        uniqueShareIds,

                    threshold:
                        "3-of-5",

                    fingerprintVerified:
                        true,

                    keyAlgorithm:
                        "AES-256",

                    secretSharing:
                        "Shamir Secret Sharing",

                    description:
                        "The protected AES-256 key was successfully reconstructed and verified using the supplied threshold shares.",

                    timestamp:
                        new Date()
                });

            return res.json({
                success:
                    true,

                message:
                    "AES-256 key reconstructed and verified successfully.",

                verification: {
                    thresholdRequired:
                        3,

                    sharesUsed:
                        uniqueShareIds.length,

                    totalShares:
                        5,

                    keyLength:
                        256,

                    algorithm:
                        "Shamir Secret Sharing",

                    fingerprintVerified:
                        true
                }
            });
        } catch (error) {
            console.error(
                "Reconstruct custody key error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Failed to reconstruct custody key."
            });
        } finally {
            if (
                reconstructedKey &&
                Buffer.isBuffer(
                    reconstructedKey
                )
            ) {
                reconstructedKey.fill(
                    0
                );
            }
        }
    }
);

app.post(
    "/api/fragments",
    verifyToken,
    requireRole("admin", "setter"),
    async (req, res) => {
        let examinationKey = null;

        try {
            const {
                examinationId,
                fragmentNumber,
                fragmentLabel,
                label,
                questionText,
                fragment,
                isDecoy
            } = req.body;

            const finalLabel =
                fragmentLabel ||
                label;

            const finalQuestion =
                questionText ||
                fragment;

            if (
                !examinationId ||
                fragmentNumber ===
                    undefined ||
                fragmentNumber ===
                    null ||
                !finalLabel ||
                !finalQuestion
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "All fragment fields are required."
                });
            }

            const number =
                Number(
                    fragmentNumber
                );

            if (
                !Number.isInteger(
                    number
                ) ||
                number < 1
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Fragment number must be a positive integer."
                });
            }

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            if (
                examinationData.custodyStatus !==
                "initialized"
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Initialize threshold custody before creating protected fragments."
                });
            }

            const custody =
                examinationData.custody ||
                {};

            if (
                custody.fingerprintVerified !==
                true
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Threshold custody must be verified before fragment encryption."
                });
            }

            const reconstructed =
                await reconstructExaminationKey(
                    examinationId,
                    3
                );

            examinationKey =
                reconstructed.key;

            let plaintext =
                String(
                    finalQuestion
                );

            let decoyMetadata =
                null;

            if (
                isDecoy === true
            ) {
                decoyMetadata =
                    createCanaryFragment({
                        examinationId,

                        examinationCode:
                            examinationData.code ||
                            "",

                        fragmentNumber:
                            number,

                        createdBy:
                            req.user.uid
                    });

                plaintext =
                    JSON.stringify(
                        decoyMetadata.payload
                    );
            }

            const encrypted =
                encryptFragment(
                    plaintext,
                    examinationKey
                );

            plaintext = "";

            const fragmentReference =
                await db
                    .collection(
                        "fragments"
                    )
                    .add({
                        examinationId,

                        examinationCode:
                            examinationData.code ||
                            null,

                        fragmentNumber:
                            number,

                        fragmentLabel:
                            String(
                                finalLabel
                            ).trim(),

                        ciphertext:
                            encrypted.ciphertext,

                        iv:
                            encrypted.iv,

                        authTag:
                            encrypted.authTag,

                        encrypted:
                            true,

                        status:
                            "encrypted",

                        encryptionAlgorithm:
                            "AES-256-GCM",

                        keyAlgorithm:
                            "AES-256",

                        keySource:
                            "examination-custody-key",

                        custodyThreshold:
                            "3-of-5",

                        plaintextPersisted:
                            false,

                        isDecoy:
                            isDecoy ===
                            true,

                        canaryId:
                            decoyMetadata
                                ?.canaryId ||
                            null,

                        createdAt:
                            new Date(),

                        createdBy:
                            req.user.uid
                    });

            await db
                .collection(
                    "audit_logs"
                )
                .add({
                    action:
                        isDecoy === true
                            ? "CANARY_FRAGMENT_CREATED"
                            : "FRAGMENT_ENCRYPTED",

                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    fragmentId:
                        fragmentReference.id,

                    fragmentNumber:
                        number,

                    actor:
                        req.user.uid,

                    actorEmail:
                        req.user.email ||
                        null,

                    role:
                        req.user.role,

                    encryptionAlgorithm:
                        "AES-256-GCM",

                    keySource:
                        "examination-custody-key",

                    threshold:
                        "3-of-5",

                    isDecoy:
                        isDecoy === true,

                    canaryId:
                        decoyMetadata
                            ?.canaryId ||
                        null,

                    plaintextPersisted:
                        false,

                    timestamp:
                        new Date()
                });

            return res.status(
                201
            ).json({
                success:
                    true,

                message:
                    isDecoy === true
                        ? "Encrypted canary fragment created successfully."
                        : "Fragment encrypted and protected successfully.",

                fragment: {
                    id:
                        fragmentReference.id,

                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    fragmentNumber:
                        number,

                    fragmentLabel:
                        String(
                            finalLabel
                        ).trim(),

                    encrypted:
                        true,

                    status:
                        "encrypted",

                    encryptionAlgorithm:
                        "AES-256-GCM",

                    keySource:
                        "examination-custody-key",

                    isDecoy:
                        isDecoy === true,

                    plaintextPersisted:
                        false
                }
            });
        } catch (error) {
            console.error(
                "Create encrypted fragment error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    error.message ||
                    "Failed to encrypt fragment."
            });
        } finally {
            if (
                examinationKey &&
                Buffer.isBuffer(
                    examinationKey
                )
            ) {
                examinationKey.fill(
                    0
                );
            }
        }
    }
);

app.get(
    "/api/fragments",
    verifyToken,
    requireRole("admin", "setter"),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .collection(
                        "fragments"
                    )
                    .orderBy(
                        "createdAt",
                        "desc"
                    )
                    .get();

            const fragments =
                snapshot.docs.map(
                    doc => {
                        const data =
                            doc.data();

                        const createdAt =
                            parseFirestoreDate(
                                data.createdAt
                            );

                        return {
                            id:
                                doc.id,

                            examinationId:
                                data.examinationId,

                            examinationCode:
                                data.examinationCode ||
                                null,

                            fragmentNumber:
                                data.fragmentNumber,

                            fragmentLabel:
                                data.fragmentLabel ||
                                "Protected Fragment",

                            encrypted:
                                data.encrypted ===
                                true,

                            status:
                                data.status ||
                                "encrypted",

                            encryptionAlgorithm:
                                data.encryptionAlgorithm ||
                                "AES-256-GCM",

                            keySource:
                                data.keySource ||
                                "examination-custody-key",

                            isDecoy:
                                data.isDecoy ===
                                true,

                            plaintextPersisted:
                                data.plaintextPersisted ===
                                true,

                            createdAt:
                                createdAt
                                    ? createdAt.toISOString()
                                    : null
                        };
                    }
                );

            return res.json({
                success:
                    true,

                fragments
            });
        } catch (error) {
            console.error(
                "Get fragments error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Failed to load fragments."
            });
        }
    }
);

app.post(
    "/api/security/initialize",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                examinationId
            } = req.body;

            if (!examinationId) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Examination ID is required."
                });
            }

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            if (
                examinationData.custody
                    ?.fingerprintVerified !==
                true
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Verify threshold custody before initializing release security."
                });
            }

            const fragments =
                await getFragments(
                    examinationId
                );

            if (
                fragments.length ===
                0
            ) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Create encrypted fragments before initializing release security."
                });
            }

            const invalid =
                fragments.some(
                    fragment =>
                        fragment.encrypted !==
                            true ||
                        fragment.plaintextPersisted ===
                            true ||
                        fragment.keySource !==
                            "examination-custody-key"
                );

            if (invalid) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "All fragments must be encrypted with the examination custody key."
                });
            }

            const mpc =
                await registerMpcState(
                    examinationId
                );

            const vdf =
                await registerVdfState(
                    examinationId,
                    mpc.manifestHash
                );

            return res.json({
                success:
                    true,

                message:
                    "MPC manifest and VDF release controls initialized.",

                security: {
                    mpc,

                    vdf,

                    canary:
                        "CLEAR",

                    releaseAgent:
                        "READY"
                }
            });
        } catch (error) {
            console.error(
                "Security initialization error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    error.message ||
                    "Security initialization failed."
            });
        }
    }
);

app.get(
    "/api/security/status/:examinationId",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                examinationId
            } = req.params;

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const data =
                examination.data();

            const fragments =
                await getFragments(
                    examinationId
                );

            const mpc =
                await verifyStoredMpc(
                    data,
                    examinationId,
                    fragments
                );

            const mpcHash =
                data.security
                    ?.mpc
                    ?.manifestHash ||
                mpc.result
                    ?.manifestHash ||
                null;

            const vdf =
                await verifyVdfState(
                    data,
                    examinationId,
                    mpcHash
                );

            const custodyVerified =
                data.custody
                    ?.fingerprintVerified ===
                true;

            const encryptedReady =
                fragments.length >
                    0 &&
                fragments.every(
                    fragment =>
                        fragment.encrypted ===
                            true &&
                        fragment.plaintextPersisted !==
                            true &&
                        fragment.keySource ===
                            "examination-custody-key"
                );

            const canaryClear =
                data.security
                    ?.canaryStatus !==
                "TRIGGERED";

            return res.json({
                success:
                    true,

                security: {
                    custody: {
                        verified:
                            custodyVerified,

                        threshold:
                            "3-of-5"
                    },

                    mpc: {
                        configured:
                            mpc.configured,

                        verified:
                            mpc.verified,

                        manifestHash:
                            mpcHash
                    },

                    vdf: {
                        configured:
                            vdf.configured,

                        verified:
                            vdf.verified,

                        timeGateOpen:
                            vdf.timeGateOpen,

                        releaseTime:
                            vdf.releaseTime ||
                            null,

                        iterations:
                            vdf.iterations ||
                            null
                    },

                    canary: {
                        status:
                            canaryClear
                                ? "CLEAR"
                                : "TRIGGERED"
                    },

                    fragments: {
                        total:
                            fragments.length,

                        encrypted:
                            encryptedReady
                    }
                }
            });
        } catch (error) {
            console.error(
                "Security status error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Unable to load security status."
            });
        }
    }
);

app.get(
    "/api/release/status/:examinationId",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                examinationId
            } = req.params;

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            const release =
                examinationData.release ||
                {};

            const releaseTime =
                parseFirestoreDate(
                    release.releaseTime ||
                    examinationData.releaseTime
                );

            const now =
                new Date();

            const fragments =
                await getFragments(
                    examinationId
                );

            const mpc =
                await verifyStoredMpc(
                    examinationData,
                    examinationId,
                    fragments
                );

            const mpcHash =
                examinationData.security
                    ?.mpc
                    ?.manifestHash ||
                mpc.result
                    ?.manifestHash ||
                null;

            const vdf =
                await verifyVdfState(
                    examinationData,
                    examinationId,
                    mpcHash
                );

            const custodyVerified =
                examinationData.custody
                    ?.fingerprintVerified ===
                true;

            const canaryClear =
                examinationData.security
                    ?.canaryStatus !==
                "TRIGGERED";

            const allFragmentsUseCustodyKey =
                fragments.every(
                    fragment =>
                        fragment.keySource ===
                        "examination-custody-key"
                );

            const fragmentsReady =
                fragments.length >
                    0 &&
                fragments.every(
                    fragment =>
                        fragment.encrypted ===
                            true &&
                        fragment.status ===
                            "encrypted" &&
                        fragment.plaintextPersisted !==
                            true
                ) &&
                allFragmentsUseCustodyKey;

            const timeGateOpen =
                releaseTime
                    ? now >=
                      releaseTime
                    : false;

            const authorized =
                release.authorized ===
                true;

            const released =
                release.released ===
                true;

            const allSecurityChecks =
                custodyVerified &&
                mpc.verified &&
                vdf.verified &&
                fragmentsReady &&
                canaryClear;

            return res.json({
                success:
                    true,

                release: {
                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    releaseTime:
                        releaseTime
                            ? releaseTime.toISOString()
                            : null,

                    currentTime:
                        now.toISOString(),

                    timeGateOpen,

                    custodyVerified,

                    mpcVerified:
                        mpc.verified,

                    vdfVerified:
                        vdf.verified,

                    canaryClear,

                    fragmentsReady,

                    encryptedFragments:
                        fragments.filter(
                            fragment =>
                                fragment.encrypted ===
                                true
                        ).length,

                    totalFragments:
                        fragments.length,

                    plaintextFragments:
                        fragments.filter(
                            fragment =>
                                fragment.plaintextPersisted ===
                                true
                        ).length,

                    securityReady:
                        allSecurityChecks,

                    authorized,

                    released,

                    executionMode:
                        release.executionMode ||
                        null,

                    plaintextPersisted:
                        release.plaintextPersisted ===
                        true,

                    releaseAgent:
                        release.releaseAgent ||
                        null
                }
            });
        } catch (error) {
            console.error(
                "Release status error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Unable to load release status."
            });
        }
    }
);

app.post(
    "/api/release/authorize",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                examinationId
            } = req.body;

            if (!examinationId) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Examination ID is required."
                });
            }

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            const release =
                examinationData.release ||
                {};

            const releaseTime =
                parseFirestoreDate(
                    release.releaseTime ||
                    examinationData.releaseTime
                );

            if (!releaseTime) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "A secure release time has not been configured."
                });
            }

            if (
                !isReleaseTimeReached(
                    releaseTime
                )
            ) {
                await db
                    .collection(
                        "audit_logs"
                    )
                    .add({
                        action:
                            "EXAMINATION_RELEASE_REJECTED",

                        examinationId,

                        examinationCode:
                            examinationData.code ||
                            null,

                        actor:
                            req.user.uid,

                        actorEmail:
                            req.user.email ||
                            null,

                        role:
                            req.user.role,

                        reason:
                            "Release attempted before configured release time.",

                        releaseTime,

                        timestamp:
                            new Date()
                    });

                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Release is locked until the configured release time."
                });
            }

            const fragments =
                await getFragments(
                    examinationId
                );

            const custodyVerified =
                examinationData.custody
                    ?.fingerprintVerified ===
                true;

            if (
                !custodyVerified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Threshold custody has not been verified."
                });
            }

            const mpc =
                await verifyStoredMpc(
                    examinationData,
                    examinationId,
                    fragments
                );

            if (
                !mpc.verified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "MPC manifest verification has not passed."
                });
            }

            const mpcHash =
                examinationData.security
                    ?.mpc
                    ?.manifestHash ||
                mpc.result
                    ?.manifestHash;

            const vdf =
                await verifyVdfState(
                    examinationData,
                    examinationId,
                    mpcHash
                );

            if (
                !vdf.verified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "VDF release verification has not passed."
                });
            }

            if (
                examinationData.security
                    ?.canaryStatus ===
                "TRIGGERED"
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Release blocked because a canary fragment was triggered."
                });
            }

            const fragmentsReady =
                fragments.length >
                    0 &&
                fragments.every(
                    fragment =>
                        fragment.encrypted ===
                            true &&
                        fragment.status ===
                            "encrypted" &&
                        fragment.plaintextPersisted !==
                            true &&
                        fragment.keySource ===
                            "examination-custody-key"
                );

            if (
                !fragmentsReady
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "All examination fragments must be encrypted with the examination custody key before release."
                });
            }

            if (
                release.authorized ===
                true
            ) {
                return res.status(
                    409
                ).json({
                    success:
                        false,

                    message:
                        "Examination release has already been authorized."
                });
            }

            const authorizationTime =
                new Date();

            const releaseData = {
                ...release,

                releaseTime,

                authorized:
                    true,

                authorizedAt:
                    authorizationTime,

                authorizedBy:
                    req.user.uid,

                released:
                    false,

                plaintextPersisted:
                    false
            };

            await db
                .collection(
                    "examinations"
                )
                .doc(
                    examinationId
                )
                .update({
                    release:
                        releaseData
                });

            await db
                .collection(
                    "audit_logs"
                )
                .add({
                    action:
                        "EXAMINATION_RELEASE_AUTHORIZED",

                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    actor:
                        req.user.uid,

                    actorEmail:
                        req.user.email ||
                        null,

                    role:
                        req.user.role,

                    releaseTime,

                    authorizedAt:
                        authorizationTime,

                    threshold:
                        "3-of-5",

                    custodyVerified:
                        true,

                    mpcVerified:
                        true,

                    vdfVerified:
                        true,

                    encryptedFragments:
                        fragments.length,

                    plaintextPersisted:
                        false,

                    timestamp:
                        new Date()
                });

            return res.json({
                success:
                    true,

                release: {
                    examinationId,

                    authorized:
                        true,

                    released:
                        false,

                    encryptedFragments:
                        fragments.length,

                    mpcVerified:
                        true,

                    vdfVerified:
                        true
                }
            });
        } catch (error) {
            console.error(
                "Release authorization error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    error.message ||
                    "Unable to authorize examination release."
            });
        }
    }
);

app.post(
    "/api/release/execute",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        let examinationKey = null;

        let plaintextBuffers = [];

        let assembledPaperBuffer =
            null;

        try {
            const {
                examinationId
            } = req.body;

            if (!examinationId) {
                return res.status(
                    400
                ).json({
                    success:
                        false,

                    message:
                        "Examination ID is required."
                });
            }

            const examination =
                await getExamination(
                    examinationId
                );

            if (!examination) {
                return res.status(
                    404
                ).json({
                    success:
                        false,

                    message:
                        "Examination not found."
                });
            }

            const examinationData =
                examination.data();

            const release =
                examinationData.release ||
                {};

            const releaseTime =
                parseFirestoreDate(
                    release.releaseTime ||
                    examinationData.releaseTime
                );

            if (!releaseTime) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "No secure release time has been configured."
                });
            }

            if (
                !isReleaseTimeReached(
                    releaseTime
                )
            ) {
                await db
                    .collection(
                        "audit_logs"
                    )
                    .add({
                        action:
                            "SECURE_RELEASE_EXECUTION_REJECTED",

                        examinationId,

                        examinationCode:
                            examinationData.code ||
                            null,

                        actor:
                            req.user.uid,

                        actorEmail:
                            req.user.email ||
                            null,

                        role:
                            req.user.role,

                        reason:
                            "Release attempted before configured release time.",

                        timestamp:
                            new Date()
                    });

                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "The time gate is still locked."
                });
            }

            if (
                examinationData.custodyStatus !==
                "initialized"
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Threshold custody has not been initialized."
                });
            }

            const custody =
                examinationData.custody ||
                {};

            if (
                custody.fingerprintVerified !==
                true
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Threshold custody has not been verified."
                });
            }

            const fragments =
                await getFragments(
                    examinationId
                );

            if (
                fragments.length ===
                0
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "No encrypted fragments are available for release."
                });
            }

            const invalidFragments =
                fragments.filter(
                    fragment =>
                        fragment.encrypted !==
                            true ||
                        fragment.status !==
                            "encrypted" ||
                        !fragment.ciphertext ||
                        !fragment.iv ||
                        !fragment.authTag ||
                        fragment.plaintextPersisted ===
                            true
                );

            if (
                invalidFragments.length >
                0
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "One or more fragments are not in a valid encrypted state."
                });
            }

            const legacyFragments =
                fragments.filter(
                    fragment =>
                        fragment.keySource !==
                        "examination-custody-key"
                );

            if (
                legacyFragments.length >
                0
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "One or more fragments were not encrypted with the examination custody key."
                });
            }

            if (
                examinationData.security
                    ?.canaryStatus ===
                "TRIGGERED"
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Release blocked because a canary fragment was triggered."
                });
            }

            const mpc =
                await verifyStoredMpc(
                    examinationData,
                    examinationId,
                    fragments
                );

            if (
                !mpc.verified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "MPC manifest verification failed. Release blocked."
                });
            }

            const mpcManifestHash =
                examinationData.security
                    ?.mpc
                    ?.manifestHash ||
                mpc.result
                    ?.manifestHash ||
                null;

            const vdf =
                await verifyVdfState(
                    examinationData,
                    examinationId,
                    mpcManifestHash
                );

            if (
                !vdf.verified
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "VDF verification failed or time gate is not satisfied."
                });
            }

            const agent =
                createReleaseAgent({
                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        "",

                    releaseAt:
                        releaseTime.toISOString()
                });

            const authorization =
                validateReleaseAuthorization({
                    authorized:
                        release.authorized ===
                        true,

                    releaseTimeReached:
                        true,

                    custodyVerified:
                        true,

                    mpcVerified:
                        true,

                    fragmentsReady:
                        true,

                    canaryClear:
                        true
                });

            if (
                !authorization.authorized
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Release-agent authorization checks failed.",

                    checks:
                        authorization
                });
            }

            const reconstructed =
                await reconstructExaminationKey(
                    examinationId,
                    3
                );

            examinationKey =
                reconstructed.key;

            const releaseFingerprint =
                createFingerprint(
                    examinationKey
                );

            const storedFingerprint =
                custody.keyFingerprint ||
                null;

            if (
                !storedFingerprint ||
                !constantTimeEqualHex(
                    releaseFingerprint,
                    storedFingerprint
                )
            ) {
                return res.status(
                    403
                ).json({
                    success:
                        false,

                    message:
                        "Release key fingerprint verification failed."
                });
            }

            const decryptedFragments =
                [];

            for (
                const currentFragment
                of fragments
            ) {
                const plaintext =
                    decryptFragment(
                        {
                            ciphertext:
                                currentFragment.ciphertext,

                            iv:
                                currentFragment.iv,

                            authTag:
                                currentFragment.authTag
                        },
                        examinationKey
                    );

                const canaryResult =
                    await recordCanaryAlert(
                        examinationId,
                        examinationData,
                        plaintext,
                        req.user.uid
                    );

                if (
                    canaryResult.triggered
                ) {
                    return res.status(
                        403
                    ).json({
                        success:
                            false,

                        message:
                            "Canary fragment detected. Release has been blocked.",

                        alert:
                            true
                    });
                }

                const plaintextBuffer =
                    Buffer.from(
                        plaintext,
                        "utf8"
                    );

                plaintextBuffers.push(
                    plaintextBuffer
                );

                decryptedFragments.push({
                    fragmentNumber:
                        Number(
                            currentFragment.fragmentNumber
                        ),

                    fragmentLabel:
                        currentFragment.fragmentLabel ||
                        "Protected Fragment",

                    plaintext
                });
            }

            const assembledPaper =
                decryptedFragments
                    .map(
                        currentFragment =>
                            `FRAGMENT ${currentFragment.fragmentNumber} — ${currentFragment.fragmentLabel}\n\n${currentFragment.plaintext}`
                    )
                    .join(
                        "\n\n----------------------------------------\n\n"
                    );

            assembledPaperBuffer =
                Buffer.from(
                    assembledPaper,
                    "utf8"
                );

            plaintextBuffers.push(
                assembledPaperBuffer
            );

            const releasePackage =
                createReleasePackage({
                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        "",

                    fragments,

                    mpcResult:
                        mpc.result,

                    vdfResult:
                        vdf,

                    custodyFingerprint:
                        releaseFingerprint
                });

            const executionRecord =
                createExecutionRecord({
                    agent,

                    releasePackage,

                    authorizedBy:
                        release.authorizedBy ||
                        req.user.uid,

                    fragmentCount:
                        fragments.length
                });

            const printHandoff =
                createPrintHandoff({
                    agent,

                    examinationId,

                    fragmentCount:
                        fragments.length
                });

            const agentAudit =
                createAgentAuditEvent({
                    agent,

                    executionRecord,

                    printHandoff
                });

            const executionTime =
                new Date();

            await db
                .collection(
                    "examinations"
                )
                .doc(
                    examinationId
                )
                .update({
                    "release.authorized":
                        true,

                    "release.authorizedAt":
                        release.authorizedAt ||
                        executionTime,

                    "release.authorizedBy":
                        release.authorizedBy ||
                        req.user.uid,

                    "release.released":
                        true,

                    "release.releasedAt":
                        executionTime,

                    "release.releasedBy":
                        req.user.uid,

                    "release.releaseAgent":
                        agent.agentId,

                    "release.executionMode":
                        "offline-agent-simulation",

                    "release.printHandoffId":
                        printHandoff.handoffId,

                    "release.mpcManifestHash":
                        mpcManifestHash,

                    "release.vdfOutput":
                        vdf.output,

                    "release.plaintextPersisted":
                        false,

                    "release.plaintextWrittenToDisk":
                        false
                });

            await db
                .collection(
                    "audit_logs"
                )
                .add({
                    action:
                        "SECURE_RELEASE_EXECUTED",

                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    actor:
                        req.user.uid,

                    actorEmail:
                        req.user.email ||
                        null,

                    role:
                        req.user.role,

                    threshold:
                        "3-of-5",

                    sharesUsed:
                        reconstructed.sharesUsed,

                    keyAlgorithm:
                        "AES-256",

                    encryptionAlgorithm:
                        "AES-256-GCM",

                    fragmentCount:
                        fragments.length,

                    releaseAgent:
                        agent.agentId,

                    executionMode:
                        "offline-agent-simulation",

                    mpcManifestHash,

                    vdfOutput:
                        vdf.output,

                    vdfIterations:
                        vdf.iterations,

                    plaintextPersisted:
                        false,

                    plaintextWrittenToDisk:
                        false,

                    timestamp:
                        executionTime
                });

            await db
                .collection(
                    "audit_logs"
                )
                .add({
                    ...agentAudit,

                    actor:
                        req.user.uid,

                    actorEmail:
                        req.user.email ||
                        null,

                    role:
                        req.user.role,

                    mpcManifestHash,

                    vdfOutput:
                        vdf.output,

                    timestamp:
                        executionTime
                });

            const result =
                sanitizeAgentResult({
                    agent,

                    executionRecord,

                    printHandoff
                });

            return res.json({
                ...result,

                release: {
                    examinationId,

                    examinationCode:
                        examinationData.code ||
                        null,

                    fragmentCount:
                        fragments.length,

                    threshold:
                        "3-of-5",

                    encryption:
                        "AES-256-GCM",

                    mpc:
                        "Verified",

                    vdf:
                        "Verified",

                    executionMode:
                        "offline-agent-simulation",

                    plaintextPersisted:
                        false,

                    plaintextWrittenToDisk:
                        false,

                    releaseAgent:
                        agent.agentId,

                    printHandoff:
                        printHandoff.handoffId,

                    releasedAt:
                        executionTime.toISOString()
                }
            });
        } catch (error) {
            console.error(
                "Secure release execution error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    error.message ||
                    "Controlled release execution failed."
            });
        } finally {
            if (
                examinationKey &&
                Buffer.isBuffer(
                    examinationKey
                )
            ) {
                examinationKey.fill(
                    0
                );
            }

            if (
                assembledPaperBuffer &&
                Buffer.isBuffer(
                    assembledPaperBuffer
                )
            ) {
                assembledPaperBuffer.fill(
                    0
                );
            }

            for (
                const buffer
                of plaintextBuffers
            ) {
                if (
                    Buffer.isBuffer(
                        buffer
                    )
                ) {
                    buffer.fill(
                        0
                    );
                }
            }

            plaintextBuffers =
                [];

            assembledPaperBuffer =
                null;
        }
    }
);

app.get(
    "/api/audit-logs",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const snapshot =
                await db
                    .collection(
                        "audit_logs"
                    )
                    .get();

            const logs =
                snapshot.docs
                    .map(
                        doc => {
                            const data =
                                doc.data();

                            const timestamp =
                                parseFirestoreDate(
                                    data.timestamp ||
                                    data.createdAt ||
                                    data.detectedAt
                                );

                            const action =
                                data.action ||
                                data.event ||
                                data.eventType ||
                                "UNKNOWN_EVENT";

                            const critical =
                                data.severity ===
                                    "CRITICAL" ||
                                data.severity ===
                                    "ALERT" ||
                                action.includes(
                                    "REJECTED"
                                ) ||
                                action.includes(
                                    "CANARY"
                                );

                            return {
                                id:
                                    doc.id,

                                action,

                                examinationId:
                                    data.examinationId ||
                                    null,

                                examinationCode:
                                    data.examinationCode ||
                                    null,

                                actor:
                                    data.actor ||
                                    data.actorUid ||
                                    null,

                                actorEmail:
                                    data.actorEmail ||
                                    null,

                                role:
                                    data.role ||
                                    null,

                                severity:
                                    critical
                                        ? (
                                            data.severity ||
                                            "CRITICAL"
                                        )
                                        : (
                                            data.severity ||
                                            "INFO"
                                        ),

                                description:
                                    data.description ||
                                    data.reason ||
                                    data.message ||
                                    "",

                                threshold:
                                    data.threshold ||
                                    null,

                                sharesUsed:
                                    Array.isArray(
                                        data.sharesUsed
                                    )
                                        ? data.sharesUsed
                                        : null,

                                fragmentNumber:
                                    data.fragmentNumber ??
                                    null,

                                fragmentCount:
                                    data.fragmentCount ??
                                    null,

                                encryptionAlgorithm:
                                    data.encryptionAlgorithm ||
                                    null,

                                keyAlgorithm:
                                    data.keyAlgorithm ||
                                    null,

                                executionMode:
                                    data.executionMode ||
                                    null,

                                releaseAgent:
                                    data.releaseAgent ||
                                    data.agentId ||
                                    null,

                                mpcManifestHash:
                                    data.mpcManifestHash ||
                                    null,

                                vdfOutput:
                                    data.vdfOutput ||
                                    null,

                                vdfIterations:
                                    data.vdfIterations ||
                                    null,

                                canaryId:
                                    data.canaryId ||
                                    null,

                                plaintextPersisted:
                                    data.plaintextPersisted ===
                                    true,

                                plaintextWrittenToDisk:
                                    data.plaintextWrittenToDisk ===
                                    true,

                                timestamp:
                                    timestamp
                                        ? timestamp.toISOString()
                                        : null
                            };
                        }
                    )
                    .sort(
                        (
                            first,
                            second
                        ) => {
                            const firstTime =
                                first.timestamp
                                    ? new Date(
                                        first.timestamp
                                    ).getTime()
                                    : 0;

                            const secondTime =
                                second.timestamp
                                    ? new Date(
                                        second.timestamp
                                    ).getTime()
                                    : 0;

                            return (
                                secondTime -
                                firstTime
                            );
                        }
                    );

            const alerts =
                logs.filter(
                    log =>
                        log.severity ===
                            "CRITICAL" ||
                        log.severity ===
                            "ALERT"
                ).length;

            const accessEvents =
                logs.filter(
                    log =>
                        log.action.includes(
                            "LOGIN"
                        ) ||
                        log.action.includes(
                            "ACCESS"
                        ) ||
                        log.action.includes(
                            "AUTH"
                        )
                ).length;

            return res.json({
                success:
                    true,

                logs,

                summary: {
                    total:
                        logs.length,

                    alerts,

                    access:
                        accessEvents
                }
            });
        } catch (error) {
            console.error(
                "Get audit logs error:",
                error
            );

            return res.status(
                500
            ).json({
                success:
                    false,

                message:
                    "Failed to load audit logs."
            });
        }
    }
);

app.use(
    (req, res) => {
        res.status(
            404
        ).json({
            success:
                false,

            message:
                "Route not found."
        });
    }
);

// ══════════════════════════════════════════════════════════════════════════════
// USER MANAGEMENT ROUTES (admin only)
// ══════════════════════════════════════════════════════════════════════════════

app.post(
    "/api/admin/users/create",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { email, password, role, displayName } = req.body;

            if (!email || !password || !role) {
                return res.status(400).json({
                    success: false,
                    message: "email, password, and role are required."
                });
            }

            const allowedRoles = ["admin", "setter", "custodian", "print-operator"];
            if (!allowedRoles.includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: `Invalid role. Must be one of: ${allowedRoles.join(", ")}`
                });
            }

            const userRecord = await firebaseAuth.createUser({
                email,
                password,
                displayName: displayName || email
            });

            await firebaseAuth.setCustomUserClaims(userRecord.uid, { role });

            await db.collection("audit_logs").add({
                action: "USER_CREATED",
                targetUid: userRecord.uid,
                targetEmail: email,
                targetRole: role,
                createdBy: req.user.uid,
                timestamp: new Date()
            });

            return res.status(201).json({
                success: true,
                message: `User created with role '${role}'.`,
                user: {
                    uid: userRecord.uid,
                    email: userRecord.email,
                    displayName: userRecord.displayName,
                    role
                }
            });
        } catch (_error) {
            const msg = _error.code === "auth/email-already-exists"
                ? "A user with this email already exists."
                : "Failed to create user.";
            return res.status(400).json({ success: false, message: msg });
        }
    }
);

app.get(
    "/api/admin/users",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const listResult = await firebaseAuth.listUsers(1000);
            const users = await Promise.all(
                listResult.users.map(async (u) => {
                    const claims = u.customClaims || {};
                    return {
                        uid: u.uid,
                        email: u.email,
                        displayName: u.displayName || u.email,
                        role: claims.role || "unknown",
                        disabled: u.disabled,
                        createdAt: u.metadata.creationTime
                    };
                })
            );
            return res.json({ success: true, users });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to list users." });
        }
    }
);

app.post(
    "/api/admin/users/assign-role",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { uid, role } = req.body;
            if (!uid || !role) {
                return res.status(400).json({ success: false, message: "uid and role are required." });
            }
            const allowedRoles = ["admin", "setter", "custodian", "print-operator"];
            if (!allowedRoles.includes(role)) {
                return res.status(400).json({ success: false, message: "Invalid role." });
            }
            await firebaseAuth.setCustomUserClaims(uid, { role });
            await db.collection("audit_logs").add({
                action: "USER_ROLE_CHANGED",
                targetUid: uid,
                newRole: role,
                changedBy: req.user.uid,
                timestamp: new Date()
            });
            return res.json({ success: true, message: `Role updated to '${role}'.` });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to update role." });
        }
    }
);

app.delete(
    "/api/admin/users/:uid",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { uid } = req.params;
            if (uid === req.user.uid) {
                return res.status(400).json({ success: false, message: "Cannot delete your own account." });
            }
            await firebaseAuth.deleteUser(uid);
            await db.collection("audit_logs").add({
                action: "USER_DELETED",
                targetUid: uid,
                deletedBy: req.user.uid,
                timestamp: new Date()
            });
            return res.json({ success: true, message: "User deleted." });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to delete user." });
        }
    }
);

// ══════════════════════════════════════════════════════════════════════════════
// EXAM ASSIGNMENT ROUTES (admin assigns actors to exams)
// ══════════════════════════════════════════════════════════════════════════════

app.post(
    "/api/admin/assign-setter",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { examinationId, setterUid } = req.body;
            if (!examinationId || !setterUid) {
                return res.status(400).json({ success: false, message: "examinationId and setterUid required." });
            }
            const userRecord = await firebaseAuth.getUser(setterUid);
            const claims = userRecord.customClaims || {};
            if (claims.role !== "setter") {
                return res.status(400).json({ success: false, message: "User is not a setter." });
            }
            await db.collection("examinations").doc(examinationId).update({
                setterAssignments: db.FieldValue
                    ? db.FieldValue.arrayUnion({ uid: setterUid, email: userRecord.email, displayName: userRecord.displayName || userRecord.email })
                    : [{ uid: setterUid, email: userRecord.email, displayName: userRecord.displayName || userRecord.email }]
            });
            const exam = await db.collection("examinations").doc(examinationId).get();
            const examData = exam.data() || {};
            const existing = examData.setterAssignments || [];
            const alreadyAssigned = existing.some(s => s.uid === setterUid);
            if (!alreadyAssigned) {
                await db.collection("examinations").doc(examinationId).update({
                    setterAssignments: [...existing, { uid: setterUid, email: userRecord.email, displayName: userRecord.displayName || userRecord.email }]
                });
            }
            await db.collection("audit_logs").add({
                action: "SETTER_ASSIGNED",
                examinationId,
                setterUid,
                setterEmail: userRecord.email,
                assignedBy: req.user.uid,
                timestamp: new Date()
            });
            return res.json({ success: true, message: "Setter assigned to examination." });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to assign setter." });
        }
    }
);

app.post(
    "/api/admin/assign-custodian",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { examinationId, custodianUid, shareNumber } = req.body;
            if (!examinationId || !custodianUid || !shareNumber) {
                return res.status(400).json({ success: false, message: "examinationId, custodianUid, and shareNumber required." });
            }
            const shareNum = Number(shareNumber);
            if (!Number.isInteger(shareNum) || shareNum < 1 || shareNum > 5) {
                return res.status(400).json({ success: false, message: "shareNumber must be 1-5." });
            }
            const userRecord = await firebaseAuth.getUser(custodianUid);
            const claims = userRecord.customClaims || {};
            if (claims.role !== "custodian") {
                return res.status(400).json({ success: false, message: "User is not a custodian." });
            }
            const exam = await db.collection("examinations").doc(examinationId).get();
            const examData = exam.data() || {};
            const existing = examData.custodianAssignments || [];
            const conflict = existing.find(c => c.shareNumber === shareNum);
            if (conflict) {
                return res.status(409).json({ success: false, message: `Share ${shareNum} is already assigned to another custodian.` });
            }
            const alreadyAssigned = existing.find(c => c.uid === custodianUid);
            if (alreadyAssigned) {
                return res.status(409).json({ success: false, message: "This custodian is already assigned a share for this exam." });
            }
            const updated = [...existing, { uid: custodianUid, email: userRecord.email, displayName: userRecord.displayName || userRecord.email, shareNumber: shareNum }];
            await db.collection("examinations").doc(examinationId).update({ custodianAssignments: updated });
            await db.collection("audit_logs").add({
                action: "CUSTODIAN_ASSIGNED",
                examinationId,
                custodianUid,
                custodianEmail: userRecord.email,
                shareNumber: shareNum,
                assignedBy: req.user.uid,
                timestamp: new Date()
            });
            return res.json({ success: true, message: `Custodian assigned share ${shareNum}.` });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to assign custodian." });
        }
    }
);

app.post(
    "/api/admin/assign-print-operator",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { examinationId, operatorUid } = req.body;
            if (!examinationId || !operatorUid) {
                return res.status(400).json({ success: false, message: "examinationId and operatorUid required." });
            }
            const userRecord = await firebaseAuth.getUser(operatorUid);
            const claims = userRecord.customClaims || {};
            if (claims.role !== "print-operator") {
                return res.status(400).json({ success: false, message: "User is not a print-operator." });
            }
            await db.collection("examinations").doc(examinationId).update({
                printOperator: { uid: operatorUid, email: userRecord.email, displayName: userRecord.displayName || userRecord.email }
            });
            await db.collection("audit_logs").add({
                action: "PRINT_OPERATOR_ASSIGNED",
                examinationId,
                operatorUid,
                operatorEmail: userRecord.email,
                assignedBy: req.user.uid,
                timestamp: new Date()
            });
            return res.json({ success: true, message: "Print operator assigned." });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to assign print operator." });
        }
    }
);

app.get(
    "/api/admin/assignments/:examinationId",
    verifyToken,
    requireRole("admin"),
    async (req, res) => {
        try {
            const { examinationId } = req.params;
            const exam = await db.collection("examinations").doc(examinationId).get();
            if (!exam.exists) {
                return res.status(404).json({ success: false, message: "Examination not found." });
            }
            const data = exam.data();
            return res.json({
                success: true,
                setterAssignments: data.setterAssignments || [],
                custodianAssignments: data.custodianAssignments || [],
                printOperator: data.printOperator || null
            });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to load assignments." });
        }
    }
);

// ══════════════════════════════════════════════════════════════════════════════
// SETTER PORTAL ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get(
    "/api/setter/my-exams",
    verifyToken,
    requireRole("setter"),
    async (req, res) => {
        try {
            const uid = req.user.uid;
            const snapshot = await db.collection("examinations").get();
            const exams = snapshot.docs
                .map(doc => ({ id: doc.id, ...doc.data() }))
                .filter(exam => {
                    const assignments = exam.setterAssignments || [];
                    return assignments.some(s => s.uid === uid);
                })
                .map(exam => ({
                    id: exam.id,
                    code: exam.code,
                    name: exam.name || exam.title,
                    status: exam.status,
                    custodyStatus: exam.custodyStatus
                }));
            return res.json({ success: true, examinations: exams });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to load assignments." });
        }
    }
);

// ══════════════════════════════════════════════════════════════════════════════
// CUSTODIAN PORTAL ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get(
    "/api/custodian/my-assignment",
    verifyToken,
    requireRole("custodian"),
    async (req, res) => {
        try {
            const uid = req.user.uid;
            const snapshot = await db.collection("examinations").get();
            let assignment = null;
            for (const doc of snapshot.docs) {
                const data = doc.data();
                const custodianAssignments = data.custodianAssignments || [];
                const match = custodianAssignments.find(c => c.uid === uid);
                if (match) {
                    // Check if this custodian already submitted their share
                    const sessionSnapshot = await db
                        .collection("custody_session_shares")
                        .where("examinationId", "==", doc.id)
                        .where("shareId", "==", match.shareNumber)
                        .get();
                    assignment = {
                        examinationId: doc.id,
                        examinationCode: data.code,
                        examinationName: data.name || data.title,
                        shareNumber: match.shareNumber,
                        custodyStatus: data.custodyStatus || "not_initialized",
                        shareSubmitted: !sessionSnapshot.empty,
                        releaseTime: data.release?.releaseTime || data.releaseTime || null
                    };
                    break;
                }
            }
            if (!assignment) {
                return res.json({ success: true, assignment: null, message: "No custody assignment found for your account." });
            }
            return res.json({ success: true, assignment });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to load custodian assignment." });
        }
    }
);

app.post(
    "/api/custodian/submit-share",
    verifyToken,
    requireRole("custodian"),
    async (req, res) => {
        try {
            const uid = req.user.uid;
            const { shareValue } = req.body;
            if (!shareValue) {
                return res.status(400).json({ success: false, message: "shareValue is required." });
            }
            // Find this custodian's assignment
            const snapshot = await db.collection("examinations").get();
            let assignment = null;
            let examinationData = null;
            for (const doc of snapshot.docs) {
                const data = doc.data();
                const assignments = data.custodianAssignments || [];
                const match = assignments.find(c => c.uid === uid);
                if (match) {
                    assignment = { examinationId: doc.id, shareNumber: match.shareNumber };
                    examinationData = data;
                    break;
                }
            }
            if (!assignment) {
                return res.status(404).json({ success: false, message: "No custody assignment found for your account." });
            }
            if (examinationData.custodyStatus !== "initialized") {
                return res.status(400).json({ success: false, message: "Custody has not been initialized for this examination." });
            }
            // Check duplicate
            const existing = await db
                .collection("custody_session_shares")
                .where("examinationId", "==", assignment.examinationId)
                .where("shareId", "==", assignment.shareNumber)
                .get();
            if (!existing.empty) {
                return res.status(409).json({ success: false, message: "Your share has already been submitted." });
            }
            await db.collection("custody_session_shares").add({
                examinationId: assignment.examinationId,
                examinationCode: examinationData.code || null,
                shareId: assignment.shareNumber,
                value: shareValue,
                submittedBy: uid,
                submittedByEmail: req.user.email || null,
                submittedAt: new Date(),
                expiresAt: new Date(Date.now() + 4 * 60 * 60 * 1000)
            });
            const allSubmitted = await db
                .collection("custody_session_shares")
                .where("examinationId", "==", assignment.examinationId)
                .get();
            const count = allSubmitted.size;
            await db.collection("audit_logs").add({
                action: "CUSTODY_SHARE_SUBMITTED",
                examinationId: assignment.examinationId,
                shareId: assignment.shareNumber,
                actor: uid,
                actorEmail: req.user.email || null,
                submittedCount: count,
                timestamp: new Date()
            });
            return res.json({
                success: true,
                message: `Share ${assignment.shareNumber} submitted successfully.`,
                submittedCount: count,
                thresholdRequired: 3,
                thresholdMet: count >= 3
            });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to submit share." });
        }
    }
);

// ══════════════════════════════════════════════════════════════════════════════
// PRINT OPERATOR PORTAL ROUTES
// ══════════════════════════════════════════════════════════════════════════════

app.get(
    "/api/print-operator/my-assignment",
    verifyToken,
    requireRole("print-operator"),
    async (req, res) => {
        try {
            const uid = req.user.uid;
            const snapshot = await db.collection("examinations").get();
            let assignment = null;
            for (const doc of snapshot.docs) {
                const data = doc.data();
                if (data.printOperator && data.printOperator.uid === uid) {
                    assignment = {
                        examinationId: doc.id,
                        examinationCode: data.code,
                        examinationName: data.name || data.title,
                        status: data.status,
                        releaseStatus: data.releaseStatus,
                        releaseTime: data.release?.releaseTime || data.releaseTime || null,
                        releaseExecuted: data.releaseStatus === "released",
                        printConfirmed: data.printConfirmed || false,
                        printConfirmedAt: data.printConfirmedAt || null
                    };
                    break;
                }
            }
            return res.json({ success: true, assignment });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to load assignment." });
        }
    }
);

app.get(
    "/api/print-operator/release-packet/:examinationId",
    verifyToken,
    requireRole("print-operator"),
    async (req, res) => {
        try {
            const uid = req.user.uid;
            const { examinationId } = req.params;
            const exam = await db.collection("examinations").doc(examinationId).get();
            if (!exam.exists) {
                return res.status(404).json({ success: false, message: "Examination not found." });
            }
            const data = exam.data();
            if (!data.printOperator || data.printOperator.uid !== uid) {
                return res.status(403).json({ success: false, message: "You are not the assigned print operator for this examination." });
            }
            if (data.releaseStatus !== "released") {
                return res.status(400).json({ success: false, message: "This examination has not been released yet. Release must be executed by the admin first." });
            }
            const releasePacket = data.releasePacket || null;
            if (!releasePacket) {
                return res.status(404).json({ success: false, message: "Release packet not found. Execute release first." });
            }
            await db.collection("audit_logs").add({
                action: "RELEASE_PACKET_DOWNLOADED",
                examinationId,
                downloadedBy: uid,
                downloadedByEmail: req.user.email || null,
                timestamp: new Date()
            });
            return res.json({
                success: true,
                releasePacket,
                examinationCode: data.code,
                releasedAt: data.releasedAt
            });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to retrieve release packet." });
        }
    }
);

app.post(
    "/api/print-operator/confirm-print",
    verifyToken,
    requireRole("print-operator"),
    async (req, res) => {
        try {
            const uid = req.user.uid;
            const { examinationId } = req.body;
            if (!examinationId) {
                return res.status(400).json({ success: false, message: "examinationId required." });
            }
            const exam = await db.collection("examinations").doc(examinationId).get();
            if (!exam.exists) {
                return res.status(404).json({ success: false, message: "Examination not found." });
            }
            const data = exam.data();
            if (!data.printOperator || data.printOperator.uid !== uid) {
                return res.status(403).json({ success: false, message: "Not the assigned print operator." });
            }
            await db.collection("examinations").doc(examinationId).update({
                printConfirmed: true,
                printConfirmedAt: new Date(),
                printConfirmedBy: uid
            });
            await db.collection("audit_logs").add({
                action: "PRINT_CONFIRMED",
                examinationId,
                examinationCode: data.code,
                confirmedBy: uid,
                confirmedByEmail: req.user.email || null,
                timestamp: new Date()
            });
            return res.json({ success: true, message: "Print confirmed. Audit trail recorded." });
        } catch (_error) {
            return res.status(500).json({ success: false, message: "Failed to confirm print." });
        }
    }
);

function logStartup() {
    console.log(
        `Server running at http://localhost:${PORT}`
    );

    console.log(
        "Firebase Admin SDK connected"
    );

    console.log(
        "Shamir 3-of-5 threshold custody enabled"
    );

    console.log(
        "AES-256-GCM fragment encryption uses examination custody keys"
    );

    console.log(
        "Software MPC encrypted-manifest computation enabled"
    );

    console.log(
        "Sequential SHA-256 VDF release gate enabled"
    );

    console.log(
        "Canary/decoy detection enabled"
    );

    console.log(
        "Controlled offline release-agent simulation enabled"
    );

    console.log(
        "Audit log API enabled"
    );
}

if (require.main === module) {
    app.listen(
        PORT,
        logStartup
    );
}

module.exports = app;
