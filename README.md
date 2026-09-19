# Secure Question Paper Management System

Web application for managing examination question fragments, role-based access, threshold-key custody, release authorization, and audit events. It uses Node.js, Express, Firebase Authentication, and Cloud Firestore.

> **Project status: prototype / demonstration system.** It contains real cryptographic primitives and server-side role checks, but it is **not ready to protect live high-stakes examinations** without addressing the security limitations in [Production readiness](#production-readiness).

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Roles](#roles)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the application](#running-the-application)
- [Validation](#validation)
- [Application workflow](#application-workflow)
- [API overview](#api-overview)
- [Project structure](#project-structure)
- [Production readiness](#production-readiness)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- Firebase ID-token authentication with server-side role checks.
- Administrative creation and assignment of exams, users, setters, custodians, and print operators.
- AES-256-GCM encryption for question fragments.
- Shamir 3-of-5 secret sharing for examination keys.
- A Wesolowski-style RSA VDF proof implementation and release-time validation.
- MPC-style manifest hashing to detect fragment-set changes.
- Canary/decoy fragment handling and Firestore-backed audit events.
- Separate browser workspaces for administrators, question setters, custodians, and print operators.

## Architecture

```text
Browser UI
    |
    v
Express server (server.js) ---- Firebase Authentication
    |                                  |
    +---- security modules             +---- Cloud Firestore
          - AES-256-GCM                      - exams
          - Shamir 3-of-5                    - encrypted fragments
          - VDF proof                        - custody/share records
          - MPC manifest                     - audit logs
          - canary checks
```

Question fragments are encrypted before being stored. The server reconstructs an examination key only during its release flow after its configured authorization, time, custody, manifest, and canary checks pass.

## Roles

| Role | Main capabilities |
| --- | --- |
| `admin` | Create exams and users, assign staff, initialize security, authorize/execute release, view audit data. |
| `setter` | View assigned workspaces and submit question fragments. |
| `custodian` | View custody assignment and submit a key-share session contribution. |
| `print-operator` | Retrieve a released packet for an assigned examination and confirm printing. |

The server enforces role checks through `verifyToken` and `requireRole`. Client-side navigation controls are convenience only and must not be treated as a security boundary.

## Requirements

- Node.js `>=20 <25` (as declared in `package.json`)
- npm
- A Firebase project with **Authentication** and **Cloud Firestore** enabled
- A Firebase Admin service-account credential

## Installation

```bash
git clone https://github.com/<your-account>/secure-question-paper.git
cd secure-question-paper
npm ci
```

Use `npm install` instead of `npm ci` only when intentionally changing dependencies.

## Configuration

Create a `.env` file in the repository root. Do not commit it.

```env
PORT=5000
# A long, unique secret stored in a secret manager in production.
FRAGMENT_ENCRYPTION_KEY=replace-with-a-long-random-secret
# Optional; defaults to 10000 in the current implementation.
VDF_ITERATIONS=10000
```

Provide Firebase Admin credentials by using **one** of these methods:

1. `FIREBASE_SERVICE_ACCOUNT_JSON` — complete service-account JSON, suitable for a deployment secret.
2. `FIREBASE_SERVICE_ACCOUNT_BASE64` — base64-encoded service-account JSON.
3. Local development only: place `firebase-service-account.json` in the project root.

The credential file and `.env` are ignored by Git. Confirm this before pushing:

```bash
git ls-files firebase-service-account.json .env
```

The command must produce no output. If a credential was ever committed, revoke/rotate it in Google Cloud before publishing the repository.

## Running the application

```bash
# Production-style local start
npm start

# Development with automatic restart
npm run dev
```

Open [http://localhost:5000](http://localhost:5000). The health endpoint is available at [http://localhost:5000/api/health](http://localhost:5000/api/health).

## Validation

```bash
# Syntax check for server.js
npm run build

# Currently identical to the syntax check; not a functional test suite
npm test

# Dependency vulnerability audit
npm audit --omit=dev
```

At the time this README was updated, `npm run build`, `npm test`, and `npm audit --omit=dev` completed successfully. The repository has no automated integration or end-to-end test suite yet.

## Application workflow

1. An administrator creates an examination and assigns the necessary users.
2. Setters submit encrypted fragments.
3. The administrator initializes custody/security records.
4. Custodians submit threshold-share contributions in the release window.
5. The administrator authorizes and executes the release after the configured checks pass.
6. The assigned print operator retrieves the release packet and confirms printing.

## API overview

All endpoints except the health check, registration route, and current Firestore diagnostic route require a Firebase ID token:

```http
Authorization: Bearer <Firebase-ID-token>
```

| Area | Representative endpoints |
| --- | --- |
| Service | `GET /api/health`, `GET /api/me` |
| Authentication/users | `POST /api/register`, `POST /api/admin/users/create`, `GET /api/admin/users`, `POST /api/admin/users/assign-role` |
| Examinations | `POST /api/examinations`, `GET /api/examinations` |
| Fragments | `POST /api/fragments`, `GET /api/fragments` |
| Custody | `POST /api/custody/initialize`, `POST /api/custodian/submit-share`, `GET /api/custody/status/:examinationId` |
| Security/release | `POST /api/security/initialize`, `GET /api/security/status/:examinationId`, `POST /api/release/authorize`, `POST /api/release/execute` |
| Print workflow | `GET /api/print-operator/release-packet/:examinationId`, `POST /api/print-operator/confirm-print` |
| Audit | `GET /api/audit-logs` |

See [server.js](server.js) for the authoritative request validation and access-control rules.

## Project structure

```text
secure-question-paper/
├── backend/
│   ├── config/firebase-admin.js       # Firebase Admin initialization
│   ├── middleware/                    # Token and role middleware
│   └── security/                      # Shamir, VDF, MPC, canary, release helpers
├── public/
│   ├── css/                           # Application styles
│   ├── js/                            # Browser controllers and shell UI
│   └── *.html                         # Role-specific pages
├── server.js                          # Express application and REST routes
├── package.json                       # Scripts and dependencies
└── README.md
```

## Production readiness

Do these before exposing the project publicly or using it beyond a demo:

- **Do not persist plaintext release material.** The current `POST /api/release/execute` flow writes `assembledPaper` into Firestore as `releasePacket`, and the print portal downloads that packet. This contradicts any claim of memory-only release. Replace it with a dedicated, short-lived, authenticated handoff to a hardened print service; never store or browser-download plaintext.
- **Remove or protect `GET /api/test-firestore`.** It is currently public and performs a Firestore write.
- **Close self-service operational-account registration.** `POST /api/register` currently allows unauthenticated creation of `setter`, `custodian`, and `print-operator` accounts. Restrict provisioning to administrators or an invitation workflow.
- **Restrict CORS.** `app.use(cors())` accepts all origins. Allow only the production origin(s) and required methods/headers.
- **Fail closed when `FRAGMENT_ENCRYPTION_KEY` is missing.** The current development fallback must be removed for deployed environments.
- **Treat the VDF accurately.** Current release timing is enforced by a server clock check; the VDF proof does not independently prevent someone from computing ahead of time. Use a proven time-lock design and independently verifiable timing source if that property is required.
- **Scope data by assignment.** Review endpoints such as metrics and fragment listing to ensure every role sees only data needed for its assigned examinations.
- **Add operational hardening.** Use rate limiting, CSRF protections where relevant, secure headers, structured logging, monitoring, backups, Firestore security rules, secret rotation, and a threat-model review.
- **Add tests.** Unit-test cryptographic helpers and authorization rules; add integration tests for every role and negative release path.
- **Commission an independent security review.** Cryptographic and high-stakes exam systems require professional design and penetration testing before production use.

## Troubleshooting

| Symptom | Likely cause | Resolution |
| --- | --- | --- |
| Server stops at startup with missing credentials | Firebase Admin credential was not supplied | Configure one service-account method described above. |
| Login/token requests return `401` | Missing, expired, or invalid Firebase ID token | Sign in again and send a current `Authorization` header. |
| Requests return `403` | Account role is missing or not authorized | Check Firebase custom claims and the matching Firestore user document. |
| Release is rejected | One or more authorization, time, custody, MPC, fragment, or canary checks failed | Inspect the response's `failedChecks` and audit records. |
| VDF processing is slow | Iteration count is high for the host | Use a suitable development value only; benchmark and threat-model production parameters. |

## License

`package.json` declares the ISC license. Add a root `LICENSE` file before publishing an open-source release so the repository includes the full license text.
