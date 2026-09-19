# Secure Question Paper Management System

A zero-trust cryptographic management platform for competitive examination question papers, engineered so that a complete, readable question paper **never exists anywhere** before the exact scheduled examination time.

---

## 📢 Recent Updates & Security Hardening

The system has undergone a major security audit, bug fix pass, and architectural refinement to enforce strict Zero Trust principles and resolve critical operational blockers.

### 1. Fixed Custody Initialization Deadlock
Previously, creating an examination left the custody status uninitialized, which blocked setters from uploading fragments and admins from initializing security, causing a system-wide deadlock.
**Resolution**: The `POST /api/examinations` endpoint now automatically generates the AES master key, splits it into Shamir 3-of-5 shares, stores them securely in the `custody_shares` collection, and marks the status as `initialized` upon exam creation.

### 2. Strict Two-Way Role Confinement (Separation of Duties)
An architectural flaw allowed administrators to view the fragments and custodians pages, which violates the zero-knowledge principle.
**Resolution**: 
* Removed cross-portal navigation: `Fragments` and `Custody` are no longer accessible from the Admin sidebar. Admins must not view fragments or hold custody shares.
* Updated `public/js/auth.js` to forcefully redirect any actor attempting to access another actor's portal back to their designated workspace.
* Removed improper `window.location.replace` lockouts in `custodians.html` and `fragments.html` that previously trapped users.

### 3. Secured Registration & Authentication
**Resolution**:
* Secured the `POST /api/register` endpoint to completely reject `role: "admin"` assignments unless the request includes a valid Bearer token from an *existing* administrator. This fixes a critical privilege escalation vulnerability.
* Removed a hardcoded backdoor in the authentication middleware that automatically granted admin rights to `admin@example.com`.
* Added startup environment variable checks to warn if critical keys (like `FRAGMENT_ENCRYPTION_KEY`) are missing.

### 4. UI Stabilization & Dependency Patches
**Resolution**:
* Fixed a critical syntax error (missing `}`) in `public/js/login.js` that was breaking the authentication flow.
* Added null-safe DOM checks in `public/js/users.js` to prevent crashes during user creation.
* Resolved `npm audit` vulnerabilities by applying version overrides (e.g., `uuid` for `gaxios`).
* Normalized the Firebase credentials file to `firebase-service-account.json`.

---

## 🛡️ Core Security Architecture & Paradigm

Traditional examination management systems store question papers on centralized servers or administrator workstations, attempting to secure them with database rules or disk encryption. However, if a complete plaintext paper exists on any machine before exam time, a single insider or breach compromises the entire national or institutional examination.

### The Three Vulnerability Points Eliminated
1. **Setter's Local Draft & Full Paper Review:** Question setters submit isolated, encrypted question fragments only. No setter or administrator ever compiles or views the complete paper before exam time.
2. **Centralized Storage & Admin Plaintext Custody:** Question fragments are encrypted with AES-256-GCM. The underlying encryption keys are split using **Shamir's Secret Sharing (3-of-5 threshold)** across 5 independent custodian nodes. Plaintext is never stored in Firestore, backend memory, or disk.
3. **Pre-Exam Print Queue & Center Staff Exfiltration:** The paper is assembled exclusively in volatile RAM via a **Verifiable Delay Function (VDF)** sequential time-lock gate. The assembled paper is handed off to an authorized print operator workstation and wiped from memory immediately upon print confirmation.

```text
       [Question Setter]
              │
       (Encrypts Fragment: AES-256-GCM)
              │
              ▼
   ┌──────────────────────┐
   │ Encrypted Fragments  │  ◄─── No full paper exists anywhere in plaintext
   │ (Stored in DB)       │
   └──────────┬───────────┘
              │
   ┌──────────┴───────────┐
   │ Shamir Secret Shares │  ◄─── 3-of-5 Custodian threshold required
   │ (K1, K2, K3, K4, K5) │
   └──────────┬───────────┘
              │
   ┌──────────▼───────────┐
   │ Software MPC Build   │  ◄─── Additive Secret Sharing manifest
   └──────────┬───────────┘
              │
   ┌──────────▼───────────┐
   │   VDF Time-Lock Gate │  ◄─── Sequential SHA-256 delay proof
   └──────────┬───────────┘
              │ (Only at exact exam release time)
              ▼
   ┌──────────────────────┐
   │ Ephemeral Memory     │  ◄─── Decrypted in-memory on air-gapped agent;
   │ Plaintext Assembly   │       Wiped immediately upon print confirmation
   └──────────────────────┘
```

---

## 👥 Strict Separation of Duties (Two-Way Role Confinement)

Every system role is cryptographically and architecturally isolated. If any actor attempts to access an unauthorized portal, they are automatically quarantined and redirected back to their designated interface:

| Role | Landing Portal | Primary Responsibilities | Strict Security Boundaries |
| :--- | :--- | :--- | :--- |
| **Administrator** | `/overview.html` | Schedules examinations, assigns staff, monitors security telemetry, and authorizes final release. | **Cannot view question plaintext; cannot submit custodian shares.** |
| **Question Setter** | `/setter.html` | Encrypts and uploads isolated question fragments for assigned exams. | **Cannot see other setters' questions, custody shares, or admin controls.** |
| **Custodian (1–5)** | `/custodian-portal.html` | Holds one individual Shamir share (3-of-5 threshold) and submits it at release authorization. | **Cannot view question fragments; cannot see other custodians' shares.** |
| **Print Operator** | `/print-operator.html` | Accesses one-time ephemeral decrypted package at scheduled release time; confirms printing. | **Cannot access paper before release time; memory wiped immediately on confirmation.** |

---

## 🔑 Preserved Evaluation Credentials

The database has been cleanly initialized for evaluation with 4 distinct role accounts:

| Role | Name | Email | Password | Assigned Portal |
| :--- | :--- | :--- | :--- | :--- |
| **Administrator** | System Administrator | `admin@test.com` | `Admin@12345` | `/overview.html` |
| **Question Setter** | Srii | `setter@test.com` | `Setter@12345` | `/setter.html` |
| **Custodian** | Krithick | `custody@test.com` | `Custody@12345` | `/custodian-portal.html` |
| **Print Operator** | Reshmi | `print@test.com` | `Print@12345` | `/print-operator.html` |

> [!NOTE]
> All accounts have their cryptographic claims (`{ role: '<role>' }`) synced in Firebase Authentication and their profile records established in Cloud Firestore.

---

## 🚀 Key Security Features

* **Zero-Knowledge Fragment Submission:** Setters upload encrypted fragments tagged by section and question number.
* **Automated Shamir Custody (3-of-5 Threshold):** Exam master keys are split into 5 cryptographic shares upon exam creation. At least 3 custodians must submit their shares to authorize decryption.
* **Software MPC Encrypted Manifest Computation:** Additive secret sharing aggregates encrypted fragment hashes and custody fingerprints into an immutable release commitment.
* **Wesolowski-style Verifiable Delay Function (VDF):** An inherently sequential, non-parallelizable SHA-256 computation gate ensures decryption keys cannot be solved prematurely, even with vast distributed computing power.
* **Canary & Decoy Honeypots:** Dynamic decoy fragments detect unauthorized database probing. Triggering a canary immediately revokes credentials and flags security alerts.
* **Ephemeral In-Memory Reassembly:** Release agent simulation performs plaintext compilation exclusively in RAM at release time, preventing any plaintext from touching disk or swap space.
* **Immutable Audit Trails:** Every administrative action, custody submission, share validation, and release event is logged with SHA-256 event chaining.
* **Hardware-Accelerated UI & Spotlight:** Custom dark-gold visual theme featuring a smooth, GPU-accelerated cursor spotlight across all portals.
* **Sub-Millisecond Response Optimization:** In-memory verification caching (`tokenCache`) and optimistic session resolution eliminate network lag and provide instant page transitions.

---

## 📁 Clean Project Structure

```text
secure-question-paper/
├── backend/
│   ├── config/
│   │   └── firebase-admin.js       # Firebase Admin SDK initialization
│   ├── middleware/
│   │   ├── auth.js                 # Token verification with in-memory TTL caching
│   │   └── role.js                 # Strict role-based route authorization
│   └── security/
│       ├── canary.js               # Decoy / canary trap management
│       ├── mpc.js                  # Software MPC manifest aggregation
│       ├── release-agent.js        # Ephemeral reassembly & print handoff
│       ├── shamir.js               # 3-of-5 Shamir Secret Sharing implementation
│       └── vdf.js                  # Sequential SHA-256 time-lock delay verification
├── public/
│   ├── css/
│   │   ├── design.css              # Universal dark-gold theme & component styles
│   │   └── login.css               # Dedicated authentication page styling
│   ├── js/
│   │   ├── auth.js                 # Client-side session management & role confinement
│   │   ├── login.js                # Instant login & role router
│   │   ├── register.js             # User onboarding & role provisioning
│   │   ├── overview.js             # Administrator dashboard metrics & pipeline
│   │   ├── exams.js                # Examination creation & scheduling
│   │   ├── security.js             # MPC commitment verification & custody telemetry
│   │   ├── release.js              # Time-gated release console & countdowns
│   │   ├── audit.js                # Immutable audit log inspection
│   │   ├── users.js                # User directory & exam role assignments
│   │   ├── setter.js               # Question setter portal & fragment upload
│   │   ├── setter-shell.js         # Dedicated setter workspace shell
│   │   ├── custodian-portal.js     # Custodian portal & share submission
│   │   ├── custodian-shell.js      # Dedicated custodian workspace shell
│   │   ├── print-operator.js       # Print operator portal & confirmation
│   │   ├── print-shell.js          # Dedicated print operator terminal shell
│   │   ├── shell.js                # Administrator workspace shell & sidebar
│   │   └── spotlight.js            # Hardware-accelerated cursor lighting
│   ├── login.html                  # Universal sign-in portal
│   ├── register.html               # New user registration portal
│   ├── overview.html               # Admin control center
│   ├── exams.html                  # Examination management
│   ├── security.html               # Cryptographic controls & MPC
│   ├── release.html                # Controlled release execution
│   ├── audit.html                  # Audit logs & compliance
│   ├── users.html                  # User directory & assignment
│   ├── setter.html                 # Question setter portal
│   ├── custodian-portal.html       # Custodian share portal
│   └── print-operator.html         # Print operator workstation portal
├── server.js                       # Main Express application & secure API endpoints
├── package.json                    # Dependencies, overrides, and scripts
└── README.md                       # Complete documentation
```

---

## ⚙️ Installation & Setup

### Prerequisites
* **Node.js**: v20.0.0 or higher
* **npm**: v9.0.0 or higher
* **Firebase Project**: Cloud Firestore and Firebase Authentication enabled

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Krithick-Rajan/Secure-Question-Paper.git
cd Secure-Question-Paper
npm install
```

### 2. Environment Configuration
Create a `.env` file in the project root:
```env
PORT=5000
FRAGMENT_ENCRYPTION_KEY=8f4c2a91d7e63b508c1a9e42f6b73015d9c4e8a2176f0b3d5a9c8e1f6247b093
VDF_ITERATIONS=120000
```
* `PORT`: Server port (default: `5000`).
* `FRAGMENT_ENCRYPTION_KEY`: 256-bit hex master key for system key wrap.
* `VDF_ITERATIONS`: Sequential squaring iterations for the VDF delay proof.

### 3. Service Account Setup
Place your Firebase Admin service account credentials in the root directory:
```text
firebase-service-account.json
```
*(This file is included in `.gitignore` and must remain private).*

### 4. Run the Application
Start the server:
```bash
npm start
```
For auto-reloading development:
```bash
npm run dev
```

Open your browser and navigate to:
```text
http://localhost:5000
```

---

## 🔄 End-to-End Workflow

1. **User Onboarding (`/users.html` or `/register.html`)**:
   * Admin registers Setters, Custodians, and Print Operators.
   * Admin assigns specific roles to an upcoming examination.
2. **Exam Creation (`/exams.html`)**:
   * Admin creates an examination with code, title, and release time.
   * **Automated Custody**: System generates Shamir 3-of-5 custody shares and marks custody initialized.
3. **Question Fragment Upload (`/setter.html`)**:
   * Assigned Question Setter logs into their private portal.
   * Inputs question text and uploads. Fragments are encrypted with AES-256-GCM.
4. **Security Telemetry (`/security.html`)**:
   * MPC Additive Secret Sharing manifest is generated and verified over encrypted fragments.
   * Wesolowski VDF sequential time-lock commitment is verified.
5. **Custodian Share Submission (`/custodian-portal.html`)**:
   * Custodians review their assigned shares and submit authorization.
   * Once 3 of 5 shares are collected, the custody threshold is satisfied.
6. **Controlled Release (`/release.html`)**:
   * Once the scheduled release time arrives and all security checks pass, Admin executes controlled release.
   * The paper is reassembled exclusively in volatile memory.
7. **Print Confirmation (`/print-operator.html`)**:
   * Print operator receives decrypted release packet at their terminal.
   * Clicks **"Confirm Print"**, which permanently wipes plaintext from volatile memory.

---

## 📡 REST API Reference

| Endpoint | Method | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `/api/health` | `GET` | No | System health and security engine status |
| `/api/me` | `GET` | Yes | Validates caller session, returns profile & role |
| `/api/register` | `POST` | Public / Admin | Register new account (admin role requires admin token) |
| `/api/overview/metrics` | `GET` | Admin | Fetch system overview counts and telemetry |
| `/api/examinations` | `GET`, `POST` | Admin | List exams or create a new exam with auto-custody |
| `/api/fragments` | `GET`, `POST` | Setter / Admin | Retrieve or upload encrypted question fragments |
| `/api/security/initialize` | `POST` | Admin | Re-initialize Shamir custody & Software MPC manifest |
| `/api/security/status/:examId` | `GET` | Admin | Fetch custody status, MPC commitment, & canary checks |
| `/api/custodian/my-assignment` | `GET` | Custodian | Retrieve active custodian assignment and share number |
| `/api/custodian/submit-share` | `POST` | Custodian | Submit a custodian key share for threshold release |
| `/api/release/status/:examId` | `GET` | Admin | Get VDF time gate, threshold status, & release readiness |
| `/api/release/execute` | `POST` | Admin | Authorize and execute controlled time-gated release |
| `/api/print-operator/my-assignment` | `GET` | Print Operator | Retrieve released paper for printing |
| `/api/print-operator/confirm-print` | `POST` | Print Operator | Confirm print execution & trigger memory wipe |
| `/api/audit-logs` | `GET` | Admin | Retrieve immutable SHA-256 chained audit logs |
| `/api/admin/users` | `GET` | Admin | Retrieve registered user accounts |
| `/api/admin/assign-setter` | `POST` | Admin | Assign a setter to an examination |
| `/api/admin/assign-custodian` | `POST` | Admin | Assign a custodian to an examination |
| `/api/admin/assign-print-operator` | `POST` | Admin | Assign a print operator to an examination |

---

## 📄 License

This project is licensed under the [ISC License](LICENSE).