# Secure Question Paper Management System

Secure Question Paper Management System is a Node.js and Firebase based web application for managing competitive examination question papers. It provides role-based access for administrators, setters, custodians, security staff, and print operators, with workflows for exam setup, paper fragment submission, custody share handling, release authorization, audit logging, and print confirmation.

## Features

- Firebase Authentication and Firestore backed user management
- Role-based access control for admin, setter, custodian, security, and print-operator workflows
- Examination creation and assignment management
- Question paper fragment submission and tracking
- Custody initialization with secret sharing support
- Security release workflow using Shamir sharing, MPC-style release manifests, VDF checks, and canary fragments
- Audit log dashboard for administrative review
- Print operator handoff and print confirmation flow
- Static frontend served directly by the Express backend

## Tech Stack

- Node.js
- Express
- Firebase Admin SDK
- Firebase Authentication
- Cloud Firestore
- HTML, CSS, and vanilla JavaScript

## Project Structure

```text
secure-question-paper/
├── backend/
│   ├── config/
│   │   └── firebase-admin.js
│   ├── middleware/
│   │   ├── auth.js
│   │   └── role.js
│   └── security/
│       ├── canary.js
│       ├── mpc.js
│       ├── release-agent.js
│       ├── shamir.js
│       └── vdf.js
├── frontend/
│   ├── css/
│   ├── js/
│   └── *.html
├── server.js
├── package.json
└── README.md
```

## Modules and Purpose

- `server.js` - main Express server, static frontend hosting, and API route definitions
- `backend/config/firebase-admin.js` - Firebase Admin SDK setup for Authentication and Firestore
- `backend/middleware/auth.js` - verifies Firebase ID tokens from protected API requests
- `backend/middleware/role.js` - restricts API access based on user roles
- `backend/security/shamir.js` - secret sharing logic for splitting and reconstructing protected values
- `backend/security/mpc.js` - encrypted release manifest and MPC-style release computation helpers
- `backend/security/vdf.js` - verifiable delay/time-lock release checks
- `backend/security/canary.js` - canary/decoy fragment creation and validation
- `backend/security/release-agent.js` - release package, authorization, execution, and print handoff helpers
- `frontend/*.html` - role-based user interface pages
- `frontend/js/*.js` - client-side logic for authentication, dashboards, forms, and API calls
- `frontend/css/*.css` - application styling
- `package.json` and `package-lock.json` - Node.js dependency and script definitions

## Prerequisites

- Node.js 18 or later
- npm
- Firebase project with Authentication and Firestore enabled
- Firebase service account key for the Admin SDK

## Setup

1. Install dependencies:

```bash
npm install
```

2. Create a `.env` file in the project root:

```env
PORT=5000
VDF_ITERATIONS=120000
```

`PORT` is optional and defaults to `5000`. `VDF_ITERATIONS` is also optional and is used by the release security workflow.

3. Add your Firebase Admin SDK service account file to the project root:

```text
firebase-service-account.json
```

Do not commit `.env` or Firebase service account files to GitHub. They are ignored by `.gitignore`.

4. Start the server:

```bash
npm start
```

For development with automatic restarts:

```bash
npm run dev
```

5. Open the application:

```text
http://localhost:5000
```

## Main Pages

- `/login.html` - user login
- `/overview.html` - admin overview
- `/users.html` - user and role management
- `/exams.html` - examination management
- `/fragments.html` - question paper fragment management
- `/custodians.html` - custody workflow
- `/security.html` - security initialization and status
- `/release.html` - release authorization and execution
- `/audit.html` - audit logs
- `/setter.html` - setter portal
- `/custodian-portal.html` - custodian portal
- `/print-operator.html` - print operator portal

## API Overview

The backend exposes APIs for:

- health checks
- examination management
- custody initialization, share submission, and status checks
- fragment submission and listing
- security initialization and release status
- release authorization and execution
- audit log retrieval
- admin user creation, role assignment, and assignment management
- setter, custodian, and print-operator portals

Most API routes require a Firebase ID token in the `Authorization` header:

```text
Authorization: Bearer <firebase-id-token>
```

## Sample Input and Output

### Sample 1: Health Check

Request:

```http
GET /api/health
```

Sample output:

```json
{
  "success": true,
  "service": "Secure Question Paper Backend",
  "status": "operational",
  "security": {
    "aes": "AES-256-GCM",
    "custody": "Shamir 3-of-5",
    "mpc": "Software MPC encrypted manifest",
    "vdf": "Sequential SHA-256 VDF prototype",
    "canary": "Enabled",
    "releaseAgent": "Enabled"
  }
}
```

### Sample 2: Create Examination

Request:

```http
POST /api/examinations
Authorization: Bearer <firebase-id-token>
Content-Type: application/json
```

Sample input:

```json
{
  "code": "CS-2026-001",
  "name": "Model Competitive Exam",
  "subject": "Computer Science",
  "examDate": "2026-10-15",
  "startTime": "10:00",
  "releaseTime": "2026-10-15T09:00:00.000Z"
}
```

Sample output:

```json
{
  "success": true,
  "message": "Examination created successfully.",
  "examination": {
    "id": "generated-firestore-document-id",
    "code": "CS-2026-001",
    "title": "Model Competitive Exam",
    "subject": "Computer Science",
    "examDate": "2026-10-15",
    "startTime": "10:00",
    "custodyStatus": "uninitialized"
  }
}
```

### Sample 3: Submit Question Paper Fragment

Request:

```http
POST /api/fragments
Authorization: Bearer <firebase-id-token>
Content-Type: application/json
```

Sample input:

```json
{
  "examinationId": "generated-firestore-document-id",
  "fragmentNumber": 1,
  "fragmentLabel": "Section A",
  "questionText": "1. Define operating system. 2. Explain process scheduling."
}
```

Sample output:

```json
{
  "success": true,
  "message": "Fragment encrypted and protected successfully.",
  "fragment": {
    "id": "generated-fragment-id",
    "examinationId": "generated-firestore-document-id",
    "fragmentNumber": 1,
    "fragmentLabel": "Section A",
    "encrypted": true,
    "status": "encrypted",
    "encryptionAlgorithm": "AES-256-GCM"
  }
}
```

## Database

This project uses Firebase Cloud Firestore as its database. No local database file is required in the repository. Runtime credentials are provided through the private `firebase-service-account.json` file, which must not be committed to GitHub.

## GitHub Push Guide

If this is a new repository:

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git push -u origin main
```

If the remote repository already exists in this folder:

```bash
git add .
git commit -m "Update project documentation"
git push
```

Before pushing, confirm that secret files are not staged:

```bash
git status --short
```

## Security Notes

- Keep `.env` private.
- Keep Firebase service account JSON files private.
- Rotate any Firebase service account key if it was ever committed or shared publicly.
- Use Firebase security rules appropriate for your production deployment.
- Review role assignments carefully before production use.

## License

This project is currently licensed under the ISC license from `package.json`.

## Deploy to Vercel

This repository deploys as a Node.js serverless application. Vercel sends all
requests to `api/index.js`, which exports the same Express app used for local
development. The `frontend/` directory is included in the serverless bundle.

1. Import this GitHub repository into Vercel.
2. In **Project Settings → Environment Variables**, add the following values
   to each environment that should run the app:

   ```text
   FIREBASE_SERVICE_ACCOUNT_JSON=<complete Firebase service-account JSON on one line>
   VDF_ITERATIONS=120000
   ```

   Alternatively, set `FIREBASE_SERVICE_ACCOUNT_BASE64` to a base64-encoded
   service-account JSON value.
3. Use `npm run build` as the Build Command when Vercel prompts for one.
4. Deploy and verify `https://<your-domain>/api/health`.

The service-account file is intentionally ignored by Git and is not uploaded to
Vercel. A deployment without one of the Firebase credential environment
variables will fail at runtime.