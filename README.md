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
