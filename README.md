# PhishNet — Phishing Simulation & Security Awareness Training Platform

PhishNet is a web-based platform that allows organizations to run controlled phishing simulations against their employees, track engagement metrics, and deliver security awareness training — all from a single admin dashboard.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Backend Setup](#2-backend-setup)
  - [3. Frontend Setup](#3-frontend-setup)
  - [4. GoPhish Setup](#4-gophish-setup)
  - [5. Environment Configuration](#5-environment-configuration)
- [Running the Application](#running-the-application)
- [Default Credentials](#default-credentials)
- [User Guide](#user-guide)
  - [Admin Dashboard](#admin-dashboard)
  - [Campaign Management](#campaign-management)
  - [Employee Management](#employee-management)
  - [Phishing Templates](#phishing-templates)
  - [Landing Pages](#landing-pages)
  - [Security Awareness Training](#security-awareness-training)
  - [Settings & SMTP](#settings--smtp)
- [Risk Scoring](#risk-scoring)
- [CSV Import Format](#csv-import-format)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Phishing Campaign Management** — Create, launch, and monitor phishing simulations with real-time tracking
- **Employee Management** — Add employees individually or via CSV bulk upload; track per-employee risk
- **Email & Landing Page Templates** — 6+ pre-built phishing templates (IT resets, HR notices, Microsoft 365, CEO fraud, etc.) with associated fake landing pages
- **Event Tracking** — Pixel-based email open tracking, click tracking, credential submission capture, and phishing report logging
- **Risk Scoring** — Automatic per-employee risk scores recalculated on every event
- **Security Awareness Training** — 8 built-in training modules with interactive quizzes, badges, and completion tracking
- **SMTP Integration** — Gmail or custom SMTP support; GoPhish-powered campaign delivery
- **Admin User Management** — Create and manage admin accounts with role-based access control
- **CSV Export** — Export campaign results and employee data

---

## Tech Stack

| Layer     | Technology                              |
|-----------|-----------------------------------------|
| Backend   | Python 3 · Flask · SQLite3              |
| Frontend  | HTML5 · Vanilla JavaScript · Custom CSS |
| Email     | GoPhish · Gmail SMTP / Custom SMTP      |
| Auth      | Session tokens (SHA-256)                |

---

## Prerequisites

Install the following before proceeding:

- **Python 3.10+** — [python.org/downloads](https://www.python.org/downloads/)
- **pip** — Bundled with Python 3.10+
- **GoPhish** — [github.com/gophish/gophish/releases](https://github.com/gophish/gophish/releases) (download the binary for your OS)
- A modern web browser (Chrome, Firefox, Edge)

---

## Project Structure

```
Final-Year-Project/
├── backend/
│   ├── app.py              # Flask API server (main entry point)
│   ├── seed_modules.py     # Seeds training module data into the database
│   ├── env.example         # Environment variable template
│   ├── .env                # Your local environment config (do not commit)
│   └── templates/          # HTML files for phishing emails and landing pages
│       ├── templates.json
│       └── landing_pages.json
└── frontend/
    ├── app.py              # Simple HTTP server for static files
    ├── config.js           # API base URL and shared fetch helpers
    ├── login.html
    ├── admin-dashboard.html
    ├── campaign-management.html
    ├── employees.html
    ├── email-templates.html
    ├── landing-pages.html
    ├── awareness-training.html
    ├── phish-profiles.html
    ├── training-admin.html
    └── settings.html
```

---

## Setup & Installation

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd Final-Year-Project
```

### 2. Backend Setup

```bash
cd backend

# Create and activate a virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install flask flask-cors requests python-dotenv
```

#### Initialize the Database

The database is created automatically when you first run the backend. To also seed the 8 built-in training modules:

```bash
python seed_modules.py
```

### 3. Frontend Setup

The frontend is plain HTML/JS and uses Python's built-in HTTP server. No build step is required.

### 4. GoPhish Setup

1. Download the GoPhish binary for your OS from the [releases page](https://github.com/gophish/gophish/releases).
2. Extract the archive and place the `gophish` executable somewhere accessible (e.g., `C:\gophish\`).
3. Run GoPhish:

   ```bash
   # Windows
   .\gophish.exe

   # macOS/Linux
   ./gophish
   ```

4. On first run, GoPhish will print a temporary admin password to the console. Log in at `https://127.0.0.1:3333` to get your **API key** from the GoPhish admin panel (Account Settings → API Key).

> GoPhish uses a self-signed certificate, so your browser will show a security warning — click "Advanced" and proceed.

### 5. Environment Configuration

In the `backend/` directory, copy the example file and fill in your values:

```bash
cp env.example .env
```

Open `.env` and configure:

```env
# Flask
SECRET_KEY=your-secret-key-change-this
FLASK_PORT=5000

# Database
DB_PATH=PhishNet.db

# GoPhish
GOPHISH_URL=https://127.0.0.1:3333
GOPHISH_API_KEY=<paste your GoPhish API key here>

# URLs
FRONTEND_URL=http://127.0.0.1:8088
BACKEND_URL=http://127.0.0.1:5000

# Default admin account (created on first run)
ADMIN_EMAIL=admin@PhishNet.com
ADMIN_PASSWORD=admin123
ADMIN_NAME=Super Admin

# Gmail SMTP (optional — for sending test emails)
GMAIL_ADDRESS=your-email@gmail.com
GMAIL_APP_PASSWORD=your-app-password
```

**Getting a Gmail App Password:**
1. Enable 2-Step Verification on your Google account.
2. Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
3. Create a new app password (select "Mail" and your device).
4. Paste the 16-character password into `GMAIL_APP_PASSWORD`.

---

## Running the Application

You need **three** terminals open simultaneously.

**Terminal 1 — GoPhish**

```bash
# Navigate to your GoPhish folder
.\gophish.exe          # Windows
./gophish              # macOS/Linux
```

**Terminal 2 — Backend API**

```bash
cd backend
# Activate venv if you created one
venv\Scripts\activate  # Windows

python app.py
# API runs at http://127.0.0.1:5000
```

**Terminal 3 — Frontend**

```bash
cd frontend
python app.py
# Frontend runs at http://127.0.0.1:8088
```

Then open your browser and navigate to:

```
http://127.0.0.1:8088/login.html
```

---

## Default Credentials

| Role  | Email                   | Password  |
|-------|-------------------------|-----------|
| Admin | admin@PhishNet.com    | admin123  |

> Change the admin password after first login via **Settings → User Management**.

---

## User Guide

### Admin Dashboard

The dashboard gives you a real-time overview of all phishing activity:

| Metric        | Description                                      |
|---------------|--------------------------------------------------|
| Emails Sent   | Total number of phishing emails dispatched       |
| Open Rate     | Percentage of employees who opened the email     |
| Click Rate    | Percentage who clicked a link                    |
| Report Rate   | Percentage who reported the email as suspicious  |
| Campaigns     | Total campaigns created                          |
| Employees     | Total employees in the system                    |
| High Risk     | Employees with a risk score ≥ 70                 |

---

### Campaign Management

**Creating a Campaign**

1. Go to **Campaigns** in the sidebar.
2. Click **New Campaign**.
3. Fill in:
   - **Name** — descriptive label for the campaign
   - **Email Template** — choose a pre-built or custom phishing template
   - **Target Employees** — select employees from the list or upload a CSV
   - **Launch Date** (optional)
4. Click **Create**. The campaign starts in **Draft** status.

**Launching a Campaign**

- Set the campaign status to **Active** using the status dropdown. This triggers GoPhish to send the phishing emails.

**Viewing Results**

- Click on a campaign row to see a per-employee breakdown: open, click, submit, and report events.
- Use **Export CSV** to download the results.

---

### Employee Management

**Adding Employees Individually**

1. Go to **Employees** → **Add Employee**.
2. Enter name, email, and department.
3. Click **Save**.

**Bulk Upload via CSV**

1. Click **Upload CSV**.
2. Your CSV must include these columns (see [CSV Import Format](#csv-import-format)).
3. Duplicate emails are skipped automatically.

**Exporting Employees**

- Click **Export CSV** to download the full employee list with risk scores.

**Risk Levels**

| Level  | Score Range |
|--------|-------------|
| Low    | 0 – 39      |
| Medium | 40 – 69     |
| High   | 70 – 100    |

---

### Phishing Templates

Navigate to **Phish Profiles** or **Email Templates** to manage templates.

**Pre-built Templates**

| Template                    | Type        | Difficulty  |
|-----------------------------|-------------|-------------|
| IT Password Reset           | Credential  | Easy        |
| HR Policy Update            | Link        | Easy        |
| Microsoft 365 Verification  | Credential  | Medium      |
| CEO Wire Transfer Request   | BEC / Link  | Hard        |
| Package Delivery Notice     | Link        | Easy        |
| LinkedIn Connection Request | Link        | Medium      |

**Creating a Custom Template**

1. Go to **Email Templates** → **New Template**.
2. Write the HTML body of the phishing email.
3. Set the sender name/email, subject, and link a landing page if needed.
4. Click **Save**.

---

### Landing Pages

Landing pages are fake login or form pages that employees are redirected to after clicking a link in a phishing email.

1. Go to **Landing Pages** → **New Landing Page**.
2. Paste or write the HTML for the fake page.
3. Enable **Capture Credentials** if you want submitted username/password pairs to be logged as tracking events.
4. Set a **Redirect URL** — where the user is sent after submitting the form (e.g., your real company login page).
5. Link the landing page to an email template.

---

### Security Awareness Training

**For Admins — Managing Modules**

1. Go to **Training Admin** to create, edit, or delete training modules.
2. Each module has:
   - HTML content (lessons, tips, real-world examples)
   - A 5-question multiple-choice quiz
   - A pass threshold of **60%** (3 out of 5 correct)

**For Employees — Taking Training**

1. Go to **Awareness Training** from the navigation.
2. Click on a module to read the content.
3. Complete the quiz at the end.
4. Pass to earn the module badge and reduce your risk score by **15 points**.

**Built-in Modules**

| # | Module                                       | Level        |
|---|----------------------------------------------|--------------|
| 1 | What is Phishing?                            | Beginner     |
| 2 | Spotting Suspicious Links & Domains          | Beginner     |
| 3 | Urgency & Social Engineering                 | Beginner     |
| 4 | Email Headers & Sender Analysis              | Intermediate |
| 5 | Business Email Compromise (BEC)              | Intermediate |
| 6 | Credential Phishing & Fake Login Pages       | Intermediate |
| 7 | Safe Email & Attachment Practices            | Intermediate |
| 8 | What To Do When You Are Phished              | Advanced     |

---

### Settings & SMTP

**SMTP Profiles**

1. Go to **Settings** → **SMTP Profiles**.
2. Click **Add SMTP Profile**.
3. Enter host, port, username, password, and a sender display name.
4. Click **Test** to verify the connection via GoPhish.
5. Click **Activate** to make it the active sending profile.

**Syncing Gmail from `.env`**

If you configured `GMAIL_ADDRESS` and `GMAIL_APP_PASSWORD` in `.env`, click **Sync from ENV** to import those credentials as an SMTP profile automatically.

**Testing GoPhish Connectivity**

In Settings, click **Test GoPhish Connection**. A green status means the backend can reach the GoPhish API at the configured URL and API key.

---

## Risk Scoring

Risk scores are calculated per employee and updated automatically after every tracking event.

| Event              | Score Change |
|--------------------|--------------|
| Email opened       | +5           |
| Link clicked       | +25          |
| Credentials submitted | +35       |
| Email reported     | −10          |
| Training module passed | −15 per module |

Scores are clamped between **0** and **100**.

---

## CSV Import Format

When bulk-uploading employees, your CSV file must have the following headers (case-insensitive):

```
name,email,department
John Smith,john.smith@company.com,Engineering
Jane Doe,jane.doe@company.com,Finance
```

- `name` — Full name of the employee
- `email` — Work email address (used as unique identifier; duplicates are skipped)
- `department` — Department or team name

---

## Troubleshooting

**Backend fails to start**
- Ensure your virtual environment is activated and all dependencies are installed.
- Check that `backend/.env` exists and `GOPHISH_URL` / `GOPHISH_API_KEY` are set.

**GoPhish connection error in Settings**
- Make sure GoPhish is running (`.\gophish.exe`).
- Verify `GOPHISH_URL` and `GOPHISH_API_KEY` in `.env` match your GoPhish admin panel.
- GoPhish uses `https` with a self-signed cert — ensure your system trusts it or the backend is configured to skip SSL verification.

**Emails not sending**
- Confirm the SMTP profile is **activated** in Settings.
- For Gmail, make sure you are using an **App Password**, not your regular account password.
- Check that GoPhish is running and the campaign is in **Active** status.

**Frontend shows "Unauthorized" or redirects to login**
- Your session may have expired — log in again.
- Make sure the backend is running at `http://127.0.0.1:5000`.
- Check `frontend/config.js` to confirm `API_URL` matches your backend address.

**Database not found / missing tables**
- Run `python seed_modules.py` from the `backend/` directory to initialize the database and seed all training content.

---

## Academic Context

This project was developed as a Final Year Project (FYP) by **Savakroth Leav**. The accompanying thesis report is located at:

```
academics/Savakroth_Leav_PhishNet_THESIS_Report.pdf
```

> **Ethical Use Notice:** PhishNet is built for authorized, internal security awareness programs only. Do not use this platform to target individuals or organizations without explicit written consent. Unauthorized phishing is illegal.
