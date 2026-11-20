# ShadowTrace SOC Console — Major Testing & Feature Report

**Document Location:** `Documentation/Member1/Major_TestingReport1.md`  
**Team:** The Three Bugs (Bit, Glitch, Scout/Cipher)  
**Application:** ShadowTrace — Role-Based Cybersecurity & Threat Intelligence SOC Console  

---

## 1. Executive Summary

ShadowTrace is a full-stack **Security Operations Center (SOC)** web application built with **Flask**, **SQLite**, and a **Cyber-Neumorphic** frontend. It enables security teams to ingest CSV log files, run automated threat-detection rules, manage security investigations, enforce Role-Based Access Control (RBAC), authenticate with Multi-Factor Authentication (Google Authenticator TOTP), and export integrity-verified PDF/CSV reports.

---

## 2. Core SOC Modules & Capabilities

### 2.1 Landing Intro & Authentication Gate
- **Landing Intro (`#landingIntroOverlay`)**: Plays the Three Bugs intro animation with **Enter Console** and **Skip Intro** controls.
- **Zero-Persistence Session Enforcement**: On every page load or refresh, `checkSession()` clears any prior session so operators must authenticate fresh (`Landing → Login → Dashboard`), matching strict SOC security standards.
- **Neumorphic Cyber Login Gate (`#neuLoginOverlay`)**:
  - Features the 3 interactive mascot pods (**Bit**, **Glitch**, **Scout**) that react to user input.
  - **Brute-Force Protection**: Throttles repeated failed login attempts with a live lockout countdown banner.
  - **Animated Transitions**: Smooth warp-out animation on login and inward-flying bug transition on logout (`performLogout()`).

### 2.2 Role-Based Access Control (RBAC)
Enforced on both the **Flask backend** (`@role_required`) and **Frontend UI** (`applyRbacUi`):
- **Administrator / Admin**: Full system control—user provisioning, role assignment, user editing/deletion, log ingestion, investigation management, threat triage, report generation, and audit trail access.
- **Analyst**: Operational SOC analyst—can upload/analyze CSV logs, create/manage investigations, triage findings & add notes, export PDF/CSV reports, and view audit trails. Cannot manage user accounts.
- **Viewer**: Read-only auditor—can view dashboards, threat detections, investigations, audit trails, and export reports. Mutating controls (upload, create investigation, triage) are disabled.

### 2.3 Multi-Factor Authentication (Google Authenticator TOTP)
- **Zero-Cost RFC 6238 TOTP**: Implemented in pure Python (`generate_totp_secret`, `get_totp_token`, `verify_totp`) in `app.py` with no external paid APIs.
- **Opt-In MFA Toggle (`/api/auth/mfa/toggle`)**: Users can enable or disable MFA in **Settings → Account Security**.
  - When **disabled**: Normal username + password login.
  - When **enabled**: Login prompts for a 6-digit Google Authenticator code (`/api/auth/login/mfa`).
- **Strict Current-Window Verification**: `verify_totp()` only accepts the active 30-second window (`offset=0`), rejecting old or expired codes with an inline styled error banner.

### 2.4 Password Policy, History & Recovery
- **Password History (`password_history` table)**:
  - Stores previous password hashes with timestamps.
  - **Last-5 Reuse Prevention**: During password reset, the system checks the current password and the last 4 historical passwords (5 total). Reusing any of them is blocked with: *"This password was already used and is in your last 5 passwords."*
- **Old Password Detection (30 Days)**:
  - On failed login, `api_login()` checks `password_history` for the last 30 days. If an old password is entered, it alerts the user: *"Incorrect password — this is an old password that was changed X day(s) ago."*
- **Forgot Password Flow (`/api/auth/forgot-password/*`)**:
  - **Step 1**: Search username (`/api/auth/forgot-password/lookup`).
  - **Step 2**: Verify 6-digit Google Authenticator code (`/api/auth/forgot-password/verify-code`) with animated `Verifying... → Verified ✓` feedback.
  - **Step 3**: Enter & confirm new password (`/api/auth/forgot-password/reset`), then return to the Login page.

### 2.5 Dashboard & Log Analyzer
- **Security Overview Dashboard (`#view-dashboard`)**: Real-time KPI cards (Total Log Events, Suspicious Events, Critical Alerts, etc.), interactive Chart.js visualizations, and Recent Threats table.
- **Log Analyzer (`#view-analyzer`)**:
  - Drag-and-drop or file-picker CSV upload, sample dataset loader, and CSV template download.
  - **File Upload History Grid**: Lists previously uploaded CSVs to reload past analyses.
  - **Severity Filtering**: Supports `All Severities`, `Critical`, `High`, `Medium`, `Low`, and `Normal` (with distinct visual badges separating `Normal` from `Low`).

### 2.6 Threat Detection Engine
- **3 Detection Rules** mapped to **Attack Types** in `#threatsTable`:
  - **RULE-01** (*Repeated Failed Logins*) → **Brute Force**
  - **RULE-02** (*Successful Login Following Repeated Failures*) → **Account Takeover**
  - **RULE-03** (*Unusual Login Activity*) → **Anomalous Access / DDoS**
- Clicking any finding row opens the **Finding Details Modal** with supporting log events and investigation notes.

### 2.7 Investigations, Reports & Audit Trail
- **Investigations (`#view-investigations`)**: Create, track, and manage security cases with evidence file uploads and SHA-256 integrity hashing.
- **Reports & Export (`#view-reports`)**: Preview reports, verify SHA-256 evidence integrity, download **PDF Reports** (ReportLab), and export **CSV** files (with formula-injection neutralization).
- **Audit Trail (`#view-audit`)**: Chronological, filterable log of all application and security events.

### 2.8 Settings (Tabbed Architecture)
Organized into 4 clean sub-tabs:
1. **Account Security**: Change Username (`/api/auth/change-username`), Change Password, Forgot Password, Enable/Disable MFA, and Connect Google Authenticator.
2. **User & Role Management** *(Admin Only)*: Create users (with email, username, role, password), edit existing users (`PATCH /api/users/<id>`), and revoke/delete users with a styled Cyber Confirmation Modal.
3. **RBAC Permissions**: Visual permissions matrix comparing Admin, Analyst, and Viewer.
4. **System & Operations**: Replay Intro animation and Log Out.

---

## 3. UI/UX & Interactive Enhancements
- **Responsive Screen-Friendly Layout**: Fluid `clamp()` spacing, dynamic viewport-based table heights (`clamp(300px, calc(100vh - 270px), 720px)`), and `display: block` scrolling on `.main` so grids never cut off at the bottom.
- **100% Opaque Sticky Table Headers**: Uses `border-collapse: separate; border-spacing: 0` and solid `#0b1122` backgrounds on `thead`, `tr`, and `th` so scrolled rows never bleed through headers.
- **Cyber Cat Paw Cursor**: Custom 20×20px glowing SVG cat paw centered on the pointer (`targetX - 10`, `targetY - 10`), turning golden on hover, tapping on click, and persisting over scrollbars and `<select>` dropdowns.
- **The Three Bugs HUD Strip (`.bugs-hud-bar`)**: Includes Speed toggle (`Fast` / `Warp` / `Chill`), `Squad Up`, `Play/Pause`, **Hide/Show** (bugs settle steadily along the bottom edge), and **Minimize** (collapses to the right edge with a `<` / `>` arrow).
