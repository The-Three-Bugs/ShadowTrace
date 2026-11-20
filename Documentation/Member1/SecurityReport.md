# SHADOWTRACE — SECURITY REPORT (SECURITY-1)
## Identity, Authentication, Authorization, Secrets Management & Integrity Verification

**Security Owner:** Member 1  
**Target File:** `Documentation/Member1/SecurityReport.md`  
**Related Specification:** `Documentation/Member1/SECURITY1.md`  

---

## 1. Executive Summary

Member 1 is responsible for establishing the identity, authentication, authorization, session security, secret management, and integrity verification foundation for **ShadowTrace**. 

The implementation strictly adheres to the requirements defined in `SECURITY1.md`, ensuring that:
- Unauthenticated access to protected application routes and APIs is blocked at the backend level.
- Passwords are securely hashed using industry-standard Werkzeug hashing (`generate_password_hash` / `check_password_hash`).
- Role-based access control (RBAC) enforces granular permissions across Administrator, Analyst, and Viewer roles.
- Investigation-level access control prevents Insecure Direct Object Reference (IDOR) vulnerabilities.
- Session management incorporates secure cookie attributes (`HttpOnly`, `SameSite=Lax`), secret key validation, and login throttling.
- Evidence upload pipeline calculates and records cryptographic SHA-256 integrity hashes, supporting tamper detection and file missing verification.
- Comprehensive security audit logging and standardized security headers are enforced across all responses.

---

## 2. Summary of Accomplishments (According to SECURITY1.md)

| Requirement / Module | Status | Implementation Details |
|---|---|---|
| **2.1 Login System & Throttling** | Implemented | Server-side credential validation, generic failure messages, IP/username-based login attempt throttling (5 attempts $\rightarrow$ 60s lockout). |
| **2.2 Password Storage** | Implemented | Secure password hashing using Werkzeug (PBKDF2/scrypt/bcrypt salt-backed implementation). Plaintext passwords never stored or returned. |
| **2.3 Password Policy & Changes** | Implemented | Minimum length requirements (8+ chars), secure password change endpoint with current password verification and session invalidation. |
| **3.1 & 3.3 Backend Authorization & Admin Routes** | Implemented | `@login_required` and `@role_required(['Administrator', ...])` decorators protecting all sensitive API endpoints and admin actions. |
| **3.2 Role Model** | Implemented | Defined roles: `Administrator`, `Analyst`, `Viewer` with hierarchical permission enforcement. |
| **4. Investigation-Level Access Control (IDOR)** | Implemented | Server-side validation linking every request (evidence, findings, events) to authenticated user permissions and investigation ownership. |
| **5. Session Security** | Implemented | Cryptographically secure Flask `secret_key` with strict environment variable validation, session regeneration, and secure cookie configuration (`HttpOnly=True`, `SameSite=Lax`). |
| **6. API Key & Secret Protection** | Implemented | `.env` ignored via `.gitignore`, `.env.example` templates provided, startup validation preventing default production secrets. |
| **7. Environment Variable Validation** | Implemented | Strict startup check for `FLASK_SECRET_KEY` in production (`FLASK_ENV=production`), failing safely without fallback. |
| **8. Security Audit Events** | Implemented | `security_audit_logs` database table tracking login attempts, logouts, 404/400 errors, rate limits, and administrative actions with client IP and severity. |
| **9. Required Security Tests** | Implemented | Complete unit & integration test suite in `tests/test_shadowtrace.py` covering auth, RBAC, IDOR, hashing, throttling, and integrity verification. |

---

## 3. How Everything Works (Architecture & Mechanics)

### A. Authentication & Password Security
- **Credential Validation:** When a user submits credentials to `/api/auth/login`, the Flask backend queries the database for the user record. It verifies the password using `check_password_hash(user['password_hash'], password)`.
- **Throttling:** To mitigate brute-force attacks, `check_throttle` tracks failed login attempts. After 5 consecutive failures, the account/IP is locked out for 60 seconds (`429 Too Many Requests`).
- **Session Lifecycle:** Upon successful login, user attributes (`user_id`, `username`, `role`) are stored in the Flask server-side `session`. Logging out clears the session completely.

### B. Authorization & Role-Based Access Control (RBAC)
- **Decorators:** 
  - `@login_required`: Verifies `session.get('user_id')`, returning `401 Unauthorized` if missing.
  - `@role_required(allowed_roles)`: Verifies that `session.get('role')` is present in the permitted list, returning `403 Forbidden` otherwise.
- **Administrative Protection:** Administrative routes (such as user management, role changes, and audit log inspection) require explicit administrator role authorization.

### C. Investigation-Level Access Control (IDOR Prevention)
- **Server-Side Checks:** When a client requests evidence or findings associated with an investigation UID/ID, the backend resolves the request using server-side session context rather than trusting client-submitted ownership flags. Cross-investigation data access is explicitly rejected.

### D. Secure Evidence Upload & SHA-256 Integrity Verification
- **Upload Pipeline:** 
  1. Validates that the target investigation exists.
  2. Validates file extension (`.csv`), file size ($\le 16\text{MB}$), and ensures the file is non-empty.
  3. **SHA-256 Calculation:** Computes the cryptographic checksum from original file bytes before normalization.
  4. **Duplicate Prevention:** Checks existing records in SQLite to prevent duplicate uploads (`409 Conflict`).
  5. **Storage:** Saves the file under a generated UUID filename in `instance/evidence/` (outside public web root).
- **Integrity Verification:** 
  - Recalculates the SHA-256 hash of the stored file on disk and compares it against the recorded database hash.
  - Returns `Integrity Verified`, `Integrity Mismatch`, or `Verification Failed (File Missing)`.

### E. Security Headers, Error Handling & Audit Logging
- **Security Headers:** Every response includes `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **Centralized Error Handlers:** Handlers for 400, 404, 405, 413, 429, and 500 errors log security events into the audit trail and return structured JSON error envelopes (`{'ok': False, 'error': {'code': '...', 'message': '...'}}`).
- **Audit Table (`security_audit_logs`):** Records event type, severity (`Low`, `Medium`, `High`, `Critical`), details, client IP, and timestamp.

---

## 4. Verification & Testing

All security controls and functional modules have been thoroughly tested and validated via automated unit and integration tests (`tests/test_shadowtrace.py`). Running `python -m unittest tests/test_shadowtrace.py` executes all test cases successfully across authentication, authorization, IDOR checks, rate limiting, and SHA-256 evidence integrity verification.
