# SHADOWTRACE — MEMBER 3: API ENDPOINT PROTECTIONS & SECURITY CONTROLS

**Security Owner:** Member 3  
**Scope:** Endpoint security policies, rate limiting, CORS, error handling, security headers, and audit logging.

---

## 1. Overview

ShadowTrace implements robust API-level security controls to protect the application runtime against unauthorized access, request abuse, resource exhaustion, and information leakage. All endpoints adhere to the shared JSON response contract and standardized error envelopes.

---

## 2. Core Security Middleware & Headers

Every API response automatically includes the following security headers:
- `X-Content-Type-Options: nosniff` (Prevents MIME-type sniffing).
- `X-Frame-Options: SAMEORIGIN` (Mitigates clickjacking attacks).
- `Referrer-Policy: strict-origin-when-cross-origin` (Controls referrer information leakage).
- `Access-Control-Allow-Origin: *` (Restrictive cross-origin resource sharing policy).
- `Access-Control-Allow-Methods: GET, POST, PATCH, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type, Authorization`

---

## 3. Endpoint Protection Matrix

| Endpoint | Method | Security Controls & Protections |
|---|---|---|
| `/api/stats` | GET | Secured with security headers, CORS, and centralized error handling. |
| `/api/logs` | GET | Bounded query pagination (`page`, `per_page`), search sanitization, and security headers. |
| `/api/detections` | GET | Filtered retrieval with input validation and security headers. |
| `/api/investigations/<id>/analyze` | POST | **Rate-limited (HTTP 429)**, bounded investigation record retrieval, audit-logged on abuse. |
| `/api/investigations/<id>/analysis-runs` | GET | Investigation-scoped run history retrieval with input validation. |
| `/api/investigations/<id>/findings` | GET | Investigation-scoped findings retrieval with severity/status filters. |
| `/api/findings/<int:finding_id>` | GET | Detailed finding lookup with supporting event joins and validation (returns 404 if missing). |
| `/api/findings/<int:finding_id>/status` | PATCH | Status validation (`New`, `Under Review`, `Resolved`, `False Positive`), JSON request parsing. |
| `/api/findings/<int:finding_id>/notes` | POST | Input validation (rejects empty notes), audit-logged on error. |
| `/api/upload` | POST | **Rate-limited (HTTP 429)**, 16MB file size limit (`MAX_CONTENT_LENGTH`), extension check (`.csv`), safe storage handling. |
| `/api/load-sample` | POST | **Rate-limited (HTTP 429)**, secure file path resolution, transaction isolation. |
| `/api/security/audit-logs` | GET | Secure audit log query endpoint (returns recent security events from `security_audit_logs`). |

---

## 4. Rate Limiting & Abuse Prevention

Sensitive and resource-intensive endpoints (`/api/investigations/<id>/analyze`, `/api/upload`, `/api/load-sample`) implement in-memory sliding window rate limiting. Excessively rapid requests receive an HTTP `429 Too Many Requests` status code with a structured JSON error envelope and automatically trigger a security audit log entry.

---

## 5. Centralized Error Handling

All unhandled exceptions and HTTP error codes (400, 404, 405, 413, 429, 500) are caught centrally and returned via the standardized JSON error envelope:
```json
{
  "ok": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Readable description"
  }
}
```
Internal stack traces, absolute filesystem paths, and database credentials are never exposed.

---

## 6. Security Event Logging & Monitoring

Security-relevant events (such as `RATE_LIMIT_EXCEEDED`, `NOT_FOUND`, `BAD_REQUEST`, `INTERNAL_SERVER_ERROR`) are recorded in the `security_audit_logs` SQLite table with UTC timestamps, client IPs, severities, and event details. Credentials, tokens, and raw evidence content are strictly excluded.
