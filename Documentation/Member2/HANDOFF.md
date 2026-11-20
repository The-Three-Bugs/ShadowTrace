# SHADOWTRACE — MEMBER 2 TO MEMBER 3 HANDOFF SPECIFICATION

**From:** Member 2 (CSV Validation & Event Normalization | Event Explorer & Timeline)  
**To:** Member 3 (Rule-Based Detection Engine | Findings Management)  
**Project:** ShadowTrace  
**Date:** November 18, 2026

---

# 1. Purpose

This document provides Member 3 with the complete technical handoff specifications, data contracts, database schemas, and API endpoints required for the Rule-Based Detection Engine and Findings Management modules to consume normalized security events produced by Member 2.

---

# 2. Normalized Event Data Model & Schema

Normalized events are persisted in the SQLite table `log_events`.

### 2.1 Database Schema (`log_events`)

```sql
CREATE TABLE IF NOT EXISTS log_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    investigation_id INTEGER,
    evidence_id INTEGER,
    source_row_number INTEGER,
    timestamp TEXT,
    normalized_timestamp TEXT,
    source_ip TEXT,
    event_type TEXT,
    username TEXT,
    status TEXT,
    severity TEXT DEFAULT 'Low',
    detection_reason TEXT,
    FOREIGN KEY (run_id) REFERENCES analysis_runs(id),
    FOREIGN KEY (investigation_id) REFERENCES investigations(id),
    FOREIGN KEY (evidence_id) REFERENCES evidence_files(id)
);
```

### 2.2 Field Definitions

- **Event ID Format:** `id` (Integer, Auto-increment primary key). Uniquely identifies each normalized event.
- **Investigation ID Relationship:** `investigation_id` (Integer, Foreign Key to `investigations.id`). Scopes events to the correct investigation.
- **Evidence ID Relationship:** `evidence_id` (Integer, Foreign Key to `evidence_files.id`). Links normalized events back to the original uploaded CSV evidence.
- **Source Row Number:** `source_row_number` (Integer). Preserves traceability back to the exact row number in the original CSV file.
- **Timestamp Representation:** 
  - `timestamp` (Text): Original raw timestamp string from the CSV.
  - `normalized_timestamp` (Text): Standardized ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SS`) parsed consistently by Member 2's timestamp normalization service.
- **Username Field:** `username` (Text). The user entity associated with the event (e.g., `admin`, `john_doe`).
- **Source IP Field:** `source_ip` (Text). The originating IP address for network/authentication activity (e.g., `192.168.1.10`).
- **Event Type Field:** `event_type` (Text). The classification of the security event (e.g., `login`, `login_attempt`, `access`).
- **Status Field:** `status` (Text). The outcome of the event (e.g., `success`, `failed`, `forbidden`).
- **Additional Metadata:** `run_id`, `severity`, and `detection_reason`.

---

# 3. Event Retrieval API (For Detection Engine Input)

Member 3's Detection Engine can query normalized events via Member 2's REST API endpoint.

### 3.1 Endpoint

```http
GET /api/investigations/<int:investigation_id>/events
```

### 3.2 Query Parameters

- `username` (string, optional): Filter by username.
- `source_ip` (string, optional): Filter by source IP.
- `event_type` (string, optional): Filter by event type.
- `status` (string, optional): Filter by event outcome (`success`, `failed`, etc.).
- `evidence_id` (integer, optional): Filter by specific evidence file ID.
- `start_date` (string, optional): ISO start date/time filter.
- `end_date` (string, optional): ISO end date/time filter.
- `sort` (string, optional): `oldest` (default) or `newest`.
- `page` (integer, optional): Page number (default `1`).
- `per_page` (integer, optional): Results per page (default `50`).

### 3.3 Success Response Contract (`200 OK`)

```json
{
  "ok": true,
  "data": {
    "events": [
      {
        "id": 10,
        "run_id": 1,
        "investigation_id": 1,
        "evidence_id": 1,
        "source_row_number": 12,
        "timestamp": "2026-10-12 10:30:00",
        "normalized_timestamp": "2026-10-12T10:30:00",
        "source_ip": "192.168.1.10",
        "event_type": "login",
        "username": "admin",
        "status": "failed",
        "severity": "Low",
        "detection_reason": "Normal activity"
      }
    ],
    "total": 1,
    "page": 1,
    "per_page": 50
  }
}
```

---

# 4. Processing Summary Structure

Member 3 (and other modules) can inspect the processing results of an evidence file via:

```http
GET /api/evidence/<int:evidence_id>/processing-summary
```

### 4.1 Response Structure (`200 OK`)

```json
{
  "ok": true,
  "data": {
    "id": 1,
    "investigation_id": 1,
    "evidence_id": 1,
    "total_rows": 100,
    "valid_rows": 94,
    "invalid_rows": 4,
    "duplicate_rows": 2,
    "processing_status": "Completed with Errors",
    "started_at": "2026-10-18 12:00:00",
    "completed_at": "2026-10-18 12:00:01",
    "error_summary": null
  }
}
```

---

# 5. Individual Event Detail API

To inspect a specific event record directly:

```http
GET /api/events/<int:event_id>
```

### 5.1 Response Structure (`200 OK`)

```json
{
  "ok": true,
  "data": {
    "id": 10,
    "run_id": 1,
    "investigation_id": 1,
    "evidence_id": 1,
    "source_row_number": 12,
    "timestamp": "2026-10-12 10:30:00",
    "normalized_timestamp": "2026-10-12T10:30:00",
    "source_ip": "192.168.1.10",
    "event_type": "login",
    "username": "admin",
    "status": "failed",
    "severity": "Low",
    "detection_reason": "Normal activity"
  }
}
```

---

# 6. Integration Boundaries & Constraints

- **Member 2 Responsibility:** Parsing CSV logs, validating headers, normalizing timestamps to ISO-8601 UTC, detecting duplicates, tracking invalid rows, storing normalized events, and providing event retrieval/filtering APIs.
- **Member 3 Responsibility:** Consuming normalized events, executing detection rules (e.g., Rule-01, Rule-02, Rule-03), generating findings, and managing finding statuses/analyst notes.
- **Separation of Concerns:** Member 2 does NOT implement detection rules or findings management. Member 3 does NOT parse or validate raw CSV evidence files directly.
