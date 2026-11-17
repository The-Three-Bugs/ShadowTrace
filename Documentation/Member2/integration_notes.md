# Member 2 — Integration Notes & Data Contract

## 1. Repository & Architecture Inspection
- **Framework:** Python Flask REST API (`app.py`), SQLite database (`database.py`), Vanilla JavaScript and HTML5/CSS3 frontend.
- **Database Connection:** Uses `sqlite3` with `Row` factory, connecting to `instance/shadowtrace.db`.
- **Existing Routes:** `/api/stats`, `/api/logs`, `/api/detections`, `/api/upload`, `/api/load-sample`, `/api/download-template`.

## 2. Confirmed CSV Schema (Member 2 Module 1)
Required columns for security log validation and normalization:
1. `timestamp` (Date and time of the event)
2. `username` (User associated with the event)
3. `source_ip` (Source IP address)
4. `event_type` (Type of security event)
5. `status` (Event outcome or status)

## 3. Data Contract & Integration Points
- **Evidence / Upload Relationship:** Member 2's validation and normalization processing builds upon uploaded CSV evidence files.
- **Normalized Events Storage:** Events will be associated with their respective investigation and evidence IDs, retaining source row numbers and standardized timestamps.
- **API Response Conventions:** Adhering to standard JSON responses (`{"ok": true, "data": ...}` / error format) as specified in the project architecture guidelines.

## 4. Scope Boundaries & Constraints
- Member 2 owns:
  1. CSV Validation & Event Normalization
  2. Event Explorer & Timeline
- Member 2 does NOT own / will NOT modify:
  - Investigation Management or Evidence Upload (Member 1).
  - Detection Engine or Findings Management (Member 3).
  - Existing dashboard UI/UX, global CSS, or navigation structure.
  - Original uploaded evidence files (which must remain unmutated).
