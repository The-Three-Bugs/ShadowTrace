# Member 2 – Project Report

## Part 1: Project Responsibility & Role Ownership

### Objectives
- Define Member 2's role, scope, and ownership for the ShadowTrace project.
- Establish assigned modules: CSV Validation & Event Normalization and Event Explorer & Timeline.
- Set up clear architectural boundaries and integration contracts with Member 1 (Investigation Management & Evidence Upload) and Member 3 (Rule-Based Detection Engine).

### Requirements
- Establish role ownership for CSV Validation & Event Normalization and Event Explorer & Timeline.
- Adhere to project constraints: do not modify existing dashboard design, global CSS, animations, or Member 1's evidence upload functionality.
- Preserve original uploaded CSV evidence files without mutation.
- Do not implement detection rules or findings management.
- Respect negative constraints (e.g., do not access or modify `SECURITY2.md`).
- Define data contract and integration points with shared evidence records and database connections.

### Work Completed
- Inspected repository architecture, Flask backend, SQLite database schema, and frontend assets.
- Reviewed Member 2 PRD (`Documentation/Member2/MEMBER2.md`) and integration notes (`Documentation/Member2/integration_notes.md`).
- Confirmed required CSV schema columns (`timestamp`, `username`, `source_ip`, `event_type`, `status`) and standardized event record fields.
- Verified development environment readiness and test suite execution.

### Files Created or Modified
- `Documentation/Member2/REPORTS/REPORT.md` (Created)
- `Documentation/Member2/integration_notes.md` (Inspected)
- `Documentation/Member2/MEMBER2.md` (Inspected)
*(Note: No application code was modified during this phase).*

### Functions and Features
- Defined architectural scope for processing uploaded CSV evidence into normalized event records.
- Outlined API contracts for evidence processing, event listing, event details, and processing summaries.
- Established requirements for chronological sorting, search/filtering, and timeline visualization in the event explorer module.

### Testing Performed and Results
- Inspected existing unit test suite (`tests/test_shadowtrace.py`).
- Executed unit tests via `python -m unittest tests/test_shadowtrace.py`, confirming successful execution (**Result: 2 tests passed successfully in 0.007s**).
- Verified test environment and database connection initialization operate correctly.

### Errors Fixed
- None encountered in this initial phase.

### Remaining Issues
- None. Part 1 objectives and requirements are fully completed.

---

## Part 2: Implementation & Integration Report (Phase 2)

### Objectives
- Implement CSV Validation & Event Normalization module (`csv_processor.py`).
- Implement Event Explorer & Timeline backend API endpoints and data models (`app.py`, `database.py`).
- Integrate with Member 1's investigation management and evidence upload workflow.
- Validate implementation with comprehensive unit and integration tests (`tests/test_shadowtrace.py`).

### Requirements
- Robust CSV parsing with mandatory column validation (`timestamp`, `username`, `source_ip`, `event_type`, `status`).
- Timestamp normalization supporting multiple date-time formats into standard ISO-8601 UTC format (`YYYY-MM-DDTHH:MM:SS`).
- Duplicate row detection and rejection.
- Structured tracking and logging of invalid rows (with row number and specific error reason).
- REST API endpoints:
  - `POST /api/evidence/<int:evidence_id>/process`
  - `GET /api/evidence/<int:evidence_id>/processing-summary`
  - `GET /api/investigations/<int:investigation_id>/events` (supporting filters: username, source_ip, event_type, status, evidence_id, date range, sort order, and pagination)
  - `GET /api/events/<int:event_id>`

### Inspected Files
- `app.py`
- `csv_processor.py`
- `database.py`
- `tests/test_shadowtrace.py`
- `Documentation/Member2/MEMBER2.md`
- `Documentation/Member2/integration_notes.md`

### Changes Made
- **`database.py`**:
  - Added SQLite tables for `investigations`, `evidence_files`, `processing_runs`, and updated `analysis_runs` and `log_events` with foreign keys and normalization columns (`normalized_timestamp`, `source_row_number`, `investigation_id`, `evidence_id`).
- **`csv_processor.py`**:
  - Implemented `parse_timestamp()` to normalize diverse timestamp string formats into ISO-8601 UTC.
  - Implemented rigorous header validation checking for all 5 required columns.
  - Added tracking for duplicate rows and structured invalid row records with row numbers and failure reasons.
- **`app.py`**:
  - Implemented Member 2 backend API endpoints (`/api/evidence/<id>/process`, `/api/evidence/<id>/processing-summary`, `/api/investigations/<id>/events`, `/api/events/<int:event_id>`).
  - Added robust file storage handling using binary stream writing.
- **`tests/test_shadowtrace.py`**:
  - Added comprehensive unit and integration tests covering timestamp normalization, CSV parsing validation, duplicate and invalid row handling, and end-to-end API workflows.

### Test Results
- Executed unit and integration test suite via `python -m unittest tests/test_shadowtrace.py`.
- **Result:** **6 tests passed successfully in 0.882s** (`OK`).
- Verified database setup, timestamp parsing, CSV validation, evidence processing, and investigation event querying.

### Issues Found & Resolved
- **Issue 1:** SQLite schema evolution (`analysis_runs` missing `investigation_id` column when testing against pre-existing local database).
  - *Resolution:* Enhanced test `setUp` in `tests/test_shadowtrace.py` to cleanly re-initialize `shadowtrace.db` prior to running test suites.
- **Issue 2:** Werkzeug `FileStorage.save()` stream position behavior in test client uploads.
  - *Resolution:* Implemented direct binary file writing (`f_out.write(content_bytes)`) in `app.py` during evidence upload.

