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

---

## Part 3: API Requirements, Event Explorer & Timeline Implementation (Phase 3)

### Objectives
- Implement and verify Member 2's assigned API requirements and endpoints (`/api/evidence/<id>/process`, `/api/evidence/<id>/processing-summary`, `/api/investigations/<id>/events`, `/api/events/<event_id>`).
- Finalize support for event search, multi-field filtering, chronological sorting (`oldest` / `newest`), and pagination.
- Ensure strict compliance with `RULES.md` and `ARCHITECTURE.md` (parameterized SQL queries, uniform JSON response contracts, immutable original evidence preservation).
- Validate all features through comprehensive unit and integration tests.

### Actual Work Completed
1. **Evidence Processing Endpoint (`POST /api/evidence/<id>/process`)**:
   - Integrated evidence file lookup with investigation foreign key association.
   - Invoked CSV validation and normalization logic to parse required headers (`timestamp`, `username`, `source_ip`, `event_type`, `status`).
   - Parsed and normalized timestamps into ISO-8601 UTC format.
   - Logged processing runs and saved normalized events with source row number and evidence references in SQLite.
2. **Processing Summary Endpoint (`GET /api/evidence/<id>/processing-summary`)**:
   - Implemented summary retrieval providing metrics for total rows, valid rows, invalid rows, duplicate rows, processing status, and error details.
3. **Event Explorer & Chronological Timeline Endpoint (`GET /api/investigations/<id>/events`)**:
   - Implemented dynamic query filtering supporting `username`, `source_ip`, `event_type`, `status`, `evidence_id`, and `start_date`/`end_date` date ranges.
   - Implemented chronological sorting (`sort=oldest` and `sort=newest`) using normalized timestamps.
   - Added server-side pagination (`page` and `per_page`).
4. **Event Detail Endpoint (`GET /api/events/<id>')**:
   - Implemented secure retrieval of individual normalized event records with full traceability back to the source CSV row and evidence ID.

### Files Created or Modified
- **`app.py`**: Added and refined Member 2 REST API endpoints (`/api/evidence/<id>/process`, `/api/evidence/<id>/processing-summary`, `/api/investigations/<id>/events`, `/api/events/<event_id>`) adhering to standardized response structures (`{"ok": true, "data": ...}`).
- **`database.py`**: Maintained schema support for `processing_runs`, `evidence_files`, and `log_events` with foreign key relationships and index structures.
- **`csv_processor.py`**: Handled robust CSV parsing, column normalization, timestamp parsing, and duplicate/invalid row separation.
- **`tests/test_shadowtrace.py`**: Added comprehensive test cases covering timestamp normalization, CSV parsing validation, API evidence processing, and event filtering/sorting.

### Implementation Details
- **Security & SQL Safety**: All database operations utilize parameterized queries (`?`) to prevent SQL injection.
- **Error Handling**: Standardized error responses (`{"ok": false, "error": {"code": "...", "message": "..."}}`) with appropriate HTTP status codes (`400`, `404`, etc.).
- **Evidence Integrity**: Original uploaded evidence files remain unmutated on disk while normalized events are stored separately with source row metadata.

### Testing Performed and Results
- Executed unit and integration test suite via `python -m unittest tests/test_shadowtrace.py`.
- **Result:** **6 tests passed successfully in 0.932s (`OK`)**.
- Verified end-to-end investigation creation, evidence upload, evidence processing, processing summary retrieval, event filtering, chronological sorting, and event detail lookup.

### Issues Resolved
- **Issue 1**: Inconsistent filtering across mixed timestamp formats.
  - *Resolution*: Leveraged SQLite `COALESCE(normalized_timestamp, timestamp)` expressions in query clauses to ensure reliable sorting and date-range filtering.
- **Issue 2**: Unbounded query performance.
  - *Resolution*: Implemented server-side pagination with default `per_page=50` limits on event exploration endpoints.

