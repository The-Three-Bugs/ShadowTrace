# SHADOWTRACE — MEMBER 3: DETECTION RULE SPECIFICATION

**Author:** Member 3 (Rule-Based Detection Engine & Findings Management)  
**Status:** Approved Specification  
**Reference:** Member 3 PRD (TASK 2), ARCHITECTURE.md, RULES.md  

---

## 1. Overview

The Rule-Based Detection Engine analyzes normalized security events to identify predefined suspicious patterns. It uses transparent, explainable detection rules rather than asserting unverified proof of compromise. Every generated finding serves as an investigative lead requiring human review.

---

## 2. Centralized Rule Structure & Configuration Model

Each detection rule in the ShadowTrace engine is defined by a standardized schema containing:
- **Rule ID:** Unique alphanumeric identifier (e.g., `RULE-01`).
- **Rule Name:** Human-readable title of the detection pattern.
- **Description:** Clear explanation of what activity the rule identifies.
- **Detection Logic:** Algorithmic criteria matching normalized event fields.
- **Threshold / Time Window:** Quantitative limits (e.g., event count, time duration).
- **Supported Event Types:** Specific log event types evaluated by the rule.
- **Default Severity:** Priority level (`Low`, `Medium`, `High`, `Critical`).
- **Enabled State:** Boolean flag (`enabled: true/false`) supporting rule toggling.
- **Limitations:** Documented constraints and false-positive considerations.

---

## 3. Initial Detection Rules Specification

### RULE-01: Repeated Failed Login Attempts
- **Rule ID:** `RULE-01`
- **Rule Name:** Repeated Failed Login Attempts
- **Description:** Identifies repeated failed login attempts associated with the same username and source IP address within a focused time window.
- **Detection Logic:** Aggregates login events where status indicates failure (`failed`, `failure`, `error`, `blocked`) grouped by source IP and username.
- **Threshold / Time Window:** At least 3 (configured initial threshold) failed login events within a 5-minute window.
- **Supported Event Types:** `login_attempt`, `login`, `authentication`.
- **Default Severity:** `Medium` (or `Critical` when exceeding higher volume thresholds).
- **Enabled State:** Enabled (`true`).
- **Limitations:** May trigger on legitimate users mistyping passwords or automated configuration tests; does not confirm unauthorized access.

### RULE-02: Successful Login Following Repeated Failures
- **Rule ID:** `RULE-02`
- **Rule Name:** Successful Login Following Repeated Failures
- **Description:** Identifies a successful login event that occurs immediately following repeated failed login attempts for the same username and source IP.
- **Detection Logic:** Evaluates chronological event streams per source IP/username; detects sequence of >= 2 failed login events followed by a successful login (`success`, `successful`).
- **Threshold / Time Window:** >= 2 failed attempts preceding a successful login within the investigation window.
- **Supported Event Types:** `login_attempt`, `login`, `authentication`.
- **Default Severity:** `Medium`.
- **Enabled State:** Enabled (`true`).
- **Limitations:** Indicates potential brute-force success or password recovery retry, but does not independently prove unauthorized access or compromise.

### RULE-03: Sensitive File Access Following Suspicious Login Activity
- **Rule ID:** `RULE-03`
- **Rule Name:** Sensitive File Access Following Suspicious Login Activity
- **Description:** Identifies sensitive file access or privilege escalation events occurring after matching suspicious login activity from the same source IP.
- **Detection Logic:** Triggers when event types match sensitive access indicators (`unauthorized`, `access_denied`, `forbidden`, `privilege_escalation`, `port_scan`, `breach`, `sensitive_file`) following suspicious authentication patterns.
- **Threshold / Time Window:** Occurrence within the same investigation session / log timeframe.
- **Supported Event Types:** `unauthorized_access`, `file_access`, `privilege_escalation`, `system_event`.
- **Default Severity:** `High`.
- **Enabled State:** Enabled (`true`).
- **Limitations:** Requires logs containing appropriate event fields and event types. If required log fields are missing, the rule is safely skipped to prevent false or misleading findings.
