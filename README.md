# 🛡️ SSH Log Analysis using Splunk

## 📌 Project Overview
This project focuses on analyzing SSH authentication logs to detect security threats such as brute-force attacks, unauthorized access attempts, and suspicious connections. Using **Splunk**, I ingested raw JSON logs, parsed critical fields, and built dashboards to visualize attack patterns.

**Lab Provider:** HAXCAMP  
**Tools Used:** Splunk Enterprise, SPL (Search Processing Language)

---

## 🎯 Objectives
The goal of this lab was to analyze SSH authentication logs to detect:
- **Successful Logins:** Identifying who connected and from where.
- **Failed Login Attempts:** detecting possible brute-force or password spraying attacks.
- **Multiple Failed Authentication Attempts:** Indicators of targeted brute-force attacks.
- **Connections Without Authentication:** Potential scanning or incomplete sessions.

---

## ⚙️ Lab Setup & Preparation
1.  **Data Source:** `ssh_log.json`
2.  **Ingestion:** Uploaded the log file to Splunk via "Add Data".
3.  **Configuration:**
    -   **Source Type:** `_json` (Automatically extracts fields)
    -   **Index:** `ssh_logs`

---

## 🛠️ Step-by-Step Analysis

### 🔹 Task 1: Ingestion and Parsing
**Objective:** Ensure logs are parsed correctly and key fields are extracted.

I validated that the following fields were correctly indexed:
-   `event_type`: (e.g., Failed SSH Login, Successful SSH Login)
-   `auth_success`: (true/false)
-   `id.orig_h`: Source IP
-   `id.resp_h`: Destination Host

**Validation Search:**
```splunk
source="ssh_logs.json" host="splunk" index="ssh_logs" sourcetype="ssh_logs" | stats count by event_type
