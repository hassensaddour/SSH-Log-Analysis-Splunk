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
  
![project](https://github.com/user-attachments/assets/1cd2bda2-0f6b-45ec-a4df-ff2485955476)

---

## ⚙️ Lab Setup & Preparation
1.  **Data Source:** `ssh_log.json`
2.  **Ingestion:** Uploaded the log file to Splunk via "Add Data".
3.  **Configuration:**
    -   **Source Type:** `_json` (Automatically extracts fields)
    -   **Index:** `ssh_logs`
<img width="1919" height="922" alt="1" src="https://github.com/user-attachments/assets/67963ace-b6cd-4f40-98ca-a6c7a104ec78" />
<img width="1919" height="923" alt="2" src="https://github.com/user-attachments/assets/af915c71-4ca3-4341-a97f-b9c57874cb78" />


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
```

<img width="1905" height="808" alt="3" src="https://github.com/user-attachments/assets/309a0756-7ad7-4ba4-a37f-94f2cb416f71" />
<img width="1919" height="913" alt="4" src="https://github.com/user-attachments/assets/6bf2aea7-ac92-4cdc-88f2-3c4f1b42fa99" />


### 🔹 Task 2: Analyze Failed Login Attempts
**Description:**
To identify potential attackers, I searched for all events labeled "Failed SSH Login". I aggregated these events by the Source IP (`id.orig_h`) to see who was generating the most failures.

**Visualization:**
I created a Bar Chart to visualize the top 10 source IPs, making it easy to spot the most aggressive attackers immediately.

**SPL Query:**
```splunk
source="ssh_logs.json" host="splunk" index="ssh_logs" sourcetype="ssh_logs" event_type="Failed SSH Login" | stats count by id.orig_h
```
<img width="1919" height="920" alt="5" src="https://github.com/user-attachments/assets/982d68e2-05df-48e3-bf16-cb4318820ec1" />
<img width="1919" height="910" alt="6" src="https://github.com/user-attachments/assets/516119ed-e95c-4265-99fb-2335bab2fb78" />

### 🔹 Task 3: Detect Multiple Failed Authentication Attempts (Brute Force)
**Description:**
Simple failed logins happen, but repeated failures indicate an attack. I searched for the specific event type "Multiple Failed Authentication Attempts" to isolate these incidents.

**Alert Configuration:**
I configured a real-time Splunk alert to trigger whenever an IP address generated **more than 5 failed attempts within a 10-minute window**. This threshold helps reduce false positives while catching active brute-force scripts.

**SPL Query:**
```splunk
source="ssh_logs.json" host="splunk" index="ssh_logs" sourcetype="ssh_logs" event_type="Multiple Failed Authentication Attempts" | stats count by id.orig_h, id.resp_h
```
<img width="1919" height="915" alt="7" src="https://github.com/user-attachments/assets/b9a4016b-7868-4bf7-95c2-695d26496bf4" />
<img width="1914" height="925" alt="8" src="https://github.com/user-attachments/assets/4d6e0712-3466-4bef-8bb7-649cb45d1c4b" />
<img width="1910" height="700" alt="9" src="https://github.com/user-attachments/assets/bd36e961-1e86-4dda-bcab-cf478c3bbe2c" />

### 🔹 Task 4: Track Successful Logins
**Description:**
It is critical to know who actually got in. I filtered for "Successful SSH Login" events and tabulated them by Source IP and Destination Host.

**Analysis:**
I compared these successful logins against the failed attempts from Task 2. If an IP appeared in both lists (many failures followed by a success), it would strongly indicate a **compromised account** or a successful brute-force break-in.

**SPL Query:**
```splunk
source="ssh_logs.json" host="splunk" index="ssh_logs" sourcetype="ssh_logs" event_type="Successful SSH Login" | stats count by id.orig_h, id.resp_h
```
<img width="1919" height="917" alt="10" src="https://github.com/user-attachments/assets/4e929221-9254-48ab-9138-7d39fc785687" />
<img width="1919" height="912" alt="11" src="https://github.com/user-attachments/assets/7a6e4c24-79ed-4ed5-8f4b-799a41adce94" />

### 🔹 Task 5: Spot Suspicious Connections Without Authentication
**Description:**
Some connections never attempt to authenticate at all. These are labeled "Connection Without Authentication" and often indicate **port scanning** (checking if port 22 is open) or incomplete handshakes.

**Visualization:**
I used a Timechart to visualize these events over time. This helps identify spikes in activity, which would indicate a coordinated scanning campaign against the network.

**SPL Query:**
Search for unauthenticated SSH connections:
```splunk
source="ssh_logs.json" host="splunk" index="ssh_logs" sourcetype="ssh_logs" event_type="Connection Without Authentication" | stats count by id.orig_h
```
<img width="1919" height="914" alt="12" src="https://github.com/user-attachments/assets/f43c1ccf-2c96-44f7-857b-8165bf2b920d" />

**SPL Query:**
Create a timechart visualization to monitor such events over time:
```splunk
source="ssh_logs.json" host="splunk" index="ssh_logs" sourcetype="ssh_logs" event_type="Connection Without Authentication" | timechart count by id.orig_h
```
<img width="1919" height="913" alt="13" src="https://github.com/user-attachments/assets/3e2e6711-a408-4aea-b79a-97afa2d6b060" />

