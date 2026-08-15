# SOCForge - Autonomous AI SOC Triage & SOAR Engine

> An enterprise-grade, AI-assisted Security Operations Center (SOC) ecosystem. SOCForge ingests host telemetry via multi-platform Wazuh agents, normalizes security events through a FastAPI middleware pipeline, and leverages LLM capabilities for real-time alert triage, threat scoring, and automated SOAR playbook execution.

## System Architecture & Data Flow

```text
                                [ Wazuh Manager ]
                                        │ (Webhook Integration: Level >= 7)
                                        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                    SOCForge Python SOAR Middleware                           │
│                                                                              │
│  [ FastAPI Listener ] ──► [ Telemetry Fusion ] ──► [ Structured LLM Engine ] │
│   (Async Webhook)          (VT API + MITRE)         (Pydantic Schema)        │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
      [ Operational Dispatcher ]             [ Incident Feedback Loop ]
   (Rich Discord SOC Webhook Cards)       (Injected back into Wazuh Dashboard)
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
                       [ Validation & Verification ]
                   (Atomic Red Team + Pytest Suite)
```

---

* ** Deployment Verified**

- [x] **Dockerized Wazuh SIEM Stack Deployed** (Indexer, Manager, Dashboard running on WSL2)

![Active Containers](assets/dockerized-wazuh.png)

- [x] **Windows 11 Host Agent** (`windows-host`) paired and active
- [x] **Kali Linux VM Agent** (`darkcipher23`) paired and active

![Wazuh Active Agents](assets/windows-kali-host-wazuh-agent.png)

---

## Phase 1: Baseline Detection & Rule Verification (Labs 1–6)

### Hands-on Lab 1: File Integrity Monitoring (FIM)

* **Objective:** Monitor critical directories (`/root`) in real-time for unauthorized file additions, modifications, or deletions.

* **Server Manager Config (`/var/ossec/etc/ossec.conf`):** Changed `no` to `yes` in the following two lines
  ```xml
    <logall>yes</logall>
    <logall_json>yes</logall_json>
   ```
![FIM manager config](assets/lab1-fim/manager-config.png)

* **Agent/Client Config (`/var/ossec/etc/ossec.conf`):** Added real-time syscheck monitoring for `/root`
  ```xml
  <directories check_all="yes" report_changes="yes" realtime="yes">/root</directories>
   ```
![FIM client config](assets/lab1-fim/client-config.png)

* **Real-Time Alert Verification:** Created and deleted test files inside /root. Wazuh immediately captured the events, firing Rule 554 (File added to the system) and Rule 553 (File deleted).

![FIM Alerts Proof](assets/lab1-fim/fim-detection.png)

### Hands-on Lab 2: Detecting Network Intrusion using Suricata IDS

* **Objective:** Ingest real-time network threat telemetry by integrating Suricata IDS on the Kali Linux agent (`darkcipher23`) to detect port scans, network reconnaissance, and suspicious user-agents.

* **Agent/Client Config (`/var/ossec/etc/ossec.conf` on Kali Linux):** Configured the Wazuh Agent log-collector daemon to parse Suricata's JSON event output (`eve.json`):
  ```xml
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
  ```
![Suricata IDS Agent config](assets/lab2-suricata/agent-config.png)

* **Ruleset:** Utilized default Emerging Threats (ET) Open ruleset managed via `suricata-update`.

* **Attack Simulation:** Executed Nmap network service enumeration and user-agent probing against target services to simulate adversary reconnaissance:
  ```bash
  nmap -sV --script=http-enum,http-headers -p 8080 192.168.0.105
  ```
![nmap execution](assets/lab2-suricata/nmap-simulation.png)

* **Real-Time Alert Verification:** Suricata analyzed incoming network packets, generated JSON alerts in eve.json, and passed them to Wazuh Manager. The manager matched rule signatures, firing Rule 86601 (Suricata: Alert - ET SCAN Possible Nmap User-Agent Observed).

![suricata alert detection](assets/lab2-suricata/suricata-ids.png)

### Hands-on Lab 3: Detecting Vulnerabilities

* **Objective:** Automatically audit endpoint software inventories against National Vulnerability Database (NVD) CVE feeds to identify unpatched software and quantify host risk exposure.

* **Server Manager Config (`/var/ossec/etc/ossec.conf` on Wazuh Manager):** Enabled the `vulnerability-detection` module with automated NVD feed synchronization:
  ```xml
  <vulnerability-detection>
    <enabled>yes</enabled>
    <run_on_start>yes</run_on_start>
    <interval>5m</interval>
  </vulnerability-detection>
  ```
![vulnerability detection enabled](assets/lab3-vulnerabilities/enabled-vuln-detection.png)

* **Real-Time Audit Verification:** Wazuh scanned installed application package inventories on windows-host and correlated them against vulnerability feeds. It flagged 20 total vulnerabilities (10 High, 9 Medium, 1 Low), identifying high-risk exposures across application frameworks (PyJWT, Werkzeug, Flask) and desktop software (Steam).

![vulnerability detection](assets/lab3-vulnerabilities/detecting-vulnerabilities.png)

### Hands-on Lab 4: Detecting Execution of Malicious Commands via Auditd

* **Objective:** Audit system calls (`execve`) on Kali Linux (`darkcipher23`) to capture process creation and command-line execution parameters in real time.

* **Agent/Client Config (/var/ossec/etc/ossec.conf on Kali Linux):** Added localfile log collector for kernel audit logs:
  ```xml
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
  ```

* **Kernel Audit Rule Config (`/etc/audit/rules.d/wazuh.rules`):** Configured persistent kernel audit rules targeting 64-bit and 32-bit execution system calls (`execve`) under elevated root privileges (`euid=0`):
  ```text
  -a exit,always -F euid=0 -F arch=b64 -S execve -k audit-wazuh-c
  -a exit,always -F euid=0 -F arch=b32 -S execve -k audit-wazuh-c
  ```
![agent auditd config](assets/lab4-command-execution/auditd-config.png)

* **Real-Time Command Execution & Alert Verification:** Executed reconnaissance and system tools (netstat, df, sort, sed). Wazuh parsed /var/log/audit/audit.log and fired Rule 80792 (Audit: Command execution captured), logging the exact binary paths and process details.

![auditd alerts](assets/lab4-command-execution/auditd-alerts.png)

### Hands-on Lab 5: Automated SSH Brute-Force Detection & Active Response Mitigation

* **Objective:** Simulate an automated SSH brute-force attack using `hydra`, trigger signature-based detection rules in Wazuh, and automatically block the attacking IP in real time using Wazuh's **Active Response** firewall-drop integration.

* **Attack Simulation Vector (Hydra):** Executed a targeted dictionary attack against the SSH service on the target endpoint:
  ```bash
  hydra -t 4 -l root -P /usr/share/john/password.lst 192.168.0.105 ssh
  ```

* **Wazuh Manager Configuration (/var/ossec/etc/ossec.conf):** Configured an active response block to trigger the firewall-drop script locally for 180 seconds whenever Rule 5763 (SSHD brute force attempt) is fired:
  ```xml
  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5763</rules_id>
    <timeout>180</timeout>
  </active-response>
  ```
![Manager ossec.conf <active-response> block](assets/lab5-ssh-bruteforce/active-response-config.png)

* **Wazuh Agent Active Response Ingestion (/var/ossec/etc/ossec.conf):** Ensured the agent forwards local mitigation logs to the manager for auditing:
  ```xml
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/active-responses.log</location>
  </localfile>
  ```
![Agent ossec.conf <localfile> block](assets/lab5-ssh-bruteforce/active-response-log-config.png)

* **Real-Time Detection & Automated Block Verification:**

- **Rule 5760:** Detected and correlated multiple SSH authentication failures generated by the Hydra brute-force attack.

- **Rule 651:** Verified successful execution of Wazuh's `firewall-drop` Active Response, resulting in the attacker's IP address being blocked at the endpoint firewall.

- **Rule 80792:** Verified via `auditd` telemetry the execution of `/var/ossec/active-response/bin/firewall-drop`, providing host-level evidence of automated response execution.

![Wazuh Dashboard showing Rule 651 & 5760](assets/lab5-ssh-bruteforce/dashboard-active-response-alerts.png)

### Hands-on Lab 6: File Integrity Monitoring (FIM) & Automated VirusTotal Malware Detection

* **Objective:** Monitor critical host directories (`/root`) using Wazuh Syscheck, create custom rules for file additions/modifications, and automate threat detection by integrating the VirusTotal API to scan file hashes in real time.

* **Custom FIM Rules Configuration (`/var/ossec/etc/rules/local_rules.xml`):** Defined custom rules to elevate Syscheck events when files are modified (`syscheck_file_changed`, SID `550`) or added (`syscheck_file_added`, SID `554`) inside the `/root` directory:
  ```xml
  <group name="local,syslog,sshd,">
    <!-- Rule 100200: File modified in /root -->
    <rule id="100200" level="7">
      <if_sid>550</if_sid>
      <field name="file">/root</field>
      <description>File modified in /root directory.</description>
    </rule>

    <!-- Rule 100201: File added to /root -->
    <rule id="100201" level="7">
      <if_sid>554</if_sid>
      <field name="file">/root</field>
      <description>File added to /root directory.</description>
    </rule>
  </group>
  ```
![local_rules.xml showing custom rules 100200 & 100201](assets/lab6-virustotal/custom-fim-rules.png)

* **VirusTotal API Integration (/var/ossec/etc/ossec.conf):** Integrated the VirusTotal threat intelligence API on the Wazuh Manager to automatically trigger hash lookups whenever rules 100200 or 100201 fire:
  ```xml
  <integration>
    <name>virustotal</name>
    <api_key>YOUR_VIRUSTOTAL_API_KEY</api_key>
    <rule_id>100200,100201</rule_id>
    <alert_format>json</alert_format>
  </integration>
  ```

* **Malware Simulation & Execution:** Downloaded the standardized EICAR malware test string directly into the monitored /root directory:

![Malware download](assets/lab6-virustotal/eicar-malware-download.png)

* **Real-Time Detection & Alert Verification:**

- **Rule 100201 triggered on file creation in /root, forwarding the file hash (SHA1: 3395856ce81f2b7382dee72602f798b642f14140) to VirusTotal.**

- **Rule 87105 (Level 12 - High Severity) fired on the Wazuh Dashboard confirming VirusTotal flagged the sample across 61 detection engines.**

![Wazuh Dashboard document details showing Rule 87105 level 12 alert](assets/lab6-virustotal/virustotal-alert.png)

---
