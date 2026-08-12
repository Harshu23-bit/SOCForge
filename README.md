# SOCForge - Autonomous AI SOC Triage & SOAR Engine

> An enterprise-grade, AI-assisted Security Operations Center (SOC) ecosystem. **SOCForge** ingests host telemetry via Sysmon and Wazuh SIEM, normalizes security events through a FastAPI middleware pipeline, and leverages LLM capabilities for real-time alert triage, threat scoring, and automated SOAR playbook execution.

Phase 1 Status: Deployment Verified

- [x] **Dockerized Wazuh SIEM Stack Deployed** (Indexer, Manager, Dashboard running on WSL2 / L: Drive)

![Active Containers](assets/dockerized-wazuh.png)

- [x] **Windows 11 Host Agent** (`windows-host`) paired and active
- [x] **Kali Linux VM Agent** (`darkcipher23`) paired and active

![Wazuh Active Agents](assets/windows-kali-host-wazuh-agent.png)

---

## Detection Verification & Evidence

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

* **Server Manager Config (`/var/ossec/etc/ossec.conf` on Wazuh Manager):**
  Enabled the `vulnerability-detection` module with automated NVD feed synchronization:
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

---
