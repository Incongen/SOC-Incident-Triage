# Incident Report: Case Tempest

## 📋 Case Overview
* **Target Environment:** Windows Workstation (`WKSTN-2961`)
* **Primary Artifacts:** `powershell.json` (Event Logs), `capture.pcapng` (Network Packet Capture), `WKSTN-2961.raw` (Memory Image)
* **Core Investigation Objective:** Analyze an end-to-end compromise involving malicious ISO payload delivery, obfuscated execution, C2 interaction, privilege escalation, and DNS-based data exfiltration.

---

## 📑 Technical Investigation & Task Execution

### Phase 1: Preparation & Tooling Setup
* Configured local CLI environment for artifact extraction:
  * Log Parsing: `jq`, `grep`, `cut`, `tr`
  * Network Forensics: `tshark`, `xxd`
  * Memory Diagnostics: Volatility 3 framework

### Phase 2: Initial Access & Stage-2 Execution
* **Delivery Mechanism:** Initial access vector identified via malicious ISO container file configured to bypass Mark-of-the-Web (MotW) controls.
* **ScriptBlock Parsing:** Filtered event logs using `jq` to isolate unique, sorted PowerShell execution strings:
  ```bash
  cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]' | jq -r '.ScriptBlockText // empty' | sort -u
