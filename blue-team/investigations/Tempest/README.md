# Incident Report - Tempest

## Overview
**Environment:** Windows Workstation 
**Captured Artefacts:** 'powershell.json' (Event Logs), 'capture.pcapng' (Captured Network Traffic), 'WKSTN-2961.raw' (Memory Image)
**Objective:** Analyze the incident to develop a clean flow of how the attack was executed through, while making use of MITRE ATT&CK TTPs.S

---

## Investigation

### Phase 1: Preparation
* Configured local CLI environment for artifact extraction:
  * Log Parsing: `jq`, `grep`, `cut`, `tr`
  * Network Forensics: `tshark`, `xxd`
  * Memory Diagnostics: Volatility 3 framework
