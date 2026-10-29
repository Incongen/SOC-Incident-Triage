# Incident Report - Boogeyman 2

## Overview
**Environment:** Windows

**Captured Artefacts:** Copy of the original Phishing E-mail, `WKSTN-2961.raw` (Memory dump of the victim's workstation)

**Tools Used:** Volatility, olevba

## Introduction

This incident covers the compromise of a host who worked as a Human Resource Specialist for a company, which started from what appeared to be an application from an open position inside the company. The resume attached to the e-mail was malicious and contained macros which downloaded malicious files and binaries to the victim's workstation. Some suspicious commands were flagged by the security team, which prompted the investigation.

---

## Investigation
* After opening the copy of the original phishing e-mail, the sender's e-mail was revealed to be `westaylor23@outlook.com`.
* The e-mail contained a malicious attachment titled `Resume_WesleyTaylor.doc` which used social engineering to manipulate the victim `maxine.beck` to open it, as she had assumed it would just be a resume.
  * **MD5 Hash of the malicious attachment:** `52c4384a0b9e248b95804352ebec6c5b`
* After using `olevba` to analyze the macros present inside the malicious attachment, the following discoveries were made:
  * **Command used:** `olevba Resume_WesleyTaylor.doc`
  * **The URL that was used for downloading the stage 2 payload was:** `hxxps://files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` was discovered under the `xHttp.open "GET"` header, which was used for downloading the stage 2 payload.
  * The process that executed the stage 2 payload was found, titled `wscript.exe` under the `shell_object.Exec` header.
  * **Under the same header `shell_object.Exec`, the file path to the stage 2 payload was discovered:** `C:\ProgramData\update.js`
* After using `Volatility` on the memory dump file `WKSTN-2961.raw`, the following discoveries were made:
  * The Process ID for the process `wscript.exe` was `4260` and the Parent Process ID was `1124`.
    * **Command used:** `vol -f WKSTN-2961.raw windows.pstree`
  * **The URL used to download the malicious stage 2 binary was:** `hxxps://files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe`
    * **Command used:** `strings WKSTN-2961.raw | grep "boogeymanisback.lol"`
  * **The malicious process used to establish a C2 connection was called:** `updater.exe` with the Process ID `6216`, and the file path `C:\Windows\Tasks\updater.exe`
    * **Commands Used:**
      * `vol -f WKSTN-2961.raw windows.netscan.netscan` was used for identifying which process was used to establish a C2 connection.
      * `vol -f WKSTN-2961.raw windows.dlllist --pid 6216` was used for identifying the file path for the process.
  * The C2 connection was made to the IPv4 address `128[.]199[.]95[.]189` over the port `8080`.
    * **Command Used:** `vol -f WKSTN-2961.raw windows.netscan.netscan`
  * The full file path of the malicious attachment was: `C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc`
    * **Command Used:** `vol -f WKSTN-2961.raw windows.filescan | grep "Resume_WesleyTaylor"`
  * The attacker then implanted a scheduled task which was set to run silently daily at the same time (9:00) to open a hidden PowerShell window which proceeds to execute a script which is stored as an encoded value inside the registry, and then decoded upon execution. This allowed the attacker to establish persistence: `schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))\"'`
    * **Commands Used:**
      * `vol -f WKSTN-2961.raw windows.memmap --dump --pid 6216`
      * `strings WKSTN-2961.raw | grep "schtasks"`

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | The victim received a phishing email containing the malicious `Resume_WesleyTaylor.doc` attachment. |
| Execution | User Execution: Malicious File | T1204.002 | The victim opened the malicious Word document, initiating the infection chain. |
| Execution | Command and Scripting Interpreter: JavaScript | T1059.007 | The document's macros used `wscript.exe` to execute the JavaScript payload at `C:\ProgramData\update.js`. |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | The attacker created a scheduled task named `Updater`, configured to run daily at 09:00. The task launched hidden PowerShell to decode and execute a script stored in the registry. |


## Conclusion
This report covered the events that occurred after a malicious document containing macros executed on a workstation. What appeared to be a benign document in reality started an attack chain where, a payload was downloaded which proceeded to download further binaries and establish persistence with the use of a scheduled task that opened a powershell window at the exact same time everyday. This was a prime example of how attackers use social engineering for successful phishing campaigns.
