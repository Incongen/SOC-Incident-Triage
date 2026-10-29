# Incident Report - Boogeyman 2

## Overview
**Environment:** Linux Ubuntu

**Captured Artefacts:** Copy of the original Phishing E-mail, `WKSTN-2961.raw` (Memory dump of the victim's workstation)

**Tools Used:** Volatility, Olevba

## Introduction



---

## Preparation
* 

## Investigation
* After opening the copy of the original phishing e-mail, the sender's e-mail was revealed to be `westaylor23@outlook.com`.
* The e-mail contained a malicious attachment titled `Resume_WesleyTaylor.doc` which used social engineering to manipulate the victim `[REDACTED]` to open it, as she had assumed it would just be a resume.
  * **MD5 Hash of the malicious attachment:** `52c4384a0b9e248b95804352ebec6c5b`
* After using `Olevba` to analyze the macros present inside the malicious attachment, the following discoveries were made:
  * **Command used:** `olevba Resume_WesleyTaylor.doc`
  * **The URL that was used for downloading the stage 2 payload was:** `hxxps://files[.]boogeymanisback[.]lol/aa2a9c53cbb80416d3b47d85538d9971/update[.]png` was discovered under the `xHttp.open "GET"` header, which was used for downloading the stage 2 payload.
  * The process that executed the stage 2 payload was found, titled `wscript.exe` under the `shell_object.Exec` header.
  * **Under the same header `shell_object.Exec`, the file path to the stage 2 payload was discovered:** `C:\ProgramData\update.js`
  * 
