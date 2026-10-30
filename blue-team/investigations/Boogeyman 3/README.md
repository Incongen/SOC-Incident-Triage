# Incident Report - Boogeyman 3

## Overview
**Environment:** Windows

**Captured Artefacts:** `ProjectFinancialSummary_Q3.pdf` (The Malicious Attachment)

**Tools Used:** Elastic (Kibana)

## Introduction



---

## Investigation
**Provided Information:**
* The Attachment was opened by the recipient.
* The events occurred between August 29th and August 30th, 2023.

**Investigation Begins**
* After searching for the artefact inside Kibana, `ProjectFinancialSummary_Q3.pdf`, some key details were found:
  * The Process ID of the process that executed the initial stage 1 payload was `6392`.
  * The payload attempted to implant a file, titled `review.dat`, in another location with the following command: `"C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat`
  * The payload was then run using the following command: `"C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer`
  * The payload then created a scheduled task to run everyday at (6:00) and execute `rundll32.exe` to load `review.dat` and invoke an exported function titled `DllRegisterServer`: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" $A = New-ScheduledTaskAction -Execute 'rundll32.exe' -Argument 'C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat,DllRegisterServer'; $T = New-ScheduledTaskTrigger -Daily -At 06:00; $S = New-ScheduledTaskSettingsSet; $P = New-ScheduledTaskPrincipal $env:username; $D = New-ScheduledTask -Action $A -Trigger $T -Principal $P -Settings $S; Register-ScheduledTask Review -InputObject $D -Force;`
* Using a filter to sort for network logs using Sysmon, 
  * **Filter used:** `event.provider: "Microsoft-Windows-Sysmon" AND event.code: 3`
  * When the implanted file successfully executed, it established a C2 connection with the IPv4 address `165.232.170.151` over the port `80`.
* The attacker attempted to bypass the UAC with a Windows executable named `fodhelper.exe` after having discovered that their current access was a local administrator.
* The attacker then proceeded to dump the credentials inside the machine after downloading a well-known credential dumping tool `Mimikatz` from the link: `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`
  * The credentials the attacker dumped were for the account `itadmin` with the NTLM hash `[REDACTED]`.
* With the brand new credentials, the attacker attempted to enumerate all the accessible file shares and accessed a file called `IT_Automation.ps1`.
  * The attacker obtained the credentials for the account `QUICKLOGISTICS\allan.smith` with the password `[REDACTED]` from the `IT_Automation.ps1` file, and proceeded to move laterally.
* 
