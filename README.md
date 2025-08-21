# Exploiting SMBv1 (MS17-010) — Lab Walkthrough
  | Educational use only. All activities performed in an isolated TryHackMe lab on virtual machines. 
  No scanning or exploitation was conducted on systems without permission.

Objective
Identify a vulnerable Windows host, exploit the SMBv1 MS17-010 vulnerability, gain a Meterpreter session, escalate privileges, and migrate to a stable SYSTEM-owned process.
## Method Overview 	
- Recon - Scan target for services and vulnerabilities.
- Exploit Selection - Choose appropriate exploit in Metasploit.
- Payload Setup - Configure payload and options.
- Initial Access - Gain shell access via exploit.
---
### 1 Recon - Service & Vulnerability Scan
My first step was to identify running services, their versions and any associated vulnerabilities.
To do this I ran Nmap with the --script vuln tag to enumerate common vulnerabilities.
This exposed the smb-vuln-ms17-010 (CVE-2017-0143, Remote Code Execution via SMBv1)

[NMap_EB_Scan1.png](https://github.com/CyberMarcR/images/blob/main/NMap_EB_Scan1.png)

[NMap_EB_Scan2.png](https://github.com/CyberMarcR/images/blob/main/NMap_EB_Scan2.png)

### 2 Exploit Selection - Choose appropriate exploit in Metasploit.
With the information gained from the scan, I then moved over to Metasploit. 
I ran a search for the exposed vulnerability and was able to select the appropriate exploit, in our case it is; ms17_010_eternalblue.

[Metasploit1.png](https://github.com/CyberMarcR/images/blob/main/Metasploit1.png)
