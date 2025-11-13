Task 1 – Network Reconnaissance & Port 
Scanning 
 
Objective / Aim of the task : 
Primary objective :  
Perform controlled network reconnaissance and port scanning on a lab network 
to identify alive hosts, enumerate open ports and services, and assess potential 
security issues. 
 
Secondary objectives : 
•  Practice using Nmap and basic network tools to collect and store scan results. 
•  Interpret scan results to identify probable service types and security risks. 
•  Provide prioritized remediation recommendations. 
•  Document the workflow, commands, and findings for submission and review. 
 
Scope & constraints : 
• Scans were performed only on the authorized lab subnet. 
• All direct IPv4 addresses have been redacted in the report (replaced with 
[HIDDEN_IP] / [HIDDEN_SUBNET]) for privacy. 
• Tests were non-destructive (no exploitation), limited to reconnaissance and 
passive/active enumeration. 
 
Tools used : 
Nmap (v7.98) : 
Primary network scanner for host discovery, port enumeration, service/version 
detection, and saving output. 
• Used flags: -sS (SYN scan), -sV (service/version detection), -p (port range), 
oN/-oX (output formats). 
 
PowerShell / Command Prompt : 
To run Nmap and system networking commands. 
GitHub : 
To upload scripts, outputs, and final report for submission: 
 
Steps performed : 
Identify local network/subnet : 
• Windows: ipconfig /all 
• Linux/macOS: ifconfig or ip addr show 
Determine network range (represented here as [HIDDEN_SUBNET]). 
Basic host discovery : 
• nmap -sn [HIDDEN_SUBNET] 
Purpose: quickly find live hosts without full port scan. 
TCP SYN scan : 
• nmap -sS -p 1-65535 [HIDDEN_SUBNET] -oN results_full.txt 
Purpose: detect open TCP ports stealthily and record full results. 
 
Results / Observations : 
Scan summary : 
• Nmap run timestamp: 2025-11-13 16:38 +0530 (preserved). 
• Nmap done: 256 IP addresses scanned; 2 hosts up 
 
Host A — [HIDDEN_IP] : 
• Host is up (latency ~0.010s). 
• Open ports: 
• 22/tcp — ssh 
• 80/tcp — http 
• 1900/tcp — upnp 
• MAC Address: 28:EE:52:A4:07:BE (TP-Link Technologies) — suggests a 
consumer router / gateway device or a device attached via that vendor NIC. 

Host B — [HIDDEN_IP] : 
•  Host is up (latency ~0.000042s). 
•  Open ports: 
➢ 135/tcp — msrpc (RPC endpoint mapper) 
➢ 139/tcp — netbios-ssn (NetBIOS session service) 
➢ 445/tcp — microsoft-ds (SMB / Windows file sharing) 
➢ 2869/tcp — icslap (related to UPnP/Internet Connection Sharing) 
➢ 3306/tcp — mysql (database) 
➢ 3389/tcp — ms-wbt-server (RDP — Remote Desktop 

Other observations : 
• Host A’s UPnP and HTTP presence suggests a router/web interface or IoT 
device. UPnP can be abused to map ports through NAT. 
• Host B’s combination of SMB, RPC, and RDP suggests a Windows host likely 
used for file sharing and remote admin. Exposed MySQL and RDP present 
higher risk if not properly protected. 
 
Analysis : 
22/tcp — SSH : 
• Purpose: Encrypted remote administration. 
• Risk: If password-based auth is enabled with weak passwords, attacker can gain shell 
access. Exposing SSH to the internet without mitigation increases risk. 
• Mitigation: Use key-based auth, disable root login, change default port optionally, allow 
only specific IPs. 

80/tcp — HTTP : 
• Purpose: Serves web pages; often administrative web UI on routers or apps. 
• Risk: Unencrypted traffic (no HTTPS) may expose credentials; web app vulnerabilities 
(e.g., outdated firmware) could allow remote code execution. 
• Mitigation: Use HTTPS, apply patches, restrict access to management interfaces, strong 
auth. 

1900/tcp — UPnP / SSDP : 
• Purpose: Allows devices to discover services on local network; common in routers and 
smart devices. 
• Risk: UPnP can be abused to open ports from WAN to LAN; many devices have insecure 
implementations. 
• Mitigation: Disable UPnP if not needed; restrict UPnP to LAN-only. 

135/tcp — MSRPC : 
• Purpose: Used by Windows RPC services for dynamic port mapping. 
• Risk: Historically abused in worm attacks and for remote information leakage. Exposing 
to untrusted networks is risky. 
• Mitigation: Restrict RPC access to trusted networks; enforce firewall rules. 

139/tcp (NetBIOS-SSN) & 445/tcp (Microsoft-DS / SMB) : 
• Purpose: File and printer sharing on Windows networks. 
• Risk: Significant — SMB has been the vector for ransomware and worm 
propagation. Unauthenticated or weakly authenticated shares may expose 
sensitive data. 
• Mitigation: Disable SMBv1, restrict SMB to internal networks, use strong 
access controls and monitoring. 

2869/tcp — icslap / UPnP related : 
• Purpose: Often used by Windows Internet Connection Sharing and UPnP 
services. 
• Risk: May indicate extra UPnP functionality that can be abused. 
• Mitigation: Limit or disable. 

3306/tcp — MySQL : 
• Purpose: Database server listener. 
• Risk: If accessible without network restrictions, attacker may attempt brute 
force or SQL-based attacks; data exfiltration risk. 
• Mitigation: Bind MySQL to localhost or internal addresses only, use strong 
credentials, restrict via firewall. 

3389/tcp — RDP : 
• Purpose: Remote GUI access to Windows machines. 
• Risk: High — RDP is frequently targeted for brute-force, credential stuffing, 
and exploitation. Public RDP exposure often leads to compromise. 
• Mitigation: Block RDP at perimeter, use VPN or jump host for remote 
access, enforce MFA and strong account policies. 
 
Recommendations : 
Immediate (High priority) 
• Restrict access to RDP (3389) and MySQL (3306) at the network perimeter 
— block from WAN and limit to specific management subnets/VPN. 
• Disable UPnP on routers unless absolutely required. 
• Close unnecessary ports and services (e.g., SMB if not needed). 

Short-term (Medium priority) 
• Enforce SSH key-based authentication and disable password authentication 
where possible. 
• Apply latest OS and firmware patches to routers and hosts. 
• Disable SMBv1 and configure SMB to require signed connections where 
feasible. 
• Configure host-based firewalls to only allow necessary services from 
trusted IPs. 

Long-term (Low priority / strategic) 
• Deploy network segmentation to separate user devices, servers, and 
management interfaces. 
• Implement VPN for administrative access from outside the LAN. 
• Introduce centralized logging and IDS/IPS to detect and alert scanning, 
lateral movement, and suspicious login attempts. 
• Schedule periodic vulnerability scanning and patch management cycles. 
Operational best practices 
• Use strong, unique passwords and account lockout policies. 
• Backup critical data and verify recovery procedures. 
• Train users about social engineering risks and suspicious activity. 
 
Conclusion (what you learned) 
• Conducting controlled Nmap scans on the lab subnet revealed two active 
hosts with a mix of consumer-device services (UPnP, HTTP) and Windows 
services (SMB, RDP, MySQL). 
• The primary risks identified are service exposure (RDP/MySQL), UPnP
enabled router behavior, and SMB-related attack surface on Windows 
hosts. 
• Practical mitigation is straightforward: restrict exposure via firewalls, 
disable unnecessary services, and employ network segmentation plus 
strong authentication. 
• The exercise reinforced the importance of redaction and ethical scanning 
practices: always obtain authorization and keep sensitive information 
secure in reports. 
