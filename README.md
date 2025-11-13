# Task 1 — Local Network Port Scan
Date: 2025-11-13
Network scanned: 192.168.0.0/24
Tools: Nmap 7.98
Findings:
- 192.168.0.1: 22(ssh), 80(http), 1900(upnp)
- 192.168.0.102: 135(msrpc), 139(netbios), 445(SMB), 2869(icslap), 3306(mysql), 3389(RDP)
Risks & Mitigations:
- Disable UPnP on router; change default password; update firmware.
- Restrict MySQL to localhost or firewall it; patch Windows; restrict RDP or use VPN.
Files:
- Task.html, - Task 1.html.
