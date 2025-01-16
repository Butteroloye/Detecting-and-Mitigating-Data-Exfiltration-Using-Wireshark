# Detecting-and-Mitigating-Data-Exfiltration-Using-Wireshark

I worked on a Lab using Hack The Box; where I received an alert from an Intrusion Detection System (IDS) regarding unusual outbound traffic originating from a workstation (IP: 192.168.1.101) during non-business hours. The alert indicated high data transfer rates to an unknown IP address (203.0.113.45). This raised concerns about potential data exfiltration.

Objective:

Investigate the unusual outbound traffic to confirm if it is malicious.
Identify the data being transferred and the method of exfiltration.
Take corrective actions to mitigate the threat and prevent recurrence.


Steps Taken:

1. Setting Up Traffic Capture with Wireshark

Opened Wireshark on a secured KALI Linux system connected to the mirrored port and began capturing live traffic.
Saved the capture session to a .pcap file for further offline analysis.

2. Filtering and Prioritizing Relevant Traffic
Applied the following filters in Wireshark to isolate the traffic from the workstation: ip.addr == 192.168.1.101
Observed continuous TCP connections to an external IP (203.0.113.45) over port 443 (HTTPS).
Narrowed the focus by filtering specifically for HTTPS traffic: ip.addr == 192.168.1.101 && tcp.port == 443

4. Decoding Suspicious Traffic
Used the "Follow TCP Stream" feature to inspect payload data. Although the traffic was encrypted (HTTPS), metadata such as the TLS Server Name Indication (SNI) revealed the domain associated with the external IP: malicious-server.com.
Cross-referenced the domain with threat intelligence platforms like VirusTotal and confirmed it was linked to a known Command and Control (C2) server.
5. Analyzing Metadata and Patterns
Detected abnormal patterns, such as large volumes of POST requests to https://malicious-server.com/upload every few seconds.
Checked packet sizes and noticed unusually large payloads, indicating potential file uploads.
6. Correlating with System Activity
Cross-referenced Wireshark logs with the workstation’s logs (using tools like Sysmon and Event Viewer) to identify the source of the traffic.
Discovered a malicious PowerShell script running on the workstation. The script was downloading files from the local system and transmitting them to the C2 server.
7. Mitigation Actions
Immediate Response:
Blocked outbound traffic to 203.0.113.45 at the firewall.
Isolated the compromised workstation from the network to contain the threat.
Forensic Preservation:
Exported Wireshark .pcap files and workstation logs for forensic analysis.
Captured a memory dump of the affected system for further investigation.
Threat Removal:
Removed the malicious script and scanned the system using endpoint security tools.
8. Root Cause Analysis
Identified the source of infection: a phishing email containing a malicious attachment disguised as an invoice.
Analyzed historical network traffic using Wireshark and found that two other systems had communicated with the same external IP, indicating they might also be compromised.
9. Preventative Measures
Strengthened email security by implementing stricter filtering rules for attachments and links.
Enhanced endpoint protection policies to monitor and block suspicious PowerShell scripts.
Conducted a company-wide awareness session on phishing and social engineering attacks.
Automated network traffic monitoring with alerts for high outbound traffic or connections to known malicious domains.
Outcome:
Successfully mitigated the data exfiltration attempt, preventing further data loss.
Identified and remediated two additional compromised systems.
Strengthened the organization's security posture with new preventative measures.
Presented a detailed incident report to stakeholders, showcasing Wireshark's role in detecting and resolving the issue.
