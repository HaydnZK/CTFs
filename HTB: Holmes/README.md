# Holmes CTF

## Quick summary
### Scope
Initial reconnaissance, log analysis, web application inspection, PCAP and host forensics across four lab challenges. This write-up captures the investigative steps I used to recover flags and artifacts, why each step worked, and lessons for future hunts.
- Targets: three web applications exposed via Docker IPs and ports — CogWork Security (threat analysis), CogWork-Intel Graph (link analysis), and CogNet Scanner (device discovery).

- Approach: browse and enumerate web apps, review access/app/WAF logs, pivot through CTI link graphs, analyze PCAPs in Wireshark, search extracted file systems for artifacts, crack KeePass vaults, and run memory inspection with Volatility.

- Outcome: discovered web shell, beacon IDs, exfiltrated database, malware indicators and hash, prompt-injection credential leak, persistence artifacts, local credentials for lateral movement, and kernel information from a memory image.

### Environment and tools used
- Lab artifacts: Docker-hosted web apps, PCAPs, extracted filesystem images, memory dump, KeePass .kdbx file.

- Tools and utilities (examples of what I used and why): curl and a browser for app inspection, text searches with grep for quick pattern hunting, Wireshark/TShark for PCAP analysis, the lab CTI web interfaces for graph pivoting,
keepass2john + John the Ripper for cracking KeePass, and Volatility 3 for memory analysis.

- When a direct timeline or network trace was not available, I searched the full extracted filesystem for strings and IP patterns to recover evidence missed by the PCAP and other provided logs.

### Methodology: how I think while hunting
- Rapid reconnaissance: open web apps in a browser, use browser inspector and basic HTTP requests to find likely inputs, upload endpoints, or interesting comments. This quickly reveals where attackers might target.

- Log triage: review access logs, app logs, and WAF logs in parallel. I look for outliers first — unusual user-agents, large POSTs, requests to upload endpoints, or WAF rules firing for downloads.

- Pivot via CTI: take an indicator (user-agent fragment, hash, or domain) into the link analysis platform, and pivot outward to the campaign or associated indicators. Partial-string matches often reveal more than exact matching.

- PCAP deep-dive: where the lab provides PCAPs, filter on the IPs/hostnames or interesting protocols and follow streams to view payloads. Save the raw streams that show exfil or credential leakage.

- Filesystem hunting: when PCAPs or logs are incomplete, run recursive string searches across the extracted filesystem for IP patterns, domain strings, hashes, or filenames referenced elsewhere.

- Correlate timelines: map timestamps from logs, PCAPs, event logs, and memory artifacts to build a coherent narrative of the attack. This is what verifies causality.

- Preserve artifacts: keep the raw PCAP, log slices, and any memory snapshots or KeePass files in an artifacts folder so the report references can be rechecked.

## Challenge 1: The Card (Initial Recon & Findings)
### Targets and first steps
Targets were the three web apps listed above. I started by loading each app in a browser and using the network inspector to see endpoints and upload locations. I also requested the public endpoints with curl to collect raw access responses. 
Those two actions quickly showed an upload endpoint and some suspicious POST traffic in the provided access logs.

#### Flag 1: Beacon ID: 4A4D
- What I looked for: periodic outbound callbacks in the logs and any small repeating identifiers tied to those callbacks.

- How I found it: I scanned the access logs for recurring outbound HTTP/S requests to external IPs and matched timestamps. The periodic callbacks contained an ID string in the query or payload that repeated regularly. That ID was 4A4D.

- Why it matters: repetitive callbacks with a fixed ID are classic C2 beacon behavior.

#### Flag 2: Initial user-agent: Lilnunc/4A4D - SpecterEye
- What I looked for: user-agent strings that didn’t match normal browser traffic or known service traffic.

- How I found it: I read through the web app access logs and compared user-agent values against the expected pool of legitimate entries. There was a single entry that looked handcrafted and never reappeared in regular traffic. That entry was
- Lilnunc/4A4D - SpecterEye.

- Extra detail: I cross-checked timestamps to ensure the suspicious UA lined up with the earliest file creation timestamps (uploads and keygen events) to confirm it was used during the initial compromise.

#### Flag 3: Web shell: /uploads/temp_4A4D.php
- What I looked for: uploaded files and WAF exceptions.

- How I found it: I inspected WAF logs for entries showing allowed POSTs to the uploads directory and then followed the corresponding access log entries to the server’s filesystem. The uploads folder contained the file temp_4A4D.php and the
- file's creation time matched the first beacon activity. WAF log entries showed attempts that should have blocked that request, but a misconfigured rule or bypass allowed it.

- Why the WAF bypass is useful: it explains persistence; web shells are effective when the WAF doesn’t sanitize or detect the specific payload.

#### Flag 4: Exfiltrated DB: database_dump_4A4D.sql
- What I looked for: large GET/POST responses, WAF alerts for data downloads, or any log entries flagged by data-exfil rules.

- How I found it: the WAF logs included a rule hit labelled for database downloads. That rule pointed to a URL that returned a download. Following the access logs for that URL led to the filename database_dump_4A4D.sql. Timestamps linked the
- download to the same campaign ID as the beacons.

- Extra verification: file size and HTTP response code confirmed a successful transfer.

#### Flag 5: Honeypot attack count: 5
- What I looked for: CTI graph activity showing campaigns and linked endpoints.

- How I found it: in the Intel Graph I searched by the user-agent fragments first and saw nothing. Then I searched for the substring 4A4D - SpecterEye, which returned several nodes. From there I focused on the node representing the central endpoint 
and expanded connected campaigns. The graph showed five distinct attack instances targeting a single endpoint that corresponded to a honeypot. The honeypot endpoint's notes indicated it was non-malicious, explaining the “honeypot” observation and count of 5.

#### Flag 6: How many tools: 9
- What I looked for: the set of distinct tool/malware nodes in the CTI campaign view.

- How I found it: after locating the campaign node, I removed filters and toggled the full campaign visualization. I manually counted unique tool nodes in the campaign that were associated with the timeline. That count was 9. The lesson: once you identify 
the pivot node, removing constraints in the graph reveals the true breadth of the campaign.

#### Flag 7: Malware hash: 7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477
- What I looked for: the malware node that culminated in a rootkit install.

- How I found it: in the CTI platform I clicked the malware node identified as a rootkit and navigated to its indicators. The platform provided the hash directly in its indicator details. No external lookups were needed. I recorded the full hash visible 
in the details.

#### Flag 8: IP linked to malware: 74.77.74.77
- What I looked for: network indicators within the malware node.

- How I found it: after selecting the malware node in the platform and expanding details, the platform listed C2 IPs and contact points. One of those IPs was 74.77.74.77. This link was clear in the platform’s connectivity tab.

#### Flag 9: Malware persistence path: /opt/lilnunc/implant/4a4d_persistence.sh
- What I looked for: file system paths and persistence artifacts included in the malware indicators panel.

- How I found it: the malware details included an observed file path where the implant created a persistence script. The path was recorded in the “crafted indicators” section of the CTI entry.

#### Flag 10: Server open ports: 11
- What I looked for: host scan results from CogNet.

- How I found it: I opened the CogNet Scanner, inspected the host details for the IP used in the campaign, and counted the open ports listed in the scan results. The scanner displayed 11 open ports for that host.

#### Flag 11: Owning organization: SenseShield MSP
- What I looked for: whois / ownership info included in scanner details.

- How I found it: the CogNet host details included an ownership field or organization name that listed SenseShield MSP. This came from the scanner’s enrichment data.

#### Flag 12: Hidden message: He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE
- What I looked for: notes, comments or service messages attached to the host.

- How I found it: while reviewing the services and notes section for the IP in CogNet, one service entry contained a comment. That comment was the quoted message plus the tag NULLINC REVENGE.

## Challenge 2: The Watchman's Residue
###Objective
Investigate the msp-helpdesk-ai capture, identify the decommissioned host and its hostname, find the initial attacker messages and confirm the credential leak via prompt injection.

#### Flag 1: Decommissioned IP: 10.0.69.45
- What I did: I opened the provided PCAP and filtered for unusual user-agent strings. There was a stream with a non-standard Windows NT user-agent and multiple POST requests to /api/messages/send. I followed that HTTP stream to see the content. 
The associated 4-tuple (src/dst IP and ports) matched a single IP that was being treated as a decommissioned host in the lab description. Filtering by the host IP and inspecting conversation frequency confirmed it was the decommissioned machine at 10.0.69.45.

#### Flag 2: Hostname: WATSON-ALPHA-2
- What I did: I filtered the PCAP for NBNS (NetBIOS) packets. There were only three NBNS packets and each contained the same NetBIOS name in the response field. I traced the source IP of those NBNS packets which matched 10.0.69.45. From the NBNS payload 
I extracted the NetBIOS name, which was WATSON-ALPHA-2. I made note of the NetBIOS suffix <1c> in a comment since it confirms a machine service type, but the flag only required the hostname.

#### Flag 3: First attacker message: Hello Old Friend
- What I did: With the IP isolated, I applied a Wireshark filter ip.addr == 10.0.69.45 and looked for HTTP POSTs. I found POST /api/messages/send events. For each POST I used Follow > HTTP Stream to inspect the raw HTTP payload. The very first meaningful 
POST payload contained the plaintext "Hello Old Friend." That payload was not obfuscated and was captured in the stream payload; I exported that stream text as evidence.

####Flag 4: When was the leak: 2025-08-19 12:02:06
- What I did: Within the same HTTP stream I noted the exact timestamp for the POST where the AI responded with credentials. Using Wireshark’s packet timestamps I recorded the packet timestamp that contained the credential leak. The packet showed the AI’s 
response payload and the timestamp 2025-08-19 12:02:06. I cross-checked nearby timestamps to confirm the sequence: initial greeting, escalation, credential disclosure.

#### Flag 5: RMM credentials: 565963039:CogWork_Central_97&65
- What I did: After isolating the HTTP stream, I scrolled through the payload until I found the AI’s response. The AI’s reply included plaintext RMM credentials. I copied the ID and password exactly from the response packet content and confirmed those 
exact credentials appeared again later in logs when a remote session started. The lab’s PCAP and server logs provided corroboration — the same credentials were used for a TeamViewer/RMM session.

#### Flag 6: Final message: JM WILL BE BACK
- What I did: Continuing to follow the conversation stream to its end, the last payload emitted by the attacker contained "JM WILL BE BACK." I captured that final segment from the same HTTP stream and noted the final packet index in the PCAP.

#### Flag 7: Attacker access time: 2025-08-20 09:58:25
- What I did: I switched to connection logs and authentication logs on the target workstation. These logs included timestamps for RMM/TeamViewer sessions. I searched for successful logins correlating to the RMM account and found an entry with timestamp 
2025-08-20 09:58:25 corresponding to a JM login event. That established when the attacker used the stolen credentials to access the workstation.

#### Flag 8: RMM account used: James Moriarty
-What I did: I reviewed TeamViewer and RMM system logs for the names associated with the incoming connections. The connection detail showed an account name under the user field. The attacker used an RMM account labeled James Moriarty. I captured the entry 
showing both the account name and the source connection ID.

#### Flag 9: Internal IP: 192.168.69.213 (attacker source)
- What I did and why it was tricky: The PCAP did not include the timeframe where the attacker connected to the internal network. I attempted to time-filter the PCAP for the RMM session window but saw nothing. Instead, I exported and recursively searched the 
extracted filesystem for IPv4 strings to find references to internal IPs stored in logs/configs. I used a recursive grep for the IPv4 regex across the challenge folder and then filtered results to private address ranges. From the list I identified 192.168.69.213 
as the internal IP associated with the attacker’s connection events referenced in local logs. This method worked because system logs and cached files sometimes persist network artifacts even when the PCAP is incomplete.

#### Flag 18L Heisen-9-WS-6 Credentials: Werni:Quantum1!
- What I found: an acquired KeePass file named "acquired file (critical).kdbx".

- How I cracked it: I converted the .kdbx to a hash format compatible with John the Ripper and used a wordlist-based attack. The cracking process returned the KeePass master password cutiepie14. Using that password I opened the KeePass vault and located 
credentials for Heisen-9-WS-6: username Werni and password Quantum1!. I confirmed the credentials were valid by matching them to recorded local authentication events in the extracted logs.

Notes: when record-level PCAPs are missing, KeePass and other credential stores in the filesystem often reveal the missing link.

## Challenge 3: The Enduring Echo (Windows host forensics)
#### Flag 2: Parent process of malicious process: C:\Windows\System32\wbem\WmiPrvSE.exe
- How I found it: I exported the Windows event logs, specifically Process Creation events (Event ID 4688 or Sysmon ProcessCreate if available). I scanned the Creator Process Name field for entries where the child process was the malicious executable or 
command lines related to attacker activity. The Creator Process Name aligned to WmiPrvSE.exe as the parent in those process creation events. This showed the attacker used WMI service processes to spawn commands.

#### Flag 6: Persistence script path: C:\Users\Werni\Appdata\Local\JM.ps1
-How I found it: I read through PowerShell operational logs and the PowerShell event log where script blocks or command lines are recorded. I searched for jm.ps1 and found repeated invocations. The event records included the full path and timestamps showing 
repeated execution that matched other lateral movement events. The repeated invocations confirmed the script’s role in persistence.

#### Flag 7: Attacker-created local username: svc_netupd
- How I found it: the JM.ps1 script either created or attempted to create local accounts. Inspecting the script content and correlating with local SAM references and user creation logs (Event ID 4720) showed that svc_netupd was created and used by the attacker. 
I validated by searching local security logs for account creation events and subsequent logon attempts using svc_netupd.

#### Flag 8:Exfiltration domain: NapoleonsBlackPearl.htb
- How I found it: JM.ps1 contained a URI or an encoded string indicating where harvested credentials would be posted. The script content included a domain string, which I decoded and verified against outbound network records where available, and/or the domain 
appeared in exfil artifact filenames. That domain was the destination for exfiltrated credentials.

## Challenge 4 — The Tunnel Without Walls (memory analysis and kernel artifacts)
#### Flag 1: Linux kernel version: 5.10.0-35-amd64
- How I found it: I analyzed the memory dump with Volatility 3. The linux banners or kernel structures in memory include the boot banner that contains the kernel version. I used the appropriate Volatility plugin to extract banners from the memory image and 
read the kernel version string directly from the banner output.

## Takeaways
#### Useful specific commands and steps
- To search for suspicious user-agents in access logs: use grep for the exact token, for example grep -i "Lilnunc" against the web access logs.

- To find uploaded web shells, search upload directories and cross-check creation timestamps in web logs with those in the filesystem. For example, search the web root for temp_4A4D.php and compare its mtime to log timestamps.

- To recover plaintext HTTP payloads in PCAPs, filter on the source IP and then follow the HTTP stream in Wireshark using the Follow > HTTP Stream option. This shows the raw POST/response payloads.

- To pull NetBIOS hostnames, filter the PCAP for nbns packets and inspect the name strings in the packet detail pane.

- To collect all IPv4 strings from an extracted filesystem, run a recursive grep with an IPv4 regex across the challenge folder and then sort/filter for private ranges to find internal IPs.

- To crack a KeePass .kdbx, convert the database to a John the Ripper compatible hash format with the keepass2john helper and run john with a wordlist like rockyou to brute-force the master password. Once cracked, open the database and review saved credentials.

#### Evidence preservation and reproducibility notes
- Save raw PCAPs and the exact log slices you used to identify each flag. Keep a small artifacts folder with the extracted HTTP stream text for any credential exfil.

- Record the exact grep patterns and Wireshark filters you used; that makes your work reproducible and auditable.

- When posting any raw evidence snippets in a public repo, consider redacting or obfuscating live credentials and IPs, unless the lab is intentionally public.

#### Lessons learned and recommendations
- Partial matches are powerful. The user-agent fragment approach is a good example: searching for the entire user-agent returned nothing, but searching for the recurring substring revealed campaign-level links.

- AI systems are a new exfil vector. Treat any natural-language endpoint that can access credentials or secrets as high-risk. Always sanitize and strictly limit response scope; log function inputs and outputs.

- When PCAP traces are incomplete, the filesystem is often the single source of truth. Logs, caches, and temp files can contain copies of the strings you need.

- Correlate across all telemetry: WAF, app logs, CTI, PCAPs, and endpoints. Correlation builds the narrative and proves how artifacts relate to each other.

- Preservation matters. Save the raw artifacts that prove each flag. That helps if you need to reproduce or justify any finding later.
