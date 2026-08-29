# The Salt Crown
## CTF Overview
This CTF involved a full-spectrum forensic investigation spanning local Windows host artifacts and complex AWS cloud environments. The challenges required analyzing registry hives to reconstruct post-exploitation staging activity, parsing raw CloudTrail event logs with `jq` to trace identity pivots, and interacting directly with live S3 APIs to investigate tampered payloads and verify data integrity.

### Complete CTF Summary
Across five distinct challenge environments, I conducted end-to-end incident response investigations to track adversary behavior, reconstruct attack chains, and verify the integrity of affected data and infrastructure.
* **Host Registry Forensics (The Compressed Truth):** Analyzed a user's `NTUSER.DAT` registry hive using `reglookup` to trace post-exploitation tooling, including KeeFarce. Established key execution timestamps, mapped primary and secondary staging directories, identified files being prepared for exfiltration, and isolated the KeePass password vault containing the targeted master keys.
* **Cloud Audit Trail Tampering (Wrong Stamp):** Configured the AWS CLI against custom API endpoints and used `jq` to parse CloudTrail event streams. Uncovered compromised long-lived credentials associated with `stonepass-warden`, tracked external adversary activity, identified a failed attempt to execute `DeleteTrail`, and documented how the attacker ultimately used `StopLogging` to blind security controls.
* **Privilege Escalation & Ledger Tampering (Ashguard):** Combined CloudTrail log analysis with live S3 API queries to trace privilege escalation through `AssumeRole` into `ashguard-order-scanner`. Identified tampered S3 object paths, inspected object version histories, and performed line-by-line diffs to prove the exact modifications made to order quantities, authorization status fields, and cryptographic ledger hashes.
* **Infrastructure Recon & Credential Harvesting (Empty Chairs):** Analyzed multi-stage CloudTrail event streams from `all_events.json` to track an external adversary at `203.0.113.88`. Traced reconnaissance activity against SQS queues, identified unauthorized access attempts targeting Secrets Manager, and mapped the attacker's successful escalation into `eastreach-dispatch-role` through an assumed role session.
* **Queue Interception & Message Manipulation (Scout Diversion - Partial):** Began investigating downstream SQS queue manipulation following the identity pivot. Filtered raw CloudTrail logs using targeted `jq` expressions to map `ReceiveMessage` and `PurgeQueue` API activity, separating internal service traffic from external actor activity to determine how fraudulent recall orders were introduced into the message workflow.

---

# The Compressed Truth
During the **The Compressed Truth** investigation, I analyzed a compromised host's `NTUSER.DAT` Windows registry hive to reconstruct the threat actor's local post-exploitation and data staging activity.

Using `reglookup` to examine 7-Zip execution, path, extraction, and compression histories, I identified the deployment of KeeFarce, established key execution timestamps, mapped both primary and secondary staging directories, traced files being prepared for archival, and ultimately identified the KeePass vault containing the targeted master keys.

The investigation demonstrated how seemingly routine application artifacts stored in a user's registry hive can be used to reconstruct an attacker's workflow even when the original tools and files are no longer available on the system.

### Flag 1: Tool Used to Extract Secrets
* **Command Used:**

```bash
reglookup -p /Software/7-Zip NTUSER.DAT 2>/dev/null
```

* **Detailed Breakdown:** I started by inspecting the target user's `NTUSER.DAT` hive to see what files or tools had been handled through 7-Zip. I targeted the `/Software/7-Zip` key tree because 7-Zip stores several useful artifacts related to extraction history, recently accessed paths, and compression activity.

The command returned a URL-encoded string containing interleaved null bytes inside the `/Software/7-Zip/Extraction/PathHistory` value:

```text
C%00:%00\%00U%00s%00e%00r%00s%00\%00v%00m%00a%00r%00r%00\%00A%00p%00p%00D%00a%00t%00a%00\%00L%00o%00c%00a%00l%00\%00T%00e%00m%00p%00\%00w%00r%00i%00t%00\%00K%00e%00e%00F%00a%00r%00c%00e%00
```

To make sense of the raw data, I stripped out the null bytes (`%00`), which cleaned the string up into a readable path:

```text
C:\Users\vmarr\AppData\Local\Temp\writ\KeeFarce\
```

Seeing `KeeFarce` in the extraction path immediately identified the tool in question. KeeFarce is an open-source post-exploitation tool designed to dump credentials from running KeePass process memory into cleartext CSV files, making it particularly useful for attackers targeting password vaults after gaining local access.

The artifact showed that the attacker had extracted or staged KeeFarce within the user's temporary directory as part of their post-exploitation activity.

### Flag 2: Day and Time the Extraction Tool Was Executed
* **Command Used:**

```bash
reglookup -p /Software/7-Zip NTUSER.DAT 2>/dev/null
```

* **Detailed Breakdown:** After identifying KeeFarce, I needed to establish when the extraction activity occurred. Windows registry keys maintain last-write timestamps that can help place artifact changes into an investigation timeline.

Looking at the metadata for the parent extraction key:

```text
/Software/7-Zip/Extraction,KEY,,2026-06-18 13:15:15
```

This gave me a timestamp of:

```text
2026-06-18 13:15:15
```

Based on the surrounding 7-Zip extraction artifacts, this timestamp marked the relevant modification to the extraction history associated with the KeeFarce staging activity, allowing me to place that step within the broader post-exploitation timeline.

### Flag 3: Primary Staging Working Directory
* **Command Used:**

```bash
reglookup -p /Software/7-Zip/FM NTUSER.DAT 2>/dev/null
```

* **Detailed Breakdown:** Next, I needed to determine where the actor was actively working on the filesystem. The 7-Zip File Manager subkey (`/Software/7-Zip/FM`) records interface settings and recently used directory locations, making it useful for reconstructing where files were being accessed and staged.

I ran `reglookup` against that subkey and examined the `PanelPath0` entry:

```text
/Software/7-Zip/FM/PanelPath0,SZ,c:\users\vmarr\desktop\working\
```

The value was stored in plain text and pointed directly to:

```text
c:\users\vmarr\desktop\working\
```

This identified the actor's primary working directory. The location on the user's desktop suggested it was being used as an active workspace where files could be collected, organized, or prepared before moving into later staging or exfiltration locations.

### Flag 4: Secondary Public Staging Directory
* **Command Used:**

```bash
reglookup -p /Software/7-Zip/FM NTUSER.DAT 2>/dev/null
```

* **Detailed Breakdown:** To determine whether the threat actor was using additional staging locations, I examined the `/Software/7-Zip/FM/CopyHistory` key. This artifact tracks destination paths where files were copied or moved through the 7-Zip interface.

The output contained another URL-encoded path with interleaved null bytes:

```text
c%00:%00\%00u%00s%00e%00r%00s%00\%00p%00u%00b%00l%00i%00c%00\%00m%00u%00s%00i%00c%00\%00s%00a%00l%00t%00w%00o%00r%00k%00
```

After removing the null bytes, the path resolved to:

```text
c:\users\public\music\saltwork\
```

This revealed a secondary staging directory located inside the shared Public Music folder. Using a public media directory for staging can help an attacker blend malicious artifacts into a location that may receive less scrutiny than more obvious temporary or user-specific directories.

### Flag 5: Exfiltration Archive Subfolder Name
* **Command Used:**

```bash
reglookup -p /Software/7-Zip/FM NTUSER.DAT 2>/dev/null
```

* **Detailed Breakdown:** To trace the data being prepared for exfiltration, I queried the `/Software/7-Zip/FM/FolderHistory` key. This key retains a history of directories and archive paths navigated through the 7-Zip File Manager.

Parsing the longer path string showed the actor opening a compressed archive and navigating through its internal directory structure:

```text
C:\Users\vmarr\Documents\Registry\oath_records_cinderbound_vol2.zip\oath_records_cinderbound_vol2\saltoaths_secretive\
```

The specific subfolder accessed inside the archive was:

```text
saltoaths_secretive
```

This helped narrow down the portion of the archive that was relevant to the investigation and provided another artifact connecting the actor's file activity to data being prepared for movement or collection.

### Flag 6: Exfiltration Archive Preparation Timestamp
* **Command Used:**

```bash
reglookup -p /Software/7-Zip NTUSER.DAT 2>/dev/null
```

* **Detailed Breakdown:** I then wanted to identify when the attacker prepared their own archive for potential exfiltration. I queried the `/Software/7-Zip/Compression` key, where 7-Zip stores artifacts related to recent compression activity and archive destinations.

The `ArcHistory` value identified the target archive path:

```text
C:\Users\Public\Pictures\shardchain.tar
```

I then checked the last-write metadata associated with the parent compression key:

```text
/Software/7-Zip/Compression,KEY,,2026-06-18 13:25:06
```

This provided the timestamp:

```text
2026-06-18 13:25:06
```

The timestamp placed the compression activity roughly ten minutes after the KeeFarce-related extraction artifacts, helping establish the sequence of the actor's workflow from credential collection toward data staging and archive preparation.

### Flag 7: Vault Location Holding Master Keys
* **Command Used:**

```bash
reglookup -p /Software/7-Zip/FM NTUSER.DAT 2>/dev/null
```

* **Detailed Breakdown:** Finally, I needed to identify the exact location of the KeePass vault containing the targeted master keys.

I revisited the complete directory progression stored in `/Software/7-Zip/FM/FolderHistory` and followed the user's navigation history:

```text
C:\Users\vmarr\Documents\Registry\shard_storage\ShardKeepass_FirstMark\
```

Combining this directory with the target database file identified during the earlier artifact analysis gave me the complete vault path:

```text
C:\Users\vmarr\Documents\Registry\shard_storage\ShardKeepass_FirstMark\ShardKeepass_FirstMark.kdbx
```

This completed the local attack chain reconstruction. Starting with the extraction of KeeFarce, I was able to trace the actor's activity through their working directories, secondary staging location, archive preparation, and finally to the KeePass vault that contained the targeted master keys.

---

## Wrong Stamp
During the **Wrong Stamp** investigation, I analyzed CloudTrail event logs from a simulated AWS environment to trace an unauthorized session, identify the compromised credentials involved, and reconstruct the exact sequence of API activity that ultimately resulted in the audit trail being disabled.

The investigation required working directly with raw CloudTrail event data, parsing nested JSON payloads, distinguishing legitimate internal activity from external attacker activity, and correlating IAM identities, source IP addresses, API calls, and error codes into a chronological attack timeline.

### Environment Setup and Credentials Configuration
I began by pointing my local AWS CLI environment at the target challenge API endpoint running on port `30656` and exporting the provided credentials:

```bash
export AWS_ENDPOINT_URL=http://154.57.164.76:30656
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=AKIA7S5LH9LH2PNCRGOD
export AWS_SECRET_ACCESS_KEY=cnpQ6lfSkpPRJTUmPsMexi4eYVaIoXNCiqe+KSCv
unset AWS_SESSION_TOKEN
```

I then verified that the configuration was working and confirmed the identity associated with my active credentials using STS:

```bash
aws sts get-caller-identity
```

The output confirmed my active access and showed that I was operating as the `stonepass-investigator` IAM user:

```json
{
    "UserId": "AIDATORIP9ANXBH2NGCD",
    "Account": "491827305948",
    "Arn": "arn:aws:iam::491827305948:user/stonepass-investigator"
}
```

### Log Extraction and Parsing Methodology
My initial attempt to list available S3 buckets directly through the AWS CLI resulted in an `AccessDenied` error because the investigation credentials did not have permission for `s3:ListAllMyBuckets`.

Rather than relying on direct infrastructure enumeration, I pivoted to the CloudTrail event history and pulled the available events using the API's maximum result limit of 50:

```bash
aws cloudtrail lookup-events --max-results 50 > cloudtrail_events.json
```

One challenge with the output was that CloudTrail stored the actual event data as nested JSON strings inside the `CloudTrailEvent` field. This meant the outer JSON structure could not be used directly to cleanly analyze individual event fields.

To handle that, I installed `jq`:

```bash
sudo apt update && sudo apt install -y jq
```

I then built a custom `jq` pipeline that extracted the embedded CloudTrail JSON and parsed the event timestamp, API action, identity, source IP address, and error status into a chronological timeline:

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r '[.eventTime, .eventName, (.userIdentity.userName // .userIdentity.type), .sourceIPAddress, (.errorCode // "SUCCESS")] | @tsv' | sort -k1,1
```

This gave me a much cleaner view of the investigation data and made it possible to follow the session activity chronologically as it moved between internal and external IP addresses.

### Detailed Findings and Analysis Breakdown
#### Flag 1: Last API Action From Internal IP
* **Finding:** `ListAccessKeys`

* **Command & Method:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r '[.eventTime, .sourceIPAddress, .eventName, (.errorCode // "SUCCESS")] | @tsv' | sort -k1,1
```

* **Detailed Breakdown:** I filtered the event timeline chronologically and tracked activity originating from the internal network address `10.30.41.118`. The logs showed routine activity associated with the `stonepass-warden` account before the session activity later appeared from an external IP address.

Isolating the final event originating from `10.30.41.118` immediately before the external activity began revealed `ListAccessKeys` as the last API action performed internally.

This was an important pivot point in the timeline because it established the final observed activity associated with the internal environment before the compromised credentials were used externally.

#### Flag 2: First API Action From Attacker IP
* **Finding:** `GetTrailStatus`

* **Command & Method:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r '[.eventTime, .sourceIPAddress, .eventName, (.errorCode // "SUCCESS")] | @tsv' | sort -k1,1
```

* **Detailed Breakdown:** I then followed the event sequence associated with the external IP address `192.0.2.55`.

The logs showed that this activity was occurring under the compromised `stonepass-warden` credentials. The first API call issued from the external IP was `GetTrailStatus`.

This was a logical reconnaissance step for the attacker because it allowed them to check the current status of the target CloudTrail configuration before attempting to interfere with logging.

#### Flag 3: Denied API Action
* **Finding:** `DeleteTrail`

* **Command & Method:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r '[.eventTime, .sourceIPAddress, .eventName, (.errorCode // "SUCCESS")] | @tsv' | sort -k1,1
```

* **Detailed Breakdown:** To identify failed attacker activity, I reviewed the event timeline for non-success error codes and destructive API operations.

The logs showed that before disabling logging, the attacker attempted to completely remove the audit trail using `DeleteTrail`. CloudTrail recorded an explicit `AccessDenied` error for the request.

This indicated that the compromised credentials did not have sufficient permissions to delete the trail entirely. Rather than stopping there, the attacker pivoted to a different action that would still achieve their goal of disrupting security visibility.

#### Flag 4: Enumerated S3 Bucket
* **Finding:** `stonepass-audit-trail-logs`

* **Command & Method:**

```bash
cat cloudtrail_events.json | grep -iE "S3"
```

* **Detailed Breakdown:** I searched the raw event payloads for S3-related activity using a case-insensitive regular expression.

Inspecting the matching event structures showed the attacker interacting with the S3 bucket:

```text
stonepass-audit-trail-logs
```

The activity included `ListObjects` and `GetBucketLocation`, indicating that the attacker was enumerating the bucket and gathering information about the storage location associated with the audit trail.

#### Flag 5: Stopped CloudTrail Trail
* **Finding:** `stonepass-audit-trail`

* **Command & Method:**

```bash
cat cloudtrail_events.json | grep -iE "CloudTrail|stop"
```

* **Detailed Breakdown:** I searched the event data for CloudTrail-related activity and potential logging disruption commands using a dual-pattern regular expression.

Reviewing the matching JSON structures revealed the targeted resource identifier under `requestParameters.name`:

```text
stonepass-audit-trail
```

This identified the specific CloudTrail trail the attacker targeted during the final stage of the attack.

#### Flag 6: IAM Username Used to Disable Trail
* **Finding:** `stonepass-warden`

* **Command & Method:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r '.sourceIPAddress' | sort -u
```

Followed by a targeted search for activity originating from the external IP:

```bash
cat cloudtrail_events.json | grep "192.0.2.55"
```

* **Detailed Breakdown:** I first extracted all unique source IP addresses from the CloudTrail events to separate internal and external activity.

I then searched specifically for events originating from `192.0.2.55` and cross-referenced the associated identity information. While an automated background attempt involving `root` generated an `InternalFailure`, the attacker activity associated with the trail disruption was performed using credentials belonging to:

```text
stonepass-warden
```

This connected the external session directly to the compromised IAM identity responsible for the unauthorized actions.

#### Flag 7: IP Address Disabling Trail
* **Finding:** `192.0.2.55`

* **Command & Method:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r '.sourceIPAddress' | sort -u
```

```bash
cat cloudtrail_events.json | grep "192.0.2.55"
```

* **Detailed Breakdown:** Comparing activity from the internal host at `10.30.41.118` against the unique source IP addresses present in the event logs isolated `192.0.2.55` as the external address associated with the attacker.

The subsequent destructive CloudTrail activity originated from this external IP, establishing it as the source responsible for issuing the trail disruption commands using the compromised credentials.

#### Flag 8: API Action Used to Disable Trail
* **Finding:** `StopLogging`

* **Command & Method:**

```bash
cat cloudtrail_events.json | grep -iE "CloudTrail|stop"
```

* **Detailed Breakdown:** Following the failed `DeleteTrail` attempt, the attacker switched tactics.

Rather than removing the CloudTrail configuration entirely, they successfully disabled active event capture by issuing the `StopLogging` API call against the target trail.

This achieved the attacker's primary objective of reducing security visibility while avoiding the permission restrictions that prevented them from deleting the trail outright.

### Attack Chain Summary
The CloudTrail evidence showed a clear progression from internal credential activity to external abuse.

The final API action observed from the internal host `10.30.41.118` was `ListAccessKeys` under the `stonepass-warden` account. Activity then shifted to the external IP `192.0.2.55`, where the attacker began using the compromised credentials.

From there, the attacker first performed reconnaissance using `GetTrailStatus`, attempted and failed to execute `DeleteTrail`, enumerated the `stonepass-audit-trail-logs` S3 bucket using operations including `ListObjects` and `GetBucketLocation`, and ultimately issued `StopLogging` against `stonepass-audit-trail`.

The investigation demonstrated a complete attack sequence involving credential compromise, external session abuse, reconnaissance, attempted defense evasion, and the successful disruption of AWS audit logging.

---

## False Order
During the **False Order** investigation, I analyzed AWS CloudTrail logs (`cloudtrail_events.json`) alongside S3 storage artifacts to reconstruct an attack involving compromised long-lived credentials, privilege escalation through IAM role assumption, and the tampering of sensitive transaction records stored in S3.

By analyzing raw CloudTrail events with `jq` and querying the live S3 API through the AWS CLI, I was able to reconstruct the complete attack timeline, track the threat actor across multiple identity contexts and source IP addresses, identify the privilege escalation path, and isolate the exact payload that had been modified.

### Detailed Findings & Investigative Methodology
#### Flag 1: Last API Action Before Attacker Activity
* **Finding:** `ListObjectsV2`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r '[.eventTime, .sourceIPAddress, .eventName] | @tsv' | head -n 20
```

* **Detailed Breakdown:** To establish a baseline of normal activity and identify where the adversary's session began, I examined the earliest events in the CloudTrail timeline and compared the event names against their source IP addresses.

The activity immediately preceding the adversary's initial connection showed legitimate administrative services performing routine bucket indexing through `ListObjectsV2`.

This gave me a clean transition point between expected environment activity and the beginning of the suspicious external session.

#### Flag 2: First API Action Called From Attacker IP
* **Finding:** `GetCallerIdentity`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.sourceIPAddress=="76.37.92.180") | [.eventTime, .eventName, .userIdentity.userName] | @tsv' | head -n 5
```

* **Detailed Breakdown:** Filtering the CloudTrail events for unique external IP addresses revealed an initial connection originating from `76.37.92.180`.

I isolated and sorted the events associated with that IP to determine the first action performed by the adversary. Upon gaining access, the attacker immediately issued `sts:GetCallerIdentity`.

This was a typical initial reconnaissance step because it allowed the attacker to verify that the stolen access key pair was valid and confirm the IAM identity and AWS account context associated with the credentials.

#### Flag 3: Denied S3 Action During Initial Probing
* **Finding:** `GetObject`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.sourceIPAddress=="76.37.92.180" and .errorCode != null) | [.eventName, .errorCode, .requestParameters.bucketName, .requestParameters.key] | @tsv'
```

* **Detailed Breakdown:** Next, I wanted to see whether the adversary attempted to directly access sensitive data using their initial identity.

I filtered the external IP's activity for events where `errorCode` was not null, which isolated failed API requests. The results showed the attacker attempting to retrieve sensitive files directly from the target S3 bucket using `GetObject`.

The request was blocked by the existing policy boundaries, indicating that while the compromised credentials provided valid AWS access, they did not initially have the permissions required to read the target object.

#### Flag 4: Error Code Returned on Denied Probe
* **Finding:** `AccessDenied`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventName=="GetObject" and .errorCode!=null) | .errorCode' | head -n 1
```

* **Detailed Breakdown:** After identifying the failed `GetObject` request, I extracted the specific error returned by AWS.

The request generated:

```text
AccessDenied
```

This confirmed that the initial IAM credentials lacked the required permissions to directly read the targeted object, forcing the adversary to look for another path to gain access.

#### Flag 5: IP Address Used for AssumeRole and Destructive S3 Operations
* **Finding:** `198.18.44.91`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventName=="AssumeRole" or .eventName=="DeleteObject") | [.eventTime, .sourceIPAddress, .eventName] | @tsv'
```

* **Detailed Breakdown:** Tracing the event stream beyond the initial reconnaissance phase revealed a change in attacker infrastructure.

The initial probing activity originated from `76.37.92.180`, but the later privilege escalation and destructive S3 activity came from a second IP address:

```text
198.18.44.91
```

This pivot marked a new stage in the attack. From this address, the adversary attempted to escalate privileges through `AssumeRole` and later carried out the object modification sequence.

#### Flag 6: Compromised Long-Lived Credentials Owner
* **Finding:** `seal-copyist-contractor`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.sourceIPAddress=="76.37.92.180" or .sourceIPAddress=="198.18.44.91") | .userIdentity.userName // empty' | sort -u
```

* **Detailed Breakdown:** I examined the `userIdentity` data associated with the attacker's initial `GetCallerIdentity` and subsequent `AssumeRole` activity to identify the owner of the compromised long-lived credentials.

The CloudTrail logs tied the static access keys directly to the IAM user:

```text
seal-copyist-contractor
```

This established the attacker's original identity context before the privilege escalation sequence introduced a separate assumed-role identity.

#### Flag 7: Failed IAM Role Assumption Attempt
* **Finding:** `ashguard-order-auditor`

* **Command Used:**

```bash
cat cloudtrail_events.json | grep -iE "IAM|assumerole|denied|deny"
```

I then refined the initial search into a cleaner `jq` query:

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventName=="AssumeRole" and .errorCode!=null) | .requestParameters.roleArn' | awk -F'/' '{print $NF}'
```

* **Detailed Breakdown:** I searched for failed `AssumeRole` events to determine whether the attacker attempted to pivot into other IAM roles before finding one they could successfully assume.

The logs revealed an attempt to assume:

```text
arn:aws:iam::638291047582:role/ashguard-order-auditor
```

The request failed due to insufficient permissions or trust policy restrictions.

This showed that the eventual successful escalation was not the attacker's first attempt and helped reconstruct the trial-and-error process they used to identify an accessible role.

#### Flag 8: Role Session Name Specified During AssumeRole
* **Finding:** `coalition-gate-clerk`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventName=="AssumeRole" and .errorCode==null) | .requestParameters.roleSessionName'
```

* **Detailed Breakdown:** Inspecting the request parameters of the successful `AssumeRole` call allowed me to capture the custom session identifier supplied by the attacker.

The adversary specified:

```text
coalition-gate-clerk
```

as the role session name.

Because AWS records this value in the resulting assumed-role session identity, the session name became an important attribution artifact when tracking the attacker's actions later in the CloudTrail logs.

#### Flag 9: IAM Role Assumed for Destructive Session
* **Finding:** `arn:aws:iam::638291047582:role/ashguard-order-scanner`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventName=="AssumeRole" and .errorCode==null) | .requestParameters.roleArn'
```

* **Detailed Breakdown:** I examined the `requestParameters.roleArn` field associated with the successful `AssumeRole` event.

The logs showed that the adversary successfully assumed:

```text
arn:aws:iam::638291047582:role/ashguard-order-scanner
```

This represented the successful privilege escalation point in the attack chain. The attacker moved from compromised long-lived IAM credentials into a temporary STS session associated with a role that had the permissions needed to interact with the target custody bucket.

#### Flag 10: Full STS Principal ARN on DeleteObject Call
* **Finding:** `arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventName=="DeleteObject") | .userIdentity.arn'
```

* **Detailed Breakdown:** To verify the exact identity context used during the destructive operation, I isolated the `DeleteObject` event and extracted the full `userIdentity.arn` value recorded by CloudTrail.

The resulting principal ARN was:

```text
arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk
```

Because the action was performed with temporary credentials generated through `AssumeRole`, the ARN captured both the assumed role and the custom session name.

This provided a direct connection between the successful privilege escalation event and the later destructive S3 activity.

#### Flag 11: Tampered S3 Object Path
* **Finding:** `s3://ashguard-order-custody/custody/east-gate-order.json`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventSource=="s3.amazonaws.com" and (.eventName=="DeleteObject" or .eventName=="PutObject")) | [.requestParameters.bucketName, .requestParameters.key] | @tsv' | head -n 1 | awk '{print "s3://" $1 "/" $2}'
```

* **Detailed Breakdown:** I filtered the S3 data events for object modification operations, specifically `DeleteObject` and `PutObject`, and extracted the affected bucket and object key.

This reconstructed the full URI of the targeted object:

```text
s3://ashguard-order-custody/custody/east-gate-order.json
```

The attacker targeted this specific transaction record during the destructive phase of the incident.

#### Flag 12: S3 API Action Marking Forged Upload
* **Finding:** `PutObject`

* **Command Used:**

```bash
jq -r '.Events[].CloudTrailEvent' cloudtrail_events.json | jq -r 'select(.eventSource=="s3.amazonaws.com") | [.eventTime, .eventName, .requestParameters.key] | @tsv'
```

* **Detailed Breakdown:** I examined the sequence of S3 API events surrounding the destructive activity.

Immediately after the original object was deleted with `DeleteObject`, the attacker issued a `PutObject` request against the same key path.

This established the full modification sequence: the original transaction record was removed and replaced with a forged JSON payload under the exact same object key.

---

### Artifact Reconstruction & Evidence Analysis
After reconstructing the CloudTrail attack sequence, I needed to determine exactly what had changed inside:

```text
s3://ashguard-order-custody/custody/east-gate-order.json
```

To do that, I queried the live S3 API, inspected the object's version history, retrieved both versions of the file, and compared the original payload against the forged replacement.

#### Step 1: Listing Object Versions
* **Command Used:**

```bash
aws s3api list-object-versions --bucket ashguard-order-custody --endpoint-url http://154.57.164.65:31402
```

* **Detailed Breakdown:** Querying the bucket's version history revealed two distinct versions of `custody/east-gate-order.json`:
  * **Original Version ID:** `f7819fa0-b08c-40c5-88a1-9a5adc8218a8`
  * **Forged Version ID (Latest):** `cb93f47b-6dc1-4929-9d45-e4c14e8573d2`

The presence of versioning allowed me to recover both the original and modified payloads instead of relying solely on the latest object state.

#### Step 2: Fetching Object Payloads
* **Commands Used:**

```bash
# Fetch Original File
aws s3api get-object --bucket ashguard-order-custody --key custody/east-gate-order.json --version-id f7819fa0-b08c-40c5-88a1-9a5adc8218a8 original_order.json --endpoint-url http://154.57.164.65:31402

# Fetch Forged File
aws s3api get-object --bucket ashguard-order-custody --key custody/east-gate-order.json --version-id cb93f47b-6dc1-4929-9d45-e4c14e8573d2 tampered_order.json --endpoint-url http://154.57.164.65:31402
```

* **Detailed Breakdown:** Using the version IDs returned by `list-object-versions`, I downloaded both iterations of the object locally.

This allowed me to preserve the original and forged versions as separate files and perform a direct comparison without altering either artifact.

#### Step 3: File Comparison and Diff Analysis
* **Command Used:**

```bash
diff original_order.json tampered_order.json
```

* **Detailed Breakdown:** Comparing the original JSON payload against the forged version revealed four significant modifications:

```json
/* Original Order (f7819fa0) */
{
  "settlement_id": "EAST-GATE-C4R2",
  "season": "winter",
  "gate": "coalition-gate",
  "issuer": "Coalition Gate Authority",
  "issued_date": "2026-01-09",
  "total_units": 1840,
  "custody_status": "SEALED",
  "order_status": "PENDING_APPROVAL",
  "witness_line": "The gatehouse clerk attested the sealed order before dawn watch.",
  "ledger_hash": "sha256:4f8c2a91e0b7d3c6a5f1e9d8c7b6a5049382716f5e4d3c2b1a0f9e8d7c6b5a4"
}

/* Forged Order (cb93f47b) */
{
  "settlement_id": "EAST-GATE-C4R2",
  "season": "winter",
  "gate": "coalition-gate",
  "issuer": "Coalition Gate Authority",
  "issued_date": "2026-01-09",
  "total_units": 920,
  "custody_status": "RELEASED",
  "order_status": "RELEASED",
  "witness_line": "Gate release authorized per emergency writ WR-4412; witness attestation waived.",
  "ledger_hash": "sha256:4f8c2a91e0b7d3c6a5f1e9d8c7b6a5049382716f5e4d3c2b1a0f9e8d7c6b5a5"
}
```

The comparison revealed four specific alterations:
* **Quantity Reduction:** `total_units` was cut in half, changing from `1840` to `920`.
* **Status Fraud:** Both `custody_status` and `order_status` were changed from `SEALED` and `PENDING_APPROVAL` to `RELEASED`.
* **Attestation Bypass:** The original witness attestation was replaced with a fabricated emergency authorization referencing writ `WR-4412`, allowing the forged order to appear as though normal approval requirements had been bypassed.
* **Hash Tampering:** The `ledger_hash` was modified from a value ending in `5a4` to one ending in `5a5`, reflecting an attempt to make the altered payload appear internally consistent.

### Full Incident Timeline
1. **Initial Access & Recon (`76.37.92.180`):** The adversary authenticated using stolen long-lived access keys belonging to `seal-copyist-contractor` and issued `GetCallerIdentity` to confirm that the credentials were valid.
2. **Access Denial (`76.37.92.180`):** The adversary attempted to directly retrieve `s3://ashguard-order-custody/custody/east-gate-order.json` using `GetObject`, but the request was blocked with `AccessDenied`.
3. **Failed Privilege Escalation (`198.18.44.91`):** After shifting infrastructure, the adversary attempted to assume `arn:aws:iam::638291047582:role/ashguard-order-auditor`, but the request failed due to insufficient permissions or trust policy restrictions.
4. **Successful Privilege Escalation (`198.18.44.91`):** The adversary successfully assumed `arn:aws:iam::638291047582:role/ashguard-order-scanner` using the custom session name `coalition-gate-clerk`, gaining a temporary STS identity with the permissions required to modify objects in the target bucket.
5. **Ledger Tampering (`198.18.44.91`):** Using the assumed-role session `arn:aws:sts::638291047582:assumed-role/ashguard-order-scanner/coalition-gate-clerk`, the adversary issued `DeleteObject` against `custody/east-gate-order.json`.
6. **Forged Replacement (`198.18.44.91`):** Immediately after deleting the original object, the attacker issued `PutObject` against the same key path and replaced the transaction record with a forged JSON payload.
7. **Evidence Reconstruction:** By querying S3 version history and comparing both object versions, I recovered the original transaction record and proved the exact changes made to the quantity, custody status, approval status, witness authorization, and ledger hash.


---

## Empty Chairs
During the Empty Chairs investigation, I analyzed AWS CloudTrail log streams (`all_events.json`) to trace a multi-stage attack against the cloud infrastructure. The investigation revealed an external adversary operating from `203.0.113.88` who initially authenticated using compromised long-lived access keys belonging to `eastreach-relay-watch`. From there, the attacker began probing internal SQS message queues and Secrets Manager for sensitive credentials.

After identifying and successfully retrieving the `eastreach/watchpost/dispatch-creds` secret, the attacker used the recovered credentials to escalate their access through `AssumeRole`. This allowed them to adopt `arn:aws:iam::719384620571:role/eastreach-dispatch-role` under the session name `dispatch-runner`. With the elevated role in place, the attacker was able to issue unauthorized commands against the watchpost infrastructure, manipulate routing data, and ultimately attempt to destroy evidence of their activity.

### Flag 1. Long-Lived Access Key Identity
* **Question:** Which IAM user name owned the long-lived access key used to start the attack chain?
* **Problem Solving & Analysis:** I started by looking at the earliest API activity in `all_events.json` and filtering for events containing an access key ID. Examining the `userIdentity` fields allowed me to connect the initial `AKIA...` credential back to the IAM user that owned it. This established the identity associated with the long-lived credential used to begin the attack chain.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.userIdentity.accessKeyId != null) | [$ct.eventTime, $ct.userIdentity.userName, $ct.userIdentity.accessKeyId] | @tsv' all_events.json | head -n 10
```

* **Answer:** `eastreach-relay-watch`

### Flag 2. Identifying the Attacker's External Infrastructure
* **Question:** From which external IP did the contractor perform the full scout diversion attack (including PurgeQueue)?
* **Problem Solving & Analysis:** I next looked at the source IPs recorded throughout the CloudTrail data. Filtering out internal `10.x.x.x` addresses helped isolate the public IPs responsible for activity outside the expected internal network. I then compared the external addresses against the S3, SQS, and STS management activity to identify the IP associated with the full malicious action chain.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | $ct.sourceIPAddress' all_events.json | sort | uniq -c | sort -nr
```

* **Answer:** `203.0.113.88`

### Flag 3. Analyzing Internal SQS Traffic
* **Question:** What is the source IP on the last ReceiveMessage before a non-internal IP performs ReceiveMessage on that same queue?
* **Problem Solving & Analysis:** I filtered the CloudTrail events down to `ReceiveMessage` operations so I could reconstruct the sequence of SQS activity. By reviewing the events chronologically and identifying the final internal request immediately before the external IP interacted with the same queue, I was able to isolate the internal source address associated with the last expected read.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventName == "ReceiveMessage") | [$ct.eventTime, $ct.sourceIPAddress] | @tsv' all_events.json
```

* **Answer:** `10.23.86.15`

### Flag 4. Access Denied Secrets Probe
* **Question:** On the live diversion source IP, which secret name returned AccessDenied on the first denied GetSecretValue call?
* **Problem Solving & Analysis:** Once I established the attacker's external IP, I used it to narrow the Secrets Manager activity to `203.0.113.88`. Filtering for `GetSecretValue` operations with a populated `errorCode` exposed the failed credential-access attempts. The `requestParameters.secretId` field then showed which secret the attacker attempted to access before finding a path to credentials they could actually retrieve.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.sourceIPAddress == "203.0.113.88" and $ct.eventName == "GetSecretValue" and $ct.errorCode != null) | [$ct.eventTime, $ct.requestParameters.secretId, $ct.errorCode] | @tsv' all_events.json
```

* **Answer:** `eastreach/watchpost/master-key`

### Flag 5. Successful Secrets Read
* **Question:** Which secret name was successfully read before the role assumption?
* **Problem Solving & Analysis:** I then looked for successful `GetSecretValue` operations from the same external IP, filtering for events where `errorCode` was null. Comparing the timestamps against the subsequent STS activity showed which secret was successfully retrieved immediately before the privilege escalation attempt. This connected the Secrets Manager activity directly to the later role pivot.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.sourceIPAddress == "203.0.113.88" and $ct.eventName == "GetSecretValue" and $ct.errorCode == null) | [$ct.eventTime, $ct.requestParameters.secretId] | @tsv' all_events.json
```

* **Answer:** `eastreach/watchpost/dispatch-creds`

### Flag 6. Failed IAM Role Assumption
* **Question:** Which IAM role name did the attacker fail to assume before the successful pivot? (role name only, not ARN)
* **Problem Solving & Analysis:** With the recovered secret establishing the credential-access portion of the attack chain, I moved into the STS events to look for privilege escalation attempts. Filtering for failed `AssumeRole` requests exposed the initial role the attacker attempted to access. The `roleArn` field provided the complete target, while the error information confirmed that the attempt was unsuccessful.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventSource == "sts.amazonaws.com" and $ct.eventName == "AssumeRole" and $ct.errorCode != null) | [$ct.eventTime, $ct.requestParameters.roleArn, $ct.errorMessage] | @tsv' all_events.json
```

* **Answer:** `eastreach-admin-role`

### Flag 7. Successful Role Assumption ARN
* **Question:** Which IAM role ARN was successfully assumed to control watchpost routing?
* **Problem Solving & Analysis:** After identifying the failed escalation attempt, I searched for successful `AssumeRole` events originating from `203.0.113.88`. Filtering for events without an `errorCode` isolated the successful pivot and allowed me to extract the exact role ARN used to gain elevated access to the watchpost routing environment.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventSource == "sts.amazonaws.com" and $ct.eventName == "AssumeRole" and $ct.errorCode == null) | [$ct.eventTime, $ct.requestParameters.roleArn] | @tsv' all_events.json
```

* **Answer:** `arn:aws:iam::719384620571:role/eastreach-dispatch-role`

### Flag 8. Session Identification
* **Question:** What roleSessionName was used on the successful AssumeRole?
* **Problem Solving & Analysis:** I examined the parameters of the successful `AssumeRole` event to identify the session created by the attacker. The `roleSessionName` value is useful here because it provides the session identifier assigned by the client when the temporary role credentials were created. This gave me the session name associated with the successful privilege escalation.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventName == "AssumeRole" and $ct.errorCode == null) | [$ct.eventTime, $ct.requestParameters.roleSessionName] | @tsv' all_events.json
```

* **Answer:** `dispatch-runner`

### Flag 9. CloudTrail Identity Types Post-Pivot
* **Question:** What IAM identity type does CloudTrail record for API calls made after the successful role pivot?
* **Problem Solving & Analysis:** After confirming the successful role assumption, I checked subsequent API activity to verify how CloudTrail represented actions performed with the temporary credentials. Looking at the `userIdentity.type` field on the post-pivot `GetObject` activity confirmed that the attacker was no longer operating solely under the original IAM user identity and was instead using the assumed role session.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.sourceIPAddress == "203.0.113.88" and $ct.eventName == "GetObject") | $ct.userIdentity.type' all_events.json
```

* **Answer:** `AssumedRole`

### Flag 10. Target SQS Queue
* **Question:** What is the SQS queue name targeted for the fraudulent scout recall order?
* **Problem Solving & Analysis:** With the attacker established as operating through the elevated role, I followed the subsequent SQS activity to identify the queue targeted by the fraudulent recall operation. Filtering for `SendMessage` calls exposed the queue URL in `requestParameters.queueUrl`, which provided the target queue associated with the injected message.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventName == "SendMessage") | [$ct.eventTime, $ct.requestParameters.queueUrl] | @tsv' all_events.json
```

* **Answer:** `eastreach-scout-recall`

### Flag 11. Injected Order ID
* **Question:** What order_id value was injected in the fraudulent scout recall order?
* **Problem Solving & Analysis:** After identifying the target queue, I examined the `messageBody` associated with the `SendMessage` event. The payload contained the order details being injected into the queue, including the `order_id` value used to identify the fraudulent recall order.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventName == "SendMessage") | $ct.requestParameters.messageBody' all_events.json
```

* **Answer:** `ORD-94827-RECALL`

### Flag 12. Injected Route Override
* **Question:** What route_override destination did the attacker set in the fraudulent order?
* **Problem Solving & Analysis:** I used the same `SendMessage` payload to inspect the routing information embedded in the fraudulent order. Parsing the message body exposed the `route_override` value, showing the destination the attacker attempted to redirect the scout toward.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventName == "SendMessage") | $ct.requestParameters.messageBody' all_events.json
```

* **Answer:** `SECTOR-9-OUTPOST`

### Flag 13. Decryption and KMS Key Analysis
* **Question:** What KMS keyId did the attacker use when decrypting the routing envelope after SendMessage?
* **Problem Solving & Analysis:** I followed the message injection into the KMS activity that occurred afterward. Filtering for `kms.amazonaws.com` events and extracting the `keyId` from `Decrypt` operations allowed me to identify the KMS key involved in decrypting the routing envelope. Correlating this activity with the preceding `SendMessage` event tied the decryption operation to the attacker's injected routing data.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventSource == "kms.amazonaws.com") | [$ct.eventTime, $ct.eventName, $ct.requestParameters.keyId] | @tsv' all_events.json
```

* **Answer:** `arn:aws:kms:us-east-1:719384620571:key/08462050-3846-2050-3846-205038462050`

### Flag 14. SNS Notification Topic
* **Question:** What SNS topic name received the diversion alert Publish call?
* **Problem Solving & Analysis:** I continued following the attack across AWS services by filtering the CloudTrail data for SNS operations. Looking specifically at `Publish` events exposed the `topicArn` in the request parameters, allowing me to identify the notification topic that received the diversion alert.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventSource == "sns.amazonaws.com") | [$ct.eventTime, $ct.eventName, $ct.requestParameters.topicArn] | @tsv' all_events.json
```

* **Answer:** `eastreach-diversion-alerts`

### Flag 15. DynamoDB Ledger Alteration
* **Question:** What DynamoDB table name received the forged ledger PutItem?
* **Problem Solving & Analysis:** I then moved to the DynamoDB events to identify where the attacker wrote the forged ledger record. Filtering for DynamoDB API calls and extracting the `tableName` associated with `PutItem` operations exposed the database table targeted by the modification.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventSource == "dynamodb.amazonaws.com") | [$ct.eventTime, $ct.eventName, $ct.requestParameters.tableName] | @tsv' all_events.json
```

* **Answer:** `eastreach-watchpost-ledger`

### Flag 16. S3 Data Event Logging Formats
* **Question:** What is the S3 access log operation field for the GetObject on signed-routing-bundle.json from the external IP?
* **Problem Solving & Analysis:** For this part of the investigation, I searched the raw log data for both S3 activity and `GetObject` operations. The resulting record used S3's REST-style operation naming rather than the standard CloudTrail API event name. This distinction was important because the field being asked for was the access log operation value, not simply the API call name.
* **Command Used:**

```bash
cat all_events.json | grep -iE "s3|GetObject"
```

* **Answer:** `REST.GET.OBJECT`

### Flag 17. CloudTrail Verification Before Destruction
* **Question:** What is the name of the CloudTrail trail the attacker verified before purging queue evidence?
* **Problem Solving & Analysis:** Before looking at the final evidence-destruction step, I checked the CloudTrail activity for signs that the attacker was verifying the state of the logging infrastructure. Filtering for `cloudtrail.amazonaws.com` events exposed a `GetTrailStatus` request, which showed that the attacker checked the logging trail before continuing with the cleanup activity.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventSource == "cloudtrail.amazonaws.com") | "\($ct.eventTime) | \($ct.eventName) | \($ct.requestParameters)"' all_events.json
```

* **Answer:** `eastreach-watchpost-trail`

### Flag 18. Queue Purge Action
* **Question:** Which API action destroyed the queue evidence at the end of the attack chain?
* **Problem Solving & Analysis:** Finally, I isolated the SQS activity and generated a chronological list of the API actions performed against the service. Reviewing the activity toward the end of the attack chain showed `PurgeQueue` being used as the final evidence-destruction action, removing the messages from the targeted queue after the fraudulent activity had been carried out.
* **Command Used:**

```bash
jq -r '.Events[]? | (.CloudTrailEvent | fromjson) as $ct | select($ct.eventSource == "sqs.amazonaws.com") | "\($ct.eventTime) | \($ct.eventName)"' all_events.json
```

* **Answer:** `PurgeQueue`

---

## Key Takeaways & Investigation Summary
### Host Forensics & Artifact Analysis
In the host forensics phase, I focused on recovering post-exploitation artifacts from a targeted Windows host by digging directly into the user's `NTUSER.DAT` registry hive. Using `reglookup`, I worked through 7-Zip history keys to reconstruct the adversary's local staging activity and establish a timeline of their actions. I tracked down where the actor dropped `KeeFarce` to dump password database secrets from memory, identified the associated execution timestamps, and mapped their staging locations across both the local desktop and hidden public directories.

Following the actor's directory traversal through the registry also helped me locate the exact exfiltration archives they prepared and trace the path back to the master password vault file they were targeting. This gave me a clearer picture of what happened on the host before the investigation moved into the cloud environment.

### AWS Incident Response & Cloud Forensics
The cloud portion of the challenge shifted the focus to deeper AWS incident response, where I parsed raw CloudTrail event logs and interacted directly with live S3 APIs using `jq` and the AWS CLI. Across scenarios such as Wrong Stamp, Ashguard, and Empty Chairs, I mapped complete multi-stage attack chains from initial access through objective execution.

I isolated compromised long-lived access keys, tracked external attacker IPs, identified failed privilege escalation attempts, and captured successful `AssumeRole` pivots used to move beyond the attacker's initial permissions. I also followed the activity across SQS, Secrets Manager, STS, KMS, SNS, DynamoDB, S3, and CloudTrail to understand how the different services fit together as the attack progressed.

Beyond identifying how attackers attempted to blind monitoring through `StopLogging` calls, I used S3 object versioning to recover both original and tampered ledger files. Comparing the versions and running payload diffs allowed me to prove exactly how transaction records, unit quantities, and attestation hashes had been altered.

### Bringing It All Together
Working through these challenges really highlighted how complementary host and cloud investigations are when you're hunting an adversary across modern environments. Whether I'm pulling URL-encoded paths out of a local Windows registry or untangling nested JSON event streams in CloudTrail to identify an assumed role session, the core approach stays the same: gather the raw data, structure it, and follow the evidence step by step.

The biggest takeaway for me was seeing how much context can be recovered by connecting seemingly isolated artifacts. A registry entry can establish what happened on an endpoint, while a CloudTrail event can show how those compromised credentials were later used against cloud infrastructure. Being able to pivot between host-level artifact recovery and cloud infrastructure analysis gives me a much more complete picture of an incident, from the moment credentials are compromised on an endpoint to the final exfiltration, tampering, or evidence-destruction attempt in the cloud.
