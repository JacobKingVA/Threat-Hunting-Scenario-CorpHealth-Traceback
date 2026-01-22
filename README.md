# 🕵️‍♂️ Threat-Hunting-Scenario-CorpHealth-Traceback


## 🎯 Scenario

Your organization recently completed a phased deployment of an internal platform known as CorpHealth — a lightweight system monitoring and maintenance framework designed to: 
 
    Track endpoint stability and performance
    Run automated post-patch health checks
    Collect system diagnostics during maintenance windows
    Reduce manual workload for operations teams 

CorpHealth operates using a mix of scheduled tasks, background services, and diagnostic scripts deployed across operational workstations.

To support this, IT provisioned a dedicated operational account.

This account was granted local administrator privileges on specific systems in order to: 

    Register scheduled maintenance tasks
    Install and remove system services
    Write diagnostic and configuration data to protected system locations
    Perform controlled cleanup and telemetry operations 

It was designed to be used only through approved automation frameworks, not through interactive sign-ins.

--Anomalous Activity-- 

In mid-November, routine monitoring began surfacing unusual activity tied to a workstation in the operations environment.

At first glance, the activity appeared consistent with normal system maintenance tasks:
 health checks, scheduled runs, configuration updates, and inventory synchronization.

However, closer review raised concerns:

    Activity occurred outside normal maintenance windows
    Script execution patterns deviated from approved baselines
    Diagnostic processes were launched manually rather than through automation
    Some actions resembled behaviors often associated with credential compromise or script misuse

Much of this activity was associated with an account that normally runs silently in the background.

> **Your mission**: 

You are taking over as the lead analyst assigned to review historical telemetry captured by: 

    Microsoft Defender for Endpoint
    Azure diagnostic and device logs (Sentinel)
    Supporting endpoint event artifacts 

You will not have live access to the machine — only its recorded activity.

Your task is to determine: 

    What system was affected
    When suspicious activity occurred
    How the activity progressed across different stages
    Whether the behavior represents authorized automation or misuse of a privileged account

The incident is not labeled as a confirmed breach.

It has been formally categorized as:

“An Operations Activity Review”

Your investigation will determine whether it remains just that — or escalates into something more.
---

## 🖥️ Environment Details

- **Host Involved**: `ch-ops-wks02`   
- **Telemetry Platform**: Microsoft Defender for Endpoint / Microsoft Sentinel (Log Analytics Workspaces)
- **Primary Threat**: Fake Maintenance Script (`MaintenanceRunner_Distributed.ps1`)

---
## 🚩 Flag 0 – Identify the Device

**Objective**: Identify the workstation which generated the unusual telemetry during outside normal maintenance hours.

**Hints:**
1. A small cluster of events during an unusual maintenance window.
2. Activity between Mid November to Early December.
3. Typical naming conventions for devices include abbreviating the company name as a prefix.

**Finding**:  
- **Device**: `ch-ops-wks02`  

**KQL Query**:
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime('2025-11-12') .. datetime('2025-12-4'))
| where DeviceName contains "ch-"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessCommandLine
```

**Notes:** Initial KQL script does not contain Device Name refinement to scan the entire workspace. However, script was refined to take into account that "CorpHealth" is the company. 'ch-ops-wks02' is the only workstation that fits the traditional naming schema illustrated in the flag hint. I was also able to narrow down the time frame more effectively for future queries.

<img width="1926" height="176" alt="image" src="https://github.com/user-attachments/assets/75189d2a-473b-48e6-b490-ec356c268745" />

---

## 🚩 Flag 1 – Identify the Unique Maintenance File

**Objective**: Identify the unique "maintenance" script that is unique to only this host.

**Hints:**
1. Focus on script-like files in locations or similar paths.
2. Think like an analyst doing "what's normal vs. what's unique on this box?".
3. Compare filenames across devices and look for a script that only shows up on CH-OPS-WKS02.

**Finding**:  
- **Potentially Malicious Maintenance Script**: `MaintenanceRunner_Distributed.ps1`   

**KQL Query (initial)**:
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-03) )
| where DeviceName == "ch-ops-wks02"
| where FolderPath has "maintenance"
| where InitiatingProcessCommandLine contains "ps1"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, FolderPath, InitiatingProcessAccountName, InitiatingProcessFileName
```
<img width="2091" height="305" alt="image" src="https://github.com/user-attachments/assets/ea45e341-58de-47d2-9cc4-6506a84b0a0e" />
<img width="1088" height="270" alt="image" src="https://github.com/user-attachments/assets/0da67b0d-d313-424d-b16d-5ea6df69f27d" />

**KQL Query (To Check for Other Hosts with the File in Question)**:
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-20) .. datetime(2025-12-03))
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed.ps1"
| summarize ScriptCount = count() by DeviceName
| order by ScriptCount desc
```
<img width="363" height="237" alt="image" src="https://github.com/user-attachments/assets/e33d0f86-2a34-4dc0-ba3b-d484c7c239eb" />

**Notes:** I wanted to first check DeviceFileEvents for any scripts that may be organized into "maintenance" tasks. Searching for a directory labeled "maintenance" seemed like a good initial path for inquiry. Additionally, searching for a powershell script seemed like a good place to start in analyzing likely automated maintenance scripts. While the file names themselves do not return much that would appear anomalous, I notice a timeframe that seems out of normal hours, and an account name that is likely unique to this host, "ops.maintenance". I expanded the first known result of this account's activity within the time window established and noticed a powershell script labeled "MainanceRunner_Distributed.ps1". I then used that script name to see if it was a task applied to other hosts. Upon review, it was unique to "ch-ops-wks01" as that was the only Device Name that was returned.

---

## 🚩 Flag 2 – Outbound Beacon Indicator

**Objective**: Determine when the maintenance script first intitiated outbound communication.

**Hints:**
1. Use DeviceNetworkEvents.
2. Filter for the exact device name and look for network activity generated by the suspicious script.
3. Compare filenames across devices and look for a script that only shows up on CH-OPS-WKS02.

**Finding**:  
- **Initial Outbound Communication Timestamp**: `2025-11-23T03:46:08.400686Z`

**KQL Query**:
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
```
<img width="2091" height="113" alt="image" src="https://github.com/user-attachments/assets/52ebe2a1-0c43-40c0-8d0b-a128f2f7da98" />

**Notes:** After identifying the first initiated outbound communication `2025-11-23T03:46:08.400686Z`, I noticed additional details that would be valuable in diving deeper into the threat hunt. I can see a suspicious outbound port and remote session device name. This KQL query leads into the next flag.

---

## 🚩 Flag 3 – Identify the Beacon Destination

**Objective**: Determine where the workstation was trying to beacon to and examine the network telemetry associated with the script execution and extract the actual network destination the host attempted to reach.

**Finding**:  
- **Remote IP:Port**: `127.0.0.1:8080`  

**KQL Query**:
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine contains "MaintenanceRunner_Distributed"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
```
<img width="378" height="67" alt="image" src="https://github.com/user-attachments/assets/093177b1-453a-4097-93cf-12bbd5e5c61a" />

**Notes:** From the previous query, it can be observed that there is a remoteIP of 127.0.0.1 and a Remote port of 8080. While 127.0.0.1 is a loopback address, it is still concerning especially with the context that remote port 8080 is being used. This can allude to port forwarding, tunneling, or proxies which can be used to deliver malware or remotely monitor the network. 

---

## 🚩 Flag 4 – Confirm the Successful Beacon Timestamp

**Objective**: Determine when the most recent (latest) timestamp where CH-OPS-WKS02 successfully connected to the beacon IP and port.

**Hints:**
1. Keep only events where InitiatingProcessCommandLine contains the maintenance script.
2. Match the RemoteIP and the RemotePort from the previous flag.
3. Take the newest entry.

**Finding**:  
- **Most Recent Connection Timestamp**: `2025-11-30T01:03:17.6985973Z`  

**KQL Query**:
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where DeviceName == "ch-ops-wks02"
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| where RemoteIP == "127.0.0.1"
| order by TimeGenerated desc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
```
<img width="2096" height="107" alt="image" src="https://github.com/user-attachments/assets/8f877cb9-26cc-4f0f-ba6a-943d44ac6ccc" />


**Notes:** I was able to narrow down the latest successful connection based on the initiating process command line script as well as the remote IP address. I verified the Remote port was 8080 in the results of the query. This is the anchor point to determine when the script reached out to the external IP. Further investigation is needed to determine what occurred as a result of that connection.

---

## 🚩 Flag 5 – Unexpected Staging Activity Detected

**Objective**: Check for staged data. What is the full file path of the First primary staging artifact created during the attack?

**Hints:**
1. Look for created files under any of the “CorpHealth” operational folders.
2. Focus especially on Diagnostics directories — attackers commonly use them for staging.

**Finding**:  
- **First Primary Staged Data File Path**: `C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv`

**KQL Query**:
```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-10)
| where DeviceName == "ch-ops-wks02"
| where FolderPath contains "CorpHealth"
| order by TimeGenerated asc  
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, SHA256
```
<img width="2065" height="275" alt="image" src="https://github.com/user-attachments/assets/82c2f1c1-f3bb-4eac-b587-e506d8c7291e" />

**Notes:** I chose to focus on files created in the "CorpHealth" operational folders on the device in question. From there, the resuls displayed files created under the "diagnostics" directory. The first one of these files that were created in the timespan being analyzed in that particular directory, the inventory_6ECFD4DF.csv file, is the first to have been generated, potentially indicating a staged file. 

---

## 🚩 Flag 6 – Confirm the Staged File's Integrity

**Objective**: Verify the file's cryptographic fingerprint (SHA-256 hash).

**Finding**:  
- **SHA-256 hash of the staged file**: `7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8`  

**KQL Query**:
```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-10)
| where DeviceName == "ch-ops-wks02"
| where FolderPath contains "CorpHealth"
| order by TimeGenerated asc  
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, SHA256
```
<img width="763" height="208" alt="image" src="https://github.com/user-attachments/assets/010c92ec-d5cd-4fc3-ab02-2731f84bb135" />

**Notes:** Using the previous flag's KQL query, the SHA-256 hash of the staged file is identified, and can be used to determine if the file is appearing elsewhere, possibly under a different name, or if a file that may appear to be the same contains different contents to the probable staged file.

---

## 🚩 Flag 7 – Identify the Duplicate Staged Artifact

**Objective**: After identifying a similarly named file, determine the full path of that file.

**Hints:**
1. Search for other files containing the word "inventory" created around the same timeframe.

**Finding**:  
- **File Path**: `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`

**KQL Query**:
```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-11-10)
| where DeviceName == "ch-ops-wks02"
| where FileName contains "inventory"
| order by TimeGenerated asc
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, SHA256
```
<img width="2082" height="63" alt="image" src="https://github.com/user-attachments/assets/fe755054-684b-4555-a3f0-8a994d1e6643" />

**Notes:** While the KQL query from the previous flag would suffice here, I decided to refine my query to specifically search for files containing the word "inventory" since it matches the staged file. It can be observed from this query that the hashes of the staged file and similarly named second file do not match. They are also in different storage paths. The second file is located in the user's temp directory. This may indicate intermediate processing which is when an attacker transforms or filters data prior to exfiltration.

---

## 🚩 Flag 8 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

**Hints:**
1. Look for registry events that occurred shortly before or after the temporary staging files were created.
2. Filter DeviceRegistryEvents by ActionType == "RegistryKeyCreated" or "RegistryValueSet". 

**Finding**:  
- **Anomalous Registry Key**: `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent`

**KQL Query**:
```kql
let TimeOfInterest = todatetime('2025-11-25T04:15:02.4575635Z');
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between ((TimeOfInterest - 3min) .. (TimeOfInterest + 3min))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, RegistryKey, InitiatingProcessCommandLine, InitiatingProcessFileName
```
<img width="1156" height="246" alt="image" src="https://github.com/user-attachments/assets/6ca14371-d575-4bb9-98a5-fddbb3e70570" />

**Notes:** The variable "TimeOfInterest" is set for the time in which the staged file and subsequent temp file were created and searched before and after that event to check for any anamolous registry activity. Right before that event occurred, a registry key was created that should not have been present. The query also shows that this key was created using PowerShell, which may indicate suspicious/malicious activity. 

---

## 🚩 Flag 9 – Scheduled Task Persistence

**Objective**: Moments after the credential-related registry anomaly, additional persistence patterns are observed. At least one scheduled task was successfully created earlier in the investigation window. Which Scheduled Task Did the Attacker First Create?

**Hints:**
1. Search DeviceRegistryEvents where: ActionType == "RegistryKeyCreated" or "RegistryValueSet"

**Finding**:  
- **File Path**: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64`

**KQL Query**:
```kql
let TimeOfInterest = todatetime('2025-11-25T04:15:02.4575635Z');
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between ((TimeOfInterest - 3min) .. (TimeOfInterest + 3min))
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| where RegistryKey contains "taskcache"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, RegistryKey, InitiatingProcessCommandLine, InitiatingProcessFileName
```
<img width="1117" height="241" alt="image" src="https://github.com/user-attachments/assets/8f642b26-1fad-4040-a2ed-11c41e196c3e" />

**Notes:** While the KQL query from the previous flag would suffice here, I decided to refine my query to specifically search for RegistryKeys containing "TaskCache". The TaskCache directory is important because it is the authoritative local record of all scheduled tasks on a Windows system. It is a valuable location to monitor for forms of persistence. Shortly after the time of interest, which is the creation of the staged and temp files from the previous flags, the "CorpHealth_A65E64" registry key was created.

---

## 🚩 Flag 10 – Registry-based Persistence

**Objective**: After observing a Run key value being created, a value written to an execution of a PowerShell script, and the value deleted shortly after, a potential ephemeral persistence event is hypothesized. What Registry Value Name was added to the Run key?

**Hints:**
1. Filter DeviceRegistryEvents for: RegistryKeyCreated, RegistryValueSet, RegistryKeyDeleted.

**Finding**:  
- **Registry Value Name**: `MaintenanceRunner`

**KQL Query**:
```kql
let TimeOfInterest = todatetime('2025-11-25T04:15:02.4575635Z');
DeviceRegistryEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between ((TimeOfInterest - 3min) .. (TimeOfInterest + 15min))
| where ActionType in ("RegistryKeyCreated", "RegistryValueSet", "RegistryKeyDeleted")
| where RegistryKey contains "run"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, InitiatingProcessCommandLine
| order by TimeGenerated asc 
```
<img width="1008" height="248" alt="image" src="https://github.com/user-attachments/assets/cff4d56f-1d81-4e6e-bec7-4a3b7faad128" />

**Notes:** While running this query without filtering for the "run" registry key would yield the correct result, adding this cleans up the results nicely since I am only concerned with the Run key being altered. It can be observed that the Value Name "MaintenanceRunner" was added to the Run key, a name that is relevant from earlier flags. Time of interest was expanded until the anomalous behavior was observed.

---

## 🚩 Flag 11 – Privilege Escalation Event Timestamp

**Objective**: During the intrusion, the attacker executed a simulated privilege-escalation action inside the MaintenanceRunner sequence. Locate the exact Timestamp (UTC) of the FIRST ConfigAdjust privilege-escalation event.

**Hints:**
1. Provide the timestamp exactly as the logs display it in its DeviceEvents logs.
2. This is not a process creation, registry modification, or network event — only an Application event. 

**Finding**:  
- **Timestamp**: `2025-11-23T03:47:21.8529749Z`

**KQL Query**:
```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where AdditionalFields contains "ConfigAdjust"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, AdditionalFields, DeviceName, InitiatingProcessCommandLine
```
<img width="2097" height="318" alt="image" src="https://github.com/user-attachments/assets/16f16606-d2ef-4d0d-91f9-fb4bf25c44a7" />

**Notes:** By searching for a configuration adjustment within the "AdditionalFields" parameter, it can be asserted that there is likely a privilege escalation or some other form of deliberate alteration likely to weaken defenses. While the Timestamp is the focus here, it is confirmed through the InitiatedProcessCommandLine that this has occured as part of the MaintenanceRunner sequence.

---

## 🚩 Flag 12 – Identify the AV Exclusion Attempt

**Objective**: What folder path did the attacker attempt to add as an exclusion in Windows Defender?

**Hints:**
1. This flag focuses on identifying the exact ExclusionPath the attacker attempted to protect from detection. (e.g. C:\...\...\...\...)

**Finding**:  
- **Folder Path**: `C:\ProgramData\Corp\Ops\staging`

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where ProcessCommandLine contains "ExclusionPath"
| order by TimeGenerated asc 
| project TimeGenerated, DeviceName, ActionType, AccountName, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="2085" height="386" alt="image" src="https://github.com/user-attachments/assets/89a30689-5bb7-4b72-ae5b-18f8d7fb8d0e" />

**Notes:** By filtering for "ExclusionPath" in ProcessCommandLine, I determined that the MaintenanceRunner PowerShell script is being executed to then try and create an exclusion in Windows Defender for the "\staging" directory. This would prevent that specific folder from real-time scanning.

---

## 🚩 Flag 13 – PowerShell Encoded Command Execution

**Objective**: During the intrusion, a PowerShell process executed using the -EncodedCommand flag. What decoded PowerShell command was executed First?

**Hints:**
1. Filter for EncodedCommand : 
    DeviceProcessEvents
    | where ProcessCommandLine contains "-EncodedCommand"
2. Filter for the AccountName in question, make sure to avoid system processes
3. Extract and decode the Base64 string:
    PowerShell Unicode Base64 decoding (local analyst method):[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("<encoded>"))
    KQL Unicode Base64 decoding (add this to your KQL): 
    | extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
    | extend Decoded = base64_decode_tostring(Enc)

**Finding**:  
- **Decoded Plaintext Command**: `Write-Output 'token-6D5E4EE08227'`

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where ProcessCommandLine contains "-EncodedCommand"
| where AccountName != "system"
| extend Enc = extract(@"-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Enc)
| order by TimeGenerated asc 
```
<img width="2057" height="243" alt="image" src="https://github.com/user-attachments/assets/d8d21df8-636f-409e-bffd-30454448796b" />

**Notes:** Since the -EncodedCommand PowerShell process is observed, this means that the attacker wanted to obfuscate what they were doing. This raises concerns so the next step would be to decode the encoded string which results in the decoded plaintext command: "Write-Output 'token-6D5E4EE08227'".

---

## 🚩 Flag 14 – Privilege Token Modification

**Objective**: Windows recorded a ProcessPrimaryTokenModified event. What is the "InitiatingProcessId" of the process whose token privileges were modified?

**Hints:**
1. Filter DeviceEvents where AdditionalFields contains either: "tokenChangeDescription" or "Privileges were added".

**Finding**:  
- **InitiatingProcessId**: `4888`

**KQL Query**:
```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where AdditionalFields contains "tokenChangeDescription" or AdditionalFields contains "Privileges were added"
| where InitiatingProcessCommandLine contains "Maintenance"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, AdditionalFields, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessId
```
<img width="2076" height="245" alt="image" src="https://github.com/user-attachments/assets/65775402-ef6f-46ff-8c7e-f5839c34c4e8" />

**Notes:** By filtering DeviceEvents for either "tokenChangeDescription" or "Privileges were added" along with narrowing down the InitiatingProcessCommandLine for the MaintenanceRunner script from flag 1, we can line up a log entry that displays the process whose token privileges were modified.

---

## 🚩 Flag 15 – Whose Token Was Modified?

**Objective**: Which security identifier (SID) did the modified token belong to?

**Hints:**
1. Start from the same query as Flag 14: Table: DeviceEvents
2. Filter on the same device and event:
   | where DeviceName == "ch-ops-wks02"
   | where AdditionalFields contains "tokenChangeDescription"

**Finding**:  
- **SID**: `S-1-5-21-1605642021-30596605-784192815-1000`

**KQL Query**:
```kql
DeviceEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where AdditionalFields contains "tokenChangeDescription" or AdditionalFields contains "Privileges were added"
| where InitiatingProcessCommandLine contains "Maintenance"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, AdditionalFields, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessId, InitiatingProcessAccountSid
```
<img width="2050" height="283" alt="image" src="https://github.com/user-attachments/assets/c3eb9349-0991-486a-bf85-aac79dc78f01" />

**Notes:** I refined the previous KQL script to include the InitiatingProcessAccountSid in order to find the original token user security principal (SID).

---

## 🚩 Flag 16 – Ingress Tool Transfer from External Dynamic Tunnel

**Objective**: After the privilege escalation, Defender recorded a new executable being written to disk on CH-OPS-WKS02. The timing and location of this file suggest it was delivered as staging material for follow-on activity. What is the name of the executable that was written to disk after the outbound request?

**Hints:**
1. Filter DeviceFileEvents by recent .exe writes.
2. Look for a file written into a user profile path.
3. Check which files were created immediately after curl.exe activity.

**Finding**:  
- **Executable Name**: `revshell.exe`

**KQL Query**:
```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where InitiatingProcessFileName contains "curl"
| order by TimeGenerated asc 
```
<img width="2012" height="118" alt="image" src="https://github.com/user-attachments/assets/27747bd8-b1dd-4923-80fe-abb4d767873e" />

**Notes:** From this query, it can be observed that the executable "revshare.exe" was written to disk on "ch-ops-wks02". The same query can be executed in DeviceNetworkEvents to line up with outbound request activity.

---

## 🚩 Flag 17 – Identify the External Download Source

**Objective**: What URL did the workstation connect to when retrieving the file?

**Hints:**
1. Search for outbound HTTPS activity initiated by curl.exe.

**Finding**:  
- **Remote URL**: `unresuscitating-donnette-smothery.ngrok-free.dev`

**KQL Query**:
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where InitiatingProcessFileName contains "curl"
| where RemotePort == "443"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl
```
<img width="1035" height="361" alt="image" src="https://github.com/user-attachments/assets/36e48ec3-8ec7-41e8-b4fc-a0f5a378e537" />

**Notes:** With this KQL query it can be observed that the host used curl.exe to reach out to a tunneling platform often used for temporary exposure of local services.

---

## 🚩 Flag 18 – Execution of the Staged Unsigned Binary

**Objective**: Shortly after the file was retrieved from the external tunnel, Defender recorded its execution on CH-OPS-WKS02. Which process executed the downloaded binary on CH-OPS-WKS02?

**Hints:**
1. Look for the execution of the file you identified in the prior flag.
2. The parent process is a common Windows shell component.
3. It was launched in a way resembling typical user interaction.
4. The execution happens after the Curl activity.

**Finding**:  
- **Process**: `explorer.exe`

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated > todatetime('2025-12-02T12:56:54.4356878Z')
| where FileName contains "revshell"
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```
<img width="1772" height="147" alt="image" src="https://github.com/user-attachments/assets/8b1be007-03d5-45e0-8e3b-f4bf10bd81a1" />

**Notes:** From this query, it can be observed that "revshell.exe" was executed by the process "explorer.exe". By using the timestamp from the previous flag, it can be observed that this occured after the Curl activity.

---

## 🚩 Flag 19 – Identify the External IP Contacted by the Executable

**Objective**: After execution on CH-OPS-WKS02, the downloaded binary attempted to initiate outbound communication to an external endpoint. Defender logged multiple failed TCP connection attempts to a remote IP on a high-nonstandard port. What external IP address did the executable attempt to contact after execution?

**Hints:**
1. Filter DeviceNetworkEvents by the executable’s name.
2. Look for ConnectionFailed or ConnectionAttempted events.

**Finding**:  
- **File Path**: `C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv`

**KQL Query**:
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where InitiatingProcessFileName contains "revshell"
| where ActionType == "ConnectionFailed"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType
```
<img width="1716" height="115" alt="image" src="https://github.com/user-attachments/assets/cab154cb-d881-4a98-b8d1-be51c297f8e0" />

**Notes:** With this KQL script, there is outbound activity observed with a failed connection to the RemoteIP "13.228.171.119" over a high nonstandard port "11746".

---

## 🚩 Flag 20 – Persistence via Startup Folder Placement

**Objective**: After the downloaded binary executed and attempted outbound communication, Defender recorded another file event involving the same executable. The file was copied into a Windows Startup directory — Which folder path did the attacker use to establish persistence for the executable?

**Hints:**
1. Search DeviceFileEvents for .exe files written outside the user profile path.
2. Look for directories containing "Start".
3. The path begins with c:\programdata\….
   
**Finding**:  
- **Folder Path**: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe`

**KQL Query**:
```kql
DeviceFileEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where FileName contains "revshell"
| where FolderPath contains "Start"
| project TimeGenerated, ActionType, DeviceName, FolderPath, InitiatingProcessAccountName
```
<img width="980" height="176" alt="image" src="https://github.com/user-attachments/assets/4191a255-7792-48ba-8812-0a2dd47ef702" />

**Notes:** By narrowing the query down to the relevant file (revshell.exe) and looking at directories containing "start", the path the attacker used to establish persistence is observed. 

---

## 🚩 Flag 21 – Identify the Remote Session Source Device

**Objective**: Several suspicious events — including file placement, network attempts, and execution — share the same remote session metadata. What is the remote session device name associated with the attacker’s activity?

**Hints:**
1. Look at any previous KQL results where InitiatingProcessRemoteSessionDeviceName is populated.
2. The same value appears repeatedly across several event types.

**Finding**:  
- **Remote Session Name**: `对手`

**KQL Query**:
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where InitiatingProcessFileName contains "revshell"
| where ActionType == "ConnectionFailed"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
```
<img width="642" height="385" alt="image" src="https://github.com/user-attachments/assets/74d83336-5775-48e0-950c-a66af54269b9" />

**Notes:** This was actually observed in earlier flags based on their respective KQL queries, however I modified a recent query to highlight the availability of the remote session name and IP address. It can be confirmed simply by using any other DeviceNetworkEvents query (as well as other queries) from previous flags.

---

## 🚩 Flag 22 – Identify the Remote Session IP Address

**Objective**: What IP address appears as the source of the remote session tied to the attacker’s activity?

**Hints:**
1. Look for fields named InitiatingProcessRemoteSessionIP.
2. The value is identical across all suspicious events.

**Finding**:  
- **Remote Session IP Address**: `100.64.100.6`

**KQL Query**:
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where InitiatingProcessFileName contains "revshell"
| where ActionType == "ConnectionFailed"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteIPType, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
```
<img width="575" height="63" alt="image" src="https://github.com/user-attachments/assets/86af3b85-dbf2-4a5b-8058-8aa60f339a58" />

**Notes:** This was achieved using the same query as the previous flag in addition to queries from earlier flags.

---

## 🚩 Flag 23 – Identify the Internal Pivot Host Used by the Attacker

**Objective**: The remote session metadata shows multiple IP addresses associated with the attacker’s activity. One of these addresses appears to be part of the internal Azure virtual network, suggesting the adversary either compromised another VM first or used an internal hop to reach CH-OPS-WKS02. Which internal IP address (non–100.64.x.x) appears as part of the attacker’s remote session metadata?

**Hints:**
1. internal Azure subnets typically start with 10.x.x.x.
2. exclude IPs in the 100.64.0.0/10 CGNAT/relay range.
3. Make sure to | distinct InitiatingProcessRemoteSessionIP

**Finding**:  
- **Internal IP**: `10.168.0.7`

**KQL Query (Initial)**:
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where InitiatingProcessRemoteSessionDeviceName contains "对手"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
```
**KQL Query (RemoteSessionIP Filter)**:
```kql
DeviceNetworkEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where InitiatingProcessRemoteSessionDeviceName contains "对手"
| order by TimeGenerated asc 
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP
| distinct InitiatingProcessRemoteSessionIP
```
<img width="747" height="207" alt="image" src="https://github.com/user-attachments/assets/380e97ad-fa52-42cb-bc74-ce4971bd5c1f" />
<img width="275" height="150" alt="image" src="https://github.com/user-attachments/assets/f02d9e51-7530-4966-b00f-a7946011c053" />

**Notes:** When using the InitiatingProcessRemoteSessionIP distinction in the KQL query, three IP addresses are observed, one external IP adress that has already been associated with the attacker and two private internal IP addresses. When observing the DeviceNetworkEvents based on the timeline of events, it can be observed that the initiating remote session IP address of 10.168.0.7 is the internal IP address that lines up with the initial anomalous activity.

## 🚩 Flag 24 – Identify the First Suspicious Logon Event

**Objective**: To determine when the adversary first accessed the system, we need to look at the earliest logon event tied to their activity. What is the earliest timestamp showing a suspicious logon to CH-OPS-WKS02?

**Hints:**
1. Use DeviceLogonEvents.
2. Sort by timestamp ascending.
3. The logon types of interest include RemoteInteractive (10), Network (3), RDP-style, and tool-based remote logons.

**Finding**:  
- **Timestamp**: `2025-11-23T03:08:31.1849379Z`

**KQL Query**:
```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where LogonType in ("RemoteInteractive" , "Network")
| where ActionType == "LogonSuccess"
| where RemoteDeviceName == "对手"
| order by TimeGenerated asc 
```
<img width="1965" height="276" alt="image" src="https://github.com/user-attachments/assets/d5228c1d-c3c4-4927-92bc-defb76200ee5" />

**Notes:** While narrowing down the DeviceLogonEvents query to only look for logons from the attacker, it can be observed that the first known instance of a suspicious logon occurs at the following timestamp: "2025-11-23T03:08:31.1849379Z"

---

## 🚩 Flag 25 – IP Address Used During the First Suspicious Logon

**Objective**: What IP address is associated with the earliest suspicious logon timestamp?

**Hints:**
1. Use the timestamp from the previous flag as your anchor point.
2. Look for the RemoteIP field in that exact logon event.
3. Compare against other later logons to confirm it is the earliest.

**Finding**:  
- **IP Address**: `104.164.168.17`

**KQL Query**:
```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where LogonType in ("RemoteInteractive" , "Network")
| where ActionType == "LogonSuccess"
| where RemoteDeviceName == "对手"
| order by TimeGenerated asc 
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteDeviceName, RemoteIP
```
<img width="557" height="241" alt="image" src="https://github.com/user-attachments/assets/dd9cc503-e03c-47f5-a7aa-b4d4f968e8e2" />

**Notes:** While projecting relevant information from the previous flag's query, it can be observed that the associated IP address from the first suspicious logon event is "104.164.168.17".

---

## 🚩 Flag 26 – Account Used During the First Suspicious Logon

**Objective**: Which account name appears in the earliest suspicious logon event?

**Hints:**
1. Use the earliest timestamp from the previous flag to anchor your search.
2. Look at the AccountName field for that exact logon event.
3. Ensure you are looking only at that first event, not the ones that follow.

**Finding**:  
- **Account Name**: `chadmin`

**KQL Query**:
```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where LogonType in ("RemoteInteractive" , "Network")
| where ActionType == "LogonSuccess"
| where RemoteDeviceName == "对手"
| order by TimeGenerated asc 
| project TimeGenerated, DeviceName, AccountName, ActionType, LogonType, RemoteDeviceName, RemoteIP
```
<img width="1592" height="32" alt="image" src="https://github.com/user-attachments/assets/b99b0efd-476d-4e32-8965-dd91aaf90d0d" />

**Notes:** Using the KQL script from the previous flag, I was able to determine the account name associated with the first suspicious logon event.

---

## 🚩 Flag 27 – Determine the Attacker’s Geographic Region

**Objective**: According to Defender geolocation enrichment, what country or region do the attacker’s IPs originate from?

**Hints:**
1. Use the suspicious IPs from the previous flag.
2. Use geo_info_from_ip_address(RemoteIP) to reveal country data.
3. All suspicious IPs belong to the same network range and should map to the same geographic region.

**Finding**:  
- **Location**: `Vietnam`

**KQL Query**:
```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between (datetime(2025-11-10) .. datetime(2025-12-03) )
| where LogonType in ("RemoteInteractive" , "Network")
| where ActionType == "LogonSuccess"
| where RemoteIP == "104.164.168.17"
| extend Geolocation = geo_info_from_ip_address(RemoteIP)
| order by TimeGenerated asc 
| project TimeGenerated, Geolocation, AccountName, ActionType, DeviceName, RemoteDeviceName, RemoteIP
```
<img width="1777" height="570" alt="image" src="https://github.com/user-attachments/assets/1b8f4b7f-a391-40e8-8fb1-e9ec5b749cf5" />

**Notes:** By using the geo_info_from_ip_address(RemoteIP) parameter it can be observed that all the suspicious activity from the attacker's IP address comes from Vietnam. The screenshot above details even more precise coordinates.

---

## 🚩 Flag 28 – First Process Launched After the Attacker Logged In

**Objective**: After establishing the attacker’s first login timestamp and origin IP, the next step is determining what they did immediately after gaining access. What was the first process launched by the attacker immediately after logging in?

**Hints:**
1. Use the timestamp from the earliest suspicious logon.
2. Search DeviceProcessEvents for processes whose AccountName matches that session.
3. Sort by timestamp ascending and pick the first process executed after the login time (Remember to reference AccountName and InitiatingProcessAccountName in your query).
4. The earliest processes are often things like cmd.exe, sethc.exe, mstsc.exe, shell access used by remote tools or it could be something as simple as viewing a file.

**Finding**:  
- **First Process**: `explorer.exe`

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where TimeGenerated between ((todatetime('2025-11-23T03:08:31.1849379Z') - 2min) .. (todatetime('2025-11-23T03:08:31.1849379Z') + 2min))
| where InitiatingProcessAccountName == "chadmin"
| order by TimeGenerated asc 
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessAccountName, InitiatingProcessCommandLine, ProcessCommandLine, FileName
```
<img width="566" height="240" alt="image" src="https://github.com/user-attachments/assets/fe9f8fc0-bd03-4926-b871-5d002c42fab5" />

**Notes:** Using this KQL query where the InitiatingProcessAccountName is specified as "chadmin", it can be observed that immediately after logging in, the attacker launched the process "explorer.exe".

---

## 🚩 Flag 29 – Identify the First File the Attacker Accessed

**Objective**: What file did the attacker open first after the previous flag?

**Hints:**
1. Use the earliest suspicious logon timestamp as your anchor point.
2. Look at DeviceProcessEvents for processes with arguments referencing files in the command line.
3. The attacker opened the file using a GUI application rather than a command-line tool.
4. Reference the previous flag's ProcessID to find this flag's InitiatingProcessID.

**Finding**:  
- **File Name**: `CH-OPS-WKS02 user-pass.txt`

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp > datetime(2025-11-23T03:08:31.1849379Z)
| where InitiatingProcessId == 5732
| order by TimeGenerated asc 
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, InitiatingProcessCommandLine, ProcessCommandLine
```
<img width="962" height="242" alt="image" src="https://github.com/user-attachments/assets/208007b9-34da-473c-b064-eb5b9f40b280" />

**Notes:** After adding to the "project" line of the previous flag's query to include ProcessId, it was determined that the ProcessId was "5732". This was then used as the InitiatingProcessId for this query. From there, it can be observed that the attacker opens up the "CH-OPS-WKS02 user-pass.txt" file using Notepad.

---

## 🚩 Flag 30 – Determine the Attacker’s Next Action After Reading the File

**Objective**: After viewing the file, the attacker moved on to their next step in the intrusion chain. Early post-logon behavior often reveals operational intent — whether they used stolen credentials, attempted lateral movement, escalated privileges, or launched additional tooling. What did the attacker do next after reading the file?

**Hints:**
1. Use the timestamp of the previous activity as an anchor.
2. Search for the next process timestamps immediately after the file was opened.
3. The next action may be: launching a command shell, attempting another logon, executing recon commands, initiating lateral movement.

**Finding**:  
- **Process Name**: `ipconfig.exe`

**KQL Query**:
```kql
DeviceProcessEvents
| where Timestamp >= todatetime('2025-11-23T03:11:00.6981995Z')
| where DeviceName == "ch-ops-wks02"
| order by TimeGenerated asc  
| take 10
| project TimeGenerated, DeviceName, AccountName, ActionType, FileName, InitiatingProcessCommandLine, InitiatingProcessFileName, ProcessCommandLine
```
<img width="687" height="280" alt="image" src="https://github.com/user-attachments/assets/c1fac464-fa1e-48c9-9015-a2ce2d1a9bfd" />

**Notes:** With this KQL query, it can be observed that the attacker launched ipconfig.exe. This can be used to display network information such as IP addresses, network interfaces, DNS information, subnets, VLANs, and more.

---

## 🚩 Flag 31 – Identify the Next Account Accessed After Recon

**Objective**: Following the attacker’s first round of local reconnaissance, the intrusion shifted from information-gathering to account-level interaction. Which user account did the attacker access immediately after their initial enumeration activity?

**Hints:**
1. Anchor your time window to the moment enumeration completed.
2. Look in DeviceLogonEvents for the next successful logon event after that timestamp.
3. Filter by the suspicious remote session device name or IP (the same one identified earlier).
4. You’re looking for the next account used, not the next process.

**Finding**:  
- **Account Name**: `ops.maintenance`

**KQL Query**:
```kql
DeviceLogonEvents
| where DeviceName == "ch-ops-wks02"
| where Timestamp > todatetime('2025-11-23T03:11:45.1631084Z')
| where ActionType == "LogonSuccess"
| where RemoteDeviceName == "对手"
| order by Timestamp asc
| take 10
| project TimeGenerated, DeviceName, AccountName, ActionType
```
<img width="676" height="135" alt="image" src="https://github.com/user-attachments/assets/8240a097-adeb-45c3-bad7-d49f005a1e69" />

**Notes:** Using this KQL query, it can be observed that the attacker accesses the "ops.maintenance" account following the completion of the initial enumeration activity. This lines up with other query results displaying that particular account linked to suspicious activity.

---

## 📌 Conclusion

After working backward through the attacker’s activity — from persistence artifacts to reconnaissance actions, then retracing their initial access — the full intrusion chain becomes clear. Each flag guided the analyst through identifying how the adversary entered the system, which accounts they leveraged, how they enumerated the host, and how they established outbound control via a reverse shell delivered through an ngrok tunnel.

By rebuilding the timeline from the inside out, the investigation not only surfaced the attacker’s tooling and behavior, but clarified intent: credential harvesting, situational awareness, and staging for remote command-and-control. Indicators such as remote session IPs, logon patterns, suspicious processes, and persistence paths provided the necessary context to confirm deliberate malicious access rather than benign administrative activity.

---
