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

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 15 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 16 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 17 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 18 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 19 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 20 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 21 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 22 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 23 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 24 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 25 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 26 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 27 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 28 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 29 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 30 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 🚩 Flag 31 – Suspicious Registry Activity

**Objective**: Analysts reviewing the event timeline notice that a suspicious PowerShell script attempted to inspect or tamper with system configuration. Which exact registry key was created or touched during this activity?

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

## 📌 Conclusion

The Phantom Hackers successfully infiltrated Bubba's system by leveraging a fake antivirus dropper named **BitSentinelCore.exe**, delivered through a phishing vector. The attack established persistence via:

- Registry modifications
- Scheduled tasks
- Dropped artifacts indicating surveillance

Every step ties back to a singular initiating event, confirming the dropper's role in the compromise.

---
