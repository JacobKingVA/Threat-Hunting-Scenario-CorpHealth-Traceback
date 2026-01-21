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

**Notes:** After identifying the first initiated outbound communication `2025-11-23T03:46:08.400686Z`, I noticed additional details that would be valuable in diving deeper into the threat hunt. I can see a suspicious outbound port and remote session device name. This KQL query leads into the next flag.
---

## 🚩 Flag 4 – Keylogger Artifact Written

**Objective**: Detect keylogging behavior or artifacts.

**Finding**:  
- **Suspicious Artifact**: `systemreport.lnk`  
- **Dropped via**: `explorer.exe` (indicating interaction)  
- **Session Origin**: BUBBA

**KQL Query**:
```kql
let VmName = "anthony-001";
let Time = datetime(2025-05-07T02:00:36.794406Z);
DeviceFileEvents
| where DeviceName == VmName
| where InitiatingProcessFileName == "explorer.exe"
| where InitiatingProcessRemoteSessionDeviceName == @"BUBBA"
| where Timestamp < datetime(2025-05-07T04:12:46.0432324Z)
```

![image](https://github.com/user-attachments/assets/29c8da74-eac4-4dfe-9a1f-148ca2aa20e3)

**Notes:** Searched for files using filters that targeted those created after executing the malware (`BitSentinelCore.exe`) and with the initiating process filename `explorer.exe`, as this was the same process that launched the malware.


---

## 🚩 Flag 5 – Registry Persistence Entry

**Objective**: Check for registry changes that provide persistence.

**Finding**:  
- **Registry Path Modified**:  
  `HKEY_CURRENT_USER\S-1-5-21-...\Microsoft\Windows\CurrentVersion\Run`  
- **Process**: `BitSentinelCore.exe`

**KQL Query**:
```kql
let VmName = "anthony-001";
let Time = datetime(2025-05-07T02:00:36.794406Z);
DeviceRegistryEvents
| where DeviceName == VmName
| where InitiatingProcessFileName contains "bitsentinelcore"
```

![image](https://github.com/user-attachments/assets/ba369c73-66c8-481b-b46b-45aa6499cc79)

**Notes:** Using MDE’s `DeviceRegistryEvents` table made it easy to identify the exact registry modification that enabled the malware to run.


---

## 🚩 Flag 6 – Daily Scheduled Task Created

**Objective**: Discover persistence through scheduled tasks.

**Finding**:  
- **Scheduled Task Name**: `UpdateHealthTelemetry`  
- **Created by**: `schtasks.exe` launched from `cmd.exe`

**KQL Query**:
```kql
let VmName ="anthony-001";
let Time = datetime(2025-05-07T02:00:36.794406Z);
DeviceProcessEvents
| where DeviceName == VmName
| where FileName contains "schtasks.exe"
| where ActionType == "ProcessCreated"
```

![image](https://github.com/user-attachments/assets/067262a6-786f-481a-9293-11c0287739d0)

**Notes:** While reviewing the `DeviceProcessEvents` table, I searched for entries containing `schtasks.exe` and found suspicious command lines with `UpdateHealthTelemetry`.

---

## 🚩 Flag 7 – Process Spawn Chain

**Objective**: Trace the attack chain of process execution.

**Finding**:  
- **Chain of Execution**:  
  `BitSentinelCore.exe → cmd.exe → schtasks.exe`

![image](https://github.com/user-attachments/assets/656377eb-0dc6-433d-820d-c0b0ccd607e8)

**Notes:** After inspecting the process tree, I was able to identify the chain of attack from the malware.

---

## 🚩 Flag 8 – Timestamp Correlation

**Objective**: Tie all activity back to a single root cause.

**Finding**:  
- **Initial Compromise Time**: `2025-05-07T02:00:36.794406Z`  
- All malicious actions—file writes, execution, registry and task creation—trace back to this timestamp.

**Notes:** When searching for the file the user originally clicked—**"BitSentinelCore"**—I retrieved the timestamp from the **`DeviceFileEvents`** table.

---

## 📌 Conclusion

The Phantom Hackers successfully infiltrated Bubba's system by leveraging a fake antivirus dropper named **BitSentinelCore.exe**, delivered through a phishing vector. The attack established persistence via:

- Registry modifications
- Scheduled tasks
- Dropped artifacts indicating surveillance

Every step ties back to a singular initiating event, confirming the dropper's role in the compromise.

---
