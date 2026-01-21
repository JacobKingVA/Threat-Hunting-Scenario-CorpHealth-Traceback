# 🕵️‍♂️ Threat-Hunting-Scenario-CorpHealth-Traceback


## 🎯 Scenario

At **Acme Corp**, the eccentric yet brilliant IT admin, **Bubba Rockerfeatherman III**, isn't just patching servers — he's the secret guardian of **trillions in digital assets**. Protected under his privileged account are **private keys, sensitive data, and intellectual gold**.

But the shadows have stirred.

A covert APT group known only as **The Phantom Hackers 👤** has launched a targeted campaign. Known for weaponizing **fileless malware**, **stealthy persistence**, and **social engineering**, their goal is clear: **steal everything without ever being seen**.

**The breach has begun.**  
A successful phishing campaign has compromised the network. Bubba is unaware that his own endpoint is now a battlefield.

> **Your mission**: Hunt through **Microsoft Defender for Endpoint (MDE)** telemetry, follow the trail, and stop the attackers before they exfiltrate the crown jewels of cyberspace.

---

## 🖥️ Environment Details

- **Host Involved**: `anthony-001`  
- **Primary User**: Bubba Rockerfeatherman III  
- **Telemetry Platform**: Microsoft Defender for Endpoint  
- **Primary Threat**: Fake Antivirus Dropper (`BitSentinelCore.exe`)

---

## 🧩 Flag 1 – Identify the Fake Antivirus Program Name

**Objective**: Identify the deceptive program that initiated the incident.

**Finding**:  
- **Malicious Binary**: `BitSentinelCore.exe`  
- **Path**: `C:\ProgramData\`  
- **Initiated from Remote Session**: `BUBBA`

**KQL Query**:
```kql
let VmName = "anthony-001";
DeviceFileEvents
| where DeviceName == VmName
| where FileName startswith "a" or FileName startswith "b" or FileName startswith "c"
| where AdditionalFields != @"{""FileType"":""Image""}"
| where InitiatingProcessRemoteSessionDeviceName == @"BUBBA"
```

**Notes:** Found the only suspicious filename that was masquerading as an antivirus.

---

## 💾 Flag 2 – Malicious File Written

**Objective**: Confirm the malicious file was written to disk.

**Finding**:  
- **Dropper Process**: `csc.exe` (Microsoft C# compiler)  
- **Dropped Binary**: `BitSentinelCore.exe`

**KQL Query**:
```kql
let VmName = "anthony-001";
let Time = datetime(2025-05-07T02:00:36.794406Z);
DeviceFileEvents
| where DeviceName == VmName
| where FolderPath contains "C:\\ProgramData\\BitSentinelCore.exe"
| project InitiatingProcessFileName
```

![image](https://github.com/user-attachments/assets/1f7fc4a8-a0f3-4a55-b688-1d9d49218e63)

**Notes:** After identifying the suspicious file `BitSentinelCore.exe`, I searched for any files containing that filename within the folder to determine the initiating process filename.

---

## 🖱️ Flag 3 – Execution of the Program

**Objective**: Determine if the fake antivirus was executed.

**Finding**:  
- **Executed Binary**: `BitSentinelCore.exe`  
- **Executed by**: Bubba via remote session

**KQL Query**:
```kql
let VmName = "anthony-001";
DeviceProcessEvents
| where DeviceName == VmName
| where FolderPath contains "BitSentinelCore.exe"
```

![image](https://github.com/user-attachments/assets/9325e17d-2389-4666-b8ad-f88b28b5d1e4)

---

## 📥 Flag 4 – Keylogger Artifact Written

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

## 🧬 Flag 5 – Registry Persistence Entry

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

## ⏱️ Flag 6 – Daily Scheduled Task Created

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

## 🔗 Flag 7 – Process Spawn Chain

**Objective**: Trace the attack chain of process execution.

**Finding**:  
- **Chain of Execution**:  
  `BitSentinelCore.exe → cmd.exe → schtasks.exe`

![image](https://github.com/user-attachments/assets/656377eb-0dc6-433d-820d-c0b0ccd607e8)

**Notes:** After inspecting the process tree, I was able to identify the chain of attack from the malware.

---

## 🕓 Flag 8 – Timestamp Correlation

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
