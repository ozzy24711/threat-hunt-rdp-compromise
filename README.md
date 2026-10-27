# Threat Hunt: Overnight RDP Alert Investigation

| | |
|---|---|
| **Tool** | Microsoft Defender Advanced Hunting (KQL) |
| **Trigger** | User reported repeated login prompts overnight |
| **Time Window Investigated** | 2-day search, narrowed to a ~6-hour overnight window |
| **Outcome** | Confirmed compromise — remote access, C2 beaconing, 3 persistence mechanisms, privilege escalation |
| **Skills Demonstrated** | KQL log analysis, process tree reconstruction, MITRE ATT&CK mapping, incident containment planning |

## Scenario

A user reported repeated login prompts on their workstation overnight. I investigated whether this represented a real compromise or a false alarm, using a guided threat-hunting exercise as training (completed via CyberRange).

## Approach

> Host: `npt-ws01` (lab environment). The compromised account name is replaced with the stand-in `svc_helpdesk` throughout.

I worked the investigation in the order a real alert triage would follow: confirm the logon, identify the source, find what ran under that account, trace outbound communication, and find persistence.

## Investigation

**1. Confirming the logon**

Queried `DeviceLogonEvents` for the host and time window. Found a successful network logon (Type 3) from an external IP under an account that had no legitimate reason to be accessing that workstation — not the account of the person who reported the issue.

**2. Identifying the source**

Same event set, reading the remote IP field for that account's logon. Found an external public IP authenticating directly to the workstation — the first clear signal this wasn't user error.

Query (Steps 1–2):

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceLogonEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, LogonType, RemoteIP, ActionType
```
![Network logon from external IP](Screenshot%202026-10-27%20040334.png)

**3. Finding the executed command**

Queried `DeviceProcessEvents` filtered to the suspicious account. Found a `cmd.exe` line silently launching an executable out of `C:\Windows\Temp\` with output redirected to a randomly-named file — a pattern consistent with remote execution tooling (I looked this pattern up rather than recognizing it on sight).

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where AccountName == "svc_helpdesk"
```

**4. Tracing the parent process**

Pivoted on that `cmd.exe` event and read `InitiatingProcessFileName`. The parent was the WMI provider host process, confirming the command was launched remotely via WMI rather than by a local user at the keyboard.

Same as Step 3, with `InitiatingProcessFileName` added to the projection.

**5. Finding command-and-control traffic**

Queried `DeviceNetworkEvents` filtered to the compromised account, projecting the remote URL and initiating process. Found outbound traffic to a domain with no legitimate business purpose, from a non-Microsoft-signed process — consistent with C2 beaconing.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceNetworkEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where InitiatingProcessAccountName == "svc_helpdesk"
| project InitiatingProcessAccountDomain, InitiatingProcessFileName, RemoteUrl, ActionType
```

Results were manually reviewed to exclude Microsoft-signed processes and known-legitimate domains (e.g. `*.microsoft.com`, `*.windows.com`).

**6. Finding the dropped file**

Queried `DeviceFileEvents` for the host and time window. Initial results were too noisy; I added filters for non-empty SHA256 values and a Temp folder path to cut the result set down, then reviewed what remained for anything under a name masquerading as a legitimate Windows process.

```kql
let start_time = datetime(2026-04-21T00:00:00.00Z);
let end_time = datetime(2026-04-23T00:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceFileEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where isnotempty(SHA256)
| where FolderPath contains "Temp"
| project InitiatingProcessAccountDomain, InitiatingProcessFileName, FolderPath, SHA256, ActionType
```

> **Time window note:** Steps 1–6 searched a two-day window to establish the timeline. Once the malicious activity was located, Steps 7–10 were narrowed to the ~6-hour overnight window (2026-04-22 02:00–08:00 UTC) where it occurred, to reduce noise.

**7. Finding registry persistence**

Queried `DeviceRegistryEvents` filtered to Run-key writes. Found a Run-key value disguised as a legitimate update/health-check entry, pointing back at the dropped file in Temp.

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceRegistryEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where isnotempty(RegistryValueName)
| where RegistryKey contains "run"
| project RegistryKey, RegistryValueData, RegistryValueName, Timestamp, ActionType
```

**8. Finding scheduled-task persistence**

Queried `DeviceProcessEvents` for command lines containing task-creation syntax. Found a `schtasks /create` command with a task name impersonating a well-known software updater, set to run daily.

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "schtasks" and ProcessCommandLine contains "/create"
| project Timestamp, ActionType, FileName, ProcessCommandLine
```

**9. Finding service-based persistence**

Same table, filtered for service-creation syntax instead. Found a single result: a service created with a name masquerading as a Windows health service, pointing at the same implant.

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "sc.exe create"
| project Timestamp, ActionType, FileName, ProcessCommandLine
```

**10. Finding the backdoor account**

Queried `DeviceProcessEvents` for `net user` and `net localgroup` commands. Found a new local account created and, in a correlated event seconds later, added to the local Administrators group — privilege escalation via a backdoor account.

```kql
let start_time = datetime(2026-04-22T02:00:00.00Z);
let end_time = datetime(2026-04-22T08:00:00.00Z);
let HostInQuestion = "npt-ws01";
DeviceProcessEvents
| where TimeGenerated between (start_time .. end_time)
| where DeviceName == HostInQuestion
| where ProcessCommandLine contains "net user" or ProcessCommandLine contains "net localgroup"
| project Timestamp, ActionType, FileName, ProcessCommandLine, AccountName
```

## ATT&CK Mapping

| Stage | Technique |
|---|---|
| Initial Access | Valid Accounts (T1078) |
| Execution | Windows Management Instrumentation (T1047) |
| Command and Control | Application Layer Protocol: Web Protocols (T1071.001) |
| Persistence | Registry Run Keys (T1547.001), Scheduled Task (T1053.005), Windows Service (T1543.003), Create Local Account (T1136.001) |
| Privilege Escalation | Account Manipulation — added to local Administrators (T1098) |

## Containment Plan

- Isolate the affected host from the network
- Disable the compromised account and the backdoor local account
- Block the C2 domain and IP at the network perimeter
- Remove all persistence mechanisms found: Run key, scheduled task, service
- Delete the dropped implant and any related output files in Temp
- Scope the investigation to check for lateral movement to other hosts

## Why This Detection Point

I started with the logon table because the original report was about login prompts happening overnight — that's the literal event the user experienced, so it's the natural place to confirm what actually happened. Two things stood out once I filtered to that account: the logon was remote, and it happened outside normal work hours. Neither one alone is definitive, but remote access at that time of night is a strong combined signal worth flagging automatically.

Going forward, I'd want MFA enforced on remote/interactive logons if it isn't already, plus an alert on execution from the Temp folder — that's an unusual place for legitimate software to run from, and it would have caught this earlier in the chain, closer to initial access instead of after persistence was already in place.
