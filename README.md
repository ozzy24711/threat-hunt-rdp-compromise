# Threat Hunt: Remote Network Logon, WMI Execution, and Persistence

| | |
|---|---|
| **Tool** | Microsoft Defender Advanced Hunting (KQL) |
| **Trigger** | User reported repeated login prompts overnight (escalated as a suspected RDP compromise) |
| **Time Window Investigated** | 2-day search, narrowed to a ~6-hour overnight window |
| **Outcome** | Confirmed compromise — remote network logon with valid credentials, WMI remote execution, C2 beaconing, 3 persistence mechanisms, privilege escalation |
| **Skills Demonstrated** | KQL log analysis, process tree reconstruction, MITRE ATT&CK mapping, detection engineering, incident containment planning |

## Scenario

A user reported repeated login prompts on their workstation overnight. I investigated whether this represented a real compromise or a false alarm, using a guided threat-hunting exercise as training (completed via CyberRange).

### Why this isn't titled "RDP"

The alert came in as a suspected RDP compromise, and that's how I started the hunt. The evidence didn't support it. An RDP session logs as `LogonType` **RemoteInteractive (Type 10)**. What I found was a **Network (Type 3)** logon, followed by commands launched by the WMI provider host (`WmiPrvSE.exe`). That points to remote execution over the network with valid credentials, not someone sitting in an interactive RDP session. I named the write-up after what the logs showed, not what the ticket assumed.

## Approach

> Host: `npt-ws01` (lab environment). The compromised account name is replaced with the stand-in `svc_helpdesk` throughout.

> **Time column:** every query filters and displays `TimeGenerated`. These Defender tables also carry `Timestamp`. `Timestamp` is when Defender recorded the event on the device; `TimeGenerated` is when the record landed in the Log Analytics workspace, so it can trail by a few seconds. I use one column throughout so the filter and the output always agree.

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
| project TimeGenerated, AccountName, LogonType, RemoteIP, ActionType
```
![Network logon from external IP](Screenshot%202026-10-27%20040334.png)

*Lab console shows the account as "helpdesk"; it is written as the stand-in "svc_helpdesk" in the queries and text.*

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
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
```

**4. Tracing the parent process**

Pivoted on that `cmd.exe` event and read `InitiatingProcessFileName`. The parent was the WMI provider host process, confirming the command was launched remotely via WMI rather than by a local user at the keyboard.

Same query as Step 3; `InitiatingProcessFileName` is in the projection for this pivot.

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
| project TimeGenerated, InitiatingProcessAccountDomain, InitiatingProcessFileName, RemoteUrl, ActionType
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
| project TimeGenerated, InitiatingProcessAccountDomain, InitiatingProcessFileName, FolderPath, SHA256, ActionType
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
| project TimeGenerated, RegistryKey, RegistryValueData, RegistryValueName, ActionType
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
| project TimeGenerated, ActionType, FileName, ProcessCommandLine
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
| project TimeGenerated, ActionType, FileName, ProcessCommandLine
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
| project TimeGenerated, ActionType, FileName, ProcessCommandLine, AccountName
```

## Detection Rule: Execution from a Temp Folder

The hunt found this attacker after persistence was already in place. This rule would have fired at Step 3, when the payload first ran out of `C:\Windows\Temp\`, before the Run key, scheduled task, service, and backdoor account existed.

```kql
// Alert: executable launched from a Temp folder by a shell or by WMI
DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where FolderPath contains @"\Temp\"
| where FileName endswith ".exe"
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "wmiprvse.exe")
    or InitiatingProcessParentFileName =~ "wmiprvse.exe"
| where ProcessVersionInfoCompanyName !has "Microsoft"
| project TimeGenerated, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName, SHA256
```

- **What it catches here:** `WmiPrvSE.exe` → `cmd.exe` → non-Microsoft executable in `C:\Windows\Temp\` (Steps 3–4).
- **Schedule:** every hour, looking back one hour, as a Sentinel analytics rule.
- **Expected false positives:** software installers and updaters that unpack to Temp. Tune by excluding known-good `SHA256` values or signers after a week of baseline, not by dropping the Temp condition.
- **Note:** as a Defender XDR custom detection instead of a Sentinel rule, the output must also include `Timestamp`, `DeviceId`, and `ReportId`.

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

Going forward, I'd want MFA enforced on remote/interactive logons if it isn't already, plus an alert on execution from the Temp folder (written out above under [Detection Rule](#detection-rule-execution-from-a-temp-folder)). Temp is an unusual place for legitimate software to run from, and that rule would have caught this earlier in the chain, closer to initial access instead of after persistence was already in place.
