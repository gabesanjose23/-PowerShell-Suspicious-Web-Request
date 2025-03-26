# PowerShell Suspicious Web Request


## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Microsoft Sentinel

##  Scenario

Sometimes when a bad actor has access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence. This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity. By leveraging commands such as Invoke-WebRequest, they can download files or scripts from an external server and immediately execute them, bypassing traditional defenses or detection mechanisms. This tactic is a hallmark of post-exploitation activity, enabling them to deploy malware, exfiltrate data, or establish communication channels with a command-and-control (C2) server. Detecting this behavior is critical to identifying and disrupting an ongoing attack.  

---

## Steps Taken

### Part 1: Create Alert Rule PowerShell Suspicious Web Request

Here I am setting up the rules to detect if there were a excessive amount of login failed attempt.


<img width="1212" alt="image" src="Screenshot 2025-03-22 161239.png">

<img width="1212" alt="image" src="Screenshot 2025-03-22 161602.png">

---

### 2. Investigate and find out if anyone has attempted to login into the machine

Next the rules that I put in place are alerted.

**Query used to locate event:**

```kql
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName, ActionType
| where EventCount >= 10
| order by EventCount
```
<img width="1212" alt="image" src="Screenshot 2025-03-22 162815.png">

<img width="1212" alt="image" src="Screenshot 2025-03-22 160732.png">

<img width="1212" alt="image" src="Screenshot 2025-03-22 163912.png">

---

### 3. Investigate the Machines 

Three different virtual machines were potentially impacted by brute force attempts from 4 different public IP:

## Details of Failed Logon Attempts

| **IP Address**       | **Hostname**                                              | **Status**      | **Failed Attempts** |
|----------------------|----------------------------------------------------------|----------------|--------------------|
| 170.64.155.135       | linux-programmatic-fix-tau.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net | LogonFailed    | 63                 |
| 112.135.212.148      | sa-mde-test-2                                             | LogonFailed    | 58                 |
| 158.101.242.63       | sa-mde-test-2                                             | LogonFailed    | 40                 |
| 185.151.86.130       | ir-sentinel-moa                                           | LogonFailed    | 40                 |


---

### 4. Containment:Isolated Devices
I isolated the Devices using MDE then I Ran anti-malware scan on all four devices within MDE.I check to see if any of the IP addresses attempting to brute force successfully logged in with the following query,but none were successful:

**Query used to locate events:**

```kql
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP in ("170.64.155.135", "112.135.212.148", "185.151.86.130", "158.101.242.63")
```
<img width="1212" alt="image" src="Screenshot 2025-03-22 164528.png">

---

## Summary

<img width="1212" alt="image" src="Screenshot 2025-03-22 165905.png">


MITRE ATT&CK - T1071.001: Web Protocols

MITRE ATT&CK - T1059.001: PowerShell

MITRE ATT&CK - T1105: Ingress Tool Transfer

MITRE ATT&CK - T1203: Exploitation for Client Execution

MITRE ATT&CK - T1041: Exfiltration Over C2 Channel

---

## Response Action

NSG was locked down to prevent RDP attempts from the public internet. Policy was proposed to require this for all VMs going forward.Additionally I set a rule only allowing my home IP address.(Alternatively we can use bastion host) 

<img width="1212" alt="image" src="Screenshot 2025-03-22 165025.png">

---
