# Malware Analysis: Ease Paint Solutions Dropper
## Overview

This repository contains the analysis of a suspected malware dropper masquerading as legitimate software from Xiamen Baishengtong Software Technology Co. Ltd., specifically linked to Ease Paint Solutions (version 2.2.0.0). The executable in question exhibits several malicious behaviors, including system modifications, persistence techniques, and potential information-stealing capabilities.
File Information
File Details

    File Name: 8724823c104bbb4ec3f7192eac1c97b482fd129e7550201cb77cae0c066ab09d.exe
    MD5: 9240aca1f525f6e95cda49f229c524a9
    SHA1: 2e8c54593b569fe814e1832b9178458a1a29502b
    SHA256: 8724823c104bbb4ec3f7192eac1c97b482fd129e7550201cb77cae0c066ab09d

## Behavioral Analysis
Key Observed Behaviors:

    Process Injection: The dropper injects malicious code into system processes. Multiple suspicious processes are observed changing regions to RWX (read, write, execute) permissions, often a sign of code injection.
    Registry Modifications: The malware performs registry key modifications to ensure persistence on the system, changing values, deleting specific keys, and checking for virtual machines through CPU information.
    Anti-Debug Techniques: It checks system time and queries processor information, indicating likely anti-debugging or virtual machine detection techniques (related to T1497).
    Network Communication: Attempts to communicate with external servers at:
        vip.bitwarsoft.com (47.251.36.78) These URLs are linked to a potential command-and-control (C2) server. The dropper may attempt to establish connections for further payloads or exfiltration.
    File Operations: The executable works with MSI installer files and .dll files in suspicious manners, which might be part of the evasion or installation of additional payloads.

## YARA Rule Detection
Capabilities Detected:

    Trojan
    Infosteal
    Lateral movement
    Crypto
    Persistence

## Possible MITRE Techniques

    T1543: Create or Modify System Process
    T1112: Modify Registry
    T1105: Ingress Tool Transfer
    T1082: System Information Discovery
    T1497: Virtualization/Sandbox Evasion
    T1070: Indicator Removal

## Network Indicators of Compromise (IOC)
Primary C2 Server:

    Domain: vip.bitwarsoft.com
    IP Address: 47.251.36.78
    Suspicious Entropy: 8

Additional IOC:

    Domain: https://www.easepaint.com/0/
    Dropped Malware: DanaBot


## Mitigation & Detection
Mitigation Strategies:

    Behavioral Monitoring: Monitor for suspicious process injections and changes in file execution permissions.
    Registry Protection: Implement policies to monitor registry changes, particularly related to persistence methods.
    Network Defense: Block network traffic to known malicious domains and C2 servers (e.g., vip.bitwarsoft.com).
    File Integrity Monitoring: Enable monitoring for MSI installer files being executed in unconventional directories.

## Detection Recommendations:

    Utilize endpoint detection and response (EDR) tools to monitor and flag behavior such as DLL injection, registry changes, and anti-debugging checks.
    Apply YARA rules to identify the malware based on its known capabilities (trojan, infostealer, crypto).

## Conclusion

This executable poses a significant threat due to its ability to manipulate system processes, hide its operations, and potentially exfiltrate data. If detected, immediate containment and remediation are advised to prevent further damage.
Further Analysis & Threat Hunting


