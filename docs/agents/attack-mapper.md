# ATT&CK Mapper Agent

## Overview

The `ATTACKMapper` parses unstructured or semi-structured forensic artifacts (syslog files, command lines, network text payloads, threat intel feeds) and automatically correlates them to MITRE ATT&CK enterprise techniques.

## Pattern Matching Engine

The mapper utilizes a catalog of compiled regular expressions and keyword signatures covering major initial access, execution, persistence, discovery, and defense evasion techniques:
- **T1190:** Exploit Public-Facing Application (Log4Shell JNDI injection patterns, Spring4Shell, WebLogic RCE)
- **T1059.004:** Unix Shell commands (`/bin/bash -c`, `curl -s | sh`)
- **T1059.001:** PowerShell execution (`powershell.exe -enc`, `Invoke-Expression`)
- **T1027:** Obfuscated Files or Information (Base64 encoding, hex decoding)
- **T1046:** Network Service Discovery (`nmap`, `masscan`, port probes)
- **T1082:** System Information Discovery (`uname -a`, `whoami`, `id`)

## API Endpoints

- `POST /attack-mapper/map-text` — Map raw text snippet to techniques.
- `POST /attack-mapper/map-file` — Map a stored forensic artifact file.
