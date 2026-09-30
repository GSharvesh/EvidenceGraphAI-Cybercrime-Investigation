"""ATT&CK technique mapping rules (ADR 0020 — rules-first approach).

Each rule is a dict with:
- ``technique_id``: ATT&CK technique identifier.
- ``technique_name``: Human-readable name.
- ``tactic``: ATT&CK tactic.
- ``confidence``: Base confidence score.
- ``patterns``: List of regex pattern strings matched against evidence text.
- ``rule_name``: Short name for traceability.

Rules are compiled once at module load time for performance.

Design rationale (ADR 0020):
- Pure regex matching is deterministic, auditable, and requires no ML model.
- The rule set is intentionally broad at this phase — false positives are
  flagged as ``inconclusive`` (confidence < 0.7).
- Rules can be extended without code changes by adding entries to this file.
"""

from __future__ import annotations

import re

_RAW_RULES: list[dict] = [
    # ── Initial Access ─────────────────────────────────────────────────────
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "confidence": 0.85,
        "rule_name": "log4shell_jndi",
        "patterns": [
            r"\$\{jndi:",
            r"jndi:ldap://",
            r"jndi:rmi://",
            r"log4j.*exploit",
            r"struts.*ognl",
        ],
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "confidence": 0.75,
        "rule_name": "http_exploit_indicators",
        "patterns": [
            r"CVE-\d{4}-\d{4,}",
            r"exploit.*public.*facing",
            r"web.*application.*exploit",
            r"\.\./\.\./",  # path traversal
            r"<script>.*</script>",  # XSS
            r"union.*select.*from",  # SQLi
        ],
    },
    # ── Execution ─────────────────────────────────────────────────────────
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "confidence": 0.80,
        "rule_name": "shell_execution",
        "patterns": [
            r"/bin/(ba)?sh\b",
            r"\bcmd\.exe\b",
            r"\bpowershell(\.exe)?\b",
            r"\bpython[23]?\s",
            r"\bperl\s",
            r"\bwscript\b",
            r"\bcscript\b",
        ],
    },
    {
        "technique_id": "T1059.001",
        "technique_name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "execution",
        "confidence": 0.90,
        "rule_name": "powershell_execution",
        "patterns": [
            r"powershell.*-enc",
            r"powershell.*bypass",
            r"powershell.*-nop",
            r"Invoke-Expression",
            r"IEX\s*\(",
            r"New-Object.*WebClient",
        ],
    },
    # ── Persistence ────────────────────────────────────────────────────────
    {
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "persistence",
        "confidence": 0.80,
        "rule_name": "scheduled_task",
        "patterns": [
            r"\bcrontab\b",
            r"\bschtasks\b",
            r"\bat\.exe\b",
            r"systemd.*service",
            r"launchd.*plist",
            r"rc\.local",
        ],
    },
    {
        "technique_id": "T1547",
        "technique_name": "Boot/Logon Autostart Execution",
        "tactic": "persistence",
        "confidence": 0.75,
        "rule_name": "autostart_persistence",
        "patterns": [
            r"HKCU.*\\Run\\",
            r"HKLM.*\\Run\\",
            r"HKCU.*\\RunOnce\\",
            r"~/.bashrc",
            r"~/.profile",
            r"/etc/rc\.",
        ],
    },
    # ── Privilege Escalation ───────────────────────────────────────────────
    {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "privilege-escalation",
        "confidence": 0.80,
        "rule_name": "priv_esc_exploit",
        "patterns": [
            r"exploit.*privilege",
            r"kernel.*exploit",
            r"setuid.*root",
            r"sudo.*exploit",
            r"privilege.*escalat",
        ],
    },
    # ── Defense Evasion ────────────────────────────────────────────────────
    {
        "technique_id": "T1027",
        "technique_name": "Obfuscated Files or Information",
        "tactic": "defense-evasion",
        "confidence": 0.65,
        "rule_name": "base64_obfuscation",
        "patterns": [
            r"base64.*decode",
            r"FromBase64String",
            r"b64decode",
            r"eval\(base64",
            r"echo.*\|.*base64",
        ],
    },
    {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "tactic": "defense-evasion",
        "confidence": 0.70,
        "rule_name": "log_clearing",
        "patterns": [
            r"rm.*\.log",
            r"truncate.*\.log",
            r"wevtutil.*cl",
            r"Clear-EventLog",
            r"del.*\\System32\\winevt",
        ],
    },
    # ── Discovery ─────────────────────────────────────────────────────────
    {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "discovery",
        "confidence": 0.70,
        "rule_name": "system_discovery",
        "patterns": [
            r"\buname\s+-a\b",
            r"\buname\s+-r\b",
            r"\bsysteminfo\b",
            r"\bhostname\b",
            r"\bwhoami\b",
            r"\bid\b",
        ],
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "discovery",
        "confidence": 0.75,
        "rule_name": "network_scan",
        "patterns": [
            r"\bnmap\b",
            r"\bmasscan\b",
            r"\bnetstat\b",
            r"\bss\s+-",
            r"\barp\s+-a\b",
        ],
    },
    # ── Lateral Movement ───────────────────────────────────────────────────
    {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "lateral-movement",
        "confidence": 0.75,
        "rule_name": "remote_services",
        "patterns": [
            r"\bssh\s+",
            r"\bpsexec\b",
            r"\bwinrm\b",
            r"\brdp\b",
            r"mstsc\.exe",
        ],
    },
    # ── Collection ────────────────────────────────────────────────────────
    {
        "technique_id": "T1005",
        "technique_name": "Data from Local System",
        "tactic": "collection",
        "confidence": 0.65,
        "rule_name": "local_data_collection",
        "patterns": [
            r"\btar\s+-c",
            r"\bzip\s+",
            r"\brar\s+",
            r"\bcp\s+-r",
            r"\brsync\b",
        ],
    },
    # ── Command and Control ────────────────────────────────────────────────
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "confidence": 0.70,
        "rule_name": "c2_application_layer",
        "patterns": [
            r"POST.*http",
            r"wget.*http",
            r"curl.*http",
            r"Invoke-WebRequest",
            r"beaconing",
            r"c2.*channel",
        ],
    },
    # ── Exfiltration ────────────────────────────────────────────────────────
    {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "confidence": 0.70,
        "rule_name": "exfil_c2",
        "patterns": [
            r"exfil",
            r"data.*transmit",
            r"upload.*sensitive",
            r"POST.*password",
            r"POST.*credential",
        ],
    },
    # ── Impact ─────────────────────────────────────────────────────────────
    {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "impact",
        "confidence": 0.75,
        "rule_name": "dos_impact",
        "patterns": [
            r"denial.*service",
            r"resource.*exhaustion",
            r"out.*of.*memory",
            r"segmentation.*fault",
            r"connection.*flood",
        ],
    },
]


class CompiledRule:
    """A compiled ATT&CK mapping rule with pre-compiled regex patterns."""

    def __init__(self, raw: dict) -> None:
        self.technique_id: str = raw["technique_id"]
        self.technique_name: str = raw["technique_name"]
        self.tactic: str = raw["tactic"]
        self.confidence: float = raw["confidence"]
        self.rule_name: str = raw["rule_name"]
        self._compiled: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE | re.MULTILINE) for p in raw["patterns"]
        ]

    def matches(self, text: str) -> tuple[bool, str | None]:
        """Returns (matched, matched_snippet) if any pattern matches the text."""
        for pat in self._compiled:
            m = pat.search(text)
            if m:
                return True, m.group(0)
        return False, None


# Pre-compile all rules at module load time
COMPILED_RULES: list[CompiledRule] = [CompiledRule(r) for r in _RAW_RULES]
