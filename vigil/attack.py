"""Catálogo MITRE ATT&CK das técnicas que o Vigil reconhece.

Nomes e táticas conferidos em attack.mitre.org (Enterprise) em 2026-11-11. O ATT&CK muda entre versões
(ex.: a tática "Defense Evasion" passou a se chamar "Stealth"): revise ao atualizar o catálogo.
"""

# id -> (nome, táticas)
TECHNIQUES = {
    "T1547.001": ("Registry Run Keys / Startup Folder", ("Persistence", "Privilege Escalation")),
    "T1547.013": ("XDG Autostart Entries", ("Persistence", "Privilege Escalation")),
    "T1053.005": ("Scheduled Task", ("Execution", "Persistence", "Privilege Escalation")),
    "T1053.003": ("Cron", ("Persistence", "Execution", "Privilege Escalation")),
    "T1543.002": ("Systemd Service", ("Persistence", "Privilege Escalation")),
    "T1546.004": ("Unix Shell Configuration Modification", ("Privilege Escalation", "Persistence")),
    "T1037.004": ("RC Scripts", ("Persistence", "Privilege Escalation")),
    "T1574.006": ("Dynamic Linker Hijacking", ("Stealth", "Execution")),
    "T1059.001": ("PowerShell", ("Execution",)),
    "T1059.004": ("Unix Shell", ("Execution",)),
    "T1027.010": ("Command Obfuscation", ("Stealth",)),
    "T1027.002": ("Software Packing", ("Stealth",)),
    "T1140": ("Deobfuscate/Decode Files or Information", ("Stealth",)),
    "T1105": ("Ingress Tool Transfer", ("Command and Control",)),
    "T1218.005": ("Mshta", ("Stealth",)),
    "T1218.010": ("Regsvr32", ("Stealth",)),
    "T1218.011": ("Rundll32", ("Stealth",)),
    "T1197": ("BITS Jobs", ("Stealth", "Persistence", "Execution")),
    "T1036.007": ("Double File Extension", ("Initial Access", "Stealth")),
    "T1036.008": ("Masquerade File Type", ("Stealth",)),
    "T1070.004": ("File Deletion", ("Stealth",)),
    # --- artefatos forenses
    "T1110": ("Brute Force", ("Credential Access",)),
    "T1078": ("Valid Accounts", ("Stealth", "Persistence", "Privilege Escalation", "Initial Access")),
    "T1136.001": ("Local Account", ("Persistence",)),
    "T1098": ("Account Manipulation", ("Persistence", "Privilege Escalation")),
    # Antes T1070.001; no ATT&CK atual a técnica vive em T1685 (a página antiga só redireciona).
    "T1685.005": ("Clear Windows Event Logs", ("Defense Impairment",)),
    "T1070.003": ("Clear Command History", ("Stealth",)),
    "T1543.003": ("Windows Service", ("Persistence", "Privilege Escalation")),
    "T1003.001": ("LSASS Memory", ("Lateral Movement", "Credential Access")),
    "T1569.002": ("Service Execution", ("Execution",)),
    "T1555": ("Credentials from Password Stores", ("Credential Access",)),
    "T1558": ("Steal or Forge Kerberos Tickets", ("Credential Access",)),
    # --- persistência ampliada e processos
    "T1098.004": ("SSH Authorized Keys", ("Persistence", "Privilege Escalation")),
    "T1053.002": ("At", ("Persistence", "Execution", "Lateral Movement", "Privilege Escalation")),
    "T1053.006": ("Systemd Timers", ("Execution", "Persistence", "Privilege Escalation")),
    "T1546.017": ("Udev Rules", ("Persistence", "Privilege Escalation")),
    "T1547.004": ("Winlogon Helper DLL", ("Persistence", "Privilege Escalation")),
    "T1546.012": ("Image File Execution Options Injection", ("Privilege Escalation", "Persistence")),
    "T1546.010": ("AppInit DLLs", ("Privilege Escalation", "Persistence")),
    "T1546.003": ("Windows Management Instrumentation Event Subscription", ("Privilege Escalation", "Persistence")),
    "T1036.005": ("Match Legitimate Resource Name or Location", ("Stealth",)),
    "T1204.002": ("Malicious File", ("Execution",)),
    "T1505.003": ("Web Shell", ("Persistence",)),
}

# Técnicas de "onde a persistência mora" (usadas no contexto da detecção, não do comando)
RUN_KEYS = "T1547.001"
SCHEDULED_TASK = "T1053.005"
CRON = "T1053.003"
SYSTEMD = "T1543.002"
SHELL_PROFILE = "T1546.004"
RC_LOCAL = "T1037.004"
XDG_AUTOSTART = "T1547.013"
LD_PRELOAD = "T1574.006"
WINDOWS_SERVICE = "T1543.003"
WINLOGON = "T1547.004"
IFEO = "T1546.012"
APPINIT = "T1546.010"
WMI_SUBSCRIPTION = "T1546.003"
AT_JOB = "T1053.002"
SYSTEMD_TIMER = "T1053.006"
UDEV = "T1546.017"
SSH_KEYS = "T1098.004"
MASQUERADE = "T1036.005"
WEB_SHELL = "T1505.003"


def url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def info(tid):
    """Dicionário serializável (vai para o relatório JSON)."""
    name, tactics = TECHNIQUES[tid]
    return {"id": tid, "name": name, "tactics": list(tactics), "url": url(tid)}


def describe(entry):
    """Texto de uma linha para a interface: 'T1547.001 · Nome (Táticas)'."""
    return f"{entry['id']} · {entry['name']} ({', '.join(entry['tactics'])})"
