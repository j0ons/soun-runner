"""Engineer guided-assessment modules.

These are the human field-work items the tool cannot fully automate but a real
AED-10k assessment must include. The tool provides a structured checklist; the
engineer fills in observations during/after the scan, and the answers fold into
the same report (with a risk rating derived from the answers).

Each module = a set of checklist items. Each item has an id, question, and the
risk implied if the answer is "no"/"fail".
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ChecklistItem:
    id: str
    question: str
    fail_risk: str         # risk if this control is missing
    fail_detail: str       # what it means if failing
    fail_fix: str          # remediation if failing


@dataclass
class EngineerModule:
    key: str
    title: str
    icon: str
    intro: str
    items: list = field(default_factory=list)


MODULES = [
    EngineerModule(
        key="backup", title="Backup & Ransomware Recovery Readiness", icon="",
        intro="Verifies the client can actually recover from a ransomware or data-loss event.",
        items=[
            ChecklistItem("backup_exists", "Are regular automated backups in place?", "critical",
                "Without backups, a ransomware attack or hardware failure means permanent data loss.",
                "Implement automated daily backups of all critical systems and data."),
            ChecklistItem("backup_offsite", "Is at least one backup copy kept offline or offsite (3-2-1 rule)?", "high",
                "If all backups are online, ransomware encrypts them too. An offline/immutable copy is the only reliable recovery path.",
                "Keep 3 copies, on 2 media types, 1 offsite/offline. Use immutable or air-gapped backup storage."),
            ChecklistItem("backup_tested", "Has a backup restore been tested in the last 90 days?", "high",
                "Untested backups frequently fail when actually needed. A backup you can't restore is not a backup.",
                "Perform and document a full restore test at least quarterly."),
            ChecklistItem("backup_encrypted", "Are backups encrypted at rest?", "medium",
                "Unencrypted backups are a data-breach risk if the backup media is stolen or accessed.",
                "Enable encryption on all backup targets (e.g. AES-256)."),
            ChecklistItem("rto_defined", "Is there a documented recovery time objective (RTO/RPO)?", "medium",
                "Without defined recovery targets, the business has no plan for how long downtime will last.",
                "Define and document RTO/RPO for critical systems and validate backups meet them."),
        ],
    ),
    EngineerModule(
        key="firewall", title="Firewall & Network Security Review", icon="",
        intro="Reviews the perimeter firewall configuration and segmentation.",
        items=[
            ChecklistItem("fw_present", "Is a dedicated firewall (not just the ISP router) in place?", "high",
                "Relying on a consumer ISP router for security leaves the network poorly protected.",
                "Deploy a business-grade firewall (FortiGate, Palo Alto, etc.) at the perimeter."),
            ChecklistItem("fw_default_deny", "Is the firewall configured default-deny on inbound?", "high",
                "A default-allow firewall exposes internal services to the internet.",
                "Set inbound policy to default-deny; explicitly allow only required services."),
            ChecklistItem("fw_no_any_any", "Are there no 'any-any' allow rules?", "high",
                "Any-any rules effectively disable the firewall for that traffic.",
                "Remove any-any rules; scope every rule to specific source, destination, and port."),
            ChecklistItem("fw_logging", "Is firewall logging enabled and reviewed?", "medium",
                "Without logging, attacks and policy violations go unnoticed.",
                "Enable logging on deny rules and forward logs to a central collector/SIEM."),
            ChecklistItem("fw_firmware", "Is the firewall firmware current and licensed?", "medium",
                "Outdated firewall firmware has known vulnerabilities; expired licenses disable protections.",
                "Keep firmware patched and security subscriptions (IPS/AV) active."),
        ],
    ),
    EngineerModule(
        key="vlan", title="VLAN / Network Segmentation Test", icon="",
        intro="Verifies sensitive systems are isolated from general user and guest traffic.",
        items=[
            ChecklistItem("vlan_exists", "Are VLANs used to segment the network?", "high",
                "A flat network lets an attacker who lands anywhere reach everything — servers, cameras, POS.",
                "Segment the network: separate VLANs for servers, staff, guest WiFi, CCTV, and POS."),
            ChecklistItem("vlan_guest_isolated", "Is guest WiFi isolated from the internal network?", "high",
                "Guest devices on the internal network can attack servers and workstations directly.",
                "Place guest WiFi on its own VLAN with no route to internal subnets."),
            ChecklistItem("vlan_cctv_isolated", "Are CCTV/IoT devices on a separate segment?", "medium",
                "Cameras and IoT are often unpatched; on the main network they become an attacker foothold.",
                "Isolate CCTV/IoT on a dedicated VLAN with restricted egress."),
            ChecklistItem("vlan_inter_acl", "Are inter-VLAN ACLs enforced (not wide open)?", "medium",
                "VLANs without ACLs between them provide no real isolation.",
                "Apply firewall rules/ACLs between VLANs allowing only required flows."),
        ],
    ),
    EngineerModule(
        key="resilience", title="Stress / Resilience & Penetration Notes", icon="",
        intro="Engineer's manual penetration-test observations and resilience checks (performed only with written authorization).",
        items=[
            ChecklistItem("pentest_authorized", "Was written authorization obtained for active testing?", "info",
                "Active/intrusive testing requires documented client sign-off.",
                "Obtain and file signed authorization before any active testing."),
            ChecklistItem("priv_esc", "Was any privilege escalation path identified?", "critical",
                "A working privilege-escalation path means an attacker can take full control.",
                "Document the path and remediate the underlying misconfiguration immediately."),
            ChecklistItem("lateral_movement", "Was lateral movement between systems possible?", "high",
                "If an attacker can move laterally, one compromised machine endangers the whole network.",
                "Enforce segmentation, unique local admin passwords (LAPS), and disable unnecessary SMB/RPC."),
            ChecklistItem("dos_resilience", "Did critical services stay stable under light load testing?", "medium",
                "Services that fall over under modest load are a business-continuity and DoS risk.",
                "Right-size critical services and add rate-limiting / failover where needed."),
        ],
    ),
]


@dataclass
class ModuleResult:
    key: str
    title: str
    icon: str
    answered: bool = False
    findings: list = field(default_factory=list)   # list[dict]
    notes: str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)


def evaluate(answers: dict) -> list[ModuleResult]:
    """Turn engineer checklist answers into findings.

    `answers` shape: { "<module_key>.<item_id>": "yes"|"no"|"na",
                       "<module_key>.notes": "free text" }
    A "no" on an item produces a finding at that item's fail_risk.
    """
    results: list[ModuleResult] = []
    for module in MODULES:
        mr = ModuleResult(key=module.key, title=module.title, icon=module.icon)
        notes = answers.get(f"{module.key}.notes", "").strip()
        mr.notes = notes
        any_answer = bool(notes)
        for item in module.items:
            ans = answers.get(f"{module.key}.{item.id}", "")
            if ans:
                any_answer = True
            if ans == "no":
                mr.findings.append({
                    "title": item.question.rstrip("?").replace("Are ", "").replace("Is ", "")
                             .replace("Was ", "").replace("Has ", "").strip().capitalize() + " — NOT in place",
                    "detail": item.fail_detail,
                    "risk": item.fail_risk,
                    "recommendation": item.fail_fix,
                })
        mr.answered = any_answer
        if mr.answered:
            results.append(mr)
    return results
