"""Rules knowledge base: turns raw findings into classified, scored exposures."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .scanners.base import Finding

DEFAULT_RULES = Path(__file__).parent / "rules" / "rules.yaml"

MITRE_TACTICS: tuple[str, ...] = (
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Impact",
)


@dataclass
class Rule:
    id: str
    title: str
    match: dict
    severity: str
    technique: dict
    gives: str
    stage: str
    effort_minutes: float
    fix_minutes: float
    why: str
    remediation: str
    fix_command: str = ""
    cves: list[str] = field(default_factory=list)
    effort_by_severity: dict = field(default_factory=dict)
    skip_severities: list = field(default_factory=list)

    def matches(self, f: Finding) -> bool:
        m = self.match
        # AWS findings only match AWS rules (and vice versa); findings that carry a
        # check id (web/Nuclei/AWS) only match rules that ask for a check.
        if (f.source == "aws") != (m.get("source") == "aws"):
            return False
        if f.check and "check_regex" not in m:
            return False
        if "source" in m and f.source != m["source"]:
            return False
        if "check_regex" in m and not re.search(m["check_regex"], f.check or "", re.IGNORECASE):
            return False
        if "product_regex" in m and not re.search(m["product_regex"], f.product or "", re.IGNORECASE):
            return False
        if "version_regex" in m and not re.search(m["version_regex"], f.version or "", re.IGNORECASE):
            return False
        # ports and service_regex are alternatives: either one identifies the service
        has_ports, has_svc = "ports" in m, "service_regex" in m
        if has_ports or has_svc:
            by_port = has_ports and f.port in m["ports"]
            by_svc = has_svc and bool(re.search(m["service_regex"], f.service or "", re.IGNORECASE))
            if not (by_port or by_svc):
                return False
        # a rule with only product/version/source/check constraints is fine as-is
        return True

    def effort_for(self, f: Finding) -> float:
        if self.effort_by_severity:
            return float(self.effort_by_severity.get((f.severity or "").lower(), self.effort_minutes))
        return float(self.effort_minutes)


class KnowledgeBase:
    def __init__(self, rules: list[Rule]):
        self.rules = rules
        self.by_id = {r.id: r for r in rules}

    @classmethod
    def load(cls, path: str | Path | None = None) -> KnowledgeBase:
        data = yaml.safe_load(Path(path or DEFAULT_RULES).read_text(encoding="utf-8"))
        rules = [Rule(**r) for r in data["rules"]]
        ids = [r.id for r in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule ids in rules file")
        return cls(rules)

    def classify(self, f: Finding) -> Rule | None:
        """First matching rule, or None if the finding carries no attack value."""
        for rule in self.rules:
            if rule.matches(f):
                if (f.severity or "").lower() in [
                    str(s).lower() for s in rule.skip_severities
                ] and rule.skip_severities:
                    return None
                return rule
        return None


def finding_key(f: Finding, rule_id: str) -> str:
    """Stable identity of an exposure across scans."""
    key = f"{f.host}|{f.port}/{f.protocol}|{rule_id}"
    if f.check:
        key += f"|{f.check}"
    return key


def build_mitre_matrix(kb: KnowledgeBase, records: list[dict]) -> list[dict]:
    """Group rules and active findings by MITRE ATT&CK Tactic phase."""
    by_tactic: dict[str, dict] = {
        tactic: {
            "tactic": tactic,
            "rules_count": 0,
            "open_count": 0,
            "fixed_count": 0,
            "accepted_count": 0,
            "techniques": {},
            "findings": [],
        }
        for tactic in MITRE_TACTICS
    }
    for rule in kb.rules:
        tactic = rule.technique.get("tactic", "Initial Access")
        if tactic not in by_tactic:
            by_tactic[tactic] = {
                "tactic": tactic,
                "rules_count": 0,
                "open_count": 0,
                "fixed_count": 0,
                "accepted_count": 0,
                "techniques": {},
                "findings": [],
            }
        bucket = by_tactic[tactic]
        bucket["rules_count"] += 1
        tid = rule.technique["id"]
        if tid not in bucket["techniques"]:
            bucket["techniques"][tid] = {
                "id": tid,
                "name": rule.technique["name"],
                "open": 0,
                "fixed": 0,
                "accepted": 0,
                "rules": [],
            }
        bucket["techniques"][tid]["rules"].append(rule.id)

    for rec in records:
        rule_id = rec.get("rule_id") or ""
        rule = kb.by_id.get(rule_id)
        if rule is None:
            continue
        tactic = rule.technique.get("tactic", "Initial Access")
        bucket = by_tactic.get(tactic)
        if bucket is None:
            continue
        tid = rule.technique["id"]
        st = rec.get("status", "OPEN")
        if st == "OPEN":
            bucket["open_count"] += 1
            if tid in bucket["techniques"]:
                bucket["techniques"][tid]["open"] += 1
        elif st == "FIXED_VERIFIED":
            bucket["fixed_count"] += 1
            if tid in bucket["techniques"]:
                bucket["techniques"][tid]["fixed"] += 1
        elif st == "ACCEPTED_RISK":
            bucket["accepted_count"] += 1
            if tid in bucket["techniques"]:
                bucket["techniques"][tid]["accepted"] += 1
        bucket["findings"].append(
            {
                "key": rec["key"],
                "host": rec["host"],
                "port": rec["port"],
                "title": rec["title"],
                "severity": rec["severity"],
                "status": st,
                "technique_id": tid,
                "technique": f"{tid} {rule.technique['name']}",
                "fix_command": rule.fix_command,
            }
        )

    out: list[dict] = []
    for tactic, bucket in by_tactic.items():
        out.append(
            {
                "tactic": tactic,
                "rules_count": bucket["rules_count"],
                "open_count": bucket["open_count"],
                "fixed_count": bucket["fixed_count"],
                "accepted_count": bucket["accepted_count"],
                "techniques": list(bucket["techniques"].values()),
                "findings": bucket["findings"],
            }
        )
    return out
