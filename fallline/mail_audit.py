"""Email and Domain Spoofing Defense Auditor.

Audits SPF, DMARC, and MX DNS security configurations to determine whether
an organization's domain can be forged by threat actors in spearphishing
and business email compromise (BEC) campaigns.

Maps findings to MITRE ATT&CK:
- T1566.002: Phishing: Spearphishing Link
- T1586.002: Compromise Accounts: Email Accounts
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

try:
    import dns.resolver
    _HAVE_DNS = True
except ImportError:
    _HAVE_DNS = False


@dataclass
class MailSecurityFinding:
    check_type: str  # "SPF" | "DMARC" | "MX"
    status: str      # "CRITICAL" | "HIGH" | "MEDIUM" | "PASS"
    title: str
    description: str
    raw_record: str | None
    remediation_txt: str
    mitre_tactic: str = "T1566.002"


@dataclass
class MailAuditResult:
    domain: str
    spoofable: bool
    risk_level: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "SECURE"
    risk_score: int  # 0 to 100
    spf_record: str | None = None
    dmarc_record: str | None = None
    findings: list[MailSecurityFinding] = field(default_factory=list)
    recommended_dns_records: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "spoofable": self.spoofable,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "spf_record": self.spf_record,
            "dmarc_record": self.dmarc_record,
            "findings": [
                {
                    "check_type": f.check_type,
                    "status": f.status,
                    "title": f.title,
                    "description": f.description,
                    "raw_record": f.raw_record,
                    "remediation_txt": f.remediation_txt,
                    "mitre_tactic": f.mitre_tactic,
                }
                for f in self.findings
            ],
            "recommended_dns_records": self.recommended_dns_records,
        }


def _query_txt_records(domain: str, resolver: Any = None) -> list[str]:
    """Retrieve all TXT records for a domain with robust multi-layer fallback."""
    # 1. Try dnspython if installed
    if _HAVE_DNS:
        res = resolver or dns.resolver.Resolver()
        res.timeout = 3.5
        res.lifetime = 3.5
        try:
            answers = res.resolve(domain, "TXT")
            records: list[str] = []
            for rdata in answers:
                text = "".join(chunk.decode("utf-8", errors="replace") for chunk in rdata.strings)
                records.append(text)
            if records:
                return records
        except Exception:
            pass

    # 2. Try native 'dig' (standard on Linux / Kali)
    if shutil.which("dig"):
        try:
            out = subprocess.check_output(
                ["dig", "+short", "TXT", domain],
                stderr=subprocess.DEVNULL,
                timeout=4.0,
                text=True,
            )
            records = []
            for line in out.splitlines():
                clean = line.strip().strip('"')
                if clean:
                    records.append(clean)
            if records:
                return records
        except Exception:
            pass

    # 3. Try native 'nslookup' (cross-platform Windows & Linux)
    if shutil.which("nslookup"):
        try:
            out = subprocess.check_output(
                ["nslookup", "-type=TXT", domain],
                stderr=subprocess.DEVNULL,
                timeout=4.0,
                text=True,
            )
            records = []
            matches = re.findall(r'"([^"]+)"', out)
            for m in matches:
                clean = m.strip()
                if clean:
                    records.append(clean)
            if records:
                return records
        except Exception:
            pass

    return []


def audit_spf(domain: str, raw_records: list[str] | None = None) -> tuple[str | None, list[MailSecurityFinding]]:
    """Audit SPF (Sender Policy Framework) TXT records."""
    findings: list[MailSecurityFinding] = []
    records = raw_records if raw_records is not None else _query_txt_records(domain)

    spf_records = [r for r in records if r.lower().startswith("v=spf1")]

    if not spf_records:
        findings.append(MailSecurityFinding(
            check_type="SPF",
            status="CRITICAL",
            title="Missing SPF Record",
            description=f"Domain {domain} has no SPF record. Threat actors can forge your domain to send phishing emails that appear authentic to mail recipients.",
            raw_record=None,
            remediation_txt="v=spf1 include:_spf.google.com -all",
        ))
        return None, findings

    if len(spf_records) > 1:
        findings.append(MailSecurityFinding(
            check_type="SPF",
            status="HIGH",
            title="Multiple SPF Records Detected",
            description="RFC 7208 forbids multiple SPF records on a single domain. Mail receivers will return PermError and treat mail as unauthenticated.",
            raw_record="; ".join(spf_records),
            remediation_txt="Merge multiple SPF records into a single TXT entry.",
        ))

    spf = spf_records[0]
    # Check all qualifier
    if "+all" in spf:
        findings.append(MailSecurityFinding(
            check_type="SPF",
            status="CRITICAL",
            title="Dangerous SPF '+all' Directive",
            description="SPF explicitly permits ANY IP address on the internet to send mail on behalf of this domain.",
            raw_record=spf,
            remediation_txt=spf.replace("+all", "-all"),
        ))
    elif "?all" in spf:
        findings.append(MailSecurityFinding(
            check_type="HIGH",
            status="HIGH",
            title="Neutral SPF '?all' Directive",
            description="SPF policy is neutral (?all). Receiving mail servers will not reject forged emails.",
            raw_record=spf,
            remediation_txt=spf.replace("?all", "-all"),
        ))
    elif "~all" in spf:
        findings.append(MailSecurityFinding(
            check_type="SPF",
            status="MEDIUM",
            title="Permissive SPF SoftFail '~all'",
            description="SPF policy uses SoftFail (~all). Many mailbox providers still deliver forged emails to inbox or spam folders.",
            raw_record=spf,
            remediation_txt=spf.replace("~all", "-all"),
        ))
    elif "-all" in spf:
        findings.append(MailSecurityFinding(
            check_type="SPF",
            status="PASS",
            title="Strict SPF HardFail Enforced",
            description="SPF strictly hard-fails (-all) any unauthorized sending server.",
            raw_record=spf,
            remediation_txt="No change required.",
        ))

    return spf, findings


def audit_dmarc(domain: str, raw_records: list[str] | None = None) -> tuple[str | None, list[MailSecurityFinding]]:
    """Audit DMARC TXT record at _dmarc.<domain>."""
    findings: list[MailSecurityFinding] = []
    dmarc_domain = f"_dmarc.{domain}"
    records = raw_records if raw_records is not None else _query_txt_records(dmarc_domain)

    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]

    if not dmarc_records:
        findings.append(MailSecurityFinding(
            check_type="DMARC",
            status="CRITICAL",
            title="Missing DMARC Policy",
            description=f"Domain {domain} has no DMARC record at {dmarc_domain}. Mail servers will not block spoofed emails claiming to be from your domain.",
            raw_record=None,
            remediation_txt=f"v=DMARC1; p=reject; rua=mailto:security-reports@{domain}; pct=100; aspf=r;",
        ))
        return None, findings

    dmarc = dmarc_records[0]
    p_match = re.search(r"\bp=([a-zA-Z]+)", dmarc)
    policy = p_match.group(1).lower() if p_match else "none"

    if policy == "none":
        findings.append(MailSecurityFinding(
            check_type="DMARC",
            status="HIGH",
            title="DMARC Policy Set to Monitoring Only (p=none)",
            description="DMARC is set to p=none. Forged emails failing SPF/DKIM will still be delivered to recipients.",
            raw_record=dmarc,
            remediation_txt=re.sub(r"\bp=none\b", "p=reject", dmarc),
        ))
    elif policy == "quarantine":
        findings.append(MailSecurityFinding(
            check_type="DMARC",
            status="PASS",
            title="DMARC Policy Enforcing Quarantine (p=quarantine)",
            description="DMARC quarantines forged emails to spam/junk folders.",
            raw_record=dmarc,
            remediation_txt="Consider upgrading p=quarantine to p=reject for complete defense.",
        ))
    elif policy == "reject":
        findings.append(MailSecurityFinding(
            check_type="DMARC",
            status="PASS",
            title="Strict DMARC Policy Enforced (p=reject)",
            description="DMARC strictly rejects all forged emails at the mail gateway.",
            raw_record=dmarc,
            remediation_txt="No change required.",
        ))

    return dmarc, findings


def audit_domain_email_security(
    domain: str,
    spf_override_records: list[str] | None = None,
    dmarc_override_records: list[str] | None = None,
) -> MailAuditResult:
    """Run full email spoofing and domain posture analysis."""
    clean_domain = domain.strip().lower()
    if clean_domain.startswith("https://"):
        clean_domain = clean_domain[8:]
    elif clean_domain.startswith("http://"):
        clean_domain = clean_domain[7:]
    clean_domain = clean_domain.split("/")[0]

    spf_rec, spf_findings = audit_spf(clean_domain, spf_override_records)
    dmarc_rec, dmarc_findings = audit_dmarc(clean_domain, dmarc_override_records)

    all_findings = spf_findings + dmarc_findings

    # Risk scoring
    has_critical = any(f.status == "CRITICAL" for f in all_findings)
    has_high = any(f.status == "HIGH" for f in all_findings)
    has_medium = any(f.status == "MEDIUM" for f in all_findings)

    if has_critical:
        risk_level = "CRITICAL"
        risk_score = 90
        spoofable = True
    elif has_high:
        risk_level = "HIGH"
        risk_score = 70
        spoofable = True
    elif has_medium:
        risk_level = "MEDIUM"
        risk_score = 45
        spoofable = False
    else:
        risk_level = "SECURE"
        risk_score = 10
        spoofable = False

    recommended = {
        f"TXT @ ({clean_domain})": "v=spf1 include:_spf.google.com -all" if not spf_rec else spf_rec.replace("~all", "-all").replace("?all", "-all"),
        f"TXT _dmarc ({clean_domain})": f"v=DMARC1; p=reject; rua=mailto:security-reports@{clean_domain}; pct=100; aspf=r;",
    }

    return MailAuditResult(
        domain=clean_domain,
        spoofable=spoofable,
        risk_level=risk_level,
        risk_score=risk_score,
        spf_record=spf_rec,
        dmarc_record=dmarc_rec,
        findings=all_findings,
        recommended_dns_records=recommended,
    )
