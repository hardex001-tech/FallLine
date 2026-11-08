"""Automated tests for FallLine Enterprise Multi-Vector Modules:
1. Mail & Domain Spoofing Defense (SPF & DMARC)
2. Web & Cloud Exposure Auditor (.env, .git, security headers)
3. Active Directory Privilege Escalation Ingestion (BloodHound)
4. Infrastructure-as-Code (IaC) Auto-Remediator (Ansible & Terraform)
"""

import pytest

from fallline.ad_ingest import (
    analyze_ad_attack_paths,
    ingest_bloodhound_file_or_data,
    parse_bloodhound_json,
)
from fallline.iac_generator import generate_ansible_playbook, generate_terraform_policy
from fallline.mail_audit import audit_dmarc, audit_domain_email_security, audit_spf
from fallline.scope import ScopeError
from fallline.web_audit import audit_web_exposure

# ==============================================================================
# 1. Mail & Domain Spoofing Tests
# ==============================================================================


def test_mail_audit_missing_spf():
    spf, findings = audit_spf("example.com", raw_records=[])
    assert spf is None
    assert len(findings) == 1
    assert findings[0].status == "CRITICAL"
    assert "Missing SPF" in findings[0].title


def test_mail_audit_permissive_spf():
    spf, findings = audit_spf("example.com", raw_records=["v=spf1 include:_spf.google.com ~all"])
    assert spf is not None
    assert any(f.status == "MEDIUM" and "SoftFail" in f.title for f in findings)


def test_mail_audit_strict_spf():
    spf, findings = audit_spf("example.com", raw_records=["v=spf1 include:_spf.google.com -all"])
    assert spf is not None
    assert any(f.status == "PASS" for f in findings)


def test_mail_audit_dmarc_missing():
    dmarc, findings = audit_dmarc("example.com", raw_records=[])
    assert dmarc is None
    assert any(f.status == "CRITICAL" and "Missing DMARC" in f.title for f in findings)


def test_mail_audit_dmarc_none_policy():
    dmarc, findings = audit_dmarc("example.com", raw_records=["v=DMARC1; p=none; sp=none;"])
    assert dmarc is not None
    assert any(f.status == "HIGH" and "Monitoring Only" in f.title for f in findings)


def test_mail_audit_dmarc_reject_policy():
    dmarc, findings = audit_dmarc("example.com", raw_records=["v=DMARC1; p=reject; pct=100;"])
    assert dmarc is not None
    assert any(f.status == "PASS" and "Strict DMARC" in f.title for f in findings)


def test_domain_security_full_flow():
    res = audit_domain_email_security(
        "targetcorp.com",
        spf_override_records=["v=spf1 ~all"],
        dmarc_override_records=["v=DMARC1; p=none;"],
    )
    assert res.domain == "targetcorp.com"
    assert res.spoofable is True
    assert res.risk_level in ("CRITICAL", "HIGH")
    assert len(res.recommended_dns_records) == 2


# ==============================================================================
# 2. Web & Cloud Exposure Auditor Tests
# ==============================================================================


def test_web_audit_scope_enforcement():
    # Attempting to scan an unauthorized public IP must raise ScopeError
    with pytest.raises(ScopeError):
        audit_web_exposure("8.8.8.8", port=80)


def test_web_audit_mock_exposed_secrets():
    mock_responses = {
        "/": (200, {"Server": "nginx"}, "<html>Welcome</html>"),
        "/.env": (200, {"Content-Type": "text/plain"}, "DB_PASSWORD=SuperSecret123!\nAWS_SECRET_KEY=AKIAXYZ"),
        "/.git/HEAD": (200, {"Content-Type": "text/plain"}, "ref: refs/heads/main\n"),
        "/config.json": (404, {}, "Not Found"),
        "/wp-config.php.bak": (404, {}, "Not Found"),
    }

    # 127.0.0.1 is in scope by default
    res = audit_web_exposure("127.0.0.1", port=80, mock_responses=mock_responses)
    assert res.target == "127.0.0.1"

    # Must flag exposed .env and .git/HEAD
    env_finding = next((f for f in res.findings if ".env" in f.target), None)
    git_finding = next((f for f in res.findings if ".git" in f.target), None)

    assert env_finding is not None
    assert env_finding.severity == "CRITICAL"
    assert git_finding is not None
    assert git_finding.severity == "CRITICAL"

    # Must flag missing security headers (HSTS, CSP)
    hsts_finding = next((f for f in res.findings if "HSTS" in f.title), None)
    assert hsts_finding is not None


# ==============================================================================
# 3. Active Directory Privilege Escalation Ingestion Tests
# ==============================================================================


def test_ad_ingest_bloodhound_chain():
    # Sample realistic BloodHound JSON export
    sample_bloodhound = [
        {
            "name": "JSMITH@CORP.LOCAL",
            "type": "User",
            "Aces": [
                {"PrincipalName": "WKST-09.CORP.LOCAL", "RightName": "AdminTo"},
            ],
        },
        {
            "name": "WKST-09.CORP.LOCAL",
            "type": "Computer",
            "Aces": [
                {"PrincipalName": "DA_SVC_ACCOUNT@CORP.LOCAL", "RightName": "HasSession"},
            ],
        },
        {
            "name": "DA_SVC_ACCOUNT@CORP.LOCAL",
            "type": "User",
            "Aces": [
                {"PrincipalName": "DOMAIN ADMINS@CORP.LOCAL", "RightName": "MemberOf"},
            ],
        },
        {
            "name": "DOMAIN ADMINS@CORP.LOCAL",
            "type": "Group",
            "Aces": [],
        },
    ]

    graph, node_types, crown_jewels = parse_bloodhound_json(sample_bloodhound)
    assert graph.number_of_nodes() == 4
    assert graph.number_of_edges() == 3
    assert "DOMAIN ADMINS@CORP.LOCAL" in crown_jewels

    paths = analyze_ad_attack_paths(graph, crown_jewels, starting_nodes=["JSMITH@CORP.LOCAL"])
    assert len(paths) == 1

    path = paths[0]
    assert path.starting_account == "JSMITH@CORP.LOCAL"
    assert path.target_crown_jewel == "DOMAIN ADMINS@CORP.LOCAL"
    assert len(path.steps) == 3
    assert path.total_ttc_minutes == (15.0 + 10.0 + 1.0)  # AdminTo (15) + HasSession (10) + MemberOf (1) = 26 mins

    # Verify choke point detection
    assert path.choke_point_step is not None
    assert "remediation" in path.remediation_command.lower() or "invoke-command" in path.remediation_command.lower()


def test_ad_ingest_wrapper():
    sample_data = {
        "data": [
            {
                "Properties": {"name": "DEV_USER@CORP.LOCAL", "type": "User"},
                "Aces": [{"PrincipalName": "DC01.CORP.LOCAL", "RightName": "GenericAll"}],
            },
            {
                "Properties": {"name": "DC01.CORP.LOCAL", "type": "Computer"},
                "Aces": [],
            },
        ],
    }
    summary = ingest_bloodhound_file_or_data(sample_data)
    assert summary.nodes_count == 2
    assert summary.users_count == 1
    assert summary.computers_count == 1
    assert "DC01.CORP.LOCAL" in summary.crown_jewels
    assert len(summary.attack_paths) == 1


# ==============================================================================
# 4. Infrastructure-as-Code (IaC) Generator Tests
# ==============================================================================


def test_iac_ansible_playbook_generation():
    findings = [
        {"port": 21, "service": "ftp", "title": "Insecure ProFTPD Daemon"},
        {"port": 23, "service": "telnet", "title": "Cleartext Telnet"},
        {"port": 3306, "service": "mysql", "title": "Remote MySQL Access"},
        {"port": 22, "service": "ssh", "title": "Root SSH Access Allowed"},
    ]
    playbook = generate_ansible_playbook(findings)
    assert "hosts: all" in playbook
    assert "become: true" in playbook
    assert "name: vsftpd" in playbook
    assert "name: openbsd-inetd" in playbook
    assert "bind-address = 127.0.0.1" in playbook
    assert "PermitRootLogin no" in playbook


def test_iac_terraform_policy_generation():
    findings = [
        {"port": 21, "service": "ftp"},
        {"port": 3306, "service": "mysql"},
    ]
    tf = generate_terraform_policy(findings)
    assert 'resource "aws_s3_account_public_access_block"' in tf
    assert 'resource "aws_security_group_rule" "revoke_ingress_21"' in tf
    assert 'resource "aws_security_group_rule" "revoke_ingress_3306"' in tf
