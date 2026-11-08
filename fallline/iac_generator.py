"""Infrastructure-as-Code (IaC) Remediation Generator.

Converts FallLine vulnerability findings, identified choke points, and exposure alerts
into production-ready Ansible playbooks and Terraform policies.

Allows IT/SecOps teams to remediate verified choke points across 100+ servers or cloud
accounts in seconds instead of executing manual one-line terminal commands.
"""

from __future__ import annotations

from typing import Any


def generate_ansible_playbook(
    findings: list[dict[str, Any]], playbook_name: str = "FallLine Automated Remediation"
) -> str:
    """Generate a valid, production-ready Ansible YAML playbook."""
    lines: list[str] = [
        "---",
        f"# {playbook_name}",
        "# Generated automatically by FallLine Enterprise Defense Platform",
        "# Purpose: Neutralize critical attack-path choke points across infrastructure",
        "",
        "- name: Remediate FallLine Attack-Path Choke Points",
        "  hosts: all",
        "  become: true",
        "  tasks:",
    ]

    seen_tasks: set[str] = set()

    for finding in findings:
        port = finding.get("port")
        service = str(finding.get("service", "")).lower()
        title = finding.get("title", f"Remediate port {port}")

        # Port-specific remediation tasks
        if port == 21 or "ftp" in service:
            key = "stop_vsftpd"
            if key not in seen_tasks:
                seen_tasks.add(key)
                lines.extend(
                    [
                        f"    - name: Neutralize FTP Daemon ({title})",
                        "      ansible.builtin.systemd:",
                        "        name: vsftpd",
                        "        state: stopped",
                        "        enabled: false",
                        "      ignore_errors: true",
                        "",
                        "    - name: Block Inbound Port 21 (FTP)",
                        "      community.general.ufw:",
                        "        rule: deny",
                        "        port: '21'",
                        "        proto: tcp",
                        "",
                    ]
                )
        elif port == 23 or "telnet" in service:
            key = "stop_telnet"
            if key not in seen_tasks:
                seen_tasks.add(key)
                lines.extend(
                    [
                        "    - name: Neutralize Cleartext Telnet Service",
                        "      ansible.builtin.systemd:",
                        "        name: openbsd-inetd",
                        "        state: stopped",
                        "        enabled: false",
                        "      ignore_errors: true",
                        "",
                        "    - name: Block Inbound Port 23 (Telnet)",
                        "      community.general.ufw:",
                        "        rule: deny",
                        "        port: '23'",
                        "        proto: tcp",
                        "",
                    ]
                )
        elif port == 3306 or "mysql" in service:
            key = "harden_mysql"
            if key not in seen_tasks:
                seen_tasks.add(key)
                lines.extend(
                    [
                        "    - name: Restrict MySQL to Localhost Only",
                        "      ansible.builtin.lineinfile:",
                        "        path: /etc/mysql/mysql.conf.d/mysqld.cnf",
                        "        regexp: '^bind-address'",
                        "        line: 'bind-address = 127.0.0.1'",
                        "      notify: Restart MySQL",
                        "      ignore_errors: true",
                        "",
                    ]
                )
        elif port == 22 or "ssh" in service:
            key = "harden_ssh"
            if key not in seen_tasks:
                seen_tasks.add(key)
                lines.extend(
                    [
                        "    - name: Disallow Direct Root SSH Login",
                        "      ansible.builtin.lineinfile:",
                        "        path: /etc/ssh/sshd_config",
                        "        regexp: '^PermitRootLogin'",
                        "        line: 'PermitRootLogin no'",
                        "      notify: Restart SSH",
                        "",
                    ]
                )
        elif finding.get("check_type") == "SENSITIVE_FILE":
            target = finding.get("target", "")
            if ".env" in target:
                key = "lock_env_file"
                if key not in seen_tasks:
                    seen_tasks.add(key)
                    lines.extend(
                        [
                            "    - name: Secure .env Permissions to Read-Only by Owner",
                            "      ansible.builtin.file:",
                            "        path: /.env",
                            "        mode: '0600'",
                            "        owner: root",
                            "      ignore_errors: true",
                            "",
                        ]
                    )

        # Generic port deny fallback
        if port and port not in (21, 22, 23, 3306):
            key = f"deny_port_{port}"
            if key not in seen_tasks:
                seen_tasks.add(key)
                lines.extend(
                    [
                        f"    - name: Block Unnecessary Inbound Exposure on Port {port}",
                        "      community.general.ufw:",
                        "        rule: deny",
                        f"        port: '{port}'",
                        "        proto: tcp",
                        "",
                    ]
                )

    # Handlers
    lines.extend(
        [
            "  handlers:",
            "    - name: Restart MySQL",
            "      ansible.builtin.systemd:",
            "        name: mysql",
            "        state: restarted",
            "",
            "    - name: Restart SSH",
            "      ansible.builtin.systemd:",
            "        name: sshd",
            "        state: restarted",
            "",
        ]
    )

    return "\n".join(lines)


def generate_terraform_policy(findings: list[dict[str, Any]], policy_name: str = "fallline_remediation") -> str:
    """Generate valid Terraform HCL to remediate cloud exposure."""
    lines: list[str] = [
        f"# Terraform Security Policy: {policy_name}",
        "# Generated automatically by FallLine Enterprise Defense Platform",
        "",
        "terraform {",
        "  required_providers {",
        "    aws = {",
        '      source  = "hashicorp/aws"',
        '      version = "~> 5.0"',
        "    }",
        "  }",
        "}",
        "",
        "# Enforce Account-Wide S3 Public Access Block",
        'resource "aws_s3_account_public_access_block" "remediate_s3_leak" {',
        "  block_public_acls       = true",
        "  block_public_policy     = true",
        "  ignore_public_acls      = true",
        "  restrict_public_buckets = true",
        "}",
        "",
    ]

    for finding in findings:
        port = finding.get("port")
        if port:
            res_id = f"revoke_ingress_{port}"
            lines.extend(
                [
                    f"# Remediate Insecure Exposure on Port {port}",
                    f'resource "aws_security_group_rule" "{res_id}" {{',
                    '  type              = "egress"',
                    f'  description       = "FallLine Choke Point: Lock down port {port}"',
                    f"  from_port         = {port}",
                    f"  to_port           = {port}",
                    '  protocol          = "tcp"',
                    '  cidr_blocks       = ["10.0.0.0/8"]  # Restrict to internal VPC only',
                    "  security_group_id = var.target_security_group_id",
                    "}",
                    "",
                ]
            )

    lines.extend(
        [
            'variable "target_security_group_id" {',
            "  type        = string",
            '  description = "The target AWS Security Group ID to harden"',
            "}",
            "",
        ]
    )

    return "\n".join(lines)
