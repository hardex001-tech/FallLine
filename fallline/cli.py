"""Command line: python -m fallline <command> ..."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .intel import Intel
from .knowledge import KnowledgeBase
from .paths import PERSPECTIVES
from .pipeline import RealToolkit, run_host_discovery, run_scan
from .report import render_csv, render_pdf, render_report, render_sarif_json
from .scanners.naabu_scanner import NaabuError
from .scanners.nmap_scanner import NmapError
from .scope import ScopeError, load_scope
from .service import assess, create_snapshot, diff_snapshot
from .store import Store
from .verify import accept_risk, reopen, verify_fix

BANNER = r"""
        / \          ______     _ _ _     _             
       /   \        |  ____|__ _| | | |   (_)_ __   ___  
      / / \ \       | |_  / _` | | | |   | | '_ \ / _ \ 
     / /   \ \      |  _|(_| | | | |___| | | | |  __/ 
    / /  ▲  \ \     |_|   \__,_|_|_|_____|_|_| |_|\___| 
   /_/__/ \__\_\    Defensive Attack-Path Verification Engine [v3.0.0]
      \__▲__/       Hardexploit Lab Edition · MITRE v14 · CISA KEV / EPSS
"""


def _stores(args):
    db = Path(args.db)
    return Store(db), KnowledgeBase.load(), Intel(db.parent / "intel_cache.json")


def print_assessment(a: dict) -> None:
    print(f"\n=== Attack path ({a['perspective']} attacker) ===")
    if a["ttc_minutes"] is None:
        print(
            "No attack path found with the open exposures."
            if a["counts"]["open"]
            else "No findings yet. Run a scan first."
        )
    else:
        print(f"Time to compromise: {a['ttc_human']}")
        for i, s in enumerate(a["path"], 1):
            where = f" (port {s['port']})" if s.get("port") else ""
            print(
                f"  {i}. {s['from']} -> {s['to']}: {s['title']}{where}  [{s['technique']}, ~{round(s['minutes'])} min]"
            )
    if a["fix_plan"]:
        print("\n=== Fix this first ===")
        for i, p in enumerate(a["fix_plan"], 1):
            after = "no path left" if p["ttc_after"] is None else f"~{round(p['ttc_after'])} min"
            print(
                f"  {i}. {p['title']} on {p['host']}:{p['port'] or '-'}  "
                f"(fix ~{round(p['fix_minutes'])} min, attacker time after: {after})"
            )
            print(f"     {p['remediation']}")
            if p.get("fix_command"):
                print(f"     cmd: {p['fix_command']}")
            print(f"     key: {p['key']}")
    c = a["counts"]
    print(f"\nOpen: {c['open']}  Verified fixed: {c['fixed_verified']}  Accepted risk: {c['accepted_risk']}")
    if not a["intel"]["available"]:
        print("Note: CISA KEV/EPSS data not loaded (run `intel-update`); using rule estimates only.")


def cmd_scan(args) -> int:
    store, kb, intel = _stores(args)
    try:
        scope = load_scope(args.scope, audit_log=args.audit_log)
        res = run_scan(
            scope, store, kb, RealToolkit(), args.target, user=args.user, top_ports=args.top_ports, web=not args.no_web
        )
    except ScopeError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except (RuntimeError, NmapError, NaabuError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 3
    print(
        f"Engine: {res['engine']}   Target: {res['target']}   Findings: {res['found']} "
        f"({res['new']} new, {res['reopened']} reopened)"
    )
    for w in res["warnings"]:
        print(f"  note: {w}")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"scan-{datetime.now():%Y%m%d-%H%M%S}.json"
    out.write_text(json.dumps({"summary": res}, indent=2), encoding="utf-8")
    print_assessment(assess(store, kb, intel, args.perspective))
    return 0


def cmd_discover(args) -> int:
    target = getattr(args, "target_opt", None) or getattr(args, "target_pos", None)
    if not target:
        print("Error: target CIDR or IP is required for discover", file=sys.stderr)
        return 2
    try:
        scope = load_scope(args.scope, audit_log=args.audit_log)
        res = run_host_discovery(scope, RealToolkit(), target, user=args.user)
    except ScopeError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except (ValueError, RuntimeError, OSError, NmapError) as exc:
        print(f"Discovery failed: {exc}", file=sys.stderr)
        return 3
    print(f"Engine: {res['engine']}   Subnet: {res['target']}   Live hosts: {res['count']}")
    for h in res["hosts"]:
        hn = f" ({h['hostname']})" if h.get("hostname") else ""
        ports = ", ".join(str(p) for p in h.get("open_ports", [])) or "-"
        svcs = ", ".join(h.get("services", [])) or "-"
        print(f"  - {h['host']}{hn}  [ports: {ports}]  [services: {svcs}]")
    return 0


def cmd_paths(args) -> int:
    store, kb, intel = _stores(args)
    print_assessment(assess(store, kb, intel, args.perspective))
    return 0


def cmd_mitre(args) -> int:
    store, kb, intel = _stores(args)
    a = assess(store, kb, intel, args.perspective)
    print("\n=== MITRE ATT&CK Tactic Matrix ===")
    for col in a["mitre_matrix"]:
        print(
            f"  {col['tactic']:<22} rules: {col['rules_count']:<2}  "
            f"open: {col['open_count']:<2}  fixed: {col['fixed_count']:<2}  "
            f"accepted: {col['accepted_count']:<2}"
        )
        for f in col["findings"]:
            if f["status"] == "OPEN":
                print(f"    - [{f['technique_id']}] {f['title']} on {f['host']}:{f['port'] or '-'}")
                if f.get("fix_command"):
                    print(f"      cmd: {f['fix_command']}")
    return 0


def cmd_snapshot(args) -> int:
    store, kb, intel = _stores(args)
    action = args.snap_action
    if action == "save":
        name = args.name or getattr(args, "arg", None) or f"Snapshot {datetime.now():%Y-%m-%d %H:%M}"
        try:
            snap = create_snapshot(store, kb, intel, name)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(
            f"Saved snapshot #{snap['id']}: {snap['name']} "
            f"(open: {snap['counts']['open']}, ext TTC: {snap['ttc_external']})"
        )
        return 0
    if action == "list":
        snaps = store.list_snapshots()
        if not snaps:
            print("No snapshots saved.")
            return 0
        for s in snaps:
            print(
                f"  #{s['id']}  {s['name']}  ({s['created_at']})  "
                f"open={s['counts']['open']} fixed={s['counts']['fixed_verified']} "
                f"ext_ttc={s['ttc_external']} chain={s['chain_length']}"
            )
        return 0
    if action == "diff":
        base_raw = args.base if args.base is not None else getattr(args, "arg", None)
        if base_raw is None:
            print("Error: --base <snapshot_id> is required for snapshot diff", file=sys.stderr)
            return 2
        try:
            base_id = int(base_raw)
            target_id = int(args.target_snap) if args.target_snap is not None else None
            diff = diff_snapshot(store, kb, intel, base_id=base_id, target_id=target_id)
        except (ValueError, KeyError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        print(f"\n=== Snapshot Diff: #{diff['base']['id']} ({diff['base']['name']}) -> {diff['target']['name']} ===")
        print(
            f"External TTC: {diff['base']['ttc_external_human']} -> {diff['target']['ttc_external_human']} "
            f"(delta: {diff['ttc_external_delta']})"
        )
        print(
            f"Internal TTC: {diff['base']['ttc_internal_human']} -> {diff['target']['ttc_internal_human']} "
            f"(delta: {diff['ttc_internal_delta']})"
        )
        print(
            f"Chain length: {diff['chain_length_before']} -> {diff['chain_length_after']} "
            f"(delta: {diff['chain_length_delta']})"
        )
        print(
            f"Changes: +{diff['counts_diff']['new']} new, "
            f"-{diff['counts_diff']['fixed']} fixed, "
            f"{diff['counts_diff']['accepted']} accepted risk"
        )
        return 0
    return 2


def cmd_verify(args) -> int:
    store, kb, _ = _stores(args)
    try:
        scope = load_scope(args.scope, audit_log=args.audit_log)
        res = verify_fix(
            store, kb, scope, RealToolkit(aws_profile=args.profile, aws_region=args.region), args.key, args.user
        )
    except ScopeError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    except KeyError:
        print("Unknown finding key. Run `paths` to list keys.", file=sys.stderr)
        return 2
    print(("VERIFIED FIXED: " if res.verified else "NOT VERIFIED: ") + res.message)
    return 0 if res.verified else 1


def cmd_accept(args) -> int:
    store, _, _ = _stores(args)
    try:
        accept_risk(store, args.key, args.reason)
    except (KeyError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print("Marked ACCEPTED_RISK (excluded from the attack path, still listed).")
    return 0


def cmd_reopen(args) -> int:
    store, _, _ = _stores(args)
    try:
        reopen(store, args.key)
    except KeyError:
        print("Unknown finding key.", file=sys.stderr)
        return 2
    print("Reopened.")
    return 0


def cmd_intel(args) -> int:
    store, kb, intel = _stores(args)
    cves = [c for r in store.all() for c in r["finding"].cves] + [c for rule in kb.rules for c in rule.cves]
    print(intel.update(cves))
    return 0


def cmd_report(args) -> int:
    store, kb, intel = _stores(args)
    who = ""
    if args.scope:
        try:
            who = load_scope(args.scope).authorized_by
        except ScopeError:
            pass
    assessment = assess(store, kb, intel, args.perspective)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = (getattr(args, "format", None) or "").lower()
    if not fmt:
        if getattr(args, "pdf", False) or out_path.suffix.lower() == ".pdf":
            fmt = "pdf"
        elif out_path.suffix.lower() in (".sarif", ".json"):
            fmt = "sarif"
        elif out_path.suffix.lower() == ".csv":
            fmt = "csv"
        else:
            fmt = "html"

    records = store.all()
    if fmt == "pdf":
        out_path.write_bytes(render_pdf(assessment, records, authorized_by=who))
    elif fmt == "sarif":
        out_path.write_text(render_sarif_json(assessment, records, kb=kb, authorized_by=who), encoding="utf-8")
    elif fmt == "csv":
        out_path.write_text(render_csv(assessment, records, kb=kb, authorized_by=who), encoding="utf-8")
    else:
        html = render_report(assessment, records, authorized_by=who)
        out_path.write_text(html, encoding="utf-8")
    print(f"Report written: {args.output}")
    return 0


def cmd_aws(args) -> int:
    store, kb, _ = _stores(args)
    try:
        findings, warnings = RealToolkit(aws_profile=args.profile, aws_region=args.region).aws_audit()
    except Exception as exc:  # noqa: BLE001
        print(f"AWS audit failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 3
    counts = store.ingest(findings, kb, target="aws", engine="aws-readonly")
    for w in warnings:
        print(f"  note: {w}")
    print(f"AWS findings: {len(findings)} ({counts['new']} new)")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from .app import create_app

    if args.demo:
        from .demo import FakeToolkit

        demo_dir = Path("data/demo")
        demo_dir.mkdir(parents=True, exist_ok=True)
        (demo_dir / "scope.yaml").write_text(
            'authorized_by: "DEMO (fake network)"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n',
            encoding="utf-8",
        )
        db = demo_dir / "demo.db"
        if db.exists():
            try:
                db.unlink()
            except OSError:
                pass
        toolkit = FakeToolkit()
        scope = load_scope(demo_dir / "scope.yaml", audit_log=demo_dir / "audit.log")
        store, kb = Store(db), KnowledgeBase.load()
        if not store.all():
            run_scan(scope, store, kb, toolkit, "192.168.56.0/24")
        if not store.list_snapshots():
            create_snapshot(store, kb, None, "Baseline (Initial Scan)")
        app = create_app(demo_dir / "scope.yaml", db, audit_log=demo_dir / "audit.log", toolkit=toolkit, demo=True)
    else:
        if not args.scope:
            print("--scope is required (or use --demo)", file=sys.stderr)
            return 2
        app = create_app(args.scope, args.db, audit_log=args.audit_log)
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "WARNING: the dashboard has no login. Binding to a non-local address exposes it to "
            "your network. Put it behind a VPN or reverse proxy with authentication."
        )
    print(f"FallLine dashboard: http://{args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_audit_mail(args) -> int:
    from .mail_audit import audit_domain_email_security

    res = audit_domain_email_security(args.domain)
    print(f"\n[+] Email & Domain Security Posture for: {res.domain}")
    print(f"    Spoofable by Attackers: {'YES (HIGH RISK)' if res.spoofable else 'NO (PROTECTED)'}")
    print(f"    Posture Score: {res.risk_score}/100 ({res.risk_level})")
    print(f"    SPF Record: {res.spf_record or 'None'}")
    print(f"    DMARC Record: {res.dmarc_record or 'None'}")
    print(f"\n[!] Findings ({len(res.findings)}):")
    for f in res.findings:
        print(f"    [{f.status}] {f.title}: {f.description}")
        print(f"        Remediation TXT: {f.remediation_txt}")
    return 0


def cmd_audit_web(args) -> int:
    from .scope import ScopeError
    from .web_audit import audit_web_exposure

    try:
        res = audit_web_exposure(args.host, port=args.port, use_ssl=args.ssl)
    except ScopeError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    print(f"\n[+] Web & Cloud Exposure Audit for: {res.target}:{res.port}")
    print(f"[!] Total Findings: {len(res.findings)}")
    for f in res.findings:
        print(f"    [{f.severity}] {f.title}")
        print(f"        Evidence: {f.evidence}")
        print(f"        Remediation: {f.remediation}")
    return 0


def cmd_ingest_ad(args) -> int:
    from .ad_ingest import ingest_bloodhound_file_or_data

    try:
        res = ingest_bloodhound_file_or_data(args.file)
    except Exception as exc:
        print(f"Failed to ingest BloodHound data: {exc}", file=sys.stderr)
        return 2
    print("\n[+] Active Directory Privilege Escalation Ingestion")
    print(
        f"    Nodes: {res.nodes_count} (Users: {res.users_count}, Computers: {res.computers_count}, Groups: {res.groups_count})"
    )
    print(f"    Edges: {res.edges_count}")
    print(f"    Crown Jewels Identified: {len(res.crown_jewels)}")
    print(f"\n[!] Critical Privilege Escalation Paths ({len(res.attack_paths)}):")
    for i, p in enumerate(res.attack_paths[:5], 1):
        print(
            f"\n  Path #{i}: {p.starting_account} -> {p.target_crown_jewel} (Est. TTC: {p.total_ttc_minutes:.0f} mins)"
        )
        for s in p.steps:
            print(f"    -> {s.description}")
        if p.choke_point_step:
            print(
                f"  [CHOKE POINT]: {p.choke_point_step.source} --{p.choke_point_step.relationship}--> {p.choke_point_step.target}"
            )
            print(f"  Remediation PowerShell:\n    {p.remediation_command}")
    return 0


def cmd_ingest_dast(args) -> int:
    from .dast_ingest import ingest_dast_report

    store, kb, intel = _stores(args)
    try:
        res = ingest_dast_report(args.file)
    except Exception as exc:
        print(f"Failed to ingest DAST report: {exc}", file=sys.stderr)
        return 2

    findings = [v.to_finding() for v in res.vulnerabilities]
    counts = store.ingest(findings, kb, target=res.scanner.lower(), engine=f"dast-{res.scanner.lower()}")

    print(f"\n[+] Ingested {res.scanner} Report")
    hosts_str = ", ".join(res.target_hosts) or "None"
    print(f"    Hosts Discovered: {hosts_str}")
    new_count = counts.get("new", 0)
    print(f"    Total Vulnerabilities: {res.total_findings} ({new_count} new into attack graph)")
    for v in res.vulnerabilities[:5]:
        print(f"    [{v.severity}] {v.title} at {v.url}")
        print(f"        WAF Remediation:\n        {v.waf_rule}")
    return 0


def cmd_export_iac(args) -> int:
    from .iac_generator import generate_ansible_playbook, generate_terraform_policy

    store, kb, intel = _stores(args)
    records = store.all()
    classified = [r for r in records if r["status"] == "OPEN"]
    findings = [
        {"port": r["finding"].port, "service": r["finding"].service, "title": r["finding"].title} for r in classified
    ]
    fmt = (args.format or "ansible").lower()
    out = Path(args.output) if args.output else None
    if fmt == "terraform":
        code = generate_terraform_policy(findings)
        if not out:
            out = Path("data/remediation.tf")
    else:
        code = generate_ansible_playbook(findings)
        if not out:
            out = Path("data/fallline_remediation.yml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(code, encoding="utf-8")
    print(f"[+] Exported {fmt.upper()} remediation to: {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fallline", description="Defensive attack-path analysis. Authorized targets only."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p, scope=False, perspective=False):
        p.add_argument("--db", default="data/fallline.db")
        if scope:
            p.add_argument("--scope", required=True, help="path to scope YAML file")
            p.add_argument("--audit-log", default=None)
            p.add_argument("--user", default=None, help="name for the audit log")
        if perspective:
            p.add_argument("--perspective", choices=PERSPECTIVES, default="external")

    p = sub.add_parser("scan", help="scan an authorized target and show the attack path")
    common(p, scope=True, perspective=True)
    p.add_argument("--target", required=True, help="IP or CIDR to scan")
    p.add_argument("--top-ports", type=int, default=1000)
    p.add_argument("--no-web", action="store_true", help="skip httpx/Nuclei stages")
    p.add_argument("--output-dir", default="data")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("discover", help="discover active hosts on an authorized subnet")
    common(p, scope=True)
    p.add_argument("target_pos", nargs="?", default=None, metavar="target_cidr", help="authorized subnet CIDR or IP")
    p.add_argument("--target", dest="target_opt", default=None, help="authorized subnet CIDR or IP")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("paths", help="show the attack path from stored findings")
    common(p, perspective=True)
    p.set_defaults(func=cmd_paths)

    p = sub.add_parser("mitre", help="show MITRE ATT&CK tactic matrix coverage and fix commands")
    common(p, perspective=True)
    p.set_defaults(func=cmd_mitre)

    p = sub.add_parser("snapshot", help="save, list, or diff assessment snapshots")
    common(p)
    p.add_argument("snap_action", choices=("save", "list", "diff"), help="snapshot action")
    p.add_argument("arg", nargs="?", default=None, help="snapshot name (for save) or base id (for diff)")
    p.add_argument("--name", default=None, help="snapshot name for save")
    p.add_argument("--base", type=int, default=None, help="base snapshot id for diff")
    p.add_argument(
        "--target",
        dest="target_snap",
        type=int,
        default=None,
        help="optional target snapshot id for diff (defaults to current state)",
    )
    p.set_defaults(func=cmd_snapshot)

    p = sub.add_parser("verify", help="re-scan ONE finding and mark it fixed only if gone")
    common(p, scope=True)
    p.add_argument("--key", required=True)
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default=None)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("accept", help="accept a risk (reason required)")
    common(p)
    p.add_argument("--key", required=True)
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_accept)

    p = sub.add_parser("reopen", help="set a finding back to OPEN")
    common(p)
    p.add_argument("--key", required=True)
    p.set_defaults(func=cmd_reopen)

    p = sub.add_parser("intel-update", help="download CISA KEV + EPSS data (cached)")
    common(p)
    p.set_defaults(func=cmd_intel)

    p = sub.add_parser("report", help="write HTML, PDF, SARIF 2.1.0, or CSV report")
    common(p, perspective=True)
    p.add_argument("--scope", default=None)
    p.add_argument("--output", default="data/report.html")
    p.add_argument(
        "--format", choices=("html", "pdf", "sarif", "csv"), default=None, help="export format (html, pdf, sarif, csv)"
    )
    p.add_argument("--pdf", action="store_true", help="write PDF report instead of HTML")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("aws-audit", help="v2: read-only AWS configuration audit")
    common(p)
    p.add_argument("--profile", default=None)
    p.add_argument("--region", default=None)
    p.set_defaults(func=cmd_aws)

    p = sub.add_parser("serve", help="start the web dashboard")
    common(p)
    p.add_argument("--scope", default=None)
    p.add_argument("--audit-log", default=None)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--demo", action="store_true", help="fake network with sample data")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("audit-mail", help="audit domain email security posture (SPF & DMARC spoofing)")
    p.add_argument("domain", help="target domain name (e.g. acme-corp.com)")
    p.set_defaults(func=cmd_audit_mail)

    p = sub.add_parser("audit-web", help="audit web application for exposed .env, .git, and security headers")
    p.add_argument("host", help="target authorized host or IP")
    p.add_argument("--port", type=int, default=80, help="port (default 80)")
    p.add_argument("--ssl", action="store_true", help="use HTTPS")
    p.set_defaults(func=cmd_audit_web)

    p = sub.add_parser("ingest-ad", help="ingest BloodHound Active Directory JSON export and find choke points")
    p.add_argument("file", help="path to BloodHound JSON export file")
    p.set_defaults(func=cmd_ingest_ad)

    p = sub.add_parser("ingest-dast", help="ingest OWASP ZAP (JSON) or Burp Suite (XML) DAST vulnerability report")
    common(p)
    p.add_argument("file", help="path to ZAP JSON or Burp XML report")
    p.set_defaults(func=cmd_ingest_dast)

    p = sub.add_parser("export-iac", help="export Ansible playbook or Terraform policy for verified choke points")
    common(p)
    p.add_argument("--format", choices=("ansible", "terraform"), default="ansible", help="remediation format")
    p.add_argument("--output", default=None, help="output file path")
    p.set_defaults(func=cmd_export_iac)

    parser.add_argument("--no-banner", action="store_true", help="suppress startup ASCII banner")
    args = parser.parse_args(argv)
    if not getattr(args, "no_banner", False) and args.command in ("serve", "scan", "paths", "discover", "mitre"):
        print(BANNER.strip("\n"))
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
