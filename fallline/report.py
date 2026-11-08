"""Plain-language HTML and PDF report ("Attack Story"). Self-contained, no external assets."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from html import escape

from .knowledge import KnowledgeBase
from .paths import humanize_minutes

CSS = """body{font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:900px;margin:2rem auto;
padding:0 1rem;color:#1b2430}h1{border-bottom:3px solid #c0392b;padding-bottom:.3rem}
.box{background:#f4f6f8;border-left:5px solid #c0392b;padding:.8rem 1rem;margin:1rem 0}
.ok{border-color:#27ae60}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccd;padding:.4rem .6rem;text-align:left;font-size:.92rem}
th{background:#eef}.sev-critical{color:#c0392b;font-weight:700}.sev-high{color:#d35400;font-weight:700}
.sev-medium{color:#b7950b}.sev-low{color:#566}small{color:#667}
code{font-family:Consolas,monospace;font-size:.84rem;background:#eef1f5;padding:.1rem .3rem;border-radius:3px}
@media print{.no-print{display:none}body{margin:.5rem auto}}"""

_SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_SCORES = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "1.0",
}


def _e(x) -> str:
    return escape(str(x))


def render_report(
    assessment: dict, records: list[dict], authorized_by: str = "", title: str = "FallLine Attack Story"
) -> str:
    ttc = assessment["ttc_minutes"]
    path = assessment["path"]
    plan = assessment["fix_plan"]
    meta = (
        f"<p><small>Generated {datetime.now():%Y-%m-%d %H:%M} &middot; perspective: "
        f"{_e(assessment['perspective'])} attacker &middot; authorized by: {_e(authorized_by or 'n/a')}"
        f"</small></p>"
    )
    parts = [
        f"<!doctype html><meta charset='utf-8'><title>{_e(title)}</title><style>{CSS}</style>",
        f"<h1>{_e(title)}</h1>",
        meta,
    ]
    if assessment["simulated_fixes"]:
        parts.append(
            "<div class='box'><b>SIMULATION.</b> This report assumes some fixes were made "
            "that have not been verified by a re-scan.</div>"
        )

    baseline_ttc = assessment.get("baseline_ttc_minutes")
    has_fixes = bool(assessment.get("counts", {}).get("fixed_verified") or assessment["simulated_fixes"])
    if has_fixes and baseline_ttc is not None:
        after_lbl = "no path" if ttc is None else humanize_minutes(ttc)
        parts.append(
            f"<div class='box ok'><b>Before fixes:</b> {_e(humanize_minutes(baseline_ttc))} &rarr; "
            f"<b>{'If fixed (simulated)' if assessment['simulated_fixes'] else 'Now (verified)'}:</b> "
            f"{_e(after_lbl)}</div>"
        )

    if ttc is None:
        parts.append(
            "<div class='box ok'><b>No attack path found</b> with the exposures currently "
            "open. That is based only on what was scanned.</div>"
        )
    else:
        parts.append(
            f"<div class='box'><b>Time to compromise: {_e(humanize_minutes(ttc))}.</b> "
            "This is a rough estimate of how long a skilled attacker would need, based on "
            "the exposures found. It orders the fixes; it is not a guarantee.</div>"
        )
        parts.append("<h2>The attack story</h2><ol>")
        for s in path:
            parts.append(
                f"<li><b>{_e(s['from'])} &rarr; {_e(s['to'])}</b>: {_e(s['title'])}"
                f"{' on port ' + _e(s['port']) if s.get('port') else ''}. "
                f"{_e(s.get('why', ''))} <small>({_e(s['technique'])}, ~{_e(round(s['minutes']))} min)"
                f"</small></li>"
            )
        parts.append("</ol>")

    parts.append("<h2>Fix this first</h2>")
    if plan:
        parts.append(
            "<table><tr><th>#</th><th>Where</th><th>Fix</th><th>Effort</th><th>Attacker time after fix</th></tr>"
        )
        for i, p in enumerate(plan, 1):
            after = "no path left" if p["ttc_after"] is None else humanize_minutes(p["ttc_after"])
            where = _e(p["host"]) + (f":{_e(p['port'])}" if p["port"] else "")
            cmd_html = f"<br><code>{_e(p['fix_command'])}</code>" if p.get("fix_command") else ""
            parts.append(
                f"<tr><td>{i}</td><td>{where}</td><td><b>{_e(p['title'])}</b><br>"
                f"{_e(p['remediation'])}{cmd_html}</td><td>~{_e(round(p['fix_minutes']))} min</td>"
                f"<td>{_e(after)}</td></tr>"
            )
        parts.append("</table>")
    else:
        parts.append("<p>Nothing to fix on the current attack path.</p>")

    parts.append(
        "<h2>All findings</h2><table><tr><th>Status</th><th>Severity</th><th>Where</th>"
        "<th>Finding</th><th>Verification</th></tr>"
    )
    sev = {e["key"]: e for e in assessment["exposures"]}
    for r in records:
        f = r["finding"]
        info = sev.get(r["key"])
        sv = info["severity"] if info else "info"
        where = _e(f.host) + (f":{_e(f.port)}" if f.port else "")
        ver = _e(r["note"]) if r["note"] else ("&mdash;" if r["status"] == "OPEN" else "")
        if r["status"] == "FIXED_VERIFIED":
            ver = f"Re-scan confirmed gone {_e(r['verified_at'])}. {ver}"
        parts.append(
            f"<tr><td>{_e(r['status'])}</td><td class='sev-{_e(sv)}'>{_e(sv)}</td>"
            f"<td>{where}</td><td>{_e(info['title'] if info else (f.service or 'service'))}"
            f"{(' ' + _e(f.product) + ' ' + _e(f.version)) if f.product else ''}</td>"
            f"<td>{ver}</td></tr>"
        )
    parts.append(
        "</table><p><small>FallLine detects exposure only. It does not exploit, guess "
        "passwords or run intrusive checks. Use it only on systems you are authorized "
        "to test.</small></p>"
    )
    return "\n".join(parts)


def _pdf_escape(text: str) -> str:
    safe = text.encode("latin-1", errors="replace").decode("latin-1")
    return safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_pdf(
    assessment: dict, records: list[dict], authorized_by: str = "", title: str = "FallLine Attack Story"
) -> bytes:
    """Build a self-contained multi-page PDF 1.4 Attack Story document with zero external dependencies."""
    ttc = assessment["ttc_minutes"]
    header_meta = (
        f"Generated {datetime.now():%Y-%m-%d %H:%M} | Perspective: {assessment['perspective']} "
        f"| Authorized by: {authorized_by or 'n/a'}"
    )
    lines: list[tuple[int, str]] = [
        (16, title),
        (9, header_meta),
        (10, ""),
    ]
    if assessment["simulated_fixes"]:
        lines.append((10, "SIMULATION: Assumes unverified fixes."))
    baseline_ttc = assessment.get("baseline_ttc_minutes")
    has_fixes = bool(assessment.get("counts", {}).get("fixed_verified") or assessment["simulated_fixes"])
    if has_fixes and baseline_ttc is not None:
        after_lbl = "no path" if ttc is None else humanize_minutes(ttc)
        lines.append((10, f"Before fixes: {humanize_minutes(baseline_ttc)} -> Current: {after_lbl}"))

    if ttc is None:
        lines.append((12, "Result: No attack path found with open exposures."))
    else:
        lines.append((12, f"Time to compromise: {humanize_minutes(ttc)}"))
        lines.append((10, ""))
        lines.append((12, "The Attack Story:"))
        for i, s in enumerate(assessment["path"], 1):
            port_txt = f" (port {s['port']})" if s.get("port") else ""
            step_line = (
                f"  {i}. {s['from']} -> {s['to']}: {s['title']}{port_txt} "
                f"[{s['technique']}, ~{round(s['minutes'])} min]"
            )
            lines.append((10, step_line))

    lines.append((10, ""))
    lines.append((12, "Fix This First:"))
    if assessment["fix_plan"]:
        for i, p in enumerate(assessment["fix_plan"], 1):
            after = "no path left" if p["ttc_after"] is None else humanize_minutes(p["ttc_after"])
            where = f"{p['host']}:{p['port']}" if p["port"] else str(p["host"])
            lines.append((10, f"  {i}. [{where}] {p['title']} (fix ~{round(p['fix_minutes'])}m -> {after})"))
            lines.append((9, f"     Action: {p['remediation'][:95]}"))
    else:
        lines.append((10, "  Nothing to fix on the current attack path."))

    lines.append((10, ""))
    lines.append((12, f"Findings Summary ({len(records)} total):"))
    sev = {e["key"]: e for e in assessment["exposures"]}
    for r in records:
        f = r["finding"]
        info = sev.get(r["key"])
        sv = (info["severity"] if info else "info").upper()
        where = f"{f.host}:{f.port}" if f.port else f.host
        ftitle = info["title"] if info else (f.service or "service")
        lines.append((9, f"  - [{r['status']}] ({sv}) {where}: {ftitle}"))

    # Paginate lines across PDF pages
    pages_streams: list[bytes] = []
    cur_cmds = ["BT", "/F1 12 Tf", "50 750 Td"]
    y = 750
    for size, text in lines:
        step = size + 5
        if y - step < 50:
            cur_cmds.append("ET")
            pages_streams.append("\n".join(cur_cmds).encode("latin-1"))
            cur_cmds = ["BT", "/F1 12 Tf", "50 750 Td"]
            y = 750
        cur_cmds.append(f"/F1 {size} Tf")
        cur_cmds.append(f"({_pdf_escape(text)}) Tj")
        cur_cmds.append(f"0 -{step} Td")
        y -= step
    cur_cmds.append("ET")
    pages_streams.append("\n".join(cur_cmds).encode("latin-1"))

    # Object 1: Catalog, Object 2: Pages, Object 3: Font
    # For each page i (0..N-1): Page object is (4 + 2*i), Content stream is (5 + 2*i)
    page_ids = [4 + 2 * i for i in range(len(pages_streams))]
    kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
    objs: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {len(pages_streams)} >>\nendobj\n".encode("latin-1"),
        b"3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]
    for i, stream_bytes in enumerate(pages_streams):
        pid = 4 + 2 * i
        cid = 5 + 2 * i
        objs.append(
            f"{pid} 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {cid} 0 R >>\nendobj\n".encode("latin-1")
        )
        objs.append(
            f"{cid} 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1")
            + stream_bytes
            + b"\nendstream\nendobj\n"
        )

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objs:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("latin-1"))
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("latin-1"))
    out.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin-1"))
    return bytes(out)


def render_sarif(
    assessment: dict,
    records: list[dict],
    kb: KnowledgeBase | None = None,
    authorized_by: str = "",
) -> dict:
    """Build a SARIF 2.1.0 report dictionary compatible with GitHub Code Scanning & VS Code."""
    kb = kb or KnowledgeBase.load()
    exp_by_key = {e["key"]: e for e in assessment.get("exposures", [])}

    sarif_rules: list[dict] = []
    for rule in kb.rules:
        sv = (rule.severity or "info").lower()
        tid = rule.technique["id"]
        tactic = rule.technique.get("tactic", "Initial Access")
        help_text = rule.remediation
        help_md = f"**Why:** {rule.why}\n\n**Remediation:** {rule.remediation}"
        if rule.fix_command:
            help_text += f"\nCommand: {rule.fix_command}"
            help_md += f"\n\n```bash\n{rule.fix_command}\n```"
        sarif_rules.append(
            {
                "id": rule.id,
                "name": rule.title,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.why},
                "help": {"text": help_text, "markdown": help_md},
                "defaultConfiguration": {"level": _SARIF_LEVELS.get(sv, "note")},
                "properties": {
                    "tags": ["security", f"MITRE/{tid}", f"Tactic/{tactic}", *rule.cves],
                    "precision": "high",
                    "security-severity": _SARIF_SCORES.get(sv, "1.0"),
                    "tactic": tactic,
                    "technique": f"{tid} {rule.technique['name']}",
                    "fix_command": rule.fix_command,
                },
            }
        )

    if any(r.get("rule_id") == "none" for r in records):
        sarif_rules.append(
            {
                "id": "unclassified-service",
                "name": "Unclassified open network service",
                "shortDescription": {"text": "Open network service without a specific attack rule"},
                "fullDescription": {"text": "An open network service was detected during scanning."},
                "help": {"text": "Review whether this service needs to be exposed."},
                "defaultConfiguration": {"level": "note"},
                "properties": {"tags": ["security"], "security-severity": "1.0"},
            }
        )

    results: list[dict] = []
    for r in records:
        f = r["finding"]
        info = exp_by_key.get(r["key"])
        rule_obj = kb.by_id.get(r["rule_id"])
        rule_id = r["rule_id"] if r["rule_id"] != "none" else "unclassified-service"
        sv = (info["severity"] if info else (rule_obj.severity if rule_obj else "info")).lower()
        title = info["title"] if info else (rule_obj.title if rule_obj else (f.title or f.service or "service"))
        tech = (
            info["technique"]
            if info
            else (f"{rule_obj.technique['id']} {rule_obj.technique['name']}" if rule_obj else "-")
        )
        tactic = info.get("tactic", "") if info else (rule_obj.technique.get("tactic", "") if rule_obj else "")
        remediation = info["remediation"] if info else (rule_obj.remediation if rule_obj else "")
        fix_cmd = info.get("fix_command", "") if info else (rule_obj.fix_command if rule_obj else "")
        where = f"{f.host}:{f.port}/{f.protocol}" if f.port else f.host
        msg_text = f"[{r['status']}] {title} on {where}."
        if remediation:
            msg_text += f" Remediation: {remediation}"
        if fix_cmd:
            msg_text += f" Command: {fix_cmd}"

        uri = f"target://{f.host}" if not str(f.host).startswith("aws:") else str(f.host)
        res_entry: dict = {
            "ruleId": rule_id,
            "level": _SARIF_LEVELS.get(sv, "note"),
            "baselineState": "absent" if r["status"] == "FIXED_VERIFIED" else "new",
            "message": {"text": msg_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": max(1, int(f.port or 1))},
                    }
                }
            ],
            "properties": {
                "key": r["key"],
                "status": r["status"],
                "severity": sv,
                "host": f.host,
                "port": f.port,
                "protocol": f.protocol,
                "service": f.service,
                "product": f.product,
                "version": f.version,
                "technique": tech,
                "tactic": tactic,
                "fix_command": fix_cmd,
                "verified_at": r.get("verified_at"),
                "note": r.get("note", ""),
            },
        }
        if r["status"] == "ACCEPTED_RISK":
            res_entry["suppressions"] = [{"kind": "external", "justification": r.get("note") or "Accepted risk"}]
        results.append(res_entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FallLine",
                        "version": "3.0.0",
                        "informationUri": "https://github.com/fallline-sec/fallline",
                        "rules": sarif_rules,
                    }
                },
                "automationDetails": {
                    "id": f"fallline/{assessment.get('perspective', 'external')}/{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
                },
                "properties": {
                    "authorized_by": authorized_by or "n/a",
                    "perspective": assessment.get("perspective", "external"),
                    "ttc_minutes": assessment.get("ttc_minutes"),
                    "ttc_human": assessment.get("ttc_human"),
                },
                "results": results,
            }
        ],
    }


def render_sarif_json(
    assessment: dict,
    records: list[dict],
    kb: KnowledgeBase | None = None,
    authorized_by: str = "",
) -> str:
    return json.dumps(render_sarif(assessment, records, kb=kb, authorized_by=authorized_by), indent=2)


def render_csv(
    assessment: dict,
    records: list[dict],
    kb: KnowledgeBase | None = None,
    authorized_by: str = "",
) -> str:
    """Build a standard CSV export of all findings for spreadsheet/ticketing import."""
    kb = kb or KnowledgeBase.load()
    exp_by_key = {e["key"]: e for e in assessment.get("exposures", [])}
    plan_keys = {p["key"] for p in assessment.get("fix_plan", [])}
    buf = io.StringIO(newline="")
    writer = csv.writer(buf)
    writer.writerow(
        [
            "key",
            "status",
            "severity",
            "host",
            "port",
            "protocol",
            "service",
            "product",
            "version",
            "rule_id",
            "title",
            "tactic",
            "technique",
            "attacker_minutes",
            "fix_minutes",
            "in_fix_plan",
            "remediation",
            "fix_command",
            "cves",
            "verified_at",
            "note",
            "authorized_by",
        ]
    )
    for r in records:
        f = r["finding"]
        info = exp_by_key.get(r["key"])
        rule_obj = kb.by_id.get(r["rule_id"])
        sv = info["severity"] if info else (rule_obj.severity if rule_obj else "info")
        title = info["title"] if info else (rule_obj.title if rule_obj else (f.title or f.service or "service"))
        tactic = info.get("tactic", "") if info else (rule_obj.technique.get("tactic", "") if rule_obj else "")
        tech = (
            info["technique"]
            if info
            else (f"{rule_obj.technique['id']} {rule_obj.technique['name']}" if rule_obj else "-")
        )
        att_min = info["attacker_minutes"] if info else (rule_obj.effort_for(f) if rule_obj else "")
        fix_min = info["fix_minutes"] if info else (rule_obj.fix_minutes if rule_obj else "")
        rem = info["remediation"] if info else (rule_obj.remediation if rule_obj else "")
        fix_cmd = info.get("fix_command", "") if info else (rule_obj.fix_command if rule_obj else "")
        cves = info["cves"] if info else list(dict.fromkeys([*(rule_obj.cves if rule_obj else []), *f.cves]))
        writer.writerow(
            [
                r["key"],
                r["status"],
                sv,
                f.host,
                f.port,
                f.protocol,
                f.service,
                f.product,
                f.version,
                r["rule_id"],
                title,
                tactic,
                tech,
                att_min,
                fix_min,
                r["key"] in plan_keys,
                rem,
                fix_cmd,
                ";".join(cves),
                r.get("verified_at") or "",
                r.get("note") or "",
                authorized_by or "",
            ]
        )
    return buf.getvalue()
