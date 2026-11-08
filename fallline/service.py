"""Glue between store, rules, intel and the path engine (used by CLI, API, report)."""

from __future__ import annotations

from .intel import Intel
from .knowledge import KnowledgeBase, build_mitre_matrix
from .paths import analyze, build_exposures, humanize_minutes
from .store import ACCEPTED, FIXED, OPEN, Store


def assess(
    store: Store,
    kb: KnowledgeBase,
    intel: Intel | None,
    perspective: str = "external",
    simulate: list[str] | tuple[str, ...] = (),
) -> dict:
    """Current assessment.

    The attack graph uses OPEN exposures only. FIXED_VERIFIED ones are gone
    (that is the whole point of verification) and ACCEPTED_RISK ones are
    excluded because a person decided to live with them; both are still listed.
    `baseline` is the same analysis as if nothing had ever been fixed, which
    drives the before/after view.
    """
    recs = store.all()
    by_key = {r["key"]: r for r in recs}
    classified = [r for r in recs if r["rule_id"] != "none"]
    all_exps = build_exposures([(r["key"], r["finding"]) for r in classified], kb, intel)
    exp_by_key = {e.key: e for e in all_exps}

    open_exps = [e for e in all_exps if by_key[e.key]["status"] == OPEN]
    non_fixed = [e for e in all_exps if by_key[e.key]["status"] != FIXED]
    baseline_exps = [e for e in all_exps if by_key[e.key]["status"] in (OPEN, FIXED)]
    open_keys = {e.key for e in open_exps}
    sim = {k for k in simulate if k in open_keys}

    result = analyze(open_exps, perspective, removed=sim)
    baseline = analyze(baseline_exps, perspective)

    records = []
    for r in recs:
        f = r["finding"]
        e = exp_by_key.get(r["key"])
        records.append(
            {
                "key": r["key"],
                "rule_id": r["rule_id"],
                "status": r["status"],
                "note": r["note"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
                "verified_at": r["verified_at"],
                "host": f.host,
                "port": f.port,
                "protocol": f.protocol,
                "service": f.service,
                "product": f.product,
                "version": f.version,
                "evidence": f.evidence,
                "title": e.rule.title if e else (f.title or f"{f.service or 'service'} (no rule)"),
                "severity": e.rule.severity if e else "info",
                "tactic": e.rule.technique.get("tactic", "") if e else "",
                "technique": f"{e.rule.technique['id']} {e.rule.technique['name']}" if e else "-",
                "remediation": e.rule.remediation if e else "",
                "fix_command": e.rule.fix_command if e else "",
                "why": e.rule.why if e else "",
                "cves": list(dict.fromkeys([*(e.rule.cves if e else []), *f.cves])),
                "classified": e is not None,
                "simulated_fixed": r["key"] in sim,
            }
        )
    result["records"] = records
    result["mitre_matrix"] = build_mitre_matrix(kb, records)
    result["baseline_ttc_minutes"] = baseline["ttc_minutes"]
    result["baseline_ttc_human"] = baseline["ttc_human"]
    result["baseline_path"] = baseline["path"]
    result["counts"] = {
        "open": sum(1 for r in recs if r["status"] == OPEN),
        "fixed_verified": sum(1 for r in recs if r["status"] == FIXED),
        "accepted_risk": sum(1 for r in recs if r["status"] == ACCEPTED),
        "excluded_accepted": len(non_fixed) - len(open_exps),
    }
    result["intel"] = {
        "available": bool(intel and intel.available),
        "updated_at": intel.updated_at if intel else None,
        "kev_entries": len(intel.kev) if intel else 0,
    }
    result["simulation"] = bool(sim)
    return result


def create_snapshot(store: Store, kb: KnowledgeBase, intel: Intel | None, name: str) -> dict:
    """Save a point-in-time snapshot of findings, TTC (external & internal), and shortest path."""
    ext = assess(store, kb, intel, "external")
    intr = assess(store, kb, intel, "internal")
    return store.save_snapshot(
        name=name,
        ttc_external=ext["ttc_minutes"],
        ttc_internal=intr["ttc_minutes"],
        chain_length=len(ext["path"]),
        counts=ext["counts"],
        records=ext["records"],
        path=ext["path"],
    )


def diff_snapshot(
    store: Store,
    kb: KnowledgeBase,
    intel: Intel | None,
    base_id: int,
    target_id: int | None = None,
) -> dict:
    """Compare a saved snapshot against current state (or another snapshot)."""
    base = store.get_snapshot(base_id)
    if base is None:
        raise KeyError(f"Unknown snapshot id: {base_id}")

    if target_id is not None:
        target = store.get_snapshot(target_id)
        if target is None:
            raise KeyError(f"Unknown snapshot id: {target_id}")
    else:
        ext = assess(store, kb, intel, "external")
        intr = assess(store, kb, intel, "internal")
        target = {
            "id": None,
            "name": "Current State",
            "created_at": None,
            "ttc_external": ext["ttc_minutes"],
            "ttc_internal": intr["ttc_minutes"],
            "chain_length": len(ext["path"]),
            "counts": ext["counts"],
            "records": ext["records"],
            "path": ext["path"],
        }

    base_by_key = {r["key"]: r for r in base["records"]}
    target_by_key = {r["key"]: r for r in target["records"]}

    new_findings = []
    for r in target["records"]:
        if r["status"] == OPEN and (r["key"] not in base_by_key or base_by_key[r["key"]]["status"] != OPEN):
            item = dict(r)
            item["change"] = "new" if r["key"] not in base_by_key else "reopened"
            new_findings.append(item)

    fixed_findings = []
    for r in base["records"]:
        if r["status"] == OPEN:
            cur = target_by_key.get(r["key"])
            if cur is None or cur["status"] == FIXED:
                item = dict(cur if cur is not None else r)
                item["change"] = "fixed"
                fixed_findings.append(item)

    accepted_findings = [dict(r) for r in target["records"] if r["status"] == ACCEPTED]

    ext_before = base["ttc_external"]
    ext_after = target["ttc_external"]
    ext_delta = round(ext_after - ext_before, 1) if (ext_before is not None and ext_after is not None) else None

    int_before = base["ttc_internal"]
    int_after = target["ttc_internal"]
    int_delta = round(int_after - int_before, 1) if (int_before is not None and int_after is not None) else None

    chain_before = int(base["chain_length"])
    chain_after = int(target["chain_length"])
    chain_delta = chain_after - chain_before

    return {
        "base": {
            "id": base["id"],
            "name": base["name"],
            "created_at": base["created_at"],
            "ttc_external": ext_before,
            "ttc_external_human": humanize_minutes(ext_before),
            "ttc_internal": int_before,
            "ttc_internal_human": humanize_minutes(int_before),
            "chain_length": chain_before,
            "counts": base["counts"],
        },
        "target": {
            "id": target["id"],
            "name": target["name"],
            "created_at": target["created_at"],
            "ttc_external": ext_after,
            "ttc_external_human": humanize_minutes(ext_after),
            "ttc_internal": int_after,
            "ttc_internal_human": humanize_minutes(int_after),
            "chain_length": chain_after,
            "counts": target["counts"],
        },
        "new_findings": new_findings,
        "fixed_findings": fixed_findings,
        "accepted_findings": accepted_findings,
        "counts_diff": {
            "new": len(new_findings),
            "fixed": len(fixed_findings),
            "accepted": len(accepted_findings),
        },
        "ttc_external_before": ext_before,
        "ttc_external_after": ext_after,
        "ttc_external_delta": ext_delta,
        "path_blocked_external": ext_before is not None and ext_after is None,
        "ttc_internal_before": int_before,
        "ttc_internal_after": int_after,
        "ttc_internal_delta": int_delta,
        "path_blocked_internal": int_before is not None and int_after is None,
        "chain_length_before": chain_before,
        "chain_length_after": chain_after,
        "chain_length_delta": chain_delta,
    }
