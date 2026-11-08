"""Verification loop: a fix only counts after a re-scan proves it.

Re-scans ONLY the one exposure (one port / one check), never the whole range.
Inconclusive results (host down, timeout, missing tool) never mark anything fixed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .knowledge import KnowledgeBase, finding_key
from .pipeline import Toolkit
from .scope import Scope, ScopeError
from .store import ACCEPTED, FIXED, OPEN, Store


@dataclass
class VerifyResult:
    key: str
    verified: bool
    status: str
    message: str

    def to_dict(self) -> dict:
        return {"key": self.key, "verified": self.verified, "status": self.status, "message": self.message}


def _result(store: Store, key: str, verified: bool, message: str) -> VerifyResult:
    rec = store.get(key)
    return VerifyResult(key, verified, rec["status"] if rec else "", message)


def verify_fix(
    store: Store, kb: KnowledgeBase, scope: Scope | None, toolkit: Toolkit, key: str, user: str | None = None
) -> VerifyResult:
    rec = store.get(key)
    if rec is None:
        raise KeyError(key)
    f = rec["finding"]
    if rec["status"] == FIXED:
        return _result(store, key, True, "Already verified as fixed.")
    if rec["status"] == ACCEPTED:
        return _result(store, key, False, "Risk is accepted; reopen it before verifying.")

    is_aws = f.source == "aws"
    if not is_aws:
        if scope is None:
            return _result(store, key, False, "No scope loaded; refusing to scan.")
        try:
            scope.check(f.host, user=user)  # re-check authorization (and log it)
        except ScopeError as exc:
            return _result(store, key, False, f"Refused: {exc}")

    if is_aws:
        try:
            current, _ = toolkit.aws_audit()
        except (OSError, ValueError, KeyError, RuntimeError, PermissionError) as exc:
            store.log_event(key, "verify_inconclusive", f"AWS audit failed: {exc.__class__.__name__}")
            return _result(
                store, key, False, f"Inconclusive: AWS audit failed ({exc.__class__.__name__}). Not marked fixed."
            )
        still = any(finding_key(c, (kb.classify(c).id if kb.classify(c) else "none")) == key for c in current)
        if still:
            store.log_event(key, "verify_failed", "still present in AWS audit")
            return _result(store, key, False, "Still present in the AWS configuration.")
        store.set_status(key, FIXED, "AWS re-audit no longer reports it", "verified_fixed")
        return _result(store, key, True, "Verified: no longer reported by the AWS audit.")

    probe = toolkit.reprobe(f)
    if probe.state == "unknown":
        store.log_event(key, "verify_inconclusive", probe.reason)
        return _result(store, key, False, f"Inconclusive: {probe.reason}. Not marked fixed.")

    if probe.state in ("closed", "filtered"):
        note = f"re-scan: port {f.port}/{f.protocol} {probe.state} ({probe.reason})"
        store.set_status(key, FIXED, note, "verified_fixed")
        return _result(store, key, True, f"Verified: {note}")

    # Port still open: is the SAME exposure still detected?
    rule = kb.by_id.get(rec["rule_id"])
    if not any(g.port == f.port for g in probe.findings):
        store.log_event(key, "verify_inconclusive", "open but no service details returned")
        return _result(
            store, key, False, "Inconclusive: port is open but the re-scan returned no details. Not marked fixed."
        )
    for g in probe.findings:
        if g.port != f.port:
            continue
        r = kb.classify(g)
        if finding_key(g, r.id if r else "none") == key:
            store.log_event(key, "verify_failed", "still detected after re-scan")
            return _result(store, key, False, "Still detected by the re-scan. Stays OPEN.")
        if (
            g.check == ""
            and rule
            and (rule.match.get("product_regex") or rule.match.get("version_regex"))
            and not (g.product or g.version)
        ):
            store.log_event(key, "verify_inconclusive", "no version information in re-scan")
            return _result(
                store,
                key,
                False,
                "Inconclusive: the re-scan could not read the service version "
                "(install Nmap for version checks). Not marked fixed.",
            )
    note = (
        f"re-scan: port {f.port} still open but the weakness "
        f"'{rec['rule_id']}' is no longer detected (service changed/patched)"
    )
    store.set_status(key, FIXED, note, "verified_fixed")
    return _result(store, key, True, f"Verified: {note}")


def accept_risk(store: Store, key: str, reason: str) -> None:
    if not reason.strip():
        raise ValueError("A reason is required to accept a risk")
    store.set_status(key, ACCEPTED, reason.strip(), "accepted_risk")


def reopen(store: Store, key: str) -> None:
    store.set_status(key, OPEN, "", "reopened")
