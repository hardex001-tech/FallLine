"""FastAPI backend + dashboard.

Run:  python -m fallline serve --scope scope.yaml
The server binds to 127.0.0.1 by default. Private targets require explicit
authorization confirmation; public targets require ownership verification
(DNS TXT record or .well-known HTTP token).
"""
from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .intel import Intel
from .knowledge import KnowledgeBase
from .paths import PERSPECTIVES
from .pipeline import RealToolkit, Toolkit, run_host_discovery, run_scan
from .report import render_csv, render_pdf, render_report, render_sarif_json
from .scanners.nmap_scanner import NmapError
from .scope import ScopeError, challenge_instructions, load_scope
from .service import assess, create_snapshot, diff_snapshot
from .store import Store
from .verify import accept_risk, reopen, verify_fix

WEB_DIR = Path(__file__).parent / "web"


class ScanReq(BaseModel):
    target: str
    top_ports: int = Field(1000, ge=1, le=65535)
    web: bool = True


class DiscoverReq(BaseModel):
    target: str


class SnapshotReq(BaseModel):
    name: str


class KeyReq(BaseModel):
    key: str


class AcceptReq(BaseModel):
    key: str
    reason: str


class SimReq(BaseModel):
    fixed: list[str] = []
    perspective: str = "external"


class AwsReq(BaseModel):
    profile: str | None = None
    region: str | None = None


class AddTargetReq(BaseModel):
    target: str
    confirm_authorization: bool = False


class ChallengeReq(BaseModel):
    target: str


class VerifyOwnershipReq(BaseModel):
    target: str
    method: str = "http"


def create_app(
    scope_path: str | Path,
    db_path: str | Path = "data/fallline.db",
    audit_log: str | Path | None = None,
    toolkit: Toolkit | None = None,
    intel: Intel | None = None,
    inline_jobs: bool = False,
    demo: bool = False,
    token_fetcher: Callable[[str], str] | None = None,
    txt_resolver: Callable[[str], list[str]] | None = None,
) -> FastAPI:
    app = FastAPI(title="FallLine", docs_url=None, redoc_url=None)
    store = Store(db_path)
    kb = KnowledgeBase.load()
    intel = intel or Intel(Path(db_path).parent / "intel_cache.json")
    toolkit = toolkit or RealToolkit()
    jobs: dict[str, dict] = {}
    lock = threading.Lock()
    scope_lock = threading.Lock()

    if demo and store.all() and not store.list_snapshots():
        create_snapshot(store, kb, intel, "Baseline (Initial Scan)")

    def scope():
        try:
            with scope_lock:
                return load_scope(scope_path, audit_log=audit_log)
        except ScopeError as exc:
            raise HTTPException(400, f"Scope problem: {exc}") from exc

    def check_perspective(p: str) -> str:
        if p not in PERSPECTIVES:
            raise HTTPException(400, f"perspective must be one of {PERSPECTIVES}")
        return p

    @app.get("/", response_class=HTMLResponse)
    def index():
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/state")
    def state(perspective: str = "external"):
        return assess(store, kb, intel, check_perspective(perspective))

    @app.get("/api/mitre")
    def mitre(perspective: str = "external"):
        a = assess(store, kb, intel, check_perspective(perspective))
        return {
            "perspective": a["perspective"],
            "counts": a["counts"],
            "tactics": a["mitre_matrix"],
        }

    @app.get("/api/snapshots")
    def list_snapshots():
        return {"snapshots": store.list_snapshots()}

    @app.post("/api/snapshots")
    def save_snapshot(req: SnapshotReq):
        try:
            snap = create_snapshot(store, kb, intel, req.name)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return snap

    @app.get("/api/snapshots/diff")
    def snapshot_diff(base_id: int, target_id: int | None = None):
        try:
            return diff_snapshot(store, kb, intel, base_id=base_id, target_id=target_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/api/targets")
    def targets():
        sc = scope()
        return {
            "authorized_by": sc.authorized_by,
            "targets": [str(n) for n in sc.networks],
            "verified_public": [str(n) for n in sc.verified_public],
            "ownership_proofs": sc.ownership_proofs,
            "demo": demo,
            "note": "Private ranges require authorization confirmation; public ranges require ownership proof.",
        }

    @app.post("/api/targets/add")
    def add_target(req: AddTargetReq):
        with scope_lock:
            try:
                sc = load_scope(scope_path, audit_log=audit_log)
                net = sc.add_private_target(req.target, confirm_authorization=req.confirm_authorization)
            except ScopeError as exc:
                raise HTTPException(400, str(exc)) from exc
            return {"added": str(net), "targets": [str(n) for n in sc.networks]}

    @app.post("/api/targets/challenge")
    def target_challenge(req: ChallengeReq):
        sc = scope()
        try:
            return challenge_instructions(req.target, sc.authorized_by)
        except ScopeError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/targets/verify-ownership")
    def target_verify_ownership(req: VerifyOwnershipReq):
        with scope_lock:
            try:
                sc = load_scope(scope_path, audit_log=audit_log)
                return sc.verify_public_target(
                    req.target,
                    method=req.method,
                    token_fetcher=token_fetcher,
                    txt_resolver=txt_resolver,
                )
            except ScopeError as exc:
                raise HTTPException(400, str(exc)) from exc

    @app.post("/api/discover")
    def discover(req: DiscoverReq):
        sc = scope()
        try:
            return run_host_discovery(sc, toolkit, req.target)
        except ScopeError as exc:
            raise HTTPException(403, str(exc)) from exc
        except (ValueError, RuntimeError, OSError, NmapError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/scan")
    def scan(req: ScanReq):
        sc = scope()
        try:
            sc.check(req.target)          # fail fast, and log, before starting a job
        except ScopeError as exc:
            raise HTTPException(403, str(exc)) from exc
        if not lock.acquire(blocking=False):
            raise HTTPException(409, "A scan is already running")
        job_id = uuid.uuid4().hex[:8]
        jobs[job_id] = {"status": "running"}

        def work():
            try:
                res = run_scan(
                    sc, store, kb, toolkit, req.target, top_ports=req.top_ports, web=req.web)
                if demo and store.all() and not store.list_snapshots():
                    create_snapshot(store, kb, intel, "Baseline (Initial Scan)")
                jobs[job_id] = {"status": "done", "result": res}
            except Exception as exc:  # noqa: BLE001
                jobs[job_id] = {"status": "error", "error": f"{exc.__class__.__name__}: {exc}"}
            finally:
                lock.release()

        if inline_jobs:
            work()
        else:
            threading.Thread(target=work, daemon=True).start()
        return {"job": job_id}

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str):
        if job_id not in jobs:
            raise HTTPException(404, "unknown job")
        return jobs[job_id]

    @app.post("/api/verify")
    def verify(req: KeyReq):
        try:
            res = verify_fix(store, kb, scope(), toolkit, req.key)
        except KeyError:
            raise HTTPException(404, "unknown finding") from None
        return res.to_dict()

    @app.post("/api/accept")
    def accept(req: AcceptReq):
        try:
            accept_risk(store, req.key, req.reason)
        except KeyError:
            raise HTTPException(404, "unknown finding") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"ok": True}

    @app.post("/api/reopen")
    def reopen_ep(req: KeyReq):
        try:
            reopen(store, req.key)
        except KeyError:
            raise HTTPException(404, "unknown finding") from None
        return {"ok": True}

    if demo:
        @app.post("/api/demo/fix")
        def demo_fix(req: KeyReq):
            """DEMO ONLY: pretend the admin patched it, inside the fake network."""
            rec = store.get(req.key)
            if rec is None or not hasattr(toolkit, "close_port"):
                raise HTTPException(404, "unknown finding")
            f = rec["finding"]
            if f.source == "aws" and hasattr(toolkit, "aws"):
                toolkit.aws = [x for x in toolkit.aws if not (
                    x.host == f.host and x.port == f.port and x.check == f.check)]
            elif f.check:
                toolkit.findings = [x for x in toolkit.findings if not (
                    x.host == f.host and x.port == f.port and x.check == f.check)]
            else:
                toolkit.close_port(f.host, f.port)
            return {"ok": True}

        @app.post("/api/demo/reset")
        def demo_reset():
            """DEMO ONLY: restore all sample_lab findings and re-scan the fake lab."""
            from .demo import sample_lab
            if hasattr(toolkit, "findings"):
                toolkit.findings = sample_lab()
            if hasattr(toolkit, "down_hosts"):
                toolkit.down_hosts.clear()
            if hasattr(toolkit, "silent_ports"):
                toolkit.silent_ports.clear()
            sc = scope()
            target = str(sc.networks[0]) if sc.networks else "192.168.56.0/24"
            res = run_scan(sc, store, kb, toolkit, target)
            for r in store.all():
                if r["status"] != "OPEN":
                    reopen(store, r["key"])
            if not store.list_snapshots():
                create_snapshot(store, kb, intel, "Baseline (Initial Scan)")
            return {"ok": True, "found": res["found"]}

    @app.post("/api/simulate")
    def simulate(req: SimReq):
        res = assess(store, kb, intel, check_perspective(req.perspective), simulate=req.fixed)
        res["label"] = "SIMULATION: nothing was changed or verified"
        return res

    @app.post("/api/intel/update")
    def intel_update():
        cves = [c for r in store.all() for c in r["finding"].cves]
        cves += [c for rule in kb.rules for c in rule.cves]
        return {"message": intel.update(cves)}

    @app.post("/api/aws-audit")
    def aws(req: AwsReq):
        tk = toolkit
        if isinstance(tk, RealToolkit):
            tk = RealToolkit(aws_profile=req.profile, aws_region=req.region)
        try:
            findings, warnings = tk.aws_audit()
        except Exception as exc:
            raise HTTPException(400, f"AWS audit failed: {exc.__class__.__name__}") from exc
        counts = store.ingest(findings, kb, target="aws", engine="aws-readonly")
        return {"found": len(findings), "warnings": warnings, **counts}

    @app.get("/api/report", response_class=HTMLResponse)
    def report(perspective: str = "external"):
        a = assess(store, kb, intel, check_perspective(perspective))
        return render_report(a, store.all(), authorized_by=scope().authorized_by)

    @app.get("/api/report.pdf")
    def report_pdf(perspective: str = "external"):
        a = assess(store, kb, intel, check_perspective(perspective))
        pdf_bytes = render_pdf(a, store.all(), authorized_by=scope().authorized_by)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": 'inline; filename="fallline-attack-story.pdf"'},
        )

    @app.get("/api/report.sarif")
    def report_sarif(perspective: str = "external"):
        a = assess(store, kb, intel, check_perspective(perspective))
        sarif_str = render_sarif_json(a, store.all(), kb=kb, authorized_by=scope().authorized_by)
        return Response(
            content=sarif_str,
            media_type="application/sarif+json",
            headers={"Content-Disposition": 'attachment; filename="fallline-findings.sarif"'},
        )

    @app.get("/api/report.csv")
    def report_csv(perspective: str = "external"):
        a = assess(store, kb, intel, check_perspective(perspective))
        csv_str = render_csv(a, store.all(), kb=kb, authorized_by=scope().authorized_by)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="fallline-findings.csv"'},
        )

    @app.get("/api/audit")
    def audit(limit: int = 50):
        sc = scope()
        path = sc.audit_log
        lines = path.read_text(encoding="utf-8").splitlines()[-limit:] if path.exists() else []
        return {"entries": lines, "events": store.events(limit)}

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    assets_dir = Path(__file__).resolve().parent.parent / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")
    return app



