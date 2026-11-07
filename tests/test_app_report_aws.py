from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from fallline.app import create_app
from fallline.aws_audit import PUBLIC_GRANTEES, ReadOnlyClient, run_audit
from fallline.cli import main as cli_main
from fallline.demo import FakeToolkit
from fallline.intel import Intel
from fallline.knowledge import KnowledgeBase
from fallline.report import render_pdf, render_report
from fallline.scope import challenge_token, load_scope
from fallline.service import assess
from fallline.store import FIXED, OPEN, Store
from fallline.verify import verify_fix

KB = KnowledgeBase.load()


class DummyBoto:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "web-sg",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }

    def list_buckets(self):
        return {"Buckets": [{"Name": "public-bucket"}, {"Name": "private-bucket"}]}

    def get_public_access_block(self, Bucket):
        if Bucket == "private-bucket":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": False}}

    def get_bucket_acl(self, Bucket):
        return {"Grants": [{"Grantee": {"URI": PUBLIC_GRANTEES[0]}}]}

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": False}}

    def get_account_summary(self):
        return {"SummaryMap": {"AccountMFAEnabled": 0}}

    def list_users(self):
        return {"Users": [{"UserName": "deploy-bot"}]}

    def list_access_keys(self, UserName):
        old_date = datetime.now(UTC) - timedelta(days=120)
        return {"AccessKeyMetadata": [{"Status": "Active", "CreateDate": old_date}]}

    def delete_bucket(self, Bucket):
        raise AssertionError("should never be called")


def test_aws_readonly_proxy_blocks_writes():
    ro = ReadOnlyClient(DummyBoto())
    assert ro.list_buckets()["Buckets"]
    with pytest.raises(PermissionError):
        ro.delete_bucket(Bucket="x")


def test_aws_audit_discovers_sg_s3_and_iam_and_verifies_fix(tmp_path):
    raw = DummyBoto()
    findings, warnings = run_audit(lambda svc: ReadOnlyClient(raw), account="111122223333", region="us-east-1")
    assert not warnings
    checks = {f.check for f in findings}
    assert checks == {"aws-sg-open-admin", "aws-s3-public", "aws-iam-root-no-mfa", "aws-iam-old-key"}

    store = Store(tmp_path / "aws.db")
    store.ingest(findings, KB, target="aws", engine="aws-readonly")
    tk = FakeToolkit()
    tk.aws = list(findings)
    sg_key = "aws:111122223333/us-east-1/sg-123|22/aws|aws-sg-open-admin|aws-sg-open-admin"
    assert not verify_fix(store, KB, None, tk, sg_key).verified
    tk.aws = [f for f in tk.aws if f.check != "aws-sg-open-admin"]
    assert verify_fix(store, KB, None, tk, sg_key).verified
    assert store.get(sg_key)["status"] == FIXED


def test_html_and_pdf_report_export(tmp_path):
    store = Store(tmp_path / "r.db")
    tk = FakeToolkit()
    store.ingest(tk.findings, KB, target="192.168.56.0/24", engine="fake")
    a = assess(store, KB, None, "external", simulate=["192.168.56.101|21/tcp|vsftpd-234-backdoor"])
    html = render_report(a, store.all(), authorized_by="Lab Owner <script>")
    assert "&lt;script&gt;" in html
    assert "SIMULATION" in html
    assert "Fix this first" in html

    pdf = render_pdf(a, store.all(), authorized_by="Lab Owner")
    assert pdf.startswith(b"%PDF-1.4")
    assert b"FallLine Attack Story" in pdf
    assert b"/Count 2" in pdf  # multi-page PDF so all 23 lab findings fit without truncation
    assert b"192.168.56.102:80: Web admin panel reachable" in pdf
    assert pdf.strip().endswith(b"%%EOF")


def test_baseline_excludes_accepted_risk(tmp_path):
    from fallline.verify import accept_risk

    store = Store(tmp_path / "base.db")
    tk = FakeToolkit()
    store.ingest(tk.findings, KB, target="192.168.56.0/24", engine="fake")
    bind_key = "192.168.56.101|1524/tcp|bindshell-1524"
    accept_risk(store, bind_key, "accepted for test")
    a = assess(store, KB, None, "external")
    assert a["ttc_minutes"] == a["baseline_ttc_minutes"]


def test_fastapi_dashboard_flow(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        'authorized_by: "Alice"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n',
        encoding="utf-8",
    )
    tk = FakeToolkit()
    intel = Intel(tmp_path / "intel.json", fetcher=lambda u: '{"vulnerabilities": [], "data": []}')
    token_store: dict[str, str] = {}
    app = create_app(
        scope_file,
        db_path=tmp_path / "app.db",
        audit_log=tmp_path / "audit.log",
        toolkit=tk,
        intel=intel,
        inline_jobs=True,
        demo=True,
        token_fetcher=lambda url: token_store.get(url, ""),
    )
    client = TestClient(app)

    # Index and initial state
    assert client.get("/").status_code == 200
    st0 = client.get("/api/state").json()
    assert st0["counts"]["open"] == 0

    # Target management & public ownership verification
    bad_req = {"target": "10.99.0.0/24", "confirm_authorization": False}
    assert client.post("/api/targets/add", json=bad_req).status_code == 400
    r_add = client.post("/api/targets/add", json={"target": "10.99.0.0/24", "confirm_authorization": True})
    assert r_add.status_code == 200 and "10.99.0.0/24" in r_add.json()["targets"]

    pub = "93.184.216.34/32"
    chal = client.post("/api/targets/challenge", json={"target": pub}).json()
    assert chal["token"] == challenge_token(pub, "Alice")
    assert client.post("/api/targets/verify-ownership", json={"target": pub, "method": "http"}).status_code == 400
    token_store[chal["http_url"]] = chal["token"]
    r_ver = client.post("/api/targets/verify-ownership", json={"target": pub, "method": "http"})
    assert r_ver.status_code == 200
    assert pub in client.get("/api/targets").json()["verified_public"]

    # Out-of-scope scan refused with 403
    assert client.post("/api/scan", json={"target": "172.16.9.9"}).status_code == 403

    # Authorized scan succeeds
    r_scan = client.post("/api/scan", json={"target": "192.168.56.0/24"})
    assert r_scan.status_code == 200
    job_id = r_scan.json()["job"]
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "done"

    st1 = client.get("/api/state").json()
    assert st1["counts"]["open"] > 0
    assert any(r["technique"].startswith("T") for r in st1["records"])
    first_key = st1["fix_plan"][0]["key"]

    # What-if simulation mode
    sim = client.post("/api/simulate", json={"fixed": [first_key], "perspective": "external"}).json()
    assert sim["simulation"] is True
    assert "SIMULATION" in sim["label"]

    # Demo fix + verification transitions finding to FIXED_VERIFIED
    assert client.post("/api/demo/fix", json={"key": first_key}).status_code == 200
    v_res = client.post("/api/verify", json={"key": first_key}).json()
    assert v_res["verified"] is True

    # Accept risk and reopen
    second_key = client.get("/api/state").json()["fix_plan"][0]["key"]
    assert client.post("/api/accept", json={"key": second_key, "reason": "isolated lab"}).status_code == 200
    assert client.post("/api/reopen", json={"key": second_key}).status_code == 200

    # Demo reset restores all 23 lab findings back to OPEN
    r_reset = client.post("/api/demo/reset")
    assert r_reset.status_code == 200 and r_reset.json()["found"] == 23
    st_after_reset = client.get("/api/state").json()
    assert st_after_reset["counts"]["fixed_verified"] == 0
    assert st_after_reset["counts"]["open"] == 23

    # Verify clean engineering labels in index.html and absence of sci-fi slogans
    index_html = client.get("/").text
    assert "Summary" in index_html
    assert "Attack Path" in index_html
    assert "Authorized Scope" in index_html
    assert "Priority Fixes" in index_html
    assert "Findings" in index_html
    assert "//" not in index_html.replace("https://", "").replace("http://", "")
    assert "SURVEILLANCE" not in index_html

    # HTML and PDF reports + audit log
    assert client.get("/api/report").status_code == 200
    pdf_resp = client.get("/api/report.pdf")
    assert pdf_resp.status_code == 200 and pdf_resp.content.startswith(b"%PDF-1.4")
    assert len(client.get("/api/audit").json()["entries"]) >= 2


def test_cli_commands_offline(tmp_path, monkeypatch):
    from fallline.scanners.naabu_scanner import NaabuError

    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        'authorized_by: "CLI Tester"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n',
        encoding="utf-8",
    )
    db_file = tmp_path / "cli.db"
    store = Store(db_file)
    tk = FakeToolkit()
    scope = load_scope(scope_file, audit_log=tmp_path / "audit.log")
    store.ingest(tk.findings, KB, target="192.168.56.0/24", engine="fake")
    assert scope.authorized_by == "CLI Tester"

    assert cli_main(["paths", "--db", str(db_file)]) == 0
    html_out = tmp_path / "story.html"
    pdf_out = tmp_path / "story.pdf"
    assert cli_main(["report", "--db", str(db_file), "--scope", str(scope_file), "--output", str(html_out)]) == 0
    assert html_out.exists()
    assert cli_main(["report", "--db", str(db_file), "--output", str(pdf_out), "--pdf"]) == 0
    assert pdf_out.read_bytes().startswith(b"%PDF-1.4")

    key = "192.168.56.101|21/tcp|vsftpd-234-backdoor"
    assert cli_main(["accept", "--db", str(db_file), "--key", key, "--reason", "testing"]) == 0
    assert cli_main(["reopen", "--db", str(db_file), "--key", key]) == 0
    assert store.get(key)["status"] == OPEN

    # Verify NaabuError during CLI scan is caught cleanly with exit code 3
    def _raise_naabu(self, net, tp):
        raise NaabuError("naabu failed")

    monkeypatch.setattr("fallline.pipeline.RealToolkit.discover", _raise_naabu)
    assert cli_main(["scan", "--db", str(db_file), "--scope", str(scope_file), "--target", "192.168.56.101"]) == 3


def test_frontend_hud_domino_and_table_execution_in_node(tmp_path):
    import json
    import shutil
    import subprocess
    from pathlib import Path

    if not shutil.which("node"):
        pytest.skip("node not installed")

    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        'authorized_by: "Alice"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n',
        encoding="utf-8",
    )
    tk = FakeToolkit()
    app = create_app(
        scope_file,
        db_path=tmp_path / "hud.db",
        audit_log=tmp_path / "audit.log",
        toolkit=tk,
        inline_jobs=True,
        demo=True,
    )
    client = TestClient(app)
    client.post("/api/scan", json={"target": "192.168.56.0/24"})
    targets_payload = client.get("/api/targets").json()
    state_payload = client.get("/api/state").json()

    web_dir = Path(__file__).resolve().parent.parent / "fallline" / "web"
    style_css = (web_dir / "style.css").read_text(encoding="utf-8")
    assert "text-shadow" not in style_css
    assert "box-shadow" not in style_css
    assert "#0d1117" in style_css
    assert "#161b22" in style_css

    app_js = (web_dir / "app.js").read_text(encoding="utf-8")
    assert "AudioContext" not in app_js
    assert "spawnSparks" not in app_js

    harness = tmp_path / "run_hud.js"
    harness.write_text(
        f"""
const targetsPayload = {json.dumps(targets_payload)};
const statePayload = {json.dumps(state_payload)};

function makeEl(tag, id = "") {{
  return {{
    tag,
    id,
    textContent: "",
    className: "",
    value: tag === "select" ? "external" : "",
    checked: true,
    disabled: false,
    href: "",
    width: 1120,
    height: 250,
    style: {{}},
    children: [],
    classList: {{
      _set: new Set(),
      toggle(c, force) {{
        if (force === undefined) {{
          if (this._set.has(c)) this._set.delete(c); else this._set.add(c);
        }} else if (force) this._set.add(c); else this._set.delete(c);
      }},
    }},
    append(...nodes) {{ this.children.push(...nodes); }},
    replaceChildren(...nodes) {{ this.children = [...nodes]; }},
    getContext() {{
      return {{
        save() {{}}, restore() {{}}, clearRect() {{}}, beginPath() {{}},
        moveTo() {{}}, lineTo() {{}}, stroke() {{}}, fill() {{}},
        arc() {{}}, translate() {{}}, rotate() {{}}, roundRect() {{}},
        fillText() {{}}, fillRect() {{}}, setLineDash() {{}},
      }};
    }},
  }};
}}

const els = new Map();
const tbody = makeEl("tbody");
global.document = {{
  getElementById(id) {{
    if (!els.has(id)) els.set(id, makeEl(id === "perspective" ? "select" : "div", id));
    return els.get(id);
  }},
  createElement(tag) {{ return makeEl(tag); }},
  querySelector(sel) {{ return sel === "#findings tbody" ? tbody : makeEl("div"); }},
}};

const rafQueue = [];
global.requestAnimationFrame = (cb) => {{ rafQueue.push(cb); }};
global.setInterval = () => 1;
global.setTimeout = (cb) => {{ rafQueue.push(cb); return 1; }};

// Simulate /api/state resolving faster than /api/targets if called in parallel
global.fetch = async (url) => {{
  if (url.startsWith("/api/targets")) {{
    await new Promise((r) => Promise.resolve().then(r));
    return {{ ok: true, json: async () => targetsPayload }};
  }}
  if (url.startsWith("/api/state")) {{
    return {{ ok: true, json: async () => statePayload }};
  }}
  return {{ ok: true, json: async () => ({{ ok: true, verified: true, message: "ok" }}) }};
}};

{app_js}

(async () => {{
  await new Promise((r) => setImmediate(r));

  if (!state.demo) throw new Error("state.demo should be true on startup before refresh()");
  if (tbody.children.length !== 23) throw new Error("Expected 23 rows, got " + tbody.children.length);

  // Check first row has Close Port, Verify, Patch+Verify, Accept, PROTOCOL / SERVICE text, and .tech-badge
  const row0 = tbody.children[0];
  const protoCell = row0.children[3].textContent;
  if (!protoCell.startsWith("TCP / ")) throw new Error("Unexpected proto cell: " + protoCell);
  const findingCell = row0.children[5];
  if (!findingCell.children.some((c) => c.className === "tech-badge")) {{
    throw new Error("Expected .tech-badge span in finding cell");
  }}
  const btnLabels = row0.children[6].children[0].children.map((b) => b.textContent);
  for (const expected of ["Close Port", "Verify", "Patch+Verify", "Accept"]) {{
    if (!btnLabels.includes(expected)) {{
      throw new Error("Missing button " + expected + " in " + JSON.stringify(btnLabels));
    }}
  }}

  // Check layoutDominoes for 1, 3, 4, 8, and 10 steps, including rotated 72-degree tip clearance
  const canvas = document.getElementById("dominoes");
  const sin72 = Math.sin((72 * Math.PI) / 180);
  for (const n of [1, 3, 4, 8, 10]) {{
    const lay = layoutDominoes(canvas, n);
    const rotatedTipX = lay.lastX + lay.w + lay.h * sin72;
    if (rotatedTipX >= lay.goalX - 24) {{
      throw new Error(`Rotated domino overlap at n=${{n}}: tipX=${{rotatedTipX}} vs goalLeft=${{lay.goalX - 24}}`);
    }}
    if (lay.startX <= lay.attX + 26) {{
      throw new Error(`Attacker overlap at n=${{n}}: startX=${{lay.startX}} vs attRight=${{lay.attX + 26}}`);
    }}
  }}

  // Test drawer mutual exclusion
  const scopeDrawer = document.getElementById("scope-manager");
  const awsDrawer = document.getElementById("aws-drawer");
  scopeDrawer.open = true;
  awsDrawer.open = true;
  awsDrawer.ontoggle();
  if (scopeDrawer.open) throw new Error("Expected scope-manager to close when aws-drawer opens");

  // Test 10-step animation + mid-animation cancellation via drawPath
  const tenSteps = Array.from({{ length: 10 }}, (_, idx) => ({{
    from: "a", to: "b", host: "192.168.56.101", port: 80 + idx,
    title: "Step " + idx, technique: "T1190 Exploit", minutes: 5, kind: "entry"
  }}));
  drawPath({{ path: tenSteps, baseline_path: tenSteps }});
  play();
  for (let step = 0; step < 180 && rafQueue.length; step++) {{
    const fn = rafQueue.shift();
    fn();
  }}
  if (!state.angles.every((a) => a === 72)) {{
    throw new Error("Expected all 10 dominoes to rotate to 72 deg, got " + JSON.stringify(state.angles));
  }}

  // Start another play() then immediately interrupt with drawPath (defended state)
  play();
  const staleTick = rafQueue.pop();
  drawPath({{ path: [], baseline_path: tenSteps }});
  if (staleTick) staleTick();
  if (state.angles.some((a) => a !== 0)) {{
    throw new Error("Stale animation frame mutated angles after drawPath reset!");
  }}
  console.log("HUD_VERIFICATION_OK");
}})().catch((err) => {{
  console.error(err);
  process.exit(1);
}});
""",
        encoding="utf-8",
    )
    proc = subprocess.run(["node", str(harness)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"Node HUD verification failed:\n{proc.stderr}\n{proc.stdout}"
    assert "HUD_VERIFICATION_OK" in proc.stdout


