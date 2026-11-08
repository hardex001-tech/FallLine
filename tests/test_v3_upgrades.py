import csv
import io
import ipaddress
import json
import socket

import pytest
from fastapi.testclient import TestClient

from fallline.app import create_app
from fallline.cli import main as cli_main
from fallline.demo import FakeToolkit
from fallline.knowledge import MITRE_TACTICS, KnowledgeBase, build_mitre_matrix
from fallline.pipeline import run_host_discovery
from fallline.report import render_csv, render_sarif
from fallline.scanners import nmap_scanner, socket_fallback
from fallline.scanners.base import Finding
from fallline.scope import ScopeError, load_scope
from fallline.service import assess, create_snapshot, diff_snapshot
from fallline.store import Store
from fallline.verify import accept_risk, verify_fix

KB = KnowledgeBase.load()


def test_every_rule_has_copy_ready_fix_command_and_all_9_mitre_tactics_covered():
    assert len(MITRE_TACTICS) == 9
    for rule in KB.rules:
        assert rule.fix_command.strip(), f"Rule {rule.id} is missing fix_command"
        assert rule.technique.get("tactic") in MITRE_TACTICS

    matrix = build_mitre_matrix(KB, [])
    assert [col["tactic"] for col in matrix] == list(MITRE_TACTICS)
    for col in matrix:
        assert col["rules_count"] >= 1, f"Tactic {col['tactic']} has no rules in rules.yaml"


def test_mitre_matrix_counts_and_fix_commands_in_assessment(tmp_path):
    store = Store(tmp_path / "mitre.db")
    tk = FakeToolkit()
    store.ingest(tk.findings, KB, target="192.168.56.0/24", engine="fake")

    a = assess(store, KB, None, "external")
    assert len(a["mitre_matrix"]) == 9
    assert all(p.get("fix_command") for p in a["fix_plan"])
    assert any(r.get("fix_command") for r in a["records"])

    init_col = next(c for c in a["mitre_matrix"] if c["tactic"] == "Initial Access")
    assert init_col["open_count"] > 0
    assert init_col["fixed_count"] == 0


def test_snapshots_save_list_and_diff_lifecycle(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        'authorized_by: "Tester"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n',
        encoding="utf-8",
    )
    scope = load_scope(scope_file, audit_log=tmp_path / "audit.log")
    store = Store(tmp_path / "snap.db")
    tk = FakeToolkit()
    store.ingest(tk.findings, KB, target="192.168.56.0/24", engine="fake")

    with pytest.raises(ValueError):
        create_snapshot(store, KB, None, "   ")

    snap1 = create_snapshot(store, KB, None, "Baseline Scan")
    assert snap1["id"] == 1
    assert snap1["counts"]["open"] == 23
    assert snap1["ttc_external"] == 17.0

    # Verify a choke-point fix (bindshell on 1524) and accept risk on vsftpd
    bind_key = "192.168.56.101|1524/tcp|bindshell-1524"
    vsftpd_key = "192.168.56.101|21/tcp|vsftpd-234-backdoor"
    tk.close_port("192.168.56.101", 1524)
    assert verify_fix(store, KB, scope, tk, bind_key).verified
    accept_risk(store, vsftpd_key, "patched via compensating control")

    # Introduce a new exposure
    store.ingest(
        [Finding("192.168.56.102", 6379, "tcp", "open", service="redis", product="Redis", version="7.0")],
        KB,
        target="192.168.56.102",
        engine="fake",
    )

    diff = diff_snapshot(store, KB, None, base_id=snap1["id"])
    assert diff["counts_diff"]["fixed"] == 1
    assert diff["fixed_findings"][0]["key"] == bind_key
    assert diff["counts_diff"]["new"] == 1
    assert diff["new_findings"][0]["port"] == 6379
    assert diff["counts_diff"]["accepted"] == 1
    assert diff["ttc_external_after"] > diff["ttc_external_before"]
    assert diff["ttc_external_delta"] > 0

    snap2 = create_snapshot(store, KB, None, "After Patching")
    assert len(store.list_snapshots()) == 2
    diff_1_2 = diff_snapshot(store, KB, None, base_id=snap1["id"], target_id=snap2["id"])
    assert diff_1_2["target"]["name"] == "After Patching"
    assert diff_1_2["counts_diff"]["fixed"] == 1

    with pytest.raises(KeyError):
        diff_snapshot(store, KB, None, base_id=999)


def test_sarif_and_csv_exports_include_mitre_and_remediation(tmp_path):
    store = Store(tmp_path / "exp.db")
    tk = FakeToolkit()
    # Include an unclassified service and an accepted risk + verified fix to test all SARIF states
    extra_unclassified = Finding("192.168.56.101", 9999, "tcp", "open", service="custom-daemon")
    store.ingest([*tk.findings, extra_unclassified], KB, target="192.168.56.0/24", engine="fake")

    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        'authorized_by: "SecOps"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n',
        encoding="utf-8",
    )
    scope = load_scope(scope_file, audit_log=tmp_path / "audit.log")
    bind_key = "192.168.56.101|1524/tcp|bindshell-1524"
    tk.close_port("192.168.56.101", 1524)
    verify_fix(store, KB, scope, tk, bind_key)
    accept_risk(store, "192.168.56.101|23/tcp|telnet-exposed", "isolated lab")

    a = assess(store, KB, None, "external")
    recs = store.all()

    sarif = render_sarif(a, recs, kb=KB, authorized_by="SecOps")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "FallLine"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "vsftpd-234-backdoor" in rule_ids
    assert "unclassified-service" in rule_ids
    assert len(run["results"]) == len(recs)
    fixed_res = next(r for r in run["results"] if r["properties"]["key"] == bind_key)
    assert fixed_res["baselineState"] == "absent"
    accepted_res = next(r for r in run["results"] if r["ruleId"] == "telnet-exposed")
    assert accepted_res["suppressions"][0]["justification"] == "isolated lab"

    csv_text = render_csv(a, recs, kb=KB, authorized_by="SecOps")
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == len(recs)
    vsftpd_row = next(r for r in rows if r["rule_id"] == "vsftpd-234-backdoor")
    assert vsftpd_row["tactic"] == "Initial Access"
    assert "systemctl" in vsftpd_row["fix_command"]
    assert vsftpd_row["authorized_by"] == "SecOps"


def test_host_discovery_enforces_scope_and_discovers_live_hosts(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        'authorized_by: "NetAdmin"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n  - 127.0.0.1/32\n',
        encoding="utf-8",
    )
    scope = load_scope(scope_file, audit_log=tmp_path / "audit.log")
    tk = FakeToolkit()

    # Out of scope is refused before touching toolkit
    with pytest.raises(ScopeError):
        run_host_discovery(scope, tk, "10.10.10.0/24")
    assert tk.calls == []

    # In-scope discovery returns live hosts with ports and services
    res = run_host_discovery(scope, tk, "192.168.56.0/24")
    assert res["count"] == 2
    hosts_by_ip = {h["host"]: h for h in res["hosts"]}
    assert set(hosts_by_ip) == {"192.168.56.101", "192.168.56.102"}
    assert hosts_by_ip["192.168.56.101"]["hostname"] == "metasploitable-lab"
    assert 21 in hosts_by_ip["192.168.56.101"]["open_ports"]

    # Socket fallback host discovery on localhost listener
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]
    try:
        found = socket_fallback.discover_hosts(ipaddress.ip_network("127.0.0.1/32"), ports={port: "test-svc"})
        conn, _ = server.accept()
        conn.close()
    finally:
        server.close()
    assert len(found) == 1
    assert found[0]["host"] == "127.0.0.1"
    assert found[0]["open_ports"] == [port]

    # Refuses overly broad subnet sweep
    with pytest.raises(ValueError):
        socket_fallback.discover_hosts(ipaddress.ip_network("10.0.0.0/16"))

    # Nmap XML host parser test
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="192.168.56.101" addrtype="ipv4"/>
        <hostnames><hostname name="lab-box.local"/></hostnames>
        <ports>
          <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
        </ports>
      </host>
    </nmaprun>"""
    parsed = nmap_scanner.parse_nmap_hosts(xml)
    assert len(parsed) == 1
    assert parsed[0]["hostname"] == "lab-box.local"
    assert parsed[0]["open_ports"] == [22]
    assert "-sT" in nmap_scanner.build_discover_command("192.168.56.0/24")


def test_v3_api_and_cli_integration(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        'authorized_by: "Alice"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n',
        encoding="utf-8",
    )
    db_file = tmp_path / "v3.db"
    tk = FakeToolkit()
    app = create_app(
        scope_file,
        db_path=db_file,
        audit_log=tmp_path / "audit.log",
        toolkit=tk,
        inline_jobs=True,
        demo=True,
    )
    client = TestClient(app)

    # Scan in demo mode auto-seeds baseline snapshot
    assert client.post("/api/scan", json={"target": "192.168.56.0/24"}).status_code == 200
    snaps = client.get("/api/snapshots").json()["snapshots"]
    assert len(snaps) == 1
    assert "Baseline" in snaps[0]["name"]

    # MITRE endpoint
    mitre_resp = client.get("/api/mitre").json()
    assert len(mitre_resp["tactics"]) == 9

    # Host discovery API
    assert client.post("/api/discover", json={"target": "10.0.0.0/24"}).status_code == 403
    disc = client.post("/api/discover", json={"target": "192.168.56.0/24"}).json()
    assert disc["count"] == 2

    # Save custom snapshot and diff after patching one finding
    assert client.post("/api/snapshots", json={"name": "  "}).status_code == 400
    s2 = client.post("/api/snapshots", json={"name": "Pre-Fix"}).json()
    first_key = client.get("/api/state").json()["fix_plan"][0]["key"]
    client.post("/api/demo/fix", json={"key": first_key})
    client.post("/api/verify", json={"key": first_key})

    diff = client.get(f"/api/snapshots/diff?base_id={s2['id']}").json()
    assert diff["counts_diff"]["fixed"] == 1
    assert client.get("/api/snapshots/diff?base_id=999").status_code == 404

    # SARIF and CSV API endpoints
    sarif_res = client.get("/api/report.sarif")
    assert sarif_res.status_code == 200
    assert json.loads(sarif_res.text)["version"] == "2.1.0"

    csv_res = client.get("/api/report.csv")
    assert csv_res.status_code == 200
    assert "fix_command" in csv_res.text.splitlines()[0]

    # CLI commands for mitre, snapshot, report (sarif & csv), and discover
    assert cli_main(["mitre", "--db", str(db_file)]) == 0
    assert cli_main(["snapshot", "save", "--db", str(db_file), "--name", "CLI Snap"]) == 0
    assert cli_main(["snapshot", "list", "--db", str(db_file)]) == 0
    assert cli_main(["snapshot", "diff", "--db", str(db_file), "--base", "1"]) == 0
    assert cli_main(["snapshot", "diff", "--db", str(db_file), "--base", "999"]) == 2

    sarif_out = tmp_path / "out.sarif"
    csv_out = tmp_path / "out.csv"
    assert cli_main(["report", "--db", str(db_file), "--format", "sarif", "--output", str(sarif_out)]) == 0
    assert json.loads(sarif_out.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert cli_main(["report", "--db", str(db_file), "--format", "csv", "--output", str(csv_out)]) == 0
    assert csv_out.exists()

    fake_host = {"host": "192.168.56.101", "hostname": "lab", "open_ports": [22], "services": ["ssh"]}
    monkeypatch.setattr(
        "fallline.pipeline.RealToolkit.discover_hosts",
        lambda self, net: ("fake", [fake_host]),
    )
    assert cli_main(["discover", "192.168.56.0/24", "--scope", str(scope_file), "--db", str(db_file)]) == 0
    assert cli_main(["discover", "10.9.9.0/24", "--scope", str(scope_file), "--db", str(db_file)]) == 2

    # NmapError in /api/discover returns HTTP 400 instead of 500
    from fallline.scanners.nmap_scanner import NmapError

    monkeypatch.setattr(
        tk,
        "discover_hosts",
        lambda net: (_ for _ in ()).throw(NmapError("nmap discovery timed out")),
    )
    err_resp = client.post("/api/discover", json={"target": "192.168.56.0/24"})
    assert err_resp.status_code == 400
    assert "timed out" in err_resp.json()["detail"]


def test_v3_frontend_ui_js_integration_in_node(tmp_path):
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
        db_path=tmp_path / "v3_ui.db",
        audit_log=tmp_path / "audit.log",
        toolkit=tk,
        inline_jobs=True,
        demo=True,
    )
    client = TestClient(app)
    client.post("/api/scan", json={"target": "192.168.56.0/24"})
    # Verify one finding and accept one risk so MITRE + Snapshot Diff have all 3 states
    bind_key = "192.168.56.101|1524/tcp|bindshell-1524"
    telnet_key = "192.168.56.101|23/tcp|telnet-exposed"
    client.post("/api/demo/fix", json={"key": bind_key})
    client.post("/api/verify", json={"key": bind_key})
    client.post("/api/accept", json={"key": telnet_key, "reason": "isolated lab"})
    client.post("/api/snapshots", json={"name": "After Hardening"})

    targets_payload = client.get("/api/targets").json()
    state_payload = client.get("/api/state").json()
    snaps_payload = client.get("/api/snapshots").json()
    diff_payload = client.get("/api/snapshots/diff?base_id=1").json()
    disc_payload = client.post("/api/discover", json={"target": "192.168.56.0/24"}).json()

    web_dir = Path(__file__).resolve().parent.parent / "fallline" / "web"
    app_js = (web_dir / "app.js").read_text(encoding="utf-8")

    harness = tmp_path / "run_v3_ui.js"
    harness.write_text(
        f"""
const targetsPayload = {json.dumps(targets_payload)};
const statePayload = {json.dumps(state_payload)};
const snapsPayload = {json.dumps(snaps_payload)};
const diffPayload = {json.dumps(diff_payload)};
const discPayload = {json.dumps(disc_payload)};

function makeEl(tag, id = "") {{
  return {{
    tag,
    id,
    textContent: "",
    className: "",
    value: tag === "select" ? (id === "perspective" ? "external" : "") : "",
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
    if (!els.has(id)) {{
      const isSelect = id === "perspective" || id === "snapshot-select" || id === "snapshot-target-select";
      els.set(id, makeEl(isSelect ? "select" : "div", id));
    }}
    return els.get(id);
  }},
  createElement(tag) {{ return makeEl(tag); }},
  querySelector(sel) {{ return sel === "#findings tbody" ? tbody : makeEl("div"); }},
}};

let copiedText = "";
if (typeof globalThis.navigator !== "undefined") {{
  Object.defineProperty(globalThis.navigator, "clipboard", {{
    value: {{
      writeText: async (txt) => {{ copiedText = txt; }},
    }},
    configurable: true,
    writable: true,
  }});
}} else {{
  global.navigator = {{
    clipboard: {{
      writeText: async (txt) => {{ copiedText = txt; }},
    }},
  }};
}}
global.requestAnimationFrame = () => 1;
global.setInterval = () => 1;
global.setTimeout = (cb) => {{ cb(); return 1; }};

global.fetch = async (url) => {{
  if (url.startsWith("/api/targets")) return {{ ok: true, json: async () => targetsPayload }};
  if (url.startsWith("/api/state")) return {{ ok: true, json: async () => statePayload }};
  if (url.startsWith("/api/snapshots/diff")) return {{ ok: true, json: async () => diffPayload }};
  if (url.startsWith("/api/snapshots")) return {{ ok: true, json: async () => snapsPayload }};
  if (url.startsWith("/api/discover")) return {{ ok: true, json: async () => discPayload }};
  return {{ ok: true, json: async () => ({{ ok: true }}) }};
}};

{app_js}

(async () => {{
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));

  // 1. Verify MITRE matrix rendered 9 tactic columns and styled chips (chip-open, chip-fixed, chip-accepted)
  const mitreGrid = document.getElementById("mitre-matrix");
  if (mitreGrid.children.length !== 9) {{
    throw new Error("Expected 9 MITRE tactic columns, got " + mitreGrid.children.length);
  }}
  const allChipClasses = mitreGrid.children.flatMap((col) => col.children.map((c) => c.className));
  if (!allChipClasses.some((cls) => cls.includes("chip-open"))) throw new Error("Missing chip-open in MITRE matrix");
  if (!allChipClasses.some((cls) => cls.includes("chip-fixed"))) throw new Error("Missing chip-fixed in MITRE matrix");
  if (!allChipClasses.some((cls) => cls.includes("chip-accepted"))) {{
    throw new Error("Missing chip-accepted in MITRE matrix");
  }}

  // 2. Verify Copy Command in Priority Fixes
  const planBox = document.getElementById("plan");
  const firstPlanItem = planBox.children[0];
  const cmdBox = firstPlanItem.children.find((c) => c.className === "cmd-box");
  if (!cmdBox) throw new Error("Expected .cmd-box in Priority Fixes item");
  const copyBtn = cmdBox.children[1];
  copyBtn.onclick();
  if (!copiedText) throw new Error("Expected copyCommand to write fix_command to clipboard");

  // 3. Verify Snapshot Diff rendered metrics + 3 diff columns (Resolved, Newly Introduced, Accepted Risk)
  const diffView = document.getElementById("snapshot-diff-view");
  if (diffView.children.length < 2) throw new Error("Expected metrics + diff-lists in snapshot-diff-view");
  const diffLists = diffView.children[1];
  if (diffLists.children.length !== 3) {{
    throw new Error("Expected 3 diff columns (fixed, new, accepted), got " + diffLists.children.length);
  }}

  // 4. Verify Host Discovery rendering + one-click Scan host button
  let scanTriggered = false;
  document.getElementById("scan-btn").onclick = () => {{ scanTriggered = true; }};
  renderDiscoveredHosts(discPayload);
  const discBox = document.getElementById("discovered-hosts");
  if (discBox.children.length !== 3) throw new Error("Expected header + 2 host cards in discovered-hosts");
  const firstHostCard = discBox.children[1];
  const scanHostBtn = firstHostCard.children[1];
  scanHostBtn.onclick();
  if (!scanTriggered || document.getElementById("target").value !== "192.168.56.101") {{
    throw new Error("Expected Scan host button to populate target and trigger scan");
  }}

  console.log("V3_UI_JS_OK");
}})().catch((err) => {{
  console.error(err);
  process.exit(1);
}});
""",
        encoding="utf-8",
    )
    proc = subprocess.run(["node", str(harness)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"Node v3 UI test failed:\n{proc.stderr}\n{proc.stdout}"
    assert "V3_UI_JS_OK" in proc.stdout
