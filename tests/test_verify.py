import ipaddress
import json
from pathlib import Path

import pytest

from fallline.demo import FakeToolkit
from fallline.intel import Intel
from fallline.knowledge import KnowledgeBase
from fallline.pipeline import run_scan
from fallline.scanners.base import Finding
from fallline.scope import ScopeError, load_scope
from fallline.store import ACCEPTED, FIXED, OPEN, Store
from fallline.verify import accept_risk, reopen, verify_fix

KB = KnowledgeBase.load()
VSFTPD = "192.168.56.101|21/tcp|vsftpd-234-backdoor"


def make(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text('authorized_by: "T"\ni_confirm_authorization: true\ntargets:\n  - 192.168.56.0/24\n')
    scope = load_scope(p, audit_log=tmp_path / "audit.log")
    store, tk = Store(tmp_path / "db.sqlite"), FakeToolkit()
    run_scan(scope, store, KB, tk, "192.168.56.0/24", user="t")
    return scope, store, tk


def test_scan_refuses_out_of_scope_and_does_not_touch_network(tmp_path):
    scope, store, tk = make(tmp_path)
    before = len(tk.calls)
    with pytest.raises(ScopeError):
        run_scan(scope, store, KB, tk, "10.0.0.5", user="t")
    assert len(tk.calls) == before
    log = Path(tmp_path / "audit.log").read_text().splitlines()
    assert json.loads(log[-1])["allowed"] is False


def test_fix_only_verified_after_rescan(tmp_path):
    scope, store, tk = make(tmp_path)
    assert store.get(VSFTPD)["status"] == OPEN
    # Claiming a fix without actually fixing: stays OPEN
    res = verify_fix(store, KB, scope, tk, VSFTPD)
    assert not res.verified and store.get(VSFTPD)["status"] == OPEN
    # Actually close the port
    tk.close_port("192.168.56.101", 21)
    res = verify_fix(store, KB, scope, tk, VSFTPD)
    assert res.verified and store.get(VSFTPD)["status"] == FIXED
    assert store.get(VSFTPD)["verified_at"]


def test_verify_rescans_only_that_port(tmp_path):
    scope, store, tk = make(tmp_path)
    tk.calls.clear()
    tk.close_port("192.168.56.101", 21)
    verify_fix(store, KB, scope, tk, VSFTPD)
    assert tk.calls == [("reprobe", "192.168.56.101", 21, "")]


def test_unreachable_host_is_never_marked_fixed(tmp_path):
    scope, store, tk = make(tmp_path)
    tk.close_port("192.168.56.101", 21)
    tk.down_hosts.add("192.168.56.101")
    res = verify_fix(store, KB, scope, tk, VSFTPD)
    assert not res.verified and "Inconclusive" in res.message
    assert store.get(VSFTPD)["status"] == OPEN


def test_upgrade_in_place_counts_as_fixed(tmp_path):
    scope, store, tk = make(tmp_path)
    old = next(f for f in tk.findings if f.port == 21)
    tk.replace(old, Finding(old.host, 21, "tcp", "open", service="ftp", product="vsftpd",
                            version="3.0.5"))
    assert verify_fix(store, KB, scope, tk, VSFTPD).verified


def test_fallback_scanner_without_version_cannot_verify(tmp_path):
    scope, store, tk = make(tmp_path)
    old = next(f for f in tk.findings if f.port == 21)
    tk.replace(old, Finding(old.host, 21, "tcp", "open", service="ftp", source="socket"))
    res = verify_fix(store, KB, scope, tk, VSFTPD)
    assert not res.verified and store.get(VSFTPD)["status"] == OPEN


def test_reappearing_fixed_item_reopens(tmp_path):
    _scope, store, tk = make(tmp_path)
    store.set_status(VSFTPD, FIXED, "x")
    counts = store.ingest([f for f in tk.findings if f.port == 21], KB)
    assert counts["reopened"] == 1 and store.get(VSFTPD)["status"] == OPEN


def test_full_rescan_never_auto_fixes(tmp_path):
    scope, store, tk = make(tmp_path)
    tk.close_port("192.168.56.101", 21)
    run_scan(scope, store, KB, tk, "192.168.56.0/24", user="t")
    assert store.get(VSFTPD)["status"] == OPEN


def test_accept_risk_needs_reason_and_blocks_verify(tmp_path):
    scope, store, tk = make(tmp_path)
    with pytest.raises(ValueError):
        accept_risk(store, VSFTPD, "  ")
    accept_risk(store, VSFTPD, "legacy system, isolated VLAN")
    assert store.get(VSFTPD)["status"] == ACCEPTED
    assert not verify_fix(store, KB, scope, tk, VSFTPD).verified
    reopen(store, VSFTPD)
    assert store.get(VSFTPD)["status"] == OPEN


def test_verify_rechecks_scope(tmp_path):
    scope, store, tk = make(tmp_path)
    store.ingest([Finding("10.9.9.9", 21, "tcp", "open", service="ftp", product="vsftpd",
                          version="2.3.4")], KB)
    res = verify_fix(store, KB, scope, tk, "10.9.9.9|21/tcp|vsftpd-234-backdoor")
    assert not res.verified and "Refused" in res.message


def test_web_check_fix_is_verified_per_check(tmp_path):
    scope, store, tk = make(tmp_path)
    key = "192.168.56.102|80/tcp|web-admin-panel|web-admin-panel"
    assert store.get(key)["status"] == OPEN
    assert not verify_fix(store, KB, scope, tk, key).verified
    tk.findings = [f for f in tk.findings if f.check != "web-admin-panel"]
    assert verify_fix(store, KB, scope, tk, key).verified
    # the web server itself is still open
    assert store.get("192.168.56.102|80/tcp|apache-old")["status"] == OPEN


def test_intel_offline_fallback(tmp_path):
    def boom(url):
        raise OSError("no network")
    i = Intel(tmp_path / "c.json", fetcher=boom)
    assert "offline" in i.update(["CVE-2011-2523"])
    assert not i.available and i.factor(["CVE-2011-2523"])[0] == 1.0


def test_intel_update_and_cache(tmp_path):
    def fetch(url):
        if "known_exploited" in url:
            return json.dumps({"vulnerabilities": [{"cveID": "CVE-2011-2523"}]})
        return json.dumps({"data": [{"cve": "CVE-2011-2523", "epss": "0.9"}]})
    i = Intel(tmp_path / "c.json", fetcher=fetch)
    assert "updated" in i.update(["CVE-2011-2523"])
    again = Intel(tmp_path / "c.json", fetcher=lambda u: (_ for _ in ()).throw(OSError()))
    assert "CVE-2011-2523" in again.kev and again.epss["CVE-2011-2523"] == 0.9
    assert again.factor(["CVE-2011-2523"])[0] < 0.4


def test_discover_respects_network():
    tk = FakeToolkit()
    _, f = tk.discover(ipaddress.ip_network("192.168.56.102/32"), 100)
    assert {x.host for x in f} == {"192.168.56.102"}
