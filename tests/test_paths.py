import math

import pytest

from fallline.demo import FakeToolkit, sample_lab
from fallline.intel import Intel
from fallline.knowledge import KnowledgeBase
from fallline.paths import (
    analyze,
    build_edges,
    build_exposures,
    build_graph,
    shortest_path,
)
from fallline.scanners.base import Finding

KB = KnowledgeBase.load()


def items(findings):
    out = []
    for f in findings:
        r = KB.classify(f)
        out.append((f"{f.host}|{f.port}|{r.id if r else 'none'}|{f.check}", f))
    return [(k, f) for k, f in out if "|none|" not in k]


def svc(host, port, service, product="", version="", **kw):
    return Finding(host, port, "tcp", "open", service=service, product=product, version=version, **kw)


def test_rules_load_and_ids_unique():
    assert len(KB.rules) > 20
    for r in KB.rules:
        assert r.technique["id"].startswith("T")
        assert r.gives in ("foothold", "data") and r.stage in ("initial", "lateral")


@pytest.mark.parametrize(
    "f,rule",
    [
        (svc("h", 21, "ftp", "vsftpd", "2.3.4"), "vsftpd-234-backdoor"),
        (svc("h", 21, "ftp", "vsftpd", "3.0.5"), "ftp-exposed"),
        (svc("h", 1524, "bindshell"), "bindshell-1524"),
        (svc("h", 513, "login"), "r-services-exposed"),
        (svc("h", 3306, "mysql", "MySQL", "5.0"), "db-exposed"),
        (svc("h", 22, "ssh", "OpenSSH", "4.7p1"), "openssh-old"),
        (svc("h", 22, "ssh", "OpenSSH", "9.6"), "ssh-exposed"),
        (svc("h", 80, "http", "nginx", "1.25"), "http-exposed"),
    ],
)
def test_classification(f, rule):
    assert KB.classify(f).id == rule


def test_unknown_service_has_no_rule():
    assert KB.classify(svc("h", 9999, "weird")) is None


def test_nuclei_info_skipped_and_critical_faster():
    info = svc("h", 80, "http", check="x-tpl", severity="info", source="nuclei")
    crit = svc("h", 80, "http", check="x-tpl", severity="critical", source="nuclei")
    low = svc("h", 80, "http", check="x-tpl", severity="low", source="nuclei")
    assert KB.classify(info) is None
    ex = build_exposures([("a", crit), ("b", low)], KB)
    assert ex[0].effort < ex[1].effort


def test_aws_findings_only_match_aws_rules():
    f = Finding("aws:1/r/sg-1", 22, "aws", "open", service="ssh", check="aws-sg-open-admin", source="aws")
    assert KB.classify(f).id == "aws-sg-open-admin"


def test_shortest_path_prefers_cheapest_entry():
    ex = build_exposures(items([svc("a", 21, "ftp", "vsftpd", "2.3.4"), svc("a", 80, "http", "nginx", "1")]), KB)
    edges = build_edges(ex)
    assert build_graph(edges) is not None
    ttc, path = shortest_path(edges)
    assert path[0].exposure.rule.id == "vsftpd-234-backdoor"
    assert ttc == 5 + 15


def test_no_path_when_nothing_exploitable():
    assert analyze([])["ttc_minutes"] is None
    only_lateral = build_exposures(items([svc("a", 445, "microsoft-ds", "Samba smbd", "4.9")]), KB)
    assert analyze(only_lateral, "external")["ttc_minutes"] is None  # outsider cannot reach SMB
    assert analyze(only_lateral, "internal")["ttc_minutes"] is not None


def test_removing_the_only_entry_breaks_the_chain():
    ex = build_exposures(items([svc("a", 21, "ftp", "vsftpd", "2.3.4")]), KB)
    res = analyze(ex)
    assert res["fix_plan"][0]["blocks_all_paths"] is True
    assert res["fix_plan"][0]["ttc_after"] is None
    sim = analyze(ex, removed={ex[0].key})
    assert sim["ttc_minutes"] is None


def test_redundant_entries_need_both_fixed():
    ex = build_exposures(items([svc("a", 21, "ftp", "vsftpd", "2.3.4"), svc("a", 23, "telnet")]), KB)
    plan = analyze(ex)["fix_plan"]
    assert [p["blocks_all_paths"] for p in plan] == [False, True]
    assert plan[0]["ttc_after"] > plan[0]["ttc_before"]


def test_lateral_movement_reaches_second_host():
    ex = build_exposures(items([svc("a", 21, "ftp", "vsftpd", "2.3.4"), svc("b", 3306, "mysql", "MySQL", "5")]), KB)
    res = analyze(ex)
    assert res["ttc_minutes"] == 20  # vsftpd(5)+post(15); db is 60 min direct


def test_intel_makes_kev_cve_faster(tmp_path):
    intel = Intel(tmp_path / "c.json", fetcher=lambda u: "{}")
    intel.kev = {"CVE-2011-2523"}
    intel.epss = {"CVE-2011-2523": 1.0}
    f = svc("a", 21, "ftp", "vsftpd", "2.3.4")
    plain = build_exposures([("k", f)], KB)[0].effort
    boosted = build_exposures([("k", f)], KB, intel)[0]
    assert boosted.effort < plain
    assert any("KEV" in n for n in boosted.notes)


def test_demo_lab_has_a_path_and_a_complete_plan():
    ex = build_exposures(items(sample_lab()), KB)
    res = analyze(ex)
    assert res["ttc_minutes"] and math.isfinite(res["ttc_minutes"])
    assert res["fix_plan"][-1]["blocks_all_paths"]
    # greedy plan never repeats an exposure
    keys = [p["key"] for p in res["fix_plan"]]
    assert len(keys) == len(set(keys))
    assert FakeToolkit()  # smoke
