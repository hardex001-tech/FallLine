import json
import socket

import pytest

from fallline.scanners import httpx, naabu, nmap, nuclei, socket_fallback
from fallline.scanners.base import Finding
from fallline.scanners.nmap_scanner import (
    build_command,
    parse_nmap_xml,
    parse_port_probe,
)

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.56.101" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21"><state state="open"/>
        <service name="ftp" product="vsftpd" version="2.3.4"/></port>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="4.7p1"/></port>
      <port protocol="tcp" portid="23"><state state="closed" reason="conn-refused"/>
        <service name="telnet"/></port>
    </ports>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_keeps_only_open_ports():
    findings = parse_nmap_xml(SAMPLE_XML)
    assert [(f.port, f.service, f.product, f.version) for f in findings] == [
        (21, "ftp", "vsftpd", "2.3.4"),
        (22, "ssh", "OpenSSH", "4.7p1"),
    ]
    assert findings[0].host == "192.168.56.101"


def test_nmap_command_is_safe():
    cmd = build_command("192.168.56.101")
    assert "-sV" in cmd
    assert not any(part.startswith("--script") or part == "-A" for part in cmd)
    assert cmd[-1] == "192.168.56.101"


def test_parse_port_probe_states():
    assert parse_port_probe(SAMPLE_XML, 21).state == "open"
    assert parse_port_probe(SAMPLE_XML, 23).state == "closed"
    assert parse_port_probe(SAMPLE_XML, 9999).state == "unknown"


def test_socket_fallback_finds_local_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]
    try:
        findings = socket_fallback.scan("127.0.0.1", ports={port: "test"})
        conn, _ = server.accept()
        conn.close()
        probe_open = socket_fallback.probe_port("127.0.0.1", port)
        conn2, _ = server.accept()
        conn2.close()
    finally:
        server.close()
    assert [f.port for f in findings] == [port]
    assert probe_open.state == "open"


def test_naabu_adapter_command_and_parse():
    cmd = naabu.build_command("192.168.56.0/24", top_ports=100)
    assert cmd[:3] == ["naabu", "-host", "192.168.56.0/24"]
    raw = "\n".join([
        json.dumps({"ip": "192.168.56.101", "port": 22, "protocol": "tcp"}),
        json.dumps({"ip": "192.168.56.101", "port": 22, "protocol": "tcp"}),
        json.dumps({"host": "192.168.56.101", "port": 3306}),
    ])
    parsed = naabu.parse_output(raw)
    assert [(f.host, f.port, f.service, f.source) for f in parsed] == [
        ("192.168.56.101", 22, "ssh", "naabu"),
        ("192.168.56.101", 3306, "mysql", "naabu"),
    ]


def test_httpx_adapter_detects_admin_and_missing_headers():
    orig = Finding("192.168.56.102", 80, "tcp", "open", service="http")
    line = json.dumps({
        "url": "http://192.168.56.102:80/phpmyadmin",
        "status_code": 200,
        "title": "phpMyAdmin Login",
        "tech": ["Apache", "PHP"],
        "header": {"server": "Apache/2.2"},
    })
    extra = httpx.parse_output(line, orig)
    checks = {f.check for f in extra}
    assert checks == {"web-admin-panel", "web-missing-headers"}
    assert "HTTP 200" in orig.evidence


def test_nuclei_safe_tags_and_forbidden_filter():
    cmd = nuclei.build_command("http://192.168.56.102:80")
    assert "-tags" in cmd and "exposure,misconfig" in cmd
    assert "-exclude-tags" in cmd
    with pytest.raises(ValueError):
        nuclei.build_command("http://192.168.56.102:80", template_id="bad;id")

    safe_line = json.dumps({
        "template-id": "git-config",
        "matched-at": "http://192.168.56.102:80/.git/config?secret=1",
        "info": {
            "name": "Git Config Exposure",
            "severity": "medium",
            "tags": ["exposure", "git"],
            "classification": {"cve-id": ["CVE-2021-0001"]},
        },
    })
    intrusive_line = json.dumps({
        "template-id": "evil-rce",
        "matched-at": "http://192.168.56.102:80/rce",
        "info": {"name": "Intrusive Exploit", "severity": "critical", "tags": ["rce", "exploit"]},
    })
    out = nuclei.parse_output(safe_line + "\n" + intrusive_line, "192.168.56.102", 80)
    assert len(out) == 1
    assert out[0].check == "git-config"
    assert "secret=1" not in out[0].evidence  # query strings stripped from evidence
    assert nmap.nmap_available() in (True, False)


def test_real_toolkit_reprobe_treats_nuclei_and_httpx_timeouts_as_inconclusive(monkeypatch):
    import subprocess

    from fallline.pipeline import RealToolkit
    from fallline.scanners import httpx_scanner, nmap_scanner, nuclei_scanner
    from fallline.scanners.base import PortProbe

    tk = RealToolkit()
    open_port_finding = Finding("192.168.56.102", 9000, "tcp", "open", service="", source="socket")
    monkeypatch.setattr(nmap_scanner, "nmap_available", lambda: False)
    monkeypatch.setattr(
        "fallline.scanners.socket_fallback.probe_port",
        lambda host, port: PortProbe(
            "open", "connected", [Finding(host, port, "tcp", "open", service="", source="socket")]
        ),
    )

    # 1. Nuclei timeout during reprobe must return PortProbe("unknown"), not raise or mark fixed
    monkeypatch.setattr(nuclei_scanner, "nuclei_available", lambda: True)

    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["nuclei"], timeout=5)

    monkeypatch.setattr(nuclei_scanner.subprocess, "run", raise_timeout)
    nuc_finding = Finding("192.168.56.102", 9000, "tcp", "open", service="http", check="git-config", source="nuclei")
    probe_nuc = tk.reprobe(nuc_finding)
    assert probe_nuc.state == "unknown"
    assert "nuclei" in probe_nuc.reason

    # 2. httpx timeout or non-zero exit during reprobe must return PortProbe("unknown"), not mark fixed
    monkeypatch.setattr(httpx_scanner, "find_binary", lambda: "/usr/bin/httpx")
    monkeypatch.setattr(httpx_scanner.subprocess, "run", raise_timeout)
    web_finding = Finding(
        "192.168.56.102", 9000, "tcp", "open", service="http", check="web-admin-panel", source="httpx"
    )
    probe_web = tk.reprobe(web_finding)
    assert probe_web.state == "unknown"
    assert "timed out" in probe_web.reason
    assert open_port_finding.port == 9000


