"""Automated unit tests for DAST Report Ingestion (OWASP ZAP & Burp Suite)."""

from fallline.dast_ingest import (
    ingest_dast_report,
    parse_burp_xml,
    parse_zap_json,
)


def test_parse_burp_suite_xml():
    sample_burp_xml = """<?xml version="1.0"?>
    <issues>
      <issue>
        <name>SQL injection</name>
        <host ip="192.168.56.103">http://192.168.56.103:80</host>
        <path>/vulnerabilities/sqli/</path>
        <severity>High</severity>
        <issueBackground>SQL injection occurs when untrusted user input is concatenated into database queries.</issueBackground>
        <remediationBackground>Use parameterized prepared statements.</remediationBackground>
      </issue>
      <issue>
        <name>Cross-site scripting (reflected)</name>
        <host ip="192.168.56.103">http://192.168.56.103:80</host>
        <path>/vulnerabilities/xss_r/</path>
        <severity>Medium</severity>
        <issueBackground>XSS occurs when browser script execution is reflected.</issueBackground>
      </issue>
    </issues>"""

    res = parse_burp_xml(sample_burp_xml)
    assert res.scanner == "BURP_SUITE"
    assert res.total_findings == 2
    assert "192.168.56.103" in res.target_hosts

    sqli = res.vulnerabilities[0]
    assert sqli.title == "SQL injection"
    assert sqli.severity == "HIGH"
    assert sqli.mitre_tactic == "T1190"
    assert "SecRule" in sqli.waf_rule

    finding = sqli.to_finding()
    assert finding.host == "192.168.56.103"
    assert finding.port == 80
    assert finding.state == "open"


def test_parse_owasp_zap_json():
    sample_zap_data = {
        "site": [
            {
                "@name": "http://192.168.56.103:80",
                "@host": "192.168.56.103",
                "@port": "80",
                "alerts": [
                    {
                        "name": "Server-Side Request Forgery",
                        "riskdesc": "High (Certain)",
                        "uri": "http://192.168.56.103:80/proxy",
                        "desc": "SSRF vulnerability detected.",
                        "solution": "Block access to internal link-local IP addresses.",
                    },
                    {
                        "name": "Directory Browsing",
                        "riskdesc": "Low (Medium)",
                        "uri": "http://192.168.56.103:80/images/",
                    },
                ],
            }
        ]
    }

    res = parse_zap_json(sample_zap_data)
    assert res.scanner == "OWASP_ZAP"
    assert res.total_findings == 2
    assert "192.168.56.103" in res.target_hosts

    ssrf = res.vulnerabilities[0]
    assert ssrf.severity == "HIGH"
    assert "169.254.169.254" in ssrf.waf_rule


def test_auto_detect_ingest_wrapper():
    xml_str = "<issues><issue><name>Test Vuln</name><host ip='127.0.0.1'>http://127.0.0.1</host></issue></issues>"
    res_xml = ingest_dast_report(xml_str)
    assert res_xml.scanner == "BURP_SUITE"
    assert res_xml.total_findings == 1

    json_str = '{"site": [{"@host": "127.0.0.1", "alerts": [{"name": "Test Alert", "riskdesc": "Medium"}]}]}'
    res_json = ingest_dast_report(json_str)
    assert res_json.scanner == "OWASP_ZAP"
    assert res_json.total_findings == 1
