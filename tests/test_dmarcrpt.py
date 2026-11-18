"""Tests for dmarcrpt. Run: python3 -m pytest -q"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dmarcrpt  # noqa: E402


def report_xml(records, policy="reject", pct=100, rua=True, domain="example.com"):
    recs = []
    for ip, count, disposition, dkim_eval, spf_eval, header_from, auth_dkim, auth_spf in records:
        recs.append(
            "<record><row><source_ip>%s</source_ip><count>%d</count>"
            "<policy_evaluated><disposition>%s</disposition><dkim>%s</dkim><spf>%s</spf>"
            "</policy_evaluated></row>"
            "<identifiers><header_from>%s</header_from></identifiers>"
            "<auth_results><dkim><domain>%s</domain><result>%s</result></dkim>"
            "<spf><domain>%s</domain><result>%s</result></spf></auth_results></record>"
            % (ip, count, disposition, dkim_eval, spf_eval, header_from,
               auth_dkim, dkim_eval, auth_spf, spf_eval)
        )
    rua_block = "<rua><report_destination>mailto:dmarc@example.com</report_destination></rua>" if rua else ""
    return (
        '<feedback><report_metadata><org_name>google.com</org_name>'
        "<report_id>12345</report_id></report_metadata>"
        '<policy_published><domain>%s</domain><p>%s</p><pct>%d</pct>%s</policy_published>'
        "%s</feedback>" % (domain, policy, pct, rua_block, "".join(recs))
    )


def write(tmp_path, xml, name="report.xml"):
    path = tmp_path / name
    path.write_text(xml, encoding="utf-8")
    return str(path)


GOOD = ("203.0.113.10", 40, "none", "pass", "pass", "example.com", "example.com", "example.com")
SPOOF = ("198.51.100.66", 7, "reject", "fail", "fail", "example.com", "example.com", "example.com")


def test_parse_extracts_metadata_and_records(tmp_path):
    path = write(tmp_path, report_xml([GOOD]))
    report = dmarcrpt.parse_report(path)
    assert report["org"] == "google.com"
    assert report["domain"] == "example.com"
    assert report["policy"]["p"] == "reject"
    assert report["policy"]["rua"] == ["mailto:dmarc@example.com"]
    assert len(report["records"]) == 1
    assert report["records"][0]["ip"] == "203.0.113.10"
    assert report["records"][0]["count"] == 40


def test_bad_xml_raises_report_error(tmp_path):
    path = write(tmp_path, "<not-feedback/>")
    try:
        dmarcrpt.parse_report(path)
    except dmarcrpt.ReportError as exc:
        assert "feedback" in str(exc)
    else:
        raise AssertionError("expected ReportError")


def test_clean_report_has_no_critical_findings(tmp_path):
    path = write(tmp_path, report_xml([GOOD]))
    reports = [dmarcrpt.parse_report(path)]
    codes = [f["code"] for f in dmarcrpt.findings(reports)]
    assert "DMARC-UNAUTHENTICATED" not in codes
    payload_summary = dmarcrpt.summary(reports)
    assert payload_summary["pass_rate"] == 100.0
    assert payload_summary["gate"] == "PASS"


def test_failed_source_is_flagged_critical(tmp_path):
    path = write(tmp_path, report_xml([GOOD, SPOOF]))
    reports = [dmarcrpt.parse_report(path)]
    found = dmarcrpt.findings(reports)
    spoof = [f for f in found if f["code"] == "DMARC-UNAUTHENTICATED"]
    assert len(spoof) == 1
    assert spoof[0]["subject"] == "198.51.100.66"
    assert spoof[0]["severity"] == "critical"
    assert "fix" in spoof[0] and spoof[0]["fix"]


def test_policy_findings(tmp_path):
    path = write(tmp_path, report_xml([GOOD], policy="none", pct=50, rua=False))
    reports = [dmarcrpt.parse_report(path)]
    codes = {f["code"] for f in dmarcrpt.findings(reports)}
    assert {"DMARC-POLICY-NONE", "DMARC-PCT-PARTIAL", "DMARC-NO-RUA"} <= codes


def test_subdomain_auth_is_aligned(tmp_path):
    rec = ("203.0.113.10", 4, "none", "pass", "pass", "example.com", "mail.example.com", "bounce.example.com")
    path = write(tmp_path, report_xml([rec]))
    reports = [dmarcrpt.parse_report(path)]
    codes = {f["code"] for f in dmarcrpt.findings(reports)}
    assert "DMARC-UNALIGNED" not in codes


def test_external_auth_domain_is_unaligned(tmp_path):
    rec = ("203.0.113.20", 3, "quarantine", "fail", "fail", "example.com", "mailer.other.net", "other.net")
    path = write(tmp_path, report_xml([rec]))
    reports = [dmarcrpt.parse_report(path)]
    codes = {f["code"] for f in dmarcrpt.findings(reports)}
    assert "DMARC-UNALIGNED" in codes


def test_min_count_filters_small_sources(tmp_path):
    path = write(tmp_path, report_xml([SPOOF]))
    reports = [dmarcrpt.parse_report(path)]
    assert not [f for f in dmarcrpt.findings(reports, min_count=10)
                if f["code"] == "DMARC-UNAUTHENTICATED"]


def test_cli_json_and_exit_codes(tmp_path, capsys):
    spoofed = write(tmp_path, report_xml([SPOOF]), "spoof.xml")
    assert dmarcrpt.main([spoofed, "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["gate"] == "FAIL"
    assert payload["summary"]["grade"] in "ABCDEF"
    assert payload["findings"]

    clean = write(tmp_path, report_xml([GOOD]), "clean.xml")
    assert dmarcrpt.main([clean]) == 0


def test_cli_fail_on_none_always_passes(tmp_path):
    spoofed = write(tmp_path, report_xml([SPOOF]))
    assert dmarcrpt.main([spoofed, "--fail-on", "none"]) == 0


def test_cli_without_input_returns_2():
    assert dmarcrpt.main([]) == 2


def test_cli_dir_scan(tmp_path):
    write(tmp_path, report_xml([GOOD]), "a.xml")
    write(tmp_path, report_xml([GOOD]), "b.xml")
    assert dmarcrpt.main(["--dir", str(tmp_path), "--json"]) == 0
