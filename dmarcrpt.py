#!/usr/bin/env python3
"""dmarcrpt - DMARC aggregate (RUA) report triage.

Reads DMARC aggregate XML reports and answers three questions:

  1. Which sources send mail as my domain?
  2. Which of those fail both DKIM and SPF (active spoofing)?
  3. Is my published policy actually enforcing anything?

Zero dependencies. Pure standard library. No network calls.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

__version__ = "1.0.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
GRADES = [(95, "A"), (85, "B"), (70, "C"), (55, "D"), (35, "E"), (0, "F")]


class ReportError(Exception):
    """Raised when a report cannot be parsed."""


def _text(node, path, default=""):
    if node is None:
        return default
    child = node.find(path)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _int(node, path, default=0):
    try:
        return int(_text(node, path, ""))
    except ValueError:
        return default


def parse_report(path):
    """Parse one DMARC aggregate XML file into a plain dict."""
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        raise ReportError("%s: %s" % (path, exc)) from exc
    if root.tag != "feedback":
        raise ReportError("%s: root element <%s>, expected <feedback>" % (path, root.tag))

    meta = root.find("report_metadata")
    policy = root.find("policy_published")
    report = {
        "file": os.path.basename(path),
        "org": _text(meta, "org_name", "unknown"),
        "domain": _text(policy, "domain", "unknown"),
        "policy": {
            "p": _text(policy, "p", "none"),
            "sp": _text(policy, "sp", ""),
            "pct": _int(policy, "pct", 100),
            "rua": [e.text.strip() for e in policy.findall("rua/report_destination") if e.text],
        },
        "records": [],
    }

    for rec in root.findall("record"):
        row = rec.find("row")
        ids = rec.find("identifiers")
        auth = rec.find("auth_results")
        report["records"].append({
            "ip": _text(row, "source_ip", "unknown"),
            "count": _int(row, "count", 1),
            "disposition": _text(row, "policy_evaluated/disposition", "none"),
            "dkim_eval": _text(row, "policy_evaluated/dkim", "fail"),
            "spf_eval": _text(row, "policy_evaluated/spf", "fail"),
            "header_from": _text(ids, "header_from", ""),
            "dkim": [(_text(d, "domain"), _text(d, "result")) for d in (auth.findall("dkim") if auth is not None else [])],
            "spf": [(_text(s, "domain"), _text(s, "result")) for s in (auth.findall("spf") if auth is not None else [])],
        })
    return report


def aggregate(reports):
    """Fold every record across every report into per-source-IP totals."""
    sources = {}
    for rep in reports:
        for rec in rep["records"]:
            src = sources.setdefault(rec["ip"], {
                "ip": rec["ip"], "orgs": set(), "domains": set(), "count": 0,
                "pass_dkim": 0, "pass_spf": 0, "pass_dmarc": 0,
                "dispositions": defaultdict(int),
                "header_from": set(), "dkim_domains": set(), "spf_domains": set(),
            })
            src["orgs"].add(rep["org"])
            src["domains"].add(rep["domain"])
            src["count"] += rec["count"]
            if rec["dkim_eval"] == "pass":
                src["pass_dkim"] += rec["count"]
            if rec["spf_eval"] == "pass":
                src["pass_spf"] += rec["count"]
            if rec["dkim_eval"] == "pass" or rec["spf_eval"] == "pass":
                src["pass_dmarc"] += rec["count"]
            src["dispositions"][rec["disposition"]] += rec["count"]
            if rec["header_from"]:
                src["header_from"].add(rec["header_from"])
            for dom, _res in rec["dkim"]:
                if dom:
                    src["dkim_domains"].add(dom)
            for dom, _res in rec["spf"]:
                if dom:
                    src["spf_domains"].add(dom)
    return sources


def _aligned(domain, candidate):
    """A domain is aligned with the org domain when equal or a subdomain of it."""
    if not domain or not candidate or domain == "unknown":
        return False
    candidate = candidate.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return candidate == domain or candidate.endswith("." + domain)


def findings(reports, min_count=1):
    """Turn the aggregate into explainable findings."""
    out = []
    sources = aggregate(reports)

    def add(sev, code, subject, detail, fix):
        out.append({"severity": sev, "code": code, "subject": subject, "detail": detail, "fix": fix})

    for ip in sorted(sources, key=lambda k: -sources[k]["count"]):
        src = sources[ip]
        if src["count"] < min_count:
            continue
        orgs = ", ".join(sorted(src["orgs"]))
        if src["pass_dkim"] == 0 and src["pass_spf"] == 0:
            add("critical", "DMARC-UNAUTHENTICATED", ip,
                "%d message(s) from %s failed both DKIM and SPF" % (src["count"], orgs),
                "If this source is not yours, it is spoofing you: keep policy at "
                "p=reject and alert on it. If it is yours, fix its SPF/DKIM alignment.")
        elif src["pass_dkim"] == 0:
            add("info", "DMARC-SPF-ONLY", ip,
                "%d message(s) from %s passed SPF only, no DKIM" % (src["count"], orgs),
                "SPF breaks on forwarding. Add DKIM signing at this sender so the "
                "result survives relays.")
        elif src["pass_spf"] == 0:
            add("low", "DMARC-DKIM-ONLY", ip,
                "%d message(s) from %s passed DKIM only, SPF failed" % (src["count"], orgs),
                "Check whether this sender uses a different envelope domain, or add "
                "its IP range to SPF if you control it.")
        external = set()
        for dom in (src["dkim_domains"] | src["spf_domains"]):
            if not any(_aligned(d, dom) for d in src["domains"]):
                external.add(dom)
        if external and src["pass_dmarc"] == 0:
            add("medium", "DMARC-UNALIGNED", ip,
                "authenticated as %s, which does not align with your domain"
                % ", ".join(sorted(external)),
                "Unauthenticated third-party sender. Verify it is a legitimate vendor, "
                "otherwise block it.")
        blocked = sum(src["dispositions"].get(d, 0) for d in ("quarantine", "reject"))
        if blocked:
            add("info", "DMARC-POLICY-BLOCKED", ip,
                "%d message(s) already quarantined or rejected for %s" % (blocked, ip),
                "Policy is doing its job. Track this volume over time to spot new campaigns.")

    seen = set()
    for rep in reports:
        dom = rep["domain"]
        if dom in seen:
            continue
        seen.add(dom)
        policy = rep["policy"]
        if policy["p"] == "none":
            add("medium", "DMARC-POLICY-NONE", dom,
                "published policy is p=none (monitor only)",
                "Spoofed mail is delivered. Move to p=quarantine with pct ramp, then p=reject.")
        if policy["pct"] < 100:
            add("medium", "DMARC-PCT-PARTIAL", dom,
                "policy applies to only %d%% of mail" % policy["pct"],
                "Set pct=100 once the affected senders are aligned.")
        if not policy["rua"]:
            add("medium", "DMARC-NO-RUA", dom,
                "no rua= destination in policy, so no aggregate reports arrive",
                "Add rua=mailto:dmarc@yourdomain so you keep this visibility.")
        if policy["p"] in ("quarantine", "reject") and not policy["sp"]:
            add("low", "DMARC-NO-SUBDOMAIN-POLICY", dom,
                "no sp= set, so subdomains inherit p=%s" % policy["p"],
                "Set sp=reject explicitly, or unused subdomains become the weak point.")

    out.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["code"]))
    return out


def summary(reports, min_count=1):
    sources = aggregate(reports)
    total = sum(s["count"] for s in sources.values())
    passed = sum(s["pass_dmarc"] for s in sources.values())
    found = findings(reports, min_count)
    rate = (100.0 * passed / total) if total else 100.0
    penalty = sum({"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}[f["severity"]] for f in found)
    score = max(0, min(100, round(rate - penalty * 0.5)))
    grade = next(g for threshold, g in GRADES if score >= threshold)
    critical = sum(1 for f in found if f["severity"] == "critical")
    high = sum(1 for f in found if f["severity"] == "high")
    return {
        "reports": len(reports),
        "domains": sorted({r["domain"] for r in reports}),
        "messages": total,
        "authenticated": passed,
        "pass_rate": round(rate, 1),
        "sources": len(sources),
        "score": score,
        "grade": grade,
        "counts": {
            sev: sum(1 for f in found if f["severity"] == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "gate": "FAIL" if critical or high else "PASS",
    }


def render(payload):
    lines = []
    s = payload["summary"]
    lines.append("dmarcrpt %s" % __version__)
    lines.append("domain(s)  : %s" % ", ".join(s["domains"]))
    lines.append("reports    : %d   sources: %d   messages: %d"
                 % (s["reports"], s["sources"], s["messages"]))
    lines.append("dmarc pass : %s%% (%d/%d)" % (s["pass_rate"], s["authenticated"], s["messages"]))
    lines.append("score      : %d/100  grade %s  gate %s" % (s["score"], s["grade"], s["gate"]))
    lines.append("")
    if payload["findings"]:
        lines.append("%-9s %-24s %-18s %s" % ("SEVERITY", "RULE", "SUBJECT", "DETAIL"))
        lines.append("-" * 104)
        for f in payload["findings"]:
            lines.append("%-9s %-24s %-18s %s"
                         % (f["severity"].upper(), f["code"], f["subject"][:18], f["detail"]))
        lines.append("")
        lines.append("fixes")
        lines.append("-" * 104)
        for f in payload["findings"]:
            if f["severity"] in ("critical", "high", "medium"):
                lines.append("[%s] %s %s" % (f["severity"][:4].upper(), f["code"], f["subject"]))
                lines.append("      %s" % f["fix"])
    else:
        lines.append("no findings: every source authenticated and aligned")
    return "\n".join(lines)


def collect(paths, directory=None):
    files = list(paths)
    if directory:
        for pattern in ("*.xml", "*.XML"):
            files.extend(sorted(glob.glob(os.path.join(directory, pattern))))
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dmarcrpt",
        description="Read DMARC aggregate (RUA) XML reports and rank who is sending mail as your domain.")
    parser.add_argument("reports", nargs="*", help="DMARC aggregate XML report file(s)")
    parser.add_argument("--dir", dest="directory", help="also read every .xml file in this directory")
    parser.add_argument("--min-count", type=int, default=1, help="ignore sources under this message count (default 1)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "info", "none"],
                        help="lowest severity that fails the run (default high)")
    parser.add_argument("--version", action="version", version="dmarcrpt " + __version__)
    args = parser.parse_args(argv)

    files = collect(args.reports, args.directory)
    if not files:
        parser.print_usage(sys.stderr)
        sys.stderr.write("dmarcrpt: no report files given\n")
        return 2

    reports, errors = [], []
    for path in files:
        try:
            reports.append(parse_report(path))
        except ReportError as exc:
            errors.append(str(exc))
    if not reports:
        for err in errors:
            sys.stderr.write("dmarcrpt: %s\n" % err)
        return 2

    report_findings = findings(reports, args.min_count)
    payload = {"summary": summary(reports, args.min_count), "findings": report_findings}
    if errors:
        payload["errors"] = errors

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render(payload))
        for err in errors:
            print("warning: %s" % err, file=sys.stderr)

    if args.fail_on == "none":
        return 0
    limit = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f["severity"]] <= limit for f in report_findings) else 0


if __name__ == "__main__":
    sys.exit(main())
