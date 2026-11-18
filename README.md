# dmarcrpt

**Read DMARC aggregate (RUA) reports and rank who is sending mail as your domain.**

Your DMARC inbox gets dozens of XML files a day and nobody reads them. `dmarcrpt` folds them into
one queue: which IPs send as you, which of those fail both DKIM and SPF, which authenticate as
some unrelated domain, and whether your published policy is enforcing anything at all.

<p>
  <img src="https://img.shields.io/badge/python-3.8%2B-0d1117?style=flat-square&logo=python&logoColor=39D353" alt="python" />
  <img src="https://img.shields.io/badge/runtime%20dependencies-zero-0d1117?style=flat-square" alt="zero dependencies" />
  <img src="https://img.shields.io/badge/network-none-0d1117?style=flat-square" alt="no network" />
  <img src="https://img.shields.io/badge/CI%20gate-exit%20codes-0d1117?style=flat-square" alt="ci gate" />
  <img src="https://img.shields.io/badge/license-MIT-0d1117?style=flat-square" alt="MIT" />
</p>

## Why

DMARC reports are the only honest record of who is sending mail as your domain. The format is
machine-friendly and human-hostile: one file per reporting org, one record per source IP, pass/fail
buried in nested XML. Reading them by hand does not scale, and the one thing you actually need to
know (is someone spoofing me right now?) is never in the summary.

`dmarcrpt` answers that in one command, offline, with no credentials and no DNS lookups.

## Install

Nothing to install. One file, standard library only.

```bash
git clone https://github.com/mehulpatel23b-pixel/dmarcrpt.git
cd dmarcrpt
python3 dmarcrpt.py --help
```

## Usage

```bash
# one report
python3 dmarcrpt.py report.xml

# a whole unzipped mailbox export
python3 dmarcrpt.py --dir ./reports

# several at once, JSON for a pipeline
python3 dmarcrpt.py a.xml b.xml --json

# only sources sending 5 or more messages, fail on medium findings
python3 dmarcrpt.py --dir ./reports --min-count 5 --fail-on medium
```

Sample output:

```text
dmarcrpt 1.0.0
domain(s)  : example.com
reports    : 3   sources: 12   messages: 842
dmarc pass : 96.4% (812/842)
score      : 84/100  grade B  gate FAIL

SEVERITY  RULE                     SUBJECT            DETAIL
----------------------------------------------------------------------------------------
CRITICAL  DMARC-UNAUTHENTICATED    198.51.100.66      7 message(s) from google.com failed both DKIM and SPF
MEDIUM    DMARC-POLICY-NONE        example.com        published policy is p=none (monitor only)

fixes
----------------------------------------------------------------------------------------
[CRIT] DMARC-UNAUTHENTICATED 198.51.100.66
      If this source is not yours, it is spoofing you: keep policy at p=reject and alert on it.
```

## Rules

| Rule | Severity | What it means |
| :-- | :-- | :-- |
| `DMARC-UNAUTHENTICATED` | critical | A source failed both DKIM and SPF. Either it is spoofing you or it is a sender you broke. |
| `DMARC-UNALIGNED` | medium | The source authenticated as a domain that does not align with yours: a third party you have not authorised. |
| `DMARC-POLICY-NONE` | medium | Policy is `p=none`, so spoofed mail is still delivered. |
| `DMARC-PCT-PARTIAL` | medium | `pct` is below 100, so only part of your mail is protected by policy. |
| `DMARC-NO-RUA` | medium | No `rua=` address, so no aggregate reports will arrive at all. |
| `DMARC-NO-SUBDOMAIN-POLICY` | low | No `sp=`, so subdomains inherit the parent policy and unused subdomains stay reachable. |
| `DMARC-SPF-ONLY` | info | Passed SPF only. SPF does not survive forwarding; add DKIM at that sender. |
| `DMARC-DKIM-ONLY` | info | Passed DKIM only. Check for an envelope-domain mismatch or a missing SPF range. |
| `DMARC-POLICY-BLOCKED` | info | Messages already quarantined or rejected. Confirms enforcement is live. |

## Scoring

`score = pass rate - penalties`, where critical findings cost the most. Grades: A 95+, B 85+,
C 70+, D 55+, E 35+, F below that. The gate fails on any finding at or above `--fail-on`
(default `high`).

## Exit codes

| Code | Meaning |
| :-- | :-- |
| `0` | No finding at or above the `--fail-on` threshold |
| `1` | Threshold breached, build should fail |
| `2` | No readable report files |

## Design

- **Offline.** The reports are already in your mailbox. No DNS, no API, no third party sees your data.
- **Zero dependencies.** Standard library XML parsing only, so the auditor brings no supply chain.
- **Explainable.** Every finding is one line of evidence plus the exact change that closes it.
- **Composable.** Stable exit codes and `--json` output drop straight into a pipeline.

## Ethics

Defensive tooling for domains you own or administer. It reads reports you are already the recipient
of, and it sends nothing.

## License

MIT. See [LICENSE](LICENSE).
