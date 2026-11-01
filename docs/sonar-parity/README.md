# Compatibility with SonarQube rules

Which SonarQube rule keys have an equivalent in sonda ([ADR-0007](../adr/0007-sonarqube-rule-parity.md)).
Refreshed by `scripts/sonar_parity.py` on 2026-11-01, against SonarQube 26.7.0.124771.

- **done**: a sonda rule covers it (`exact` in sonda's catalog);
  **partial**: a sonda rule is related but differs, for example syntactic where
  SonarQube uses taint analysis; **todo**: not covered yet.
- **tier** is a first guess at the analysis needed: `syntactic` (tree-sitter queries),
  `types` (a type checker, tagged type-dependent), `dataflow` (symbolic execution).
  It's confirmed when a rule is implemented.

| Language | Rules (not deprecated) | Done | Partial | Todo: syntactic | Todo: types | Todo: dataflow |
|---|---|---|---|---|---|---|
| JavaScript | 461 | 349 | 41 | 19 | 52 | 0 |
| TypeScript | 481 | 367 | 41 | 20 | 53 | 0 |
| Python | 397 | 360 | 14 | 23 | 0 | 0 |
| Java | 703 | 691 | 12 | 0 | 0 | 0 |
| C | not available on this SonarQube edition | | | | | |
| C++ | not available on this SonarQube edition | | | | | |
| C# | 446 | 337 | 51 | 58 | 0 | 0 |

## Security standards

CWE ids and OWASP Top 10 2021 categories in sonda's catalog, compared with
SonarQube's for the keys each rule covers exactly. Rules without an exact key
aren't compared.

13 rules differ:

| Rule | sonda | SonarQube |
|---|---|---|
| `js/hardcoded-ip` | none | CWE-547, A01 |
| `js/iam-action-wildcard` | CWE-269, A01 | CWE-269 |
| `js/iam-kms-resource-wildcard` | CWE-284, A01 | CWE-284, CWE-732 |
| `js/static-assets-after-session` | CWE-200, A01 | CWE-16, CWE-668 |
| `py/hardcoded-ip` | none | CWE-547, A01 |
| `py/upload-with-body` | CWE-20, A03 | none |
| `py/regex-catastrophic-backtracking` | CWE-1333 | CWE-1333, A04 |
| `java/broadcast-without-permission` | CWE-927 | CWE-927, A04 |
| `java/hardcoded-ip` | none | CWE-547, A01 |
| `java/regex-catastrophic-backtracking` | CWE-1333 | CWE-1333, A04 |
| `java/upload-size-unlimited` | CWE-400, CWE-770 | CWE-400, CWE-770, A05 |
| `cs/request-size-unlimited` | CWE-400, CWE-770 | CWE-400, CWE-770, A05 |
| `cs/hardcoded-ip` | none | CWE-547, A01 |

Per-language details: the `.csv` files in this directory.
