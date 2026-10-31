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
| JavaScript | 461 | 286 | 41 | 82 | 52 | 0 |
| TypeScript | 481 | 294 | 41 | 93 | 53 | 0 |
| Python | 397 | 359 | 14 | 24 | 0 | 0 |
| Java | 703 | 377 | 11 | 294 | 0 | 21 |
| C | not available on this SonarQube edition | | | | | |
| C++ | not available on this SonarQube edition | | | | | |
| C# | 446 | 51 | 3 | 392 | 0 | 0 |

## Security standards

CWE ids and OWASP Top 10 2021 categories in sonda's catalog, compared with
SonarQube's for the keys each rule covers exactly. Rules without an exact key
aren't compared.

6 rules differ:

| Rule | sonda | SonarQube |
|---|---|---|
| `js/hardcoded-ip` | none | CWE-547, A01 |
| `py/hardcoded-ip` | none | CWE-547, A01 |
| `py/upload-with-body` | CWE-20, A03 | none |
| `py/regex-catastrophic-backtracking` | CWE-1333 | CWE-1333, A04 |
| `java/broadcast-without-permission` | CWE-927 | CWE-927, A04 |
| `java/hardcoded-ip` | none | CWE-547, A01 |

Per-language details: the `.csv` files in this directory.
