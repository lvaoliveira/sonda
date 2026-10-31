# Compatibility with SonarQube rules

Which SonarQube rule keys have an equivalent in sonda ([ADR-0007](../adr/0007-sonarqube-rule-parity.md)).
Refreshed by `scripts/sonar_parity.py` on 2026-10-31, against SonarQube 26.7.0.124771.

- **done**: a sonda rule covers it (`exact` in sonda's catalog);
  **partial**: a sonda rule is related but differs, for example syntactic where
  SonarQube uses taint analysis; **todo**: not covered yet.
- **tier** is a first guess at the analysis needed: `syntactic` (tree-sitter queries),
  `types` (a type checker, tagged type-dependent), `dataflow` (symbolic execution).
  It's confirmed when a rule is implemented.

| Language | Rules (not deprecated) | Done | Partial | Todo: syntactic | Todo: types | Todo: dataflow |
|---|---|---|---|---|---|---|
| JavaScript | 461 | 167 | 20 | 199 | 75 | 0 |
| TypeScript | 481 | 158 | 18 | 227 | 78 | 0 |
| Python | 397 | 6 | 2 | 389 | 0 | 0 |
| Java | 703 | 9 | 1 | 672 | 0 | 21 |
| C | not available on this SonarQube edition | | | | | |
| C++ | not available on this SonarQube edition | | | | | |

## Security standards

CWE ids and OWASP Top 10 2021 categories in sonda's catalog, compared with
SonarQube's for the keys each rule covers exactly. Rules without an exact key
aren't compared.

All match.

Per-language details: the `.csv` files in this directory.
