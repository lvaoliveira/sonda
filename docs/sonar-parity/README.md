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
| JavaScript | 461 | 420 | 41 | 0 | 0 | 0 |
| TypeScript | 481 | 440 | 41 | 0 | 0 | 0 |
| Python | 397 | 360 | 14 | 23 | 0 | 0 |
| Java | 703 | 691 | 12 | 0 | 0 | 0 |
| C | not available on this SonarQube edition | | | | | |
| C++ | not available on this SonarQube edition | | | | | |
| C# | 446 | 353 | 90 | 3 | 0 | 0 |

## Known gaps

Rules sonda leaves out on purpose, and the decision records that say what
would change that.

| Language | Key | Reason |
|---|---|---|
| C# | S1944 | Invalid casts: needs the values reaching a cast and types from other files. [Why](../adr/0015-csharp.md) |
| C# | S3220 | Calls resolving to a `params` overload: needs C#'s overload resolution. [Why](../adr/0015-csharp.md) |
| C# | S6802 | Lambdas in loops in Blazor markup: checks `.razor` files, which sonda doesn't parse. [Why](../adr/0015-csharp.md) |

## Security standards

CWE ids and OWASP Top 10 2021 categories in sonda's catalog, compared with
SonarQube's for the keys each rule covers exactly. Rules without an exact key
aren't compared.

15 rules differ:

| Rule | sonda | SonarQube |
|---|---|---|
| `js/hardcoded-ip` | none | CWE-547, A01 |
| `js/iam-action-wildcard` | CWE-269, A01 | CWE-269 |
| `js/iam-kms-resource-wildcard` | CWE-284, A01 | CWE-284, CWE-732 |
| `js/regex-catastrophic-backtracking` | CWE-1333 | CWE-1333, A04 |
| `js/wallet-phrase-hardcoded` | CWE-798, A07 | CWE-259, CWE-798, A07 |
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
