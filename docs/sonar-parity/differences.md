# Where sonda and SonarQube differ

sonda's findings compared with SonarQube's on the same commit of real
projects, one language at a time
([ADR-0007](../adr/0007-sonarqube-rule-parity.md),
[release-1.0.md](../release-1.0.md), M4). Every difference is a bug, which
gets fixed, a known gap, or a deliberate change, each listed below.

## How

`scripts/sonar_compare.py` reads a sonda JSON report and the SonarQube
project's issues, and pairs them: the same file, the same SonarQube rule key
(the keys a sonda rule's `sonar` field lists), and lines at most one apart.

```sh
sonda scan . -f json -o sonda.json --no-gate --new-code none
python3 scripts/sonar_compare.py --server http://sonarqube:9000 \
    --token-file ~/.sonar_token --project my-project --report sonda.json \
    --commit "$(git rev-parse HEAD)" --details differences.json
```

It compares only the files SonarQube analyzed as main code: it runs few rules
on test files. A sonda issue counts as a difference only when SonarQube's
quality profile has the rule's key active; sonda's rules without a SonarQube
key, and those whose key is off there, are counted apart. SonarQube runs
its default profile (Sonar way) and sonda its default rules.

## Results

| Project | Language | Commit | SonarQube's issues sonda raises | sonda's issues SonarQube doesn't |
|---|---|---|---|---|
| arandu | JavaScript | `ecb5cc9` | 145 of 150 | 8 |

## SonarQube issues sonda does not raise

- **Types sonda doesn't know (4), a known gap.** These rules need a value's
  type, and the value comes from where sonda can't see it (see [below](#rules-that-depend-on-knowing-a-type)):
  - `S6959`: `reduce()` without an initial value, on an array returned by a
    function imported from another file.
  - `S6551` (2): values in a template literal that are a library callback's
    parameters, typed by the library's declarations.
  - `S6594`: `match()` on an element of an array that a Node.js API
    returned.
- **`S2245` (1), deliberate.** sonda's `js/math-random-secret` is only
  related to this key: it reports `Math.random()` where the value becomes a
  secret, a token or a password. SonarQube asks for a review of every call.

## sonda issues SonarQube does not raise

- **`common/cognitive-complexity` (4), cause not known.** Four functions at
  16 or 17, over the threshold of 15, that SonarQube scores at most 15.
  Per file, sonda's total equals SonarQube's on 36 of 65 files; the others
  differ in both directions, by up to 26. Scoring the functions by hand from
  the published specification gives sonda's numbers or more, so SonarQube
  departs from it somewhere. Measuring SonarQube's score on small files, one
  construct at a time, is the next step.
- **`js/sql-built-dynamically` (4), deliberate.** It reports `prepare()`
  with an interpolated table name. SonarQube's rule covers `query` and
  `execute` of `mysql`, `pg` and similar drivers, not `better-sqlite3`.
  sonda's rule is labelled as only related to `S2077`.

## Rules that depend on knowing a type

SonarQube resolves types through the project; sonda reads one file. Rules
that need it (`reduce` without an initial value, `.at()` instead of
`length - 1`, `String.match` instead of `RegExp.exec`, `.sort()` without a
compare function, `${object}`) report a value only where the file shows
what it is: a literal, a well-known producer, a local declared as one, or a
call to a function in the same file. A parameter, or anything that comes
from another file, is left alone.
