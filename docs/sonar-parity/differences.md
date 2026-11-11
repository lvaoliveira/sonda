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
| arandu | JavaScript | `ecb5cc9` | 145 of 150 | 4 |
| sonda | TypeScript (TSX), Rust | `f5a07dd` | 44 of 44 | 0 |

On sonda's own code, SonarQube raises nothing on the Python scripts, and
its Rust issues are all cognitive complexity (33, every one matched). The
TypeScript ones led to the accessibility and key rules measured
[below](#accessibility-and-keys-measured).

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

- **`js/sql-built-dynamically` (4), deliberate.** It reports `prepare()`
  with an interpolated table name. SonarQube's rule covers `query` and
  `execute` of `mysql`, `pg` and similar drivers, not `better-sqlite3`.
  sonda's rule is labelled as only related to `S2077`.

## Cognitive complexity, measured

SonarQube's JavaScript and TypeScript analyzer departs from the published
specification in two ways, found by scanning small files with SonarQube
26.7, one construct each, and reading back each file's
`cognitive_complexity` and the rule's issues:

- **`||` adds nothing.** `if (a || b)` scores 1, `if (a && b)` 2,
  `(a && b) || (!a && d)` 2. Its Python (`or`) and Java (`||`) analyzers
  count both, as the specification does.
- **A file's total counts callbacks one level deeper**, as the
  specification nests functions, except directly in an outermost function
  with no structure of its own (a wrapper such as
  `return xs.map((x) => ...)`). Logical operators don't make it more than
  a wrapper. The rule itself scores each function on its own, flat: a
  callback with 8 `if`s inside a function with one more is 1 and 8 for the
  rule, 17 for the file.

sonda does the same. On arandu, every file's total equals SonarQube's
(2,353 in all), and the functions over the threshold are the same 31.

## Accessibility and keys, measured

Scanned the same way, one JSX element per file, on SonarQube 26.7:

- **S6819, a role a native tag has.** Reported on a `div`, `span` or `svg`
  for each role with a native element (`button`, `img`, `status`,
  `option`, `listbox`, `heading`, `list`, `textbox`, `progressbar`,
  `separator`, `dialog`, `group`, `row`, `navigation` and others), with a
  role chosen by a ternary taken as written. Not reported: `role="img"` on
  an element with content or on a named `svg`; `role="status"` with
  `aria-live`; an `option` inside a `listbox`, a `row` inside a `table`,
  and a listbox or table written with them (a list with its items is
  reported). The last is fitted to what was observed, not understood.
- **S6479 and S6477, keys in a `map`.** Elements returned through a
  ternary or `&&` count. A key is the index when it is nothing else: `i`,
  `` `row-${i}` ``, `i.toString()`, on the returned element or one inside
  it. `` `${x.id}-${i}` ``, `x.id + i` and `'row' + i` aren't reported.

## Rules that depend on knowing a type

SonarQube resolves types through the project; sonda reads one file. Rules
that need it (`reduce` without an initial value, `.at()` instead of
`length - 1`, `String.match` instead of `RegExp.exec`, `.sort()` without a
compare function, `${object}`) report a value only where the file shows
what it is: a literal, a well-known producer, a local declared as one, or a
call to a function in the same file. A parameter, or anything that comes
from another file, is left alone.
