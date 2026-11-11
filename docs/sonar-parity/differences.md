# Where sonda and SonarQube differ

sonda's findings compared with SonarQube's on the same commit of real
projects, one language at a time
([ADR-0007](../adr/0007-sonarqube-rule-parity.md),
[release-1.0.md](../release-1.0.md), M4). Every difference is a bug, which
gets fixed, a known gap, or a deliberate change, each listed below.

## How

Both tools scan the same commit, `scripts/sonar_compare.py` pairs their
issues by file, rule key and line, and every difference is read and
classified. Where reading the code doesn't explain one, SonarQube is
measured on small files, one case each. [comparing.md](comparing.md) has
the steps, the commands and what was learned along the way.

## Results

| Project | Language | Commit | SonarQube's issues sonda raises | sonda's issues SonarQube doesn't |
|---|---|---|---|---|
| arandu | JavaScript | `ecb5cc9` | 145 of 150 | 4 |
| sonda | TypeScript (TSX), Rust | `8b30263` | 51 of 51 | 0 |
| CPython, 7 packages¹ | Python | `bf6623a` | 471 of 510 | 37 |
| ha-budgetthuis-prices | Python | `f563c0d` | 3 of 3 | 2 |

¹ `asyncio`, `email`, `json`, `http`, `logging`, `concurrent` and `urllib`
under `Lib/`. SonarQube couldn't parse 6 of their 93 files (`lazy import`,
new in Python 3.15), so those are left out: the script skips any file
SonarQube indexed without lines of code.

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

## Python, measured

Small files on SonarQube 26.7, one case each. Where SonarQube departs from
what sonda did, sonda now does the same:

- **Cognitive complexity (S3776).** A function nested in another is part
  of it, one level deeper unless the one around it only wraps it (defines
  functions and returns one), and the rule reports the outermost function
  only. A loop's `else` costs 1; `match` costs nothing.
- **Names (S100, S116, S117).** Not reported: methods and fields of a class
  with a base, CONSTANT_CASE locals, a parameter assigned again (reported
  at the parameter).
- **Unused (S1481, S1172).** Not reported: the halves of a loop's tuple.
  Unused parameters of a method of a class with a base are still reported
  when the base is known.
- **Exceptions (S5754, S7497, S108).** `except SystemExit` that doesn't
  re-raise is reported, and a catch-all after a clause that re-raises
  SystemExit isn't. Swallowing a cancellation counts in a coroutine only,
  a `return` included; `exceptions.CancelledError` through a relative
  import isn't followed. `except ...: pass` isn't an empty block.
- **Other rules.** S1110 is doubled parentheses only; S1066 is reported at
  the inner `if`; S8572 needs `exc_info=True`; S8521 is a membership test
  on a known dictionary; S7517 is unpacking a dictionary's keys; S5717 is a
  mutable default changed in place (`append`, `d[k] = ...`), not `+=`;
  S1192 treats hyphenated words as identifiers; S107 allows 13 parameters,
  not counting `self`; S1135 and S1134 know TODO and FIXME, not XXX.

Measured in a second round:

- **Once per name.** A local, a field (per class) or a builtin shadowed is
  reported where an assignment first binds it; a loop's `for a, b in`
  doesn't count as that binding. A name declared `global` isn't a local.
- **Unused locals.** Class attributes, even of a class in a function, and a
  parenthesized tuple `(a, b) = t` aren't reported.
- **Duplicated strings.** Of an implicit concatenation, only the first part
  counts; bytes don't.
- **Smaller ones.** S8492 needs a known set; S6660 is `==` and `!=`, not
  `is`; S1656 leaves `X = X` at module level; S1066 leaves two ifs with a
  comment between them; S2772 leaves a function's docstring and `pass`;
  S1871 leaves one-line branches in a chain with an else.

And in a third:

- **Cognitive complexity, every file.** A try's `else` costs 1 and nests its
  body; code outside functions counts for the file; a class defined in a
  function restarts at no nesting and stays part of the function's score;
  only a function that defines one function and returns it is a wrapper.
  Every CPython file's total and every calibration file's equals
  SonarQube's.
- **Commented-out code.** A block of comment lines is judged as a whole: it
  is code when, without its `#`s, it parses as Python and holds a
  statement other than an expression (a lone call isn't enough). A block
  that starts with prose doesn't parse. A comment after code on its line is
  judged alone. A docstring that parses as code counts too.
- **Smaller ones.** S1172 doesn't count the parameter's name in the
  docstring as a use; S1871 reports every repeated branch; S8510 sees
  names in a loop's tuple; S5709 includes a class deriving `BaseException`;
  S2201 leaves a lone call in a try body; S8518 leaves an index used to
  assign `seq[i]`; S3626 leaves a jump in a branch another branch follows;
  S1186 leaves an empty override of a method of a base in the same file;
  S1481 leaves names such as `dummy`; S5527 is reported where the context
  is made.

### What remains in Python

On CPython, 39 of SonarQube's issues and 37 of sonda's:

**Known gaps**, needing what sonda doesn't read (other modules, or the
standard library's signatures):
- `py/unused-parameter`, sonda only (14): methods that override a method
  of a base class in another module; SonarQube follows the import, sonda
  can't see the base.
- S930 (5): calls with an argument the callee doesn't take, the callee in
  another module or a C extension (`binascii.b2a_base64(wrapcol=...)`).
- S2638 (1): an override whose signature differs from `list.pop`'s.

**Deliberate:**
- S7504 (4): `for x in list(d.values()):` — sonda keeps the copy when the
  loop iterates a dictionary view, since the body may change the
  dictionary and removing `list()` would then raise.
- S6353 (3): `[0-9]` three times in one pattern is one issue in sonda,
  three in SonarQube.
- `py/unused-parameter`, SonarQube only (4): methods of classes deriving a
  standard-library class (`logging.Handler`), which sonda treats as
  possible overrides whose signature callers rely on.
- S6659 (2): `x[i+1:] == ""` and `x[1:] == ':'`, which SonarQube reads as
  `endswith`; neither is one.
- S1764 (1): `o != o`, the test for NaN.
- S2245 (1): `py/random-secret` reports a random value used as a secret
  only.
- `py/mutable-default` (2): a mutable default the function doesn't
  change.

**Not explained**, each measured or bisected without finding the rule
SonarQube follows:
- S1110 (12): parentheses SonarQube calls redundant in multi-line or
  bitwise expressions; exact copies of the same shapes aren't reported in
  isolation.
- `py/mergeable-if` (10): an exact copy of one case isn't reported by
  SonarQube either; removing its comment and its docstring together makes
  it reported, either one alone doesn't.
- About 20 issues, one or two per key: S1481 (2), S5857 (2), S8572 (2),
  S125 (1 each way), S1192 (`"%s:%s"`), S3358, S5843, S5869, S6035,
  S6659, S7483, S8513, S8786.

On ha-budgetthuis-prices, both of sonda's own (S7503 on an options flow
step, S7632 on a `# noqa` with an explanation) aren't explained.

## Rules that depend on knowing a type

SonarQube resolves types through the project; sonda reads one file. Rules
that need it (`reduce` without an initial value, `.at()` instead of
`length - 1`, `String.match` instead of `RegExp.exec`, `.sort()` without a
compare function, `${object}`) report a value only where the file shows
what it is: a literal, a well-known producer, a local declared as one, or a
call to a function in the same file. A parameter, or anything that comes
from another file, is left alone.
