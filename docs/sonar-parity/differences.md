# Where Sonda and SonarQube differ

A check of Sonda against SonarQube's own results, run once on one JavaScript
project: the Sonar way profile (391 JavaScript rules) had raised 143 issues on
a revision, and Sonda scanned that same revision with its default rules.

| | Result |
|---|---|
| Sonar issues Sonda also raised (same file, within a line, a rule carrying the same Sonar key) | 136 of 143 |
| Sonda issues on those files with no Sonar counterpart, where the profile has the rule | 11 |

This is one project and one language. It says nothing about TypeScript, JSX,
Vue or the other languages.

## Sonar issues Sonda does not raise (7)

- `S6959`: the array is returned by a function imported from another file;
  SonarQube follows it, Sonda reads one file.
- `S6551` (2), `S2245`, `S7776`, `S5976`, one nested ternary: needs types,
  or a different position convention.

## Sonda issues SonarQube did not raise (11)

- `common/cognitive-complexity` (4 functions at 16 or 17, threshold 15).
  Sonda's score is 1 or 2 points above SonarQube's on about two thirds of the
  functions checked, and the cause is not known. Dropping the extra count for
  `else`, for what a ternary contains, or for logical operators in
  declarations each fixed some functions and broke others, so none is applied.
- `js/sql-built-dynamically` (5): flags `prepare()` with an interpolated
  table name. SonarQube's rule covers `query` and `execute` of `mysql`, `pg`
  and similar, not `better-sqlite3`. Kept: it is labelled as only related to
  `S2077`.
- `js/hardcoded-secret` (1): a 50-character client secret with entropy
  4.74 bits per character. SonarQube's default threshold is 5.0, so it stays
  quiet. Kept: it is a real secret.
- `js/express-version-disclosure` (1): `this.app = express()` with no
  `x-powered-by` handling. SonarQube raised nothing; Sonda keeps the finding.

## Rules that depend on knowing a type

SonarQube resolves types through the project; Sonda reads one file. Rules
that need it (`reduce` without an initial value, `.at()` instead of
`length - 1`, `String.match` instead of `RegExp.exec`, `.sort()` without a
compare function, `${object}`) report a value only where the file shows
what it is: a literal, a well-known producer, a local declared as one, or a
call to a function in the same file. A parameter, or anything that comes
from another file, is left alone.
