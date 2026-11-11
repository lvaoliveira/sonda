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
| sonda | TypeScript (TSX), Rust | `f9c9bba` | 69 of 69 | 0 |
| CPython, 7 packages¹ | Python | `bf6623a` | 471 of 510 | 37 |
| ha-budgetthuis-prices | Python | `f563c0d` | 3 of 3 | 2 |
| Apache Commons Lang | Java | `5d2715b` | 890 of 918 | 2 |
| apigen.springboot² | Java (Spring Boot) | `ef13838` | 121 of 171 | 11 |
| eGovFrame common components² | Java (Spring) | `14313bc` | 3,726 of 4,878 | 868 |
| eGovFrame common components² | JavaScript (browser scripts) | `14313bc` | 450 of 454 | 279 |

¹ `asyncio`, `email`, `json`, `http`, `logging`, `concurrent` and `urllib`
under `Lib/`. SonarQube couldn't parse 6 of their 93 files (`lazy import`,
new in Python 3.15), so those are left out: the script skips any file
SonarQube indexed without lines of code.

² Compared with SonarCloud's analysis of the same commit, its built-in
"Sonar way comprehensive" profile and a newer analyzer than SonarQube 26.7:
where the two disagreed, SonarQube 26.7 was measured and is the reference.
Both projects use SonarCloud's automatic analysis ("Autoscan for Java"),
which doesn't build: without the compiled classes and the libraries, it
leaves out what needs a type it can't resolve, so its results differ from
SonarQube's with `sonar.java.binaries` on rules that need types.

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

## JavaScript in the browser, measured

eGovFrame's common components ship plain browser scripts: `var`, globals,
`document.write`, DOM calls and regexes, unlike arandu's modules. Every
difference there was measured on SonarQube 26.7, small files one case
each, and sonda now does the same:

- **Lines.** A carriage return alone ends a line, as in files saved on old
  Macs; sonda read such a file as one line, with every issue on line 1. A
  method call in a chain over several lines is reported on its method's
  line.
- **Each one.** S4144 reports every copy of a function, comparing
  declarations, methods and functions given to a variable anywhere in the
  file, nested ones too, but not an object's properties, with a body of
  three lines or more. S2392 is reported at the declaration, once; a `var`
  declared again in another branch is the same variable, not an unused one
  (S1481). S2703 reports a name once, where it's first assigned.
- **Broader.** S1854 includes the last value given to a local that nothing
  reads after, an empty string too. S6535 reads a regex's escapes: outside
  a class only a metacharacter or `/` needs one; in a class, `^` only
  first and `-` only between two characters. S6557 includes
  `/^abc/.test(s)`, in parentheses too; S7781 `split(a).join(b)`, and in
  plain JavaScript any receiver of `replace`. S8786 includes an unanchored
  pattern starting with a repetition with more after it (`/\s+$/`,
  `/\d+x/`), and two repetitions separated by characters both match
  (`/[^@]+\.[^@]+$/`). S6397 includes a class of one escaped character
  (`[\.]`). S7740 includes `self = this`, S6660 an `if` after a comment,
  S4138 a loop over a property (`field.options`). S2681 includes a body on
  the `if`'s line followed by a line indented under it, a tab counting as
  one column, reported at that line. S1126 includes an `if` returning a
  boolean before a `return` of one, the same value or not. S1481 includes
  names starting with `_`. S1874 includes `document.write`, `writeln` and
  `all`.
- **Narrower.** S5148 is a URL written as a string, not one in a variable;
  S7721 leaves a function inside an IIFE; S7768 is `insertBefore` or
  `replaceChild` on plain names (not `x.parentNode`, `this` or
  `p.firstChild`), and not `appendChild`; S5850 leaves `^a|b$`, where each
  alternative has an anchor; S7780 leaves a string ending in a backslash,
  which `String.raw` can't hold, and one escaped backslash is enough.
- **A key.** `js/global-isnan` is S7773, which covers `isNaN` with the
  other globals that `Number` has; S6679 is something else, a value
  compared with itself.

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

## Java, measured

Apache Commons Lang at `5d2715b`, compiled (`sonar.java.binaries`) and
analyzed as Java 8, the version its `pom.xml` targets.

- **The Java version matters.** SonarQube skips a rule whose suggestion
  needs a newer Java than the project's: `@Deprecated(since, forRemoval)`
  needs 9, comma-separated case labels 14, `CharSequence.isEmpty()` 15.
  sonda now reads the version from the build file, or `[java] version`.
- **Positions and counts.** A TODO in a Javadoc is reported on its line;
  the use of legacy dates once per file, with no line; a block of
  commented-out lines once.
- **Narrower than sonda was.** S2129 is `new String()` or `new
  String("x")`, not a conversion; S1319 leaves locals; S1452 leaves
  `Class<?>`; S3014 is a declaration of a `ThreadGroup`, not a type
  argument or an override's parameter; S3706 is a collection's own
  `stream()`; S1301 counts `default`; S2390 is a subclass's static member;
  S1192 leaves exception messages out.
- **Deprecated code (S1133).** An element deprecated by its Javadoc tag
  alone is reported. One whose tag says what to do isn't: the tag's text,
  in any case, holds both "use" and "instead", even inside other words
  ("because", "Insteadly"), or "will be removed in" or "to be removed in"
  on one line. "May be removed in", "Removed in 4" and "Prefer x instead"
  are still reported, and the rest of the Javadoc doesn't count.
- **Brain methods (S6541).** All four at once: 65 lines of code or more
  (comments and blank lines don't count), a cyclomatic complexity of 15 or
  more, control structures nested 3 deep (an `else if` doesn't nest), and
  7 or more parameters, locals and fields used.
- **Class coupling (S6539).** More than 20 of the project's own types:
  fields, locals, parameters and type arguments. The JDK's types, the
  class's nested types and type parameters, and a class only named in a
  static call don't count.

And in a second round:

- **Loop counters (S127).** A write in the body to a variable the `for`
  header declares, each one, at any depth; not a variable declared before
  the loop, even one the header updates or compares.
- **Restricted names (S6213).** `var`, `yield` and `record` as any name: a
  local, a field, a parameter, a catch or for-each variable.
- **Int arithmetic widened (S2184).** Declared, assigned with `=`,
  returned, or passed where a long is expected; a division only when the
  result becomes a `double` or `float`. `r += x * y` isn't reported.
- **Narrower than sonda was:**
  - S1118 leaves a private nested class and a class with a nested enum or
    interface.
  - S1452 leaves private methods and `Collector<T, ?, R>`.
  - S1319 is public fields and public methods' types; protected and
    package-private ones aren't reported.
  - S1845 leaves a getter with its field's name. A field and a method
    differing by case are left when the field is less visible than the
    method: fitted to what was observed, not understood.
  - S117 leaves a final variable named like a constant (`MAX_SIZE`).
  - S116 leaves static fields, constant or not.
  - S1488 leaves an annotated local and is reported at the declaration.
  - S2129 reports a `BigInteger` or `BigDecimal` from a string literal only.
  - S1121 leaves `(x = f()) != 0` wherever it is.
  - S2143 counts `Date` and `Calendar`, an import included, not
    `SimpleDateFormat`, `DateFormat`, `java.sql` or a name written out.

And in a third, with the other files' declarations
([ADR-0020](../adr/0020-cross-file-declarations.md#java)):

- **Across files.** An override widening `protected` to `public` isn't
  useless (S1185), nor `equals`, `hashCode`, `toString`, a final one or one
  with another annotation, and `@Override` isn't needed to be one. A class
  is serializable through a parent in another file or the JDK's
  (`Exception`, `MessageFormat`); its field is reported when its type isn't
  serializable (`Object`, `Type`, `Thread`, a project type without
  `Serializable`, a type variable without such a bound), when it's a
  collection interface and not private, or when it holds a type that
  isn't serializable (S1948). An `equals` counts at any distance up the
  superclasses (S2160); any varargs constructor or method takes an array
  literal (S3878). Inheritance depth counts ancestors up to `Object`, more
  than 5 (S110).
- **Commented-out code (S125).** A line is code when it ends with a brace,
  holds `if(`, `for(`, `while(`, `catch(`, `switch(`, `try{` or `else{`
  with spaces removed, or ends with `;` and has a keyword, `&&`, `||` or a
  camelCase word among its space-separated words. The keywords are a list
  of SonarQube's, without `new`, `do`, `break` or `char`.
- **Smaller ones.** S1135 is each line with a tag; S1193 the catch's first
  statement; S3024 a concatenation appended in a loop; S4144 leaves
  single-statement methods; S1130 leaves unchecked exceptions; S112
  reports `throws Exception` with nothing in the body to pass it on;
  S3599 is an anonymous class that is only an initializer; S3398 a method
  one inner class uses; S106 any use of `System.out`; S1182 a `clone()`
  not calling `super.clone()` itself; S1612 `() -> x.run()` too; S4276 a
  boxed primitive in or out; S3011 a field written by reflection.

And on a Spring Boot application, apigen.springboot, each difference
measured on SonarQube 26.7 with small files, Spring, Lombok and JUnit
annotations as stubs, and a library as a jar on the classpath:

- **Positions.** An issue about an annotated class, method or
  constructor is on its name, below the annotations.
- **Across files.** S1161 is an override of a method with a body without
  `@Override`, not `Object`'s methods nor an abstract one implemented, and
  `fit(double)` doesn't override `fit(N)`. S3252 is a static method reached
  through a subclass. S6539 counts the project's own types: not a
  library's, and not one only created with `new`.
- **Narrower than sonda was:**
  - S112 leaves `throw new RuntimeException(e)` in a catch; `throws
    Exception` is excused only by a call that throws one (`call()`,
    `close()`, a method of the class declaring it).
  - S1118 leaves protected and package-private constructors.
  - S1110 is doubled parentheses; S7158 leaves `equals("")`.
  - S899 is a file's `delete()` and `createNewFile()`, not `mkdirs()`.
  - S2139 is logging then `throw e`; S2737 leaves a rethrow before a broader
    catch.
  - S1450 leaves classes with Lombok's `@Data`, `@Getter`, `@Setter` or
    `@Value`; S4030 is a list or set the method creates, not a map.
  - S1452 leaves overrides; S1186 leaves an abstract class's empty methods
    and constructors with parameters; S1192 leaves constants' own values;
    S1172 leaves serialization hooks; S2970 is test code only; S5960 is an
    assertion called, not a test library imported.
  - S1075 is a path assigned to a name containing `path` or `filename`, or
    passed to `new File`, absolute with three parts or more, or a URI.
- **Each one.** S1165 every field, S5993 every constructor, S6208 every
  group of labels at its last one, S4030 every collection, S3400 at the
  `return`, and a regex in a constant passed to `matches` at the constant.
- **`@SuppressWarnings`** silences as SonarQube honors it: `"all"` or a rule
  key, over the annotated declaration.

And on eGovFrame's common components, each difference measured on
SonarQube 26.7 the same way:

- **Across files.** `throws Exception` isn't S112's when a call in the body
  reaches a method declaring it, in another file too; implementations of a
  supertype's method are left. S1452 is reported once per wildcard
  directly in the type, at the interface, not its implementations.
  `toString()` overriding a project class's is S1161's.
- **Loggers.** S3457 reports a message built by concatenation, a
  `toString()` argument, and placeholders that don't match the arguments;
  a last exception is set aside when it's more than the placeholders take,
  and never fills one alone (`error("{}", e)` is reported). S2629 reports a
  costly concatenation (not of literals, getters or `getMessage()`) or a
  call with arguments, or `toString()`, given as an argument.
- **Positions.** A method call is reported at its name: in a chain over
  several lines, each call on its own line. A `/* */` comment of code at
  its first line of code; a stereotype's bean name at its string.
- **Smaller ones.** S6830 is a stereotype's bean name too; S1126 is an `if`
  returning a boolean before a `return` of one, the same value or not;
  S5411 includes `!b`; S1643 includes `s = s + x`; S8491 is a run of
  Javadocs before a declaration, other comments between them aside; S3516
  is boolean methods; S115 leaves arrays; S2093 is a resource created with
  `new`; S3626 reaches through `if` branches, `try` and `catch`, not a
  labeled jump; S5361 reads the Java string (an escaped metacharacter is
  plain text).

Then the rest of eGovFrame's differences, a few issues per key, in three
calibration projects compiled for Java 17:

- **Java versions.** SonarQube tags the rules it runs only from a Java
  version (`java9` to `java22`): `List.reversed()` (S6876), `Math.clamp`
  (S6885) and a `switch` over an `if` chain (S6880) need 21. sonda skips
  each by its key when the build file targets an older Java, and
  `StringBuilder.isEmpty()` (S7158) before 15.
- **Across files.** S2387 is a field named like an ancestor's, in any file,
  other than a static or private one. A reader's or stream's `close()`
  throws an `IOException`, which doesn't pass `throws Exception` on (S112);
  `AutoCloseable.close()` does.
- **Suppressions.** `@SuppressWarnings("unused")` silences S1481, S1068,
  S1144 and S1172.
- **Broader.** S108 is every empty block: loops, branches, `synchronized`
  and `try`. S1481 includes a local assigned but never read; S1700 a field
  named like its class in any case; S1170 a `null` or constant expression;
  S1948 a `List<?>`; S2445 a parameter; S6813 `@Autowired(required =
  false)`; S6830 `@Bean("egov.x")`; S7158 a StringBuilder's length; S2119 a
  `SecureRandom` kept in a local; S2142 an InterruptedException wrapped in
  another; S2153 `int i = Integer.valueOf(c)`; S3358 each nested ternary,
  in a condition too; S1075 `dir + "/" + name` in `new File`; S1117 a
  for-each variable; S1118 a class with a Lombok logger; S1143 a `throw`,
  in a catch inside the `finally` too; S1141 a `try` in a catch when an
  outer `try` holds it all; S1872 `getSimpleName()`; S2209 and S2696
  `this.field` for a static one; S2479 a no-break space; S2629 a call with
  arguments as the message; S2677 `readLine() != null`; S3416
  `LogFactory.getLog`; S4144 methods differing only in comments; S1126 a
  comment before the second `return`; S6397 `[-]` and `[\\]`; S8786 two
  repetitions around characters both could match (`.*[a-z].*`); S1319
  `ConcurrentHashMap`.
- **Narrower.** S1643 leaves a string declared inside the loop; S1871 an
  `if`/`else` alike (S3923's); S128 a case ending in an `if`/`else` or a
  `try` that returns every way; S2445 a field nothing reassigns; S2201
  `parseInt` in a `try` that catches; S2140 a SecureRandom; S2692
  `lastIndexOf`; S3064 anything but a field behind two null checks; S3824
  an `if` doing more than the put; S6905 a query not passed to a call;
  S6912 an `execute` that isn't JDBC's; S1319 `Vector`; S2629 a bare
  `toString()` as the message.
- **Positions.** An annotated field is reported at its name; S2168 at the
  `synchronized`, S3824 at the `get`, S2737 at the `throw`, S6816 at the
  `@Value`.
- **A rule that checked something else.** S6816 is a `@Nullable` field
  injected by `@Value("${name}")` without a default; sonda's rule checked
  `@Autowired(required = false)` instead.

### Still open in Java

On Commons Lang, 28 of SonarQube's issues and 2 of sonda's:

- **Known gap, data flow (15):** S2259, null dereferences SonarQube finds by
  following calls (`getLength(array) < 2` before `array[0]`) and paths.
- **Deliberate (11):** S2245. `java/random-secret` reports a random value
  that becomes a secret; SonarQube asks for a review of every
  `ThreadLocalRandom` and random-utility call.
- **Known gap, the JDK's declarations (2):** S1161, a method overriding
  `CharSequence.isEmpty()`, a default method of the JDK; S3014, a lambda's
  parameter whose type is inferred as `ThreadGroup`.
- **Not explained (2 sonda only):** `java/brain-method`, reported by
  SonarQube when their file is scanned alone or copied into a file of its
  own, but not in the whole project.

On apigen.springboot, 50 of SonarCloud's issues and 11 of sonda's:

- **SonarCloud's profile and version (45):** rules off in Sonar way and in
  sonda by default (S6204, S6201: 24); rules added after SonarQube 26.7
  (S9391, S9149, S9397: 14); S6096, from the commercial security analyzer
  (7). Not counted against sonda.
- **SonarCloud differs from SonarQube 26.7 (8 sonda only):** S6809 (4),
  S3011 (2), S1481 and S3516, each measured to be reported by 26.7.
- **Known gap, data flow (3):** S2259.
- **Not explained (5):** three unused imports SonarCloud leaves and one it
  reports, all in files without anything unusual; and one of two S5869
  issues on the same constant, which sonda reports once.

On eGovFrame's common components, 1,152 of SonarCloud's Java issues and
868 of sonda's:

- **SonarCloud's newer rules and profile (1,020):** S9438 (968), S9396,
  S9439, S9355 and S9436 (11), added after 26.7; S7476, S6201 and S6204
  (41), off in Sonar way.
- **Autoscan or a newer analyzer, where SonarQube 26.7 reports what sonda
  reports (783):** S3752 (414), S112 (136, calls into a library it couldn't
  resolve, or a library's exception thrown), S117 (58), S1452 (33,
  supertypes in a library), S2629, S3457, S1192 and S2093, S115 on enum
  constants, S2143 on an import, S4488 (28, not explained: 26.7 doesn't
  report it in small files either).
- **Not measured, needing a library's types (7):** S3753 (5) on
  `@SessionAttributes`, S1989 on a servlet's `doGet`, S1130 on a library's
  exception.
- **SonarCloud differs from SonarQube 26.7, each measured on 26.7 (70 sonda
  only, 4 SonarCloud only):** 26.7 reports unused imports (S1128, 23,
  SonarCloud none under `upstream/`), `replaceAll` on a getter's string
  (S5361, 16), catches with the same body (S2147, 11, a subclass's too),
  `File.delete()` (S4042, 8), an override that only calls `super` (S1185),
  a lambda with one statement in braces (S1602), `return null` for an array
  (S1168), `new BigDecimal("100")` (S2129), `while (true)` left by an
  exception (S2189), a static field set from an instance method (S2696),
  `setAccessible` (S3011), a volatile `SecureRandom` (S3077), a method
  always returning `true` (S3516) and a charset by name (S4719). It
  doesn't report `throws NullPointerException` (S1695, 2), a Javadoc before
  a local (S8491) or an email pattern given to `Pattern.compile` (S8786).
- **Known gaps (75):** S1130 (53), whether a checked exception is thrown
  needs the libraries' signatures; S5411 (11), a `Boolean` returned by
  another file's method; S2259 (10), data flow; S3252 (1), a library's
  constant reached through a subclass.
- **Deliberate (61):** S6035 (44), S6353 (7) and S6397 (2), one issue per
  pattern, not one per occurrence, as for Python's S6353; S5332 (7) and a
  password passed to `setPassword` (1), sonda's rules only related to
  SonarQube's, which check a URL or credential reaching an API.

eGovFrame's JavaScript, measured [above](#javascript-in-the-browser-measured):
4 of SonarCloud's issues and 279 of sonda's remain.

- **SonarCloud differs from SonarQube 26.7 (279 sonda only, 1 SonarCloud
  only):** S3504, `var`: 26.7 reports each one; SonarCloud reports them in
  a few files and none in the files with many, a newer analyzer's choice
  not worked out. S1874 on an `onkeypress` handler, which 26.7 doesn't
  report.
- **Known gap, taint (3):** S5696, a script's `src` set from a parameter:
  sonda doesn't follow tainted values into the DOM.

## Rules that depend on knowing a type

SonarQube resolves types through the project; sonda reads one file. Rules
that need it (`reduce` without an initial value, `.at()` instead of
`length - 1`, `String.match` instead of `RegExp.exec`, `.sort()` without a
compare function, `${object}`) report a value only where the file shows
what it is: a literal, a well-known producer, a local declared as one, or a
call to a function in the same file. A parameter, or anything that comes
from another file, is left alone.
