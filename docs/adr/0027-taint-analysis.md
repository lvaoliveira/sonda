# ADR-0027: Taint analysis for injection vulnerabilities

- Status: **proposed**
- Date: 2026-11-07

## Context

sonda finds injection vulnerabilities by their shape. `cs/sql-built-dynamically`
flags `new SqlCommand("SELECT … WHERE id = " + id, c)`; Java, JavaScript and
Python have the same rule, and there are rules for OS commands, `eval` and
anonymous LDAP binds. A shape is where a value ends up, never where it came
from, so these rules are wrong in both directions:

- **They miss the query built one line earlier.** `var q = "SELECT … " + id;
  new SqlCommand(q, c)` passes a variable, and the rule only reads the
  argument it's given.
- **They flag strings nobody controls.** A query concatenated from constants,
  or from a value the code itself computed, reads exactly like one built from
  a request parameter.

Users ask about this, and the README and the website list it as the main
limitation against SonarQube. SonarQube's answer is **taint analysis**: it
follows a value from a **source** (a request parameter, a header, a form
field) through assignments, string operations and calls, across files, to a
**sink** (a query, a command, a file path), and reports the path unless a
**sanitizer** (a parameterized query, a path normalized against a root)
cleans it on the way. Those rules live in repositories of their own
(`javasecurity`, `jssecurity`, `pythonsecurity`,
`roslyn.sonaranalyzer.security.cs`): S3649 SQL injection, S2076 OS command
injection, S2083 path injection, S5131 cross-site scripting, S5146 open
redirect, S5144 server-side request forgery, S2091 XPath and S2078 LDAP
injection, among others. They come only with SonarQube's commercial editions,
which is why [sonar-parity](../sonar-parity/README.md), measured against the
Community Build, doesn't count them.

What sonda already has, from [ADR-0008](0008-semantic-layer.md) and its
follow-ups:

| Piece | JavaScript/TypeScript | C# |
|---|---|---|
| S1: scopes and symbols (which declaration a name is) | built (`semantic/js.rs`) | built (`semantic/cs.rs`) |
| S2: a control-flow graph per function | not built | built (`semantic/cs_cfg.rs`) |
| S3: data flow over the graph | none | liveness only |
| S4: types, with the platform's declarations as data ([ADR-0022](0022-platform-types.md)) | none | built (`semantic/cs_infer.rs`, `semantic/dotnet.rs`) |
| Summaries across files ([ADR-0020](0020-cross-file-declarations.md)) | none | declarations (`semantic/cs_index.rs`) |

Python, Java and C/C++ have no semantic layer yet.

The constraints are the ones every rule has. Analysis runs per file in
sandboxed workers; the analyzed code is never run; every loop is bounded and
a file that runs out of time loses only its semantic findings; the output is
deterministic. And sonda's rules aim to be worth a reviewer's time: a taint
rule that floods a project with paths nobody can follow would be turned off,
and then it finds nothing.

## Decision

Taint analysis is built in phases, like the semantic layer, each shipping
with the rules it makes possible. **C# first**, because it already has the
control-flow graph, the types and the cross-file index that taint needs;
**JavaScript/TypeScript second**, because that's where most web code that
sonda analyzes is.

### The model: sources, sinks, sanitizers and propagators, as data

What counts as a source, a sink, a sanitizer or a propagator is data, one
table per language and framework, beside the rules that use it (as
[ADR-0022](0022-platform-types.md) ships the platform's types as data), not
code in each rule:

- **Sources:** where outside input enters. For ASP.NET Core:
  `HttpRequest.Query`, `.Form`, `.Headers`, `.Cookies`, `.Path`,
  `.RouteValues`, and the parameters of controller actions and minimal-API
  handlers. For Express and similar: `req.query`, `req.body`, `req.params`,
  `req.headers`, `req.cookies`.
- **Sinks**, each with the rule it belongs to, and which of its arguments
  matters: a command's text (`new SqlCommand(text, …)`, `.CommandText = …`,
  `ExecuteSqlRaw`, `connection.query(text)`), a process's file name and
  arguments, a file path, a redirect URL, an outgoing request's URL, an
  XPath expression or an LDAP filter.
- **Sanitizers:** what makes a value safe for a given sink, and only for
  that one. A parameter added with `SqlParameter` or a `?` placeholder is
  safe for SQL; `Path.GetFileName` is safe for a path; HTML encoding is safe
  for XSS but not for SQL. A sanitizer clears the taint for its sinks only.
- **Propagators:** operations whose result carries their input's taint:
  concatenation, interpolation, `string.Format`, `StringBuilder.Append` and
  `ToString`, `Substring`, `Trim`, `Split`, `Join`, collection reads and
  writes, and so on.

C# matches members by their resolved type (`System.Data.SqlClient.SqlCommand`,
not any class named `SqlCommand`), which S4 makes possible. JavaScript
matches by what a name was imported from (`child_process`, `pg`, `mysql2`),
which S1 resolves.

### T1: within one function, C#

A forward **may**-analysis over `cs_cfg`'s graph: which variables may hold
a tainted value at each block, and where the taint came from. It's a
fixed-point computation like liveness, bounded the same way: a cap on rounds
and on the variables tracked per function, past which the function gets no
taint findings (and a warning), never a guess.

- Assignments, declarations, `out` arguments and deconstruction carry taint
  from right to left. Fields and properties are tracked as a whole object,
  not field by field: if any field of `o` is tainted, `o.Anything` is.
- A call to a method the tables don't know returns an untainted value. This
  misses flows through the program's own helpers until T3, but it never
  invents a path through code sonda didn't read.
- A finding is a source reaching a sink argument with no sanitizer for that
  sink on the way.

### T2: within one function, JavaScript and TypeScript

JavaScript has scopes (S1) but no control-flow graph. T2 starts
**flow-insensitive**: within a function, a variable that is ever assigned a
tainted value counts as tainted everywhere in it. Taint is a may-analysis,
so this over-approximates, and the cost is precision when a variable is
reassigned to a safe value later in the function. That's rare in the code
taint rules care about, and a control-flow graph for JavaScript (ADR-0008's
S2) replaces it when it's built, without changing the rules.

### T3: across functions, within one file

Each function gets a **summary**: which parameters flow to its return value,
and which parameters reach which sinks, unsanitized. Summaries are computed
callees first; recursion is handled by iterating to a fixed point with the
same caps. A call to a function in the same file applies its summary instead
of T1's "untainted" default. This is the step that turns "the query is built
in a helper" from a miss into a finding.

### T4: across files

Summaries cross files the way declarations do in
[ADR-0020](0020-cross-file-declarations.md): each worker reports its
functions' summaries, the scanner builds an index, and a second pass
re-checks only the functions whose calls resolve to another file's summary.
C# resolves calls with `cs_index`; JavaScript through relative imports.
Calls into dependencies stay modeled by the tables, not analyzed: sonda
doesn't read `node_modules` or NuGet packages.

### The rules

Each sink kind is a new rule, with SonarQube's taint key as its exact
equivalent: `cs/sql-injection` (S3649), `cs/command-injection` (S2076),
`cs/path-injection` (S2083), `cs/open-redirect` (S5146), `cs/ssrf` (S5144),
`cs/xpath-injection` (S2091), `cs/ldap-injection` (S2078), then the same for
`js/`. Cross-site scripting (S5131) waits for a model of the templating
engines, which is larger than the others.

The shape rules (`*/sql-built-dynamically`, the command and `eval` rules)
**stay**. They are equivalents of different SonarQube rules (S2077 and
friends, which the Community Build has), they catch code with no visible
source, such as a library, and they cost nothing. A line both kinds report
shows both issues: the shape and, with its path, the injection.

### Reporting a path

A taint finding is only useful if the reader can follow it. Issues get an
optional **flow**: the source, each assignment or call it passed through,
and the sink, each with a location and a short message ("request parameter
`id`", "concatenated into `q`", "passed to `SqlCommand`"). It's capped at a
fixed number of steps; a longer path keeps its first and last steps.

- **SARIF:** `codeFlows`, which GitHub code scanning and IDEs already show.
- **JSON:** a `flow` list on the issue. [stability.md](../stability.md)
  adds fields without a new `report_version`.
- **Server and web app:** the issue page lists the steps beside the code,
  and the fingerprint stays the sink's, so a path that changes in the middle
  doesn't reopen a triaged issue.

## Consequences

- **Precision before recall.** Unknown calls are untainted, sanitizers are
  per sink, and every finding has a path a reviewer can check. sonda will
  miss flows SonarQube's commercial engine finds, especially before T3 and
  T4, and says so in the README; it shouldn't report flows that aren't there.
- **The tables are most of the work, and grow over time.** The engine is
  generic; each framework (ASP.NET Core, then Express, then others) is rows
  of data with tests. A missing source or sink is a miss, not a crash, and
  adding one is a small, reviewable change.
- **Validation.** Each phase is measured on projects with documented
  vulnerabilities (OWASP Juice Shop and NodeGoat for JavaScript, WebGoat.NET
  for C#), for which of them it finds, and on the seven open-source C#
  projects ADR-0020 used, for false positives. A phase ships when its rules'
  findings on those projects have been reviewed, like any rule batch.
- **Cost.** T1 and T2 add a fixed point per function, within the existing
  per-file budget. T4 adds a second pass, like ADR-0020's. Each phase is
  benchmarked on a large repository before it ships.
- **Report format.** `flow` is an addition to the JSON report and to SARIF,
  so older consumers ignore it. The server stores it with the issue.
- **Not covered:** Python and Java, until each has a semantic layer; flows
  through dependencies' own code; second-order injection, where a value is
  stored and read back later; and custom sources and sinks in `sonda.toml`,
  which wait until the built-in tables have settled.
- **Reachability** (the [roadmap](../roadmap.md)'s "whether a finding is on
  a path from a public entry point") reuses T3 and T4's summaries and the
  sources' entry points, so it gets cheaper once they're built.
