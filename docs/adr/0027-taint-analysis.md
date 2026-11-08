# ADR-0027: Taint analysis for injection vulnerabilities

- Status: **accepted** (2026-11-07). T1 built, for every sink kind above
  but cross-site scripting: `cs/sql-injection`, `cs/command-injection`,
  `cs/path-injection`, `cs/open-redirect`, `cs/ssrf`, `cs/xpath-injection`
  and `cs/ldap-injection`, with the path in the JSON report and SARIF,
  stored by the server and shown on the issue page. T3 built: through the
  functions of the same file. T2 built, for JavaScript and TypeScript:
  `js/sql-injection`, `js/command-injection`, `js/path-injection`,
  `js/open-redirect`, `js/ssrf` and `js/code-injection`. T4 built:
  through other files' functions, with each step of the path in its file,
  for JavaScript and TypeScript, and for C# in the calls' direction.
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

As built (2026-11-07), three choices the text above left open:

- **Controllers are found as ASP.NET Core finds them:** a public class named
  `…Controller`, or marked `[Controller]` or `[ApiController]`, or deriving
  from `ControllerBase`. Projects derive their controllers from a base of
  their own, in another file, which T1 can't see: in Jellyfin, nopCommerce
  and Kavita, most of them. An action's parameters are sources, except
  `[FromServices]` ones; a minimal API handler's are when they're strings
  or bound by a `[From…]` attribute, since its other parameters are mostly
  services.
- **Types no injection fits through clear the taint,** as a sanitizer for
  every sink: numbers, `bool`, `Guid`, dates and times, enums, and nullable
  ones, so `int.Parse(id)` is safe by its type. Not every value type:
  `char` can be a quote, and `StringValues` holds strings.
- **Provider types match by name and imported namespace.** ADO.NET providers
  (`Microsoft.Data.SqlClient`, Npgsql, MySQL, SQLite, Oracle), EF Core and
  Dapper ship as packages, outside the platform's declarations: a name counts
  when its namespace is imported and the file declares no type of that name.
  A variable set to `x.CreateCommand()` is a command too.

Measured on WebGoat.NET (OWASP's, and its ASP.NET Core port) and on seven
applications (Bitwarden's server, Jellyfin, BTCPay Server, eShop,
nopCommerce, Squidex, Kavita; 18,000 C# files): no findings. The benchmark's
injections all pass through a repository class in another file, which is
T3's and T4's; the applications have no flow T1 should report. A query
concatenated from a parameter, planted in one real controller action of each
application, was found in all seven, with its path; the scan time didn't
change.

The other sinks (2026-11-07) brought three more choices:

- **Sanitizers per sink, as the model says, some of them checks rather than
  transformations.** `Path.GetFileName` makes a value safe for paths only.
  For redirects and server-side requests, a URL whose leftmost text fixes
  where it goes, `"https://api.example.com/" + x` or a path on this site
  `"/orders/" + x`, directly or through a variable or constant set to it,
  can't change the host. And a value a function checks is safe for that
  sink: `Url.IsLocalUrl(x)` and IdentityServer's validation for redirects,
  `x.StartsWith(root)` and helpers named like path checks for paths. A check
  anywhere in the function counts, not only one that guards the sink:
  precision before recall.
- **A controller's own `Request` and `Response`** are the request's and the
  response's, though type inference doesn't resolve them through the
  platform's base class: unqualified, or through `HttpContext`, and not
  shadowed by a local of that name.
- **A file with no possible source isn't analyzed.** A controller, a
  request or a `Map…` handler shows in the file's text; 628 of Bitwarden's
  6,221 files do. With the seven rules, its scan takes 0.5 s more, on 12.

On WebGoat.NET's port and the same seven applications, the first version
reported 13 issues. Eight were checks or fixed hosts, which the choices
above cover and the tests now reproduce. Five remain, by each rule's
definition:
- WebGoat.NET's port redirects to its login form's return URL, one of its
  deliberate vulnerabilities;
- four are in two of the applications, and on review none is exploitable:
  an administrator's endpoint whose purpose is to test a directory the
  administrator chose, and a file name built from a request's value after
  every `.` is removed from it, so no `..` can leave the directory. The
  rules don't model removing characters; such a case stays a finding to
  review.

One line per sink kind, planted in a real controller action of each
application, was found 42 times out of 42.

### T2: within one function, JavaScript and TypeScript

JavaScript has scopes (S1) but no control-flow graph. T2 starts
**flow-insensitive**: within a function, a variable that is ever assigned a
tainted value counts as tainted everywhere in it. Taint is a may-analysis,
so this over-approximates, and the cost is precision when a variable is
reassigned to a safe value later in the function. That's rare in the code
taint rules care about, and a control-flow graph for JavaScript (ADR-0008's
S2) replaces it when it's built, without changing the rules.

As built (2026-11-07):

- **The file is one fixed point.** Variables are the scopes' declarations,
  so one handler's never mix with another's, and a callback sees its
  handler's: `db.connect(() => db.query(q))` is a flow. A variable keeps
  the first path that reached it.
- **Sources** are a request's members (`query`, `body`, `params`,
  `headers`, `cookies`, `url`, `path`, `file`, Next.js's `nextUrl`) and
  methods (`get`, `header`, `json`), in a handler: a function passed to a
  route (`app.get('/x', fn)`, `router.use(fn)`), one whose first parameter
  is `req` or `ctx` (Express's and Koa's controllers, defined apart from
  their routes, Strapi's, Next.js's `getServerSideProps`), or `request`
  next to a response or typed as a request, a Next.js route handler
  (`export async function GET(request, { params })`), and NestJS's and
  routing-controllers' decorated parameters (`@Query('id') id`). Koa's
  `ctx.request` is a request too, and destructuring reads its members:
  `({ query }, res) =>`, `const { body: { name } } = req`.
- **Sinks resolve through imports**, the way C#'s resolve by type: `exec`
  is `child_process`'s whatever it's called here (`import { exec as run }`,
  `const cp = require('node:child_process')`, `require('child_process').exec`),
  and `axios.create()` is axios. Globals count when nothing in the file
  declares them (`fetch`, `eval`). A response's methods are sinks on a
  handler's parameters (`res.redirect`, `res.sendFile`, `ctx.redirect`,
  a `Location` header). SQL has no import to resolve by, since the client
  is usually built elsewhere: `query`, `execute`, `run`, `all` and `get`
  are sinks when the text the value was built into reads as SQL, and the
  raw ones (`$queryRawUnsafe`, `whereRaw`, `knex.raw`) always. A tagged
  template (`` sql`… ${id}` ``) passes its values apart.
- **`js/code-injection`** (S5334) is JavaScript's own sink: `eval`,
  `new Function`, `vm.runIn…Context`, and a string to `setTimeout`. XPath
  and LDAP have no JavaScript rule: neither is common in Node code.
- **Sanitizers and checks**, as T1's, plus what JavaScript code does:
  - a number, or an unknown call's result, isn't tainted, nor is an object
    literal or the request object itself;
  - `path.basename` for paths; for URLs, text of the program's own that
    ends the host before the value (`` `${base}/groups/${slug}` ``,
    `./callback?`), a URL object's parts after its host
    (`to.pathname = x`), and `x.replace(/^\/share/, '/s')`;
  - for every sink, an allowlist that checks the value itself
    (`['asc', 'desc'].includes(order)`, `allowed.has(new URL(u).hostname)`,
    and a ternary on one), a pattern that matches a whole value
    (`/^[\w-]+$/.test(x)`, or an imported name like `themeNamePattern`),
    and equality with a literal, in the branch where it's equal.

Measured on OWASP Juice Shop, NodeGoat and seven applications (Ghost,
NodeBB, Directus, Strapi, Outline, Payload and Immich):

- **The deliberate vulnerabilities are found:** NodeGoat's three `eval`s,
  its open redirect and its SSRF; Juice Shop's SQL injections in its login
  and search, its SSRF, the two path traversals in its code-review routes,
  and nine in the deliberately vulnerable variants it ships as data. Not
  found: those outside these rules (NoSQL injection, a template's layout),
  a stored value read back (second-order), and its redirect challenge,
  whose allowlist check is named like one and is wrong by design.
- **The seven applications:** the first version reported 19 issues. Ten
  were checks or fixed hosts, which the choices above cover and the tests
  now reproduce, and one was Payload's `req.payload`, its own instance
  rather than a request's body (hapi's name, dropped). Nine remain, and on
  review none is exploitable:
  - two redirect to an ActivityPub object's own URL, which is the feature;
  - three redirect to the request's own path, which its route matched; one
    of them strips its leading slashes by reassigning the variable, which a
    flow-insensitive analysis doesn't see;
  - two are checked in another file: a redirect URI validated by a service
    before it throws, and a version its route takes as digits only. T4
    sees the first;
  - two are in a codemod's test fixtures.
- **Recall in real files:** one line per sink kind, planted in a real
  handler of eight of the applications, was found 48 times out of 48.
- **Cost:** scan times grow by 2% at most (Ghost, the largest: 18.2 s
  to 18.5 s).

### T3: across functions, within one file

Each function gets a **summary**: which parameters flow to its return value,
and which parameters reach which sinks, unsanitized. Summaries are computed
callees first; recursion is handled by iterating to a fixed point with the
same caps. A call to a function in the same file applies its summary instead
of T1's "untainted" default. This is the step that turns "the query is built
in a helper" from a miss into a finding.

As built (2026-11-07):

- **A summary per function and sink kind, per parameter:** the function is
  analyzed with one parameter tainted at a time, and its summary records the
  parameters that reach its return value, those that reach a sink (with the
  path from the parameter), and a request's value it reads and returns
  itself (`string Id() => Request.Query["id"]`). A call splices the path:
  the caller's steps, "passed to `Find`", the callee's from its parameter.
- **Checks cross calls too.** A function that checks a parameter (T1's
  guards) checks the matching argument of every call to it, so a validation
  helper that calls `IsPathWithinDirectory` covers its callers.
- **Recursion isn't iterated to a fixed point,** as planned above: a function
  whose summary is being computed counts, for a call back to it, as one
  without a summary. That can only miss a path through the recursion, never
  invent one.
- **Calls resolve** by type inference to a method or local function of the
  file, else by a name and arity only one function has, called unqualified,
  on `this`, or on its own class. Overloads inference can't tell apart
  resolve to nothing.
- **A sink reached by several callers is reported once,** with its shortest
  path.
- **Cost:** summaries are computed once, and only for functions that reach a
  sink, themselves or through their calls, which a walk without analysis
  tells; each call's resolution is computed once. The scan times of the
  seven applications are unchanged.

Measured on the same applications: two helpers planted in a real controller
action of each, one with the sink and one returning the query, were found
14 times out of 14. Two issues T3 first reported were guarded by a check
inside a helper, which led to checks crossing calls. One new issue looks
like a real vulnerability in one of the applications; its details are
withheld here until its maintainers have been told.

### T4: across files

Summaries cross files the way declarations do in
[ADR-0020](0020-cross-file-declarations.md): each worker reports its
functions' summaries, the scanner builds an index, and a second pass
re-checks only the functions whose calls resolve to another file's summary.
C# resolves calls with `cs_index`; JavaScript through relative imports.
Calls into dependencies stay modeled by the tables, not analyzed: sonda
doesn't read `node_modules` or NuGet packages.

As built for JavaScript and TypeScript (2026-11-08), with one change to the
plan: **no second pass.** Re-checking callers would parse their files
again, in a second round of workers. Instead each worker reports, as facts,
everything the scanner needs to join paths without the syntax, and the
scanner joins them in the project pass (`semantic/taint_project.rs`), as
ADR-0020's rules join declarations. That's SonarQube's design too, as far
as its documentation shows: its language analyzers export each method's
control-flow graph, and a separate engine follows taint across all of them.
Summaries are the smaller step; if they prove too coarse, workers can
export a compact graph per function instead, and only the project pass
changes.

- **What a file reports, per taint rule, as one JSON fact:**
  - the summary of each function it exports (ES and CommonJS exports,
    exported classes' methods and default-exported objects' members):
    which parameters reach a sink, the return value, or another file's
    function, each with its path, and a request's value it returns itself;
  - each request's value it passes to another file's function, with its
    path to the call;
  - each sink another file's function's result reaches, with the request's
    values in that call's arguments and the path after it.

  Positions are resolved in the worker, where the source is; so are each
  sink's fingerprint and its line's suppression comment.
- **Calls resolve through relative imports:** named, default and namespace
  imports, `require`, an instance made with `new`, and NestJS's injected
  services (`this.users.find(x)`, `users` a constructor's parameter typed
  with an imported class). `./users` is `users.ts`, `users.js`,
  `users/index.ts`…, and `./users.js` is `users.ts` too. A package's import
  isn't the project's, and an alias such as `@/lib` isn't resolved yet.
- **The project pass** follows a value through up to four files, and a
  result back through one. Each sink is reported once, in its file, by its
  shortest path, and each step of the path names its file when it isn't
  the issue's (`path` in the JSON report, its own location in SARIF).
- **Within one file too:** the same summaries make a helper of the file a
  flow, as T3 did for C#: "passed to `find`", "`find`'s parameter `id`",
  "returned by `build`".
- **A result's SQL:** a query method's text must read as SQL, and when the
  text is another file's function's result, that function's summary says
  whether it does.
- **Not seen:** a response passed to another file's helper under a name
  other than `res`, `response`, `reply` or `ctx`; a request object passed
  to another file's function (its values are, its members aren't followed
  through the call); and flows through a function's own fields.
- **Cost:** summaries are computed once per function and per rule, over
  the writes and calls of that function only. A file stops following
  values past a fixed budget of expressions, so no file costs unbounded
  time.

Measured on the same corpus as T2:

- **Recall across files:** a helper module planted next to a real handler
  of eight of the applications, one exported function per sink kind, each
  called with a request's value: **48 found of 48**, each in the helper
  with its path starting in the handler.
- **Precision:** no new issue in the nine applications. The first version
  reported two through same-file helpers, both false: a folder its caller
  checked with `isPathInside` before passing it (checks now apply where a
  value is passed on, as at a sink), and multer's `req.file.path`, a path
  the server chose (an upload's sources are now only its names:
  `originalname`, `name`).
- **Cost:** scans take 0.6 s more than T2's at most (Strapi, 5.4 s to
  6.0 s); with the taint rules off and on, the largest difference is 22%,
  on the same application.

As built for C# (2026-11-08), on the same facts and project pass:

- **Calls resolve through ADR-0020's index.** A call names its receiver's
  declared type as written (`IOrderService` for a field, a property, a
  parameter or a local, the type of a `new` one, or the type of a static
  call), with the namespace and the type it's written in; the project pass
  resolves it as C# would, through the file's `using`s. An interface or a
  base class reaches the summaries of each of its implementations and
  subclasses in the project, as dependency injection would. A platform's
  method isn't the project's, and a name that resolves to several types
  resolves to none.
- **Summaries** are keyed by the type's full name and the method's name
  and arity (`App.Services.OrderService`0`, `Find/1`), for its methods
  that aren't private.
- **Only the calls' direction:** a controller's value through services to
  a repository's sink. A value returned from another file's method isn't
  followed yet: C#'s flow-sensitive analysis needs a way to keep a
  "returned by another file" value that doesn't lose a request's own.
- **Cost, which shaped it:**
  - files without a request's value are now analyzed too, for their
    summaries, but only methods with a sink of the rule (by the sink
    tables' names in their text) or a parameter passed on to another
    file's method;
  - that second kind is read from the syntax, not the analysis: a
    parameter that can carry text (not a number, a `Guid`, a date) passed
    as an argument, a member of one, or in a concatenation or an
    interpolation, not through another call, which may sanitize it. The
    first version analyzed each such method per parameter, which made a
    scan of Jellyfin 7 s longer;
  - what every rule asks alike (each call's other file's method, each
    method's parameters passed on) is computed once per file.

Measured on the T1 corpus:

- **Recall across files:** a static helper class planted in another file
  of each of seven applications' controllers, one method per sink kind,
  each called from the action with its request parameter: **49 found of
  49**.
- **Precision:** the first version reported seven new issues. Two were
  return URLs nopCommerce's services check with a helper named
  `CheckIsLocalUrl`; a check named like `IsLocalUrl` now counts. Five
  remain, in Jellyfin, none exploitable on review: an endpoint any user
  can call with paths a library monitor only reads the metadata of, four
  sinks in one method, and an administrator's endpoint whose purpose is to
  download an image from the URL given.
- **Cost:** scans take 2.2 s more at most (nopCommerce, 5.1 s to 7.3 s);
  Bitwarden, the largest, 1.1 s more on 12 s.

### The rules

Each sink kind is a new rule, with SonarQube's taint key as its exact
equivalent: `cs/sql-injection` (S3649), `cs/command-injection` (S2076),
`cs/path-injection` (S2083), `cs/open-redirect` (S5146), `cs/ssrf` (S5144),
`cs/xpath-injection` (S2091), `cs/ldap-injection` (S2078), then for
JavaScript and TypeScript `js/sql-injection`, `js/command-injection`,
`js/path-injection`, `js/open-redirect`, `js/ssrf` and `js/code-injection`
(S5334). Cross-site scripting (S5131) waits for a model of the templating
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
