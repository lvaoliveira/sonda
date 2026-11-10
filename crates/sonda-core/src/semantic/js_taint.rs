//! Taint analysis for JavaScript and TypeScript, phase T2 (ADR-0027): which
//! values that came from a request reach a sink, and by what path.
//!
//! JavaScript has scopes (S1) but no control-flow graph yet, so this is
//! **flow-insensitive**: a variable that is ever assigned a request's value
//! counts as holding it everywhere. Variables are declarations of the
//! file's scopes, so a closure sees what its outer function's variables
//! hold, and one handler's variables never mix with another's. The whole
//! file is one fixed point over its writes; a variable keeps the first path
//! that reached it.
//!
//! Precision before recall, as the ADR says:
//! - a call this module doesn't know returns an untainted value, so a
//!   program's own escaping helper sanitizes, and so does a helper that
//!   builds the query (until T4's summaries);
//! - a number can't inject: `parseInt`, `Number`, arithmetic and
//!   comparisons give untainted values;
//! - object literals and the request object itself aren't tainted, only
//!   the request's members (`req.query`, `ctx.request.body`).
//!
//! Sources are the request's members in a handler: a function passed to a
//! route (`app.get('/x', (req, res) => …)`), one whose first parameter is
//! `req` (or `request`, with a response next to it or a request's type),
//! a Next.js route handler (`export async function GET(request)`), and
//! NestJS's decorated parameters (`@Query('id') id`).
//!
//! Sinks resolve through the file's imports, the way C#'s resolve by type:
//! `exec` is a sink when it's `child_process`'s, whatever it's called here.

use super::taint::{
    CallFact, Callee, Facts, Finding, Key, ReturnFact, SinkKind, Step, SummaryFact, TaintResult,
    cap,
};
use super::{DeclId, Model};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

/// Rounds of the fixed point; past it, the file reports nothing.
const MAX_ROUNDS: usize = 64;
/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;
/// How deep an expression is followed for its taint.
const MAX_DEPTH: u32 = 64;

type Path<'t> = Vec<Step<'t>>;

/// A sink's name, and the arguments that take the value.
type SinkCall<'t> = (String, Vec<Node<'t>>);

/// A path that starts at another file's function's result: a request's
/// value only if that function returns one, which the project pass
/// decides. Its first step is the call, with this message.
const FROM_CALL: &str = "\u{1}";
/// Functions summarized per file, and summaries exported, at most.
const MAX_SUMMARIES: usize = 256;
/// Expressions followed for their taint in one file, at most: past it,
/// what's left is untainted, so a pathological file costs a bounded time
/// and loses only findings, as a file past its deadline does.
const MAX_EVALUATIONS: u64 = 5_000_000;

fn from_call(path: &Path) -> bool {
    path.first().is_some_and(|s| s.message == FROM_CALL)
}

// ---------------------------------------------------------------- tables

/// A request's members that hold what its sender chose. Express, Koa
/// (`ctx.query`, `ctx.request.body`), Fastify, hapi (`payload`), Next.js
/// (`nextUrl`, `searchParams`, a route's `params`) and multer (`file`).
const REQUEST_MEMBERS: &[&str] = &[
    "query",
    "body",
    "params",
    "headers",
    "cookies",
    "url",
    "originalUrl",
    "path",
    "querystring",
    "search",
    "href",
    "nextUrl",
    "searchParams",
];

/// An uploaded file's members its sender chose: multer's and formidable's
/// original name, express-fileupload's `name`.
const UPLOAD_NAMES: &[&str] = &["originalname", "originalFilename", "name"];

/// A request's methods that return what its sender chose: a header
/// (`req.get`, `req.header`), a parameter, or the body.
const REQUEST_METHODS: &[&str] = &[
    "get",
    "header",
    "param",
    "json",
    "text",
    "formData",
    "arrayBuffer",
    "blob",
];

/// A request object's members that are request objects too: Koa's
/// `ctx.request`, and `ctx.req`, Node's own.
const REQUEST_OBJECTS: &[&str] = &["request", "req"];

/// Methods that register a route handler.
const ROUTE_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "del", "all", "options", "head", "use",
];

/// The types a handler's request parameter has.
const REQUEST_TYPES: &[&str] = &[
    "Request",
    "NextRequest",
    "NextApiRequest",
    "FastifyRequest",
    "IncomingMessage",
];

/// A handler's response parameter, by name, when its first is `request`.
const RESPONSE_NAMES: &[&str] = &["res", "response", "reply", "rep", "h"];

/// Next.js route handlers: exported functions named after a method.
const NEXT_ROUTES: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/// NestJS's and routing-controllers' parameter decorators: those that hold
/// a request's value, and those that are the request itself.
const PARAM_DECORATORS: &[&str] = &[
    "Query",
    "Param",
    "Body",
    "Headers",
    "UploadedFile",
    "UploadedFiles",
    "QueryParam",
    "QueryParams",
    "HeaderParam",
    "CookieParam",
    "BodyParam",
];
const REQUEST_DECORATORS: &[&str] = &["Req", "Request"];

/// Methods whose result carries their receiver's value: a string's, an
/// array's, a map's or a `URLSearchParams`'s.
const PROPAGATING_METHODS: &[&str] = &[
    "toString",
    "valueOf",
    "trim",
    "trimStart",
    "trimEnd",
    "toLowerCase",
    "toUpperCase",
    "toLocaleLowerCase",
    "toLocaleUpperCase",
    "normalize",
    "replace",
    "replaceAll",
    "slice",
    "substring",
    "substr",
    "padStart",
    "padEnd",
    "repeat",
    "split",
    "at",
    "join",
    "concat",
    "flat",
    "reverse",
    "filter",
    "get",
    "getAll",
    "json",
    "text",
];

/// Functions whose result carries their arguments' value.
const PROPAGATING_GLOBALS: &[&str] = &[
    "String",
    "decodeURIComponent",
    "decodeURI",
    "encodeURI",
    "unescape",
];

/// A global's methods whose result carries their arguments' value.
const PROPAGATING_STATICS: &[(&str, &str)] = &[
    ("JSON", "parse"),
    ("JSON", "stringify"),
    ("Buffer", "from"),
    ("Array", "from"),
    ("Object", "values"),
    ("String", "raw"),
];

/// Modules whose functions' results carry their arguments' value.
const PROPAGATING_MODULES: &[&str] = &["path", "url", "util", "querystring"];

/// Methods that add their argument to their receiver: `parts.push(x)`.
const INTO_RECEIVER: &[&str] = &["push", "unshift"];

/// Calls that run SQL text as given: a value reaching them is a finding.
const SQL_RAW: &[&str] = &[
    "$queryRawUnsafe",
    "$executeRawUnsafe",
    "raw",
    "whereRaw",
    "orWhereRaw",
    "havingRaw",
    "orderByRaw",
    "groupByRaw",
    "joinRaw",
    "fromRaw",
    "unsafe",
    "literal",
];

/// Calls that run a query, under names other libraries use for other
/// things: a value reaching them is a finding when the text it was built
/// into reads as SQL.
const SQL_QUERY: &[&str] = &[
    "query", "execute", "exec", "run", "all", "get", "each", "prepare",
];

/// Which arguments of a sink take the value.
#[derive(Clone, Copy)]
enum Args {
    First,
    FirstTwo,
    Last,
    All,
}

/// A module's functions that are sinks: `(module, names, kind, args)`.
/// `default` is the module itself, called (`axios(url)`).
const MODULE_SINKS: &[(&str, &[&str], SinkKind, Args)] = &[
    (
        "child_process",
        &[
            "exec",
            "execSync",
            "spawn",
            "spawnSync",
            "execFile",
            "execFileSync",
            "fork",
        ],
        SinkKind::Command,
        Args::First,
    ),
    (
        "execa",
        &[
            "default",
            "execa",
            "execaSync",
            "execaCommand",
            "execaCommandSync",
            "$",
        ],
        SinkKind::Command,
        Args::First,
    ),
    ("shelljs", &["exec"], SinkKind::Command, Args::First),
    (
        "fs",
        &[
            "readFile",
            "readFileSync",
            "writeFile",
            "writeFileSync",
            "appendFile",
            "appendFileSync",
            "createReadStream",
            "createWriteStream",
            "unlink",
            "unlinkSync",
            "rm",
            "rmSync",
            "rmdir",
            "rmdirSync",
            "readdir",
            "readdirSync",
            "mkdir",
            "mkdirSync",
            "open",
            "openSync",
            "truncate",
            "truncateSync",
            "outputFile",
            "outputFileSync",
            "remove",
            "removeSync",
            "readJson",
            "readJsonSync",
            "writeJson",
            "writeJsonSync",
            "emptyDir",
            "emptyDirSync",
        ],
        SinkKind::Path,
        Args::First,
    ),
    (
        "fs",
        &[
            "copyFile",
            "copyFileSync",
            "rename",
            "renameSync",
            "cp",
            "cpSync",
            "copy",
            "copySync",
            "move",
            "moveSync",
            "symlink",
            "symlinkSync",
            "link",
            "linkSync",
        ],
        SinkKind::Path,
        Args::FirstTwo,
    ),
    (
        "axios",
        &[
            "default", "get", "post", "put", "patch", "delete", "head", "options", "request",
        ],
        SinkKind::Ssrf,
        Args::First,
    ),
    (
        "node-fetch",
        &["default", "fetch"],
        SinkKind::Ssrf,
        Args::First,
    ),
    (
        "cross-fetch",
        &["default", "fetch"],
        SinkKind::Ssrf,
        Args::First,
    ),
    (
        "isomorphic-fetch",
        &["default"],
        SinkKind::Ssrf,
        Args::First,
    ),
    (
        "undici",
        &["fetch", "request", "stream"],
        SinkKind::Ssrf,
        Args::First,
    ),
    (
        "got",
        &[
            "default", "get", "post", "put", "patch", "delete", "head", "stream",
        ],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("http", &["get", "request"], SinkKind::Ssrf, Args::First),
    ("https", &["get", "request"], SinkKind::Ssrf, Args::First),
    (
        "request",
        &[
            "default", "get", "post", "put", "patch", "del", "delete", "head",
        ],
        SinkKind::Ssrf,
        Args::First,
    ),
    (
        "superagent",
        &[
            "default", "get", "post", "put", "patch", "del", "delete", "head",
        ],
        SinkKind::Ssrf,
        Args::First,
    ),
    (
        "ky",
        &["default", "get", "post", "put", "patch", "delete", "head"],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("needle", &["get", "head"], SinkKind::Ssrf, Args::First),
    (
        "next/navigation",
        &["redirect", "permanentRedirect"],
        SinkKind::Redirect,
        Args::First,
    ),
    (
        "next/server",
        &["redirect"],
        SinkKind::Redirect,
        Args::First,
    ),
    (
        "vm",
        &[
            "runInNewContext",
            "runInContext",
            "runInThisContext",
            "compileFunction",
            "Script",
        ],
        SinkKind::Code,
        Args::First,
    ),
];

/// Globals that are sinks.
const GLOBAL_SINKS: &[(&str, SinkKind, Args)] = &[
    ("fetch", SinkKind::Ssrf, Args::First),
    ("eval", SinkKind::Code, Args::First),
    ("Function", SinkKind::Code, Args::All),
    ("setTimeout", SinkKind::Code, Args::First),
    ("setInterval", SinkKind::Code, Args::First),
];

/// A response's methods that are sinks: `res.redirect(url)`.
const RESPONSE_SINKS: &[(&str, SinkKind, Args)] = &[
    ("redirect", SinkKind::Redirect, Args::Last),
    ("location", SinkKind::Redirect, Args::First),
    ("sendFile", SinkKind::Path, Args::First),
    ("download", SinkKind::Path, Args::First),
];

/// Names a response goes by outside a handler's own parameters.
const RESPONSE_RECEIVERS: &[&str] = &["res", "response", "reply", "ctx"];

/// Modules under another name: `node:fs`, `fs/promises`, `fs-extra`.
fn normalize_module(m: &str) -> &str {
    let m = m.strip_prefix("node:").unwrap_or(m);
    match m {
        "fs/promises" | "fs-extra" | "graceful-fs" | "original-fs" => "fs",
        "path/posix" | "path/win32" => "path",
        "child_process" | "child-process-promise" => "child_process",
        "superagent" | "supertest" => "superagent",
        _ => m,
    }
}

// ---------------------------------------------------------------- entry

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    // A file without a sink can still pass a value on to another file's
    // function, through a relative import, or export a function that
    // builds what another file passes to one.
    let has = |n: &[u8]| src.windows(n.len()).any(|w| w == n);
    if !(might_have_sinks(src, kind) || has(b"./") || has(b"export")) {
        return TaintResult::default();
    }
    let Some(root) = m.root else {
        return TaintResult::default();
    };
    let Some(cx) = Cx::new(m, src, kind, root) else {
        return TaintResult::default();
    };
    let Some(state) = cx.run_scoped(cx.initial.clone_with(true), None) else {
        return TaintResult::default();
    };
    let reached = cx.reached(None, &state);
    let mut findings: Vec<Finding<'t>> = Vec::new();
    let mut facts = Facts::default();
    for r in reached {
        match r {
            Reach::Sink { path, sink } => findings.push(Finding {
                sink,
                steps: cap(path),
            }),
            Reach::Open {
                path,
                callee,
                arg,
                call,
            } => facts.calls.push(CallFact {
                steps: cap(path),
                call,
                callee,
                arg,
            }),
            Reach::FromCall {
                call,
                after,
                sink,
                needs_sql,
            } => {
                if let Some(callee) = cx.callee_of(call) {
                    let args = arguments(call)
                        .into_iter()
                        .enumerate()
                        .filter_map(|(i, a)| {
                            cx.taint(a, &state, 0)
                                .filter(|p| !from_call(p))
                                .map(|p| (i, cap(p)))
                        })
                        .collect();
                    facts.returns.push(ReturnFact {
                        call,
                        callee,
                        args,
                        after: cap(after),
                        sink,
                        needs_sql,
                    });
                }
            }
        }
    }
    findings.sort_by_key(|f| (f.sink.start_byte(), f.steps.len()));
    findings.dedup_by_key(|f| f.sink.id());
    facts.summaries = cx.exported_summaries(&state);
    TaintResult { findings, facts }
}

/// Whether the file can have a sink of this kind.
fn might_have_sinks(src: &[u8], kind: SinkKind) -> bool {
    let has = |n: &[u8]| src.windows(n.len()).any(|w| w == n);
    let words: &[&[u8]] = match kind {
        SinkKind::Sql => &[
            b"query", b"execute", b"exec", b"raw", b"Raw", b"unsafe", b"run(", b"all(", b"get(",
            b"each(", b"prepare", b"literal",
        ],
        SinkKind::Command => &[b"child_process", b"execa", b"shelljs", b"child-process"],
        SinkKind::Path => &[b"fs", b"sendFile", b"download"],
        SinkKind::Redirect => &[b"redirect", b"location", b"Location"],
        SinkKind::Ssrf => &[
            b"fetch",
            b"axios",
            b"got",
            b"http",
            b"request",
            b"superagent",
            b"ky",
            b"needle",
            b"undici",
        ],
        SinkKind::Code => &[b"eval", b"Function", b"vm", b"setTimeout", b"setInterval"],
        SinkKind::XPath | SinkKind::Ldap => &[],
    };
    words.iter().any(|w| has(w))
}

// ---------------------------------------------------------------- the file

/// What a name imported or required from a module is: the module, and the
/// export (`exec`), or None for the module itself (`import fs from 'fs'`,
/// `const cp = require('child_process')`, `axios.create()`).
struct Import {
    module: String,
    member: Option<String>,
    /// `import x from 'm'`: the module's default export.
    default: bool,
}

/// A write of a value into a variable or a pattern.
struct Write<'t> {
    target: Node<'t>,
    value: Node<'t>,
    /// `q += x`, and `parts.push(x)`: the target keeps what it had.
    adds: bool,
}

/// What the fixed point finds: the variables that hold a request's value,
/// with its path, and those that hold a request.
#[derive(Default)]
struct State<'t> {
    tainted: HashMap<DeclId, Path<'t>>,
    requests: HashSet<DeclId>,
    /// Whether other files' functions' results count, as paths that start
    /// at the call: for the file's own run, not a summary's.
    from_calls: bool,
}

impl<'t> State<'t> {
    fn clone_with(&self, from_calls: bool) -> Self {
        State {
            tainted: self.tainted.clone(),
            requests: self.requests.clone(),
            from_calls,
        }
    }
}

/// What a value reaches: a sink, another file's function, or a sink by way
/// of another file's function's result.
enum Reach<'t> {
    Sink {
        path: Path<'t>,
        sink: Node<'t>,
    },
    Open {
        path: Path<'t>,
        callee: Callee,
        arg: usize,
        call: Node<'t>,
    },
    FromCall {
        call: Node<'t>,
        after: Path<'t>,
        sink: Node<'t>,
        /// A query method whose text this file doesn't show as SQL: the
        /// other function's result has to read as SQL.
        needs_sql: bool,
    },
}

/// What a function's parameters reach, each analyzed alone (T3's summary,
/// for JavaScript).
#[derive(Default)]
struct FnSummary<'t> {
    /// Its return value reads as SQL: `'SELECT … ' + id`.
    returns_sql: bool,
    to_return: Vec<(usize, Path<'t>)>,
    to_sink: Vec<(usize, Path<'t>, Node<'t>)>,
    /// The path ends with "passed to `f`" at the call.
    to_call: Vec<(usize, Path<'t>, Callee, usize)>,
}

struct Cx<'a, 't> {
    m: &'a Model<'t>,
    src: &'a [u8],
    kind: SinkKind,
    /// Each declaration by its name's node.
    by_node: HashMap<usize, DeclId>,
    imports: HashMap<DeclId, Import>,
    /// A handler's parameters: its request, and its response.
    handler_params: HashSet<DeclId>,
    /// Requests and request values as the handlers declare them.
    initial: State<'t>,
    writes: Vec<Write<'t>>,
    /// Every call and `new`, for the sinks.
    calls: Vec<Node<'t>>,
    /// Each function's index in the model, by its node.
    fn_index: HashMap<usize, usize>,
    summaries: RefCell<HashMap<usize, Rc<FnSummary<'t>>>>,
    /// The writes' indices by their target's position, and the calls'
    /// (sorted by position), so a function's are a range.
    writes_by_start: Vec<usize>,
    /// Each variable's writes, for what it was set to.
    writes_by_decl: HashMap<DeclId, Vec<usize>>,
    /// What each handler checks, and each call's sink, computed once.
    checks: RefCell<HashMap<usize, Rc<HashSet<String>>>>,
    sinks: RefCell<HashMap<usize, Option<SinkCall<'t>>>>,
    /// Expressions followed so far, against `MAX_EVALUATIONS`.
    evaluations: std::cell::Cell<u64>,
    /// Functions whose summary is being computed: a call back to one
    /// counts as one without a summary.
    busy: RefCell<HashSet<usize>>,
    /// Each class body's typed fields and constructor parameters, by name,
    /// read once: a large class has a call through a field on most lines.
    field_types: RefCell<HashMap<usize, Rc<HashMap<String, Node<'t>>>>>,
}

impl<'a, 't> Cx<'a, 't> {
    fn new(m: &'a Model<'t>, src: &'a [u8], kind: SinkKind, root: Node<'t>) -> Option<Self> {
        let by_node = m
            .decls
            .iter()
            .enumerate()
            .map(|(i, d)| (d.node.id(), i))
            .collect();
        let mut cx = Cx {
            m,
            src,
            kind,
            by_node,
            imports: HashMap::new(),
            handler_params: HashSet::new(),
            initial: State::default(),
            writes: Vec::new(),
            calls: Vec::new(),
            fn_index: m
                .functions
                .iter()
                .enumerate()
                .map(|(i, f)| (f.node.id(), i))
                .collect(),
            summaries: RefCell::new(HashMap::new()),
            busy: RefCell::new(HashSet::new()),
            field_types: RefCell::new(HashMap::new()),
            writes_by_start: Vec::new(),
            writes_by_decl: HashMap::new(),
            checks: RefCell::new(HashMap::new()),
            sinks: RefCell::new(HashMap::new()),
            evaluations: std::cell::Cell::new(0),
        };
        cx.walk(root)?;
        for f in &m.functions {
            cx.handler(f.node, &f.params);
        }
        cx.calls.sort_by_key(|c| c.start_byte());
        let mut by_start: Vec<usize> = (0..cx.writes.len()).collect();
        by_start.sort_by_key(|&i| cx.writes[i].target.start_byte());
        cx.writes_by_start = by_start;
        for (i, w) in cx.writes.iter().enumerate() {
            let t = unwrap(w.target);
            if t.kind() == "identifier"
                && let Some(d) = cx.decl(t)
            {
                cx.writes_by_decl.entry(d).or_default().push(i);
            }
        }
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        std::str::from_utf8(&self.src[n.byte_range()]).unwrap_or("")
    }

    /// The declaration a name declares or refers to.
    fn decl(&self, name: Node) -> Option<DeclId> {
        self.by_node
            .get(&name.id())
            .copied()
            .or_else(|| self.m.decl_id_of(name))
    }

    /// One pass over the tree: imports, writes and calls.
    fn walk(&mut self, root: Node<'t>) -> Option<()> {
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "import_statement" => self.import(n),
                "variable_declarator" => {
                    if let (Some(name), Some(value)) = (
                        n.child_by_field_name("name"),
                        n.child_by_field_name("value"),
                    ) {
                        self.required(name, value);
                        // `const exec = run`, where `run` is imported.
                        if name.kind() == "identifier"
                            && let Some(import) = self.import_of(value)
                        {
                            let (module, member, default) =
                                (import.module.clone(), import.member.clone(), import.default);
                            self.add_import_as(name, &module, member, default);
                        }
                        self.writes.push(Write {
                            target: name,
                            value,
                            adds: false,
                        });
                    }
                }
                "assignment_expression" | "augmented_assignment_expression" => {
                    if let (Some(left), Some(right)) = (
                        n.child_by_field_name("left"),
                        n.child_by_field_name("right"),
                    ) {
                        self.writes.push(Write {
                            target: left,
                            value: right,
                            adds: n.kind() == "augmented_assignment_expression",
                        });
                    }
                }
                "for_in_statement" => {
                    if let (Some(left), Some(right)) = (
                        n.child_by_field_name("left"),
                        n.child_by_field_name("right"),
                    ) {
                        self.writes.push(Write {
                            target: left,
                            value: right,
                            adds: false,
                        });
                    }
                }
                "call_expression" | "new_expression" => {
                    self.calls.push(n);
                    if let Some((receiver, name)) = method(n)
                        && INTO_RECEIVER.contains(&self.text(name))
                        && receiver.kind() == "identifier"
                    {
                        for a in arguments(n) {
                            self.writes.push(Write {
                                target: receiver,
                                value: a,
                                adds: true,
                            });
                        }
                    }
                }
                _ => {}
            }
            if self.writes.len() > MAX_WRITES {
                return None;
            }
            stack.extend(children(n).into_iter().rev());
        }
        Some(())
    }

    fn import(&mut self, n: Node<'t>) {
        let Some(source) = n.child_by_field_name("source") else {
            return;
        };
        let module = normalize_module(string_value(self.text(source))).to_string();
        let mut stack = children(n);
        while let Some(c) = stack.pop() {
            match c.kind() {
                "import_clause" | "namespace_import" | "named_imports" => {
                    stack.extend(children(c));
                }
                // `import x from 'm'`, directly in the clause; a namespace's
                // name is in `namespace_import`.
                "identifier" => {
                    let default = c.parent().is_some_and(|p| p.kind() == "import_clause");
                    self.add_import_as(c, &module, None, default);
                }
                "import_specifier" => {
                    let Some(name) = c.child_by_field_name("name") else {
                        continue;
                    };
                    let local = c.child_by_field_name("alias").unwrap_or(name);
                    let member = string_value(self.text(name)).to_string();
                    let member = (member != "default").then_some(member);
                    self.add_import(local, &module, member);
                }
                _ => {}
            }
        }
        // `import x = require('m')`, TypeScript's.
        if let Some(clause) = children(n)
            .into_iter()
            .find(|c| c.kind() == "import_require_clause")
            && let Some(name) = clause.named_child(0)
        {
            self.add_import(name, &module, None);
        }
    }

    fn add_import(&mut self, local: Node, module: &str, member: Option<String>) {
        self.add_import_as(local, module, member, false);
    }

    fn add_import_as(&mut self, local: Node, module: &str, member: Option<String>, default: bool) {
        if let Some(d) = self.decl(local) {
            self.imports.insert(
                d,
                Import {
                    module: module.to_string(),
                    member,
                    default,
                },
            );
        }
    }

    /// `const cp = require('child_process')`, `const { exec } = require(…)`,
    /// `const { promises: fsp } = require('fs')`, `const run = require('m').x`,
    /// and `const api = axios.create(…)`, an instance of its module.
    fn required(&mut self, name: Node<'t>, value: Node<'t>) {
        let value = unwrap(value);
        let (module, member) = if let Some(module) = require_of(value, self.src) {
            (module, None)
        } else if value.kind() == "member_expression"
            && let Some(module) = value
                .child_by_field_name("object")
                .and_then(|o| require_of(unwrap(o), self.src))
        {
            let property = value
                .child_by_field_name("property")
                .map(|p| self.text(p).to_string());
            (module, property)
        } else if let Some((receiver, method_name)) = method(value)
            && matches!(self.text(method_name), "create" | "extend")
            && let Some(import) = self.import_of(receiver)
        {
            (import.module.clone(), None)
        } else {
            return;
        };
        let module = normalize_module(&module).to_string();
        match name.kind() {
            "identifier" => self.add_import(name, &module, member),
            "object_pattern" if member.is_none() => {
                for c in children(name) {
                    match c.kind() {
                        "shorthand_property_identifier_pattern" => {
                            let key = self.text(c).to_string();
                            self.add_import(c, &module, Some(key));
                        }
                        "pair_pattern" => {
                            if let (Some(k), Some(v)) =
                                (c.child_by_field_name("key"), c.child_by_field_name("value"))
                                && v.kind() == "identifier"
                            {
                                let key = string_value(self.text(k)).to_string();
                                self.add_import(v, &module, Some(key));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    fn import_of(&self, n: Node) -> Option<&Import> {
        let n = unwrap(n);
        matches!(n.kind(), "identifier" | "type_identifier")
            .then(|| self.decl(n))
            .flatten()
            .and_then(|d| self.imports.get(&d))
    }

    // ------------------------------------------------------------ sources

    /// Whether function `f` is a handler, and what its parameters hold.
    fn handler(&mut self, f: Node<'t>, params: &[Vec<DeclId>]) {
        let nodes = param_nodes(f);
        if nodes.is_empty() {
            return;
        }
        // NestJS and routing-controllers: decorated parameters, in any method.
        for (i, p) in nodes.iter().enumerate() {
            for d in decorators(*p) {
                let name = self.text(d);
                let Some(decls) = params.get(i) else { continue };
                if PARAM_DECORATORS.contains(&name) {
                    for &decl in decls {
                        self.initial.tainted.insert(
                            decl,
                            vec![Step {
                                node: self.m.decls[decl].node,
                                message: format!("request parameter `{}`", self.m.decls[decl].name),
                            }],
                        );
                    }
                } else if REQUEST_DECORATORS.contains(&name) {
                    self.initial.requests.extend(decls.iter().copied());
                }
            }
        }
        let next_route = self.is_next_route(f);
        if !(next_route || self.is_route_argument(f) || self.named_like_handler(&nodes)) {
            return;
        }
        for decls in params {
            self.handler_params.extend(decls.iter().copied());
        }
        // The request: the first parameter, and for a Next.js route the
        // second too, which holds the route's `params`.
        let requests = if next_route { 2 } else { 1 };
        for (i, decls) in params.iter().enumerate().take(requests) {
            let pattern = nodes.get(i).map(|n| pattern_of(*n));
            match pattern {
                Some(p) if p.kind() == "identifier" => {
                    self.initial.requests.extend(decls.iter().copied());
                }
                // `({ query, body }, res) => …`: the request's members.
                Some(_) => {
                    for &decl in decls {
                        let node = self.m.decls[decl].node;
                        let Some(key) = pattern_key(node, self.src) else {
                            continue;
                        };
                        if REQUEST_MEMBERS.contains(&key.as_str()) {
                            self.initial.tainted.insert(
                                decl,
                                vec![Step {
                                    node,
                                    message: format!("the request's `{key}`"),
                                }],
                            );
                        } else if REQUEST_OBJECTS.contains(&key.as_str()) {
                            self.initial.requests.insert(decl);
                        }
                    }
                }
                None => {}
            }
        }
    }

    /// `app.get('/x', (req, res) => …)`, `router.use(fn)`,
    /// `router.route('/x').post(fn)`.
    fn is_route_argument(&self, f: Node) -> bool {
        let Some(args) = f.parent().filter(|p| p.kind() == "arguments") else {
            return false;
        };
        let Some(call) = args.parent().filter(|c| c.kind() == "call_expression") else {
            return false;
        };
        let Some((receiver, name)) = method(call) else {
            return false;
        };
        let name = self.text(name);
        if !ROUTE_METHODS.contains(&name) {
            return false;
        }
        let first = arguments(call).into_iter().next();
        let path_like = first.is_some_and(|a| match a.kind() {
            "string" | "template_string" => {
                let v = string_value(self.text(a));
                v.starts_with('/') || v.starts_with('*')
            }
            "regex" | "array" => true,
            _ => false,
        });
        let on_route = method(unwrap(receiver)).is_some_and(|(_, n)| self.text(n) == "route");
        path_like || on_route || name == "use"
    }

    /// `export async function GET(request, { params })`, and
    /// `export const POST = async (req) => …`.
    fn is_next_route(&self, f: Node) -> bool {
        let (name, declaration) = match f.kind() {
            "function_declaration" => (f.child_by_field_name("name"), f),
            _ => match f.parent().filter(|p| p.kind() == "variable_declarator") {
                Some(d) => (d.child_by_field_name("name"), d),
                None => return false,
            },
        };
        let exported = std::iter::successors(declaration.parent(), |p| p.parent())
            .take(2)
            .any(|p| p.kind() == "export_statement");
        exported && name.is_some_and(|n| NEXT_ROUTES.contains(&self.text(n)))
    }

    /// A function whose first parameter is `req` or `ctx`, or `request`
    /// next to a response or with a request's type: Express's and Koa's
    /// controllers, defined apart from their routes, and Node's
    /// `createServer` callbacks.
    fn named_like_handler(&self, nodes: &[Node]) -> bool {
        let Some(first) = nodes.first() else {
            return false;
        };
        let name = pattern_of(*first);
        if name.kind() != "identifier" {
            return false;
        }
        let typed = first
            .child_by_field_name("type")
            .is_some_and(|t| REQUEST_TYPES.contains(&type_name(self.text(t))));
        match self.text(name) {
            // `ctx`: Koa's context, a Strapi controller's, and Next.js's
            // `getServerSideProps(ctx)`; its request members are the
            // request's.
            "req" | "ctx" => true,
            "request" | "_req" | "_request" => {
                typed
                    || nodes.get(1).is_some_and(|second| {
                        let s = pattern_of(*second);
                        s.kind() == "identifier" && RESPONSE_NAMES.contains(&self.text(s))
                    })
            }
            _ => typed,
        }
    }

    // ------------------------------------------------------------ fixed point

    /// The fixed point from `state`, over the writes in `scope` (a
    /// function, for a summary), or the whole file's.
    fn run_scoped(&self, mut state: State<'t>, scope: Option<Node>) -> Option<State<'t>> {
        let writes: Vec<&Write<'t>> = match scope {
            None => self.writes.iter().collect(),
            Some(s) => {
                let start = |i: &usize| self.writes[*i].target.start_byte();
                let lo = self
                    .writes_by_start
                    .partition_point(|i| start(i) < s.start_byte());
                let hi = self
                    .writes_by_start
                    .partition_point(|i| start(i) < s.end_byte());
                self.writes_by_start[lo..hi]
                    .iter()
                    .map(|&i| &self.writes[i])
                    .filter(|w| within(w.target, s))
                    .collect()
            }
        };
        for _ in 0..MAX_ROUNDS {
            let mut changed = false;
            for w in &writes {
                changed |= self.bind(w, &mut state);
            }
            if !changed {
                return Some(state);
            }
        }
        None
    }

    /// Applies one write; whether the state changed.
    fn bind(&self, w: &Write<'t>, state: &mut State<'t>) -> bool {
        let target = unwrap(w.target);
        match target.kind() {
            "identifier" => {
                let Some(decl) = self.decl(target) else {
                    return false;
                };
                if !w.adds && self.is_request(w.value, state) {
                    return state.requests.insert(decl);
                }
                if settled(state, decl) {
                    return false;
                }
                let Some(mut path) = self.taint(w.value, state, 0) else {
                    return false;
                };
                if !replaces(state, decl, &path) {
                    return false;
                }
                let name = self.text(target);
                let into = if w.adds && w.target.parent().is_some_and(|p| p.kind() == "arguments") {
                    format!("added to `{name}`")
                } else if w.adds || is_built(unwrap(w.value)) {
                    format!("concatenated into `{name}`")
                } else {
                    format!("assigned to `{name}`")
                };
                path.push(Step {
                    node: target,
                    message: into,
                });
                state.tainted.insert(decl, cap(path));
                true
            }
            "object_pattern" | "array_pattern" => self.bind_pattern(target, w.value, state),
            // `options.url = x`: the object holds it.
            "member_expression" | "subscript_expression" => {
                let Some(object) = target.child_by_field_name("object").map(unwrap) else {
                    return false;
                };
                if object.kind() != "identifier" {
                    return false;
                }
                // `to.pathname = x`, `to.search = x`: a URL's parts after its
                // host don't change where it goes.
                if matches!(self.kind, SinkKind::Redirect | SinkKind::Ssrf)
                    && target.child_by_field_name("property").is_some_and(|p| {
                        matches!(
                            self.text(p),
                            "pathname" | "search" | "hash" | "query" | "searchParams"
                        )
                    })
                {
                    return false;
                }
                let Some(decl) = self.decl(object) else {
                    return false;
                };
                if settled(state, decl)
                    || state.requests.contains(&decl)
                    || self.handler_params.contains(&decl)
                {
                    return false;
                }
                let Some(mut path) = self.taint(w.value, state, 0) else {
                    return false;
                };
                if !replaces(state, decl, &path) {
                    return false;
                }
                path.push(Step {
                    node: target,
                    message: format!("assigned to `{}`", self.text(target)),
                });
                state.tainted.insert(decl, cap(path));
                true
            }
            _ => false,
        }
    }

    /// `const { id } = req.query`, `const { query } = req`, `const [a] = xs`.
    fn bind_pattern(&self, pattern: Node<'t>, value: Node<'t>, state: &mut State<'t>) -> bool {
        let from_request = self.is_request(value, state);
        let carried = if from_request {
            None
        } else {
            self.taint(value, state, 0)
        };
        if !from_request && carried.is_none() {
            return false;
        }
        let mut changed = false;
        for name in pattern_names(pattern) {
            let Some(decl) = self.decl(name) else {
                continue;
            };
            if settled(state, decl) {
                continue;
            }
            if from_request {
                let Some(key) = pattern_key(name, self.src) else {
                    continue;
                };
                if REQUEST_MEMBERS.contains(&key.as_str()) {
                    state.tainted.insert(
                        decl,
                        vec![Step {
                            node: name,
                            message: format!("the request's `{key}`"),
                        }],
                    );
                    changed = true;
                } else if REQUEST_OBJECTS.contains(&key.as_str()) {
                    changed |= state.requests.insert(decl);
                }
            } else if let Some(path) = carried.as_ref().filter(|p| replaces(state, decl, p)) {
                let mut path = path.clone();
                path.push(Step {
                    node: name,
                    message: format!("read into `{}`", self.text(name)),
                });
                state.tainted.insert(decl, cap(path));
                changed = true;
            }
        }
        changed
    }

    /// Whether an expression is a request: a handler's, or Koa's
    /// `ctx.request`.
    fn is_request(&self, n: Node, state: &State) -> bool {
        let n = unwrap(n);
        match n.kind() {
            "identifier" => self.decl(n).is_some_and(|d| state.requests.contains(&d)),
            "member_expression" => {
                n.child_by_field_name("property")
                    .is_some_and(|p| REQUEST_OBJECTS.contains(&self.text(p)))
                    && n.child_by_field_name("object")
                        .is_some_and(|o| self.is_request(o, state))
            }
            _ => false,
        }
    }

    /// The path of the first request's value an expression carries, or None.
    fn taint(&self, n: Node<'t>, state: &State<'t>, depth: u32) -> Option<Path<'t>> {
        let evaluations = self.evaluations.get() + 1;
        self.evaluations.set(evaluations);
        if depth > MAX_DEPTH || evaluations > MAX_EVALUATIONS {
            return None;
        }
        let d = depth + 1;
        match n.kind() {
            "identifier" => self
                .decl(n)
                .and_then(|decl| state.tainted.get(&decl).cloned()),
            "parenthesized_expression"
            | "await_expression"
            | "non_null_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion"
            | "spread_element" => n
                .named_children(&mut n.walk())
                .find(|c| !c.kind().contains("type"))
                .and_then(|c| self.taint(c, state, d)),
            "member_expression" => {
                let object = n.child_by_field_name("object")?;
                let property = self.text(n.child_by_field_name("property")?);
                if self.is_request(object, state) {
                    return REQUEST_MEMBERS.contains(&property).then(|| {
                        vec![Step {
                            node: n,
                            message: format!("the request's `{property}`"),
                        }]
                    });
                }
                // An upload's name is its sender's; where it was stored
                // (multer's `path`, `filename`) is the server's.
                if UPLOAD_NAMES.contains(&property) && self.is_upload(object, state) {
                    return Some(vec![Step {
                        node: n,
                        message: format!("the uploaded file's `{property}`"),
                    }]);
                }
                if property == "length" {
                    return None;
                }
                self.taint(object, state, d).map(|p| deepen(p, object, n))
            }
            "subscript_expression" => {
                let object = n.child_by_field_name("object")?;
                if self.is_request(object, state) {
                    return None;
                }
                self.taint(object, state, d).map(|p| deepen(p, object, n))
            }
            "binary_expression" => {
                let op = n.child_by_field_name("operator").map(|o| self.text(o));
                let left = n.child_by_field_name("left")?;
                let right = n.child_by_field_name("right")?;
                match op {
                    Some("+") => {
                        if self.fixes_origin(n, state, d) {
                            return None;
                        }
                        self.taint(left, state, d)
                            .or_else(|| self.taint(right, state, d))
                    }
                    Some("||" | "??") => self
                        .taint(left, state, d)
                        .or_else(|| self.taint(right, state, d)),
                    Some("&&") => self.taint(right, state, d),
                    _ => None,
                }
            }
            "template_string" => {
                if self.fixes_origin(n, state, d) {
                    return None;
                }
                children(n)
                    .into_iter()
                    .filter(|c| c.kind() == "template_substitution")
                    .filter_map(|c| c.named_child(0))
                    .find_map(|e| self.taint(e, state, d))
            }
            // `ok.includes(x) ? x : 'jpg'`: the branch its condition checked.
            "ternary_expression" => n
                .child_by_field_name("consequence")
                .filter(|c| {
                    !n.child_by_field_name("condition").is_some_and(|cond| {
                        self.checked_values(cond).contains(self.text(unwrap(*c)))
                    })
                })
                .and_then(|c| self.taint(c, state, d))
                .or_else(|| {
                    n.child_by_field_name("alternative")
                        .and_then(|a| self.taint(a, state, d))
                }),
            "array" => children(n)
                .into_iter()
                .find_map(|e| self.taint(e, state, d)),
            "sequence_expression" => n
                .named_child(n.named_child_count().saturating_sub(1) as u32)
                .and_then(|l| self.taint(l, state, d)),
            "assignment_expression" => n
                .child_by_field_name("right")
                .and_then(|r| self.taint(r, state, d)),
            "call_expression" => self.call_taint(n, state, d),
            "new_expression" => {
                let ctor = self.text(n.child_by_field_name("constructor")?);
                let first = arguments(n).into_iter().next()?;
                match ctor {
                    "URL" if self.fixes_origin(first, state, d) => None,
                    "URL" | "String" | "URLSearchParams" => self.taint(first, state, d),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn call_taint(&self, call: Node<'t>, state: &State<'t>, d: u32) -> Option<Path<'t>> {
        let args = call.child_by_field_name("arguments")?;
        // A tagged template, `sql\`… ${id}\``, passes its values apart.
        if args.kind() == "template_string" {
            return None;
        }
        let any_arg = || {
            arguments(call)
                .into_iter()
                .find_map(|a| self.taint(a, state, d))
        };
        // A function of this file: what its summary returns.
        if let Some(j) = self.local_function(call) {
            return self.through_local(call, j, state, d);
        }
        // Another file's: a request's value if it returns one, which the
        // project pass decides.
        if state.from_calls && self.callee_of(call).is_some() {
            return Some(vec![Step {
                node: call,
                message: FROM_CALL.to_string(),
            }]);
        }
        let callee = unwrap(call.child_by_field_name("function")?);
        if callee.kind() == "identifier" {
            let name = self.text(callee);
            if let Some(import) = self.import_of(callee) {
                return self
                    .module_propagates(&import.module, import.member.as_deref())
                    .then(any_arg)
                    .flatten();
            }
            if self.decl(callee).is_none() && PROPAGATING_GLOBALS.contains(&name) {
                return any_arg();
            }
            if self.decl(callee).is_none()
                && name == "encodeURIComponent"
                && !matches!(self.kind, SinkKind::Redirect | SinkKind::Ssrf)
            {
                return any_arg();
            }
            return None;
        }
        let (receiver, method_name) = method(call)?;
        let name = self.text(method_name);
        // `req.get('x')`, `await request.json()`: the request's values.
        if self.is_request(receiver, state) {
            return REQUEST_METHODS.contains(&name).then(|| {
                vec![Step {
                    node: call,
                    message: format!("the request's `{name}`"),
                }]
            });
        }
        if let Some(import) = self.import_of(receiver) {
            return self
                .module_propagates(&import.module, Some(name))
                .then(any_arg)
                .flatten();
        }
        let receiver = unwrap(receiver);
        if receiver.kind() == "identifier"
            && self.decl(receiver).is_none()
            && PROPAGATING_STATICS.contains(&(self.text(receiver), name))
        {
            return any_arg();
        }
        if !PROPAGATING_METHODS.contains(&name) {
            return None;
        }
        if self.replaces_origin(call, name) {
            return None;
        }
        self.taint(receiver, state, d)
            .or_else(|| (name == "concat").then(any_arg).flatten())
    }

    /// Whether a module's function returns what it's given: `path.join`,
    /// `util.format`, but not `path.basename` for a path's sink.
    fn module_propagates(&self, module: &str, member: Option<&str>) -> bool {
        PROPAGATING_MODULES.contains(&module)
            && !(self.kind == SinkKind::Path && module == "path" && member == Some("basename"))
    }

    /// For a request (SSRF) or a redirect: a URL whose text before the
    /// request's value fixes where it goes. Its leftmost part may fix it,
    /// `"https://api.example.com/" + x` or a local `` `/orders/${id}` ``, or
    /// a path or query after a value of the program's own,
    /// `` `${base}/groups/${slug}` ``: what follows can't change the host.
    fn fixes_origin(&self, n: Node<'t>, state: &State<'t>, d: u32) -> bool {
        if !matches!(self.kind, SinkKind::Ssrf | SinkKind::Redirect) {
            return false;
        }
        if self.fixed_prefix(n, 4) {
            return true;
        }
        let mut before = String::new();
        for part in url_parts(n) {
            match part.kind() {
                "string_fragment" => before.push_str(self.text(part)),
                "string" => before.push_str(string_value(self.text(part))),
                _ if self.taint(part, state, d + 1).is_some() => break,
                _ => {}
            }
        }
        separates_host(&before)
    }

    /// `p.replace(/^\/share/, '/s')`: a value that now starts with a path
    /// of this site; and `p.replace(/^\/+/, '/')`, which leaves one slash.
    fn replaces_origin(&self, call: Node, name: &str) -> bool {
        if !matches!(self.kind, SinkKind::Ssrf | SinkKind::Redirect)
            || !matches!(name, "replace" | "replaceAll")
        {
            return false;
        }
        let args = arguments(call);
        let (Some(pattern), Some(with)) = (args.first(), args.get(1)) else {
            return false;
        };
        if pattern.kind() != "regex" || with.kind() != "string" {
            return false;
        }
        let source = pattern
            .child_by_field_name("pattern")
            .map_or("", |p| self.text(p));
        let with = string_value(self.text(*with));
        source.starts_with('^')
            && (self.fixed_prefix(args[1], 0)
                || (matches!(source, "^\\/+" | "^/+" | "^[\\/]+" | "^[/\\]+") && with == "/"))
    }

    fn fixed_prefix(&self, n: Node, depth: u8) -> bool {
        let mut first = unwrap(n);
        while first.kind() == "binary_expression" {
            match first.child_by_field_name("left") {
                Some(l) => first = unwrap(l),
                None => return false,
            }
        }
        let prefix: String = match first.kind() {
            "string" => string_value(self.text(first)).to_string(),
            "template_string" => children(first)
                .into_iter()
                .take_while(|c| c.kind() != "template_substitution")
                .filter(|c| c.kind() == "string_fragment")
                .map(|c| self.text(c))
                .collect(),
            "identifier" if depth > 0 => {
                return self
                    .decl(first)
                    .and_then(|d| self.m.decls[d].declarator)
                    .and_then(|d| d.child_by_field_name("value"))
                    .is_some_and(|v| self.fixed_prefix(v, depth - 1));
            }
            _ => return false,
        };
        let absolute = prefix.split_once("://").is_some_and(|(scheme, rest)| {
            !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                && rest.find('/').is_some_and(|slash| slash > 0)
        });
        let local =
            prefix.starts_with('/') && prefix.chars().nth(1).is_some_and(|c| c != '/' && c != '\\');
        // `./callback?`, `original?`, `?page=`: relative to this page.
        let relative = !prefix.starts_with(['/', '\\'])
            && prefix
                .find(['/', '?', '#'])
                .is_some_and(|end| !prefix[..end].contains(':'));
        absolute || local || relative
    }

    // ------------------------------------------------------------ sinks

    /// What the request's values reach from the calls in `scope` (a
    /// function, for a summary), or the whole file's: sinks, this file's
    /// helpers' sinks, and other files' functions.
    fn reached(&self, scope: Option<Node>, state: &State<'t>) -> Vec<Reach<'t>> {
        let mut out = Vec::new();
        let calls = match scope {
            None => &self.calls[..],
            Some(s) => {
                let lo = self
                    .calls
                    .partition_point(|c| c.start_byte() < s.start_byte());
                let hi = self
                    .calls
                    .partition_point(|c| c.start_byte() < s.end_byte());
                &self.calls[lo..hi]
            }
        };
        for &call in calls {
            let sink = self
                .sinks
                .borrow_mut()
                .entry(call.id())
                .or_insert_with(|| self.sink(call, &self.initial))
                .clone();
            if let Some((name, args)) = sink {
                for arg in args {
                    let Some(mut path) = self.taint(arg, state, 0) else {
                        continue;
                    };
                    let needs_sql = self.kind == SinkKind::Sql
                        && SQL_QUERY.contains(&name.as_str())
                        && !self.reads_as_sql(arg, 3);
                    if needs_sql && !from_call(&path) {
                        continue;
                    }
                    let scope = outermost_function(call, self.m);
                    let checked = self.checks_of(scope);
                    if self.is_checked(&checked, call, arg, &path) {
                        continue;
                    }
                    path.push(Step {
                        node: call,
                        message: format!("passed to `{name}`"),
                    });
                    out.push(self.reach_sink(path, call, needs_sql));
                    break;
                }
                continue;
            }
            // A helper of this file whose parameter reaches a sink, or
            // another file's function.
            if let Some(j) = self.local_function(call) {
                let summary = self.summary(j);
                let name = self.function_name(j);
                for (i, arg) in arguments(call).into_iter().enumerate() {
                    if !summary.to_sink.iter().any(|t| t.0 == i)
                        && !summary.to_call.iter().any(|t| t.0 == i)
                    {
                        continue;
                    }
                    let Some(path) = self.taint(arg, state, 0) else {
                        continue;
                    };
                    if self.is_checked(
                        &self.checks_of(outermost_function(call, self.m)),
                        call,
                        arg,
                        &path,
                    ) {
                        continue;
                    }
                    let into = |inner: &Path<'t>| {
                        let mut p = path.clone();
                        p.push(Step {
                            node: call,
                            message: format!("passed to `{name}`"),
                        });
                        p.extend(inner.iter().cloned());
                        p
                    };
                    for (_, inner, sink) in summary.to_sink.iter().filter(|t| t.0 == i) {
                        out.push(self.reach_sink(into(inner), *sink, false));
                    }
                    if !from_call(&path) {
                        for (_, inner, callee, a) in summary.to_call.iter().filter(|t| t.0 == i) {
                            out.push(Reach::Open {
                                path: into(inner),
                                callee: callee.clone(),
                                arg: *a,
                                call,
                            });
                        }
                    }
                }
                continue;
            }
            if let Some(callee) = self.callee_of(call) {
                let checked = self.checks_of(outermost_function(call, self.m));
                for (i, arg) in arguments(call).into_iter().enumerate() {
                    if let Some(path) = self
                        .taint(arg, state, 0)
                        .filter(|p| !from_call(p) && !self.is_checked(&checked, call, arg, p))
                    {
                        out.push(Reach::Open {
                            path,
                            callee: callee.clone(),
                            arg: i,
                            call,
                        });
                    }
                }
            }
        }
        out
    }

    /// A sink reached: by a request's value, or by another file's
    /// function's result, which the project pass follows.
    fn reach_sink(&self, path: Path<'t>, sink: Node<'t>, needs_sql: bool) -> Reach<'t> {
        if from_call(&path) {
            Reach::FromCall {
                call: path[0].node,
                after: path[1..].to_vec(),
                sink,
                needs_sql,
            }
        } else {
            Reach::Sink { path, sink }
        }
    }

    // ------------------------------------------------------------ calls

    /// The function of this file a call calls: `build(x)`, with `build`
    /// declared here as a function or a variable set to one.
    fn local_function(&self, call: Node<'t>) -> Option<usize> {
        if call.kind() != "call_expression" {
            return None;
        }
        let callee = unwrap(call.child_by_field_name("function")?);
        if callee.kind() != "identifier" {
            return None;
        }
        let decl = &self.m.decls[self.decl(callee)?];
        let parent = decl.node.parent()?;
        let function = match parent.kind() {
            "function_declaration" | "generator_function_declaration" => parent,
            "variable_declarator" => unwrap(parent.child_by_field_name("value")?),
            _ => return None,
        };
        self.fn_index.get(&function.id()).copied()
    }

    /// The name a function goes by in a path.
    fn function_name(&self, j: usize) -> String {
        let f = self.m.functions[j].node;
        f.child_by_field_name("name")
            .or_else(|| {
                let p = f.parent()?;
                match p.kind() {
                    "variable_declarator" => p.child_by_field_name("name"),
                    "pair" => p.child_by_field_name("key"),
                    // `exports.find = (id) => …`
                    "assignment_expression" => p
                        .child_by_field_name("left")
                        .map(|l| l.child_by_field_name("property").unwrap_or(l)),
                    _ => None,
                }
            })
            .map_or_else(|| "function".to_string(), |n| self.text(n).to_string())
    }

    /// A call to this file's function `j`: its result, when its summary
    /// says an argument reaches it.
    fn through_local(
        &self,
        call: Node<'t>,
        j: usize,
        state: &State<'t>,
        d: u32,
    ) -> Option<Path<'t>> {
        let summary = self.summary(j);
        let name = self.function_name(j);
        let args = arguments(call);
        summary.to_return.iter().find_map(|(p, inner)| {
            let mut path = self.taint(*args.get(*p)?, state, d)?;
            path.push(Step {
                node: call,
                message: format!("passed to `{name}`"),
            });
            path.extend(inner.iter().cloned());
            path.push(Step {
                node: call,
                message: format!("returned by `{name}`"),
            });
            Some(cap(path))
        })
    }

    /// The other file's function a call calls, through a relative import:
    /// `find(x)` imported from `./users`, `users.find(x)` with `users` its
    /// namespace or `require`, `service.find(x)` with `service` set to
    /// `new UserService()`, and NestJS's `this.users.find(x)`, with `users`
    /// a constructor's parameter of an imported class's type.
    fn callee_of(&self, call: Node<'t>) -> Option<Callee> {
        if call.kind() != "call_expression" {
            return None;
        }
        let relative = |i: &Import| i.module.starts_with("./") || i.module.starts_with("../");
        let name_of = |i: &Import| {
            i.member
                .clone()
                .or_else(|| i.default.then(|| "default".to_string()))
        };
        let callee = unwrap(call.child_by_field_name("function")?);
        if callee.kind() == "identifier" {
            let import = self.import_of(callee).filter(|i| relative(i))?;
            return Some(Callee::Js {
                spec: import.module.clone(),
                name: name_of(import),
                member: None,
            });
        }
        let (receiver, member) = method(call)?;
        let member = Some(self.text(member).to_string());
        let receiver = unwrap(receiver);
        if let Some(import) = self.import_of(receiver).filter(|i| relative(i)) {
            return Some(Callee::Js {
                spec: import.module.clone(),
                name: name_of(import),
                member,
            });
        }
        // An instance: `const s = new UserService()`, or a parameter or a
        // field of an imported class's type.
        let class = match receiver.kind() {
            "identifier" => {
                let decl = &self.m.decls[self.decl(receiver)?];
                decl.declarator
                    .and_then(|d| d.child_by_field_name("value"))
                    .map(unwrap)
                    .filter(|v| v.kind() == "new_expression")
                    .and_then(|v| v.child_by_field_name("constructor"))
                    .or_else(|| self.declared_type(decl.node))
            }
            "member_expression" => {
                let object = receiver.child_by_field_name("object")?;
                if object.kind() != "this" {
                    return None;
                }
                let field = self.text(receiver.child_by_field_name("property")?);
                self.field_type(receiver, field)
            }
            _ => None,
        }?;
        let import = self.import_of(class).filter(|i| relative(i))?;
        Some(Callee::Js {
            spec: import.module.clone(),
            name: name_of(import).or_else(|| Some(self.text(class).to_string())),
            member,
        })
    }

    /// The type a parameter is declared with: `users: UsersService`.
    fn declared_type(&self, name: Node<'t>) -> Option<Node<'t>> {
        let param = name.parent().filter(|p| {
            matches!(
                p.kind(),
                "required_parameter" | "optional_parameter" | "public_field_definition"
            )
        })?;
        type_identifier(param)
    }

    /// The type of `this.field` in the class around `at`: a constructor's
    /// parameter with an accessibility modifier (NestJS's injection), or a
    /// field declared with a type.
    fn field_type(&self, at: Node<'t>, field: &str) -> Option<Node<'t>> {
        let body = std::iter::successors(at.parent(), |p| p.parent())
            .find(|p| p.kind() == "class_body")?;
        let types = self.field_types.borrow().get(&body.id()).cloned();
        let types = types.unwrap_or_else(|| {
            let types = Rc::new(self.class_field_types(body));
            self.field_types
                .borrow_mut()
                .insert(body.id(), types.clone());
            types
        });
        types.get(field).copied()
    }

    /// A class body's typed constructor parameters and fields, by name: the
    /// first of each name, in the order of the members.
    fn class_field_types(&self, body: Node<'t>) -> HashMap<String, Node<'t>> {
        let mut types: HashMap<String, Node<'t>> = HashMap::new();
        for member in children(body) {
            match member.kind() {
                "method_definition"
                    if member
                        .child_by_field_name("name")
                        .is_some_and(|n| self.text(n) == "constructor") =>
                {
                    for p in param_nodes(member) {
                        if pattern_of(p).kind() == "identifier"
                            && let Some(t) = type_identifier(p)
                        {
                            types
                                .entry(self.text(pattern_of(p)).to_string())
                                .or_insert(t);
                        }
                    }
                }
                "public_field_definition" => {
                    if let Some(n) = member.child_by_field_name("name")
                        && let Some(t) = type_identifier(member)
                    {
                        types.entry(self.text(n).to_string()).or_insert(t);
                    }
                }
                _ => {}
            }
        }
        types
    }

    // ------------------------------------------------------------ summaries

    /// What function `j`'s parameters reach, each analyzed alone, computed
    /// once. A call back to a function being summarized finds none.
    fn summary(&self, j: usize) -> Rc<FnSummary<'t>> {
        if let Some(s) = self.summaries.borrow().get(&j) {
            return s.clone();
        }
        if !self.busy.borrow_mut().insert(j) || self.summaries.borrow().len() >= MAX_SUMMARIES {
            return Rc::default();
        }
        let s = Rc::new(self.compute_summary(j));
        self.busy.borrow_mut().remove(&j);
        self.summaries.borrow_mut().insert(j, s.clone());
        s
    }

    fn compute_summary(&self, j: usize) -> FnSummary<'t> {
        let f = &self.m.functions[j];
        let name = self.function_name(j);
        let returns = return_values(f.node, &self.fn_index);
        let mut summary = FnSummary {
            returns_sql: self.kind == SinkKind::Sql
                && returns.iter().any(|r| self.reads_as_sql(*r, 3)),
            ..FnSummary::default()
        };
        for (p, decls) in f.params.iter().enumerate() {
            if decls.is_empty() {
                continue;
            }
            let tainted = decls
                .iter()
                .map(|&d| {
                    let decl = &self.m.decls[d];
                    (
                        d,
                        vec![Step {
                            node: decl.node,
                            message: format!("`{name}`'s parameter `{}`", decl.name),
                        }],
                    )
                })
                .collect();
            let start = State {
                tainted,
                requests: HashSet::new(),
                from_calls: false,
            };
            let Some(state) = self.run_scoped(start, Some(f.node)) else {
                continue;
            };
            if let Some(path) = returns.iter().find_map(|r| self.taint(*r, &state, 0)) {
                summary.to_return.push((p, cap(path)));
            }
            for r in self.reached(Some(f.node), &state) {
                match r {
                    Reach::Sink { path, sink } => summary.to_sink.push((p, cap(path), sink)),
                    Reach::Open {
                        mut path,
                        callee,
                        arg,
                        call,
                    } => {
                        path.push(Step {
                            node: call,
                            message: format!("passed to `{}`", callee.display()),
                        });
                        summary.to_call.push((p, cap(path), callee, arg));
                    }
                    Reach::FromCall { .. } => {}
                }
            }
        }
        summary
    }

    /// The summaries of the functions this file exports, for other files.
    fn exported_summaries(&self, state: &State<'t>) -> Vec<SummaryFact<'t>> {
        let mut out = Vec::new();
        for (key, j) in self.exports() {
            if out.len() >= MAX_SUMMARIES {
                break;
            }
            let summary = self.summary(j);
            // A request's value it reads and returns itself.
            let returns_source = return_values(self.m.functions[j].node, &self.fn_index)
                .into_iter()
                .find_map(|r| self.taint(r, state, 0).filter(|p| !from_call(p)))
                .map(cap);
            if summary.to_sink.is_empty()
                && summary.to_return.is_empty()
                && summary.to_call.is_empty()
                && returns_source.is_none()
            {
                continue;
            }
            out.push(SummaryFact {
                key,
                returns_sql: summary.returns_sql,
                to_sink: summary.to_sink.clone(),
                to_return: summary.to_return.clone(),
                returns_source,
                to_call: summary.to_call.clone(),
            });
        }
        out
    }

    /// The functions other files can call, by the key they call them by:
    /// ES exports (`export function f`, `export const f = () => …`,
    /// `export default`, `export { f as g }`), CommonJS's (`module.exports =
    /// …`, `exports.f = …`), and the methods of exported classes and
    /// objects.
    fn exports(&self) -> Vec<(Key, usize)> {
        let Some(root) = self.m.root else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "export_statement" if n.child_by_field_name("source").is_none() => {
                    let default =
                        children(n).is_empty() || n.child(1).is_some_and(|c| c.kind() == "default");
                    if let Some(d) = n.child_by_field_name("declaration") {
                        match d.kind() {
                            "lexical_declaration" | "variable_declaration" => {
                                for v in children(d)
                                    .into_iter()
                                    .filter(|v| v.kind() == "variable_declarator")
                                {
                                    if let (Some(name), Some(value)) = (
                                        v.child_by_field_name("name"),
                                        v.child_by_field_name("value"),
                                    ) {
                                        self.export_value(&mut out, self.text(name), value);
                                    }
                                }
                            }
                            _ => {
                                let name = if default {
                                    "default"
                                } else {
                                    d.child_by_field_name("name")
                                        .map_or("default", |x| self.text(x))
                                };
                                self.export_value(&mut out, name, d);
                            }
                        }
                    } else if let Some(v) = n.child_by_field_name("value") {
                        self.export_value(&mut out, "default", v);
                    }
                    for clause in children(n)
                        .into_iter()
                        .filter(|c| c.kind() == "export_clause")
                    {
                        for spec in children(clause) {
                            let (Some(local), alias) = (
                                spec.child_by_field_name("name"),
                                spec.child_by_field_name("alias"),
                            ) else {
                                continue;
                            };
                            let exported = self.text(alias.unwrap_or(local));
                            self.export_value(&mut out, exported, local);
                        }
                    }
                }
                "assignment_expression" => {
                    let (Some(left), Some(right)) = (
                        n.child_by_field_name("left"),
                        n.child_by_field_name("right"),
                    ) else {
                        stack.extend(children(n));
                        continue;
                    };
                    let target = self.text(left);
                    if target == "module.exports" {
                        if unwrap(right).kind() == "object" {
                            for (k, v) in self.object_members(unwrap(right)) {
                                self.export_value(&mut out, &k, v);
                            }
                        } else {
                            self.export_value(&mut out, "default", right);
                        }
                    } else if let Some(name) = target
                        .strip_prefix("module.exports.")
                        .or_else(|| target.strip_prefix("exports."))
                        .filter(|n| !n.contains('.'))
                    {
                        self.export_value(&mut out, name, right);
                    }
                }
                _ => {}
            }
            stack.extend(children(n));
        }
        out.sort_by(|a, b| (&a.0.export, &a.0.member, a.1).cmp(&(&b.0.export, &b.0.member, b.1)));
        out.dedup_by(|a, b| a.0 == b.0);
        out
    }

    /// An exported value's functions: a function, a name set to one, a
    /// class's methods, a default-exported object's members.
    fn export_value(&self, out: &mut Vec<(Key, usize)>, name: &str, value: Node<'t>) {
        let value = unwrap(value);
        let key = |member: Option<&str>| Key {
            export: name.to_string(),
            member: member.map(str::to_string),
        };
        if let Some(&j) = self.fn_index.get(&value.id()) {
            out.push((key(None), j));
            return;
        }
        match value.kind() {
            "identifier" => {
                let Some(d) = self.decl(value) else { return };
                let node = self.m.decls[d].node;
                let Some(parent) = node.parent() else { return };
                match parent.kind() {
                    "function_declaration" | "generator_function_declaration" => {
                        if let Some(&j) = self.fn_index.get(&parent.id()) {
                            out.push((key(None), j));
                        }
                    }
                    "variable_declarator" => {
                        if let Some(v) = parent.child_by_field_name("value") {
                            self.export_value(out, name, v);
                        }
                    }
                    "class_declaration" | "abstract_class_declaration" => {
                        self.export_value(out, name, parent);
                    }
                    _ => {}
                }
            }
            "class_declaration" | "abstract_class_declaration" | "class" => {
                let Some(body) = value.child_by_field_name("body") else {
                    return;
                };
                for m in children(body)
                    .into_iter()
                    .filter(|m| m.kind() == "method_definition")
                {
                    if let (Some(n), Some(&j)) =
                        (m.child_by_field_name("name"), self.fn_index.get(&m.id()))
                    {
                        out.push((key(Some(self.text(n))), j));
                    }
                }
            }
            "object" if name == "default" => {
                for (k, v) in self.object_members(value) {
                    if let Some(&j) = self.fn_index.get(&unwrap(v).id()) {
                        out.push((key(Some(&k)), j));
                    }
                }
            }
            _ => {}
        }
    }

    /// An object literal's members and their values: `{ f, g: h, k() {} }`.
    fn object_members(&self, object: Node<'t>) -> Vec<(String, Node<'t>)> {
        children(object)
            .into_iter()
            .filter_map(|p| match p.kind() {
                "pair" => Some((
                    string_value(self.text(p.child_by_field_name("key")?)).to_string(),
                    p.child_by_field_name("value")?,
                )),
                "shorthand_property_identifier" => Some((self.text(p).to_string(), p)),
                "method_definition" => {
                    Some((self.text(p.child_by_field_name("name")?).to_string(), p))
                }
                _ => None,
            })
            .collect()
    }

    /// The sink a call is for this analysis's kind: its name, and the
    /// arguments that take the value.
    fn sink(&self, call: Node<'t>, state: &State<'t>) -> Option<(String, Vec<Node<'t>>)> {
        let callee = unwrap(
            call.child_by_field_name("function")
                .or_else(|| call.child_by_field_name("constructor"))?,
        );
        let args = arguments(call);
        let pick = |spec: Args| -> Vec<Node<'t>> {
            match spec {
                Args::First => args.iter().take(1).copied().collect(),
                Args::FirstTwo => args.iter().take(2).copied().collect(),
                Args::Last => args.last().copied().into_iter().collect(),
                Args::All => args.clone(),
            }
        };
        let from_module = |module: &str, member: &str| {
            MODULE_SINKS
                .iter()
                .find(|(m, names, k, _)| *k == self.kind && *m == module && names.contains(&member))
                .map(|(_, _, _, spec)| (member.to_string(), pick(*spec)))
        };
        // `exec(x)` imported, `eval(x)` a global.
        if callee.kind() == "identifier" {
            let name = self.text(callee);
            if let Some(import) = self.import_of(callee) {
                let member = import.member.as_deref().unwrap_or("default");
                return from_module(&import.module, member).map(|(_, a)| (name.to_string(), a));
            }
            if self.decl(callee).is_none() {
                return GLOBAL_SINKS
                    .iter()
                    .find(|(g, k, _)| *g == name && *k == self.kind)
                    .map(|(_, _, spec)| (name.to_string(), pick(*spec)));
            }
            return None;
        }
        let (receiver, method_name) = method(call)?;
        let name = self.text(method_name);
        // `cp.exec(x)`, `fs.promises.readFile(x)`, `require('fs').readFile(x)`.
        let mut root = unwrap(receiver);
        while root.kind() == "member_expression" {
            root = unwrap(root.child_by_field_name("object")?);
        }
        // A module's function, when it's one of the tables'; else the
        // methods below, on whatever the module returned (`models.db.query`).
        if let Some(import) = self.import_of(root)
            && let Some(found) = from_module(&import.module.clone(), name)
        {
            return Some(found);
        }
        if let Some(module) = require_of(root, self.src)
            && let Some(found) = from_module(normalize_module(&module), name)
        {
            return Some(found);
        }
        let receiver = unwrap(receiver);
        match self.kind {
            SinkKind::Redirect | SinkKind::Path if self.is_response(receiver, state) => {
                if let Some((_, _, spec)) = RESPONSE_SINKS
                    .iter()
                    .find(|(m, k, _)| *m == name && *k == self.kind)
                {
                    // `res.sendFile(name, { root })` stays under `root`.
                    if name == "sendFile" && args.get(1).is_some_and(|o| self.has_key(*o, "root")) {
                        return None;
                    }
                    return Some((name.to_string(), pick(*spec)));
                }
                // `res.setHeader('Location', x)`, `res.writeHead(302, { Location: x })`.
                if self.kind == SinkKind::Redirect {
                    if matches!(name, "setHeader" | "set" | "header" | "append")
                        && args.first().is_some_and(|h| {
                            string_value(self.text(*h)).eq_ignore_ascii_case("location")
                        })
                    {
                        return Some((
                            name.to_string(),
                            args.iter().skip(1).take(1).copied().collect(),
                        ));
                    }
                    if name == "writeHead" {
                        let location = args
                            .iter()
                            .filter(|a| a.kind() == "object")
                            .find_map(|o| self.value_of_key(*o, "location"));
                        return location.map(|v| (name.to_string(), vec![v]));
                    }
                }
                None
            }
            SinkKind::Sql if SQL_RAW.contains(&name) || SQL_QUERY.contains(&name) => {
                Some((name.to_string(), args.iter().take(1).copied().collect()))
            }
            _ => None,
        }
    }

    /// A handler's parameter, a `res`, or Koa's `ctx.response`.
    fn is_response(&self, n: Node, state: &State) -> bool {
        match n.kind() {
            "identifier" => {
                self.decl(n).is_some_and(|d| {
                    self.handler_params.contains(&d) || state.requests.contains(&d)
                }) || RESPONSE_RECEIVERS.contains(&self.text(n))
            }
            "member_expression" => n
                .child_by_field_name("property")
                .is_some_and(|p| matches!(self.text(p), "response" | "res")),
            _ => false,
        }
    }

    fn has_key(&self, object: Node, key: &str) -> bool {
        unwrap(object).kind() == "object"
            && children(unwrap(object))
                .into_iter()
                .any(|p| match p.kind() {
                    "pair" => p
                        .child_by_field_name("key")
                        .is_some_and(|k| string_value(self.text(k)) == key),
                    "shorthand_property_identifier" => self.text(p) == key,
                    _ => false,
                })
    }

    fn value_of_key(&self, object: Node<'t>, key: &str) -> Option<Node<'t>> {
        children(object).into_iter().find_map(|p| {
            (p.kind() == "pair"
                && p.child_by_field_name("key")
                    .is_some_and(|k| string_value(self.text(k)).eq_ignore_ascii_case(key)))
            .then(|| p.child_by_field_name("value"))
            .flatten()
        })
    }

    /// Whether the text a query was built from reads as SQL: its literal
    /// parts, or those of what the variable was set to.
    fn reads_as_sql(&self, n: Node, depth: u8) -> bool {
        let n = unwrap(n);
        let mut text = String::new();
        let mut names = Vec::new();
        let mut stack = vec![n];
        while let Some(c) = stack.pop() {
            match c.kind() {
                "string_fragment" => text.push_str(self.text(c)),
                "identifier" => names.push(c),
                _ => stack.extend(children(c)),
            }
        }
        if looks_like_sql(&text) {
            return true;
        }
        depth > 0
            && names.iter().filter_map(|i| self.decl(*i)).any(|d| {
                self.writes_by_decl.get(&d).is_some_and(|ws| {
                    ws.iter()
                        .any(|&w| self.reads_as_sql(self.writes[w].value, depth - 1))
                })
            })
    }

    /// Whether the handler checked a value before `call`: the argument,
    /// the names and members in it, or a variable the value went through.
    fn is_checked(&self, checked: &HashSet<String>, call: Node, arg: Node, path: &Path) -> bool {
        let mut mentioned = vec![unwrap(arg)];
        let mut stack = children(unwrap(arg));
        while let Some(c) = stack.pop() {
            if matches!(c.kind(), "identifier" | "member_expression") {
                mentioned.push(c);
            }
            stack.extend(children(c));
        }
        mentioned.extend(path.iter().map(|s| s.node));
        let equal = self.equal_to_literal(call);
        mentioned
            .iter()
            .any(|m| checked.contains(self.text(*m)) || equal.contains(self.text(*m)))
    }

    /// An upload: `req.file`, `req.files`, an element or member of them.
    fn is_upload(&self, n: Node, state: &State) -> bool {
        let mut n = unwrap(n);
        loop {
            match n.kind() {
                "member_expression" | "subscript_expression" => {
                    let Some(object) = n.child_by_field_name("object").map(unwrap) else {
                        return false;
                    };
                    let property = n.child_by_field_name("property").map(|p| self.text(p));
                    if matches!(property, Some("file" | "files")) && self.is_request(object, state)
                    {
                        return true;
                    }
                    n = object;
                }
                _ => return false,
            }
        }
    }

    /// `checked_values` of a handler, computed once.
    fn checks_of(&self, scope: Option<Node>) -> Rc<HashSet<String>> {
        let key = scope.map_or(0, |s| s.id());
        self.checks
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| Rc::new(scope.map(|s| self.checked_values(s)).unwrap_or_default()))
            .clone()
    }

    /// What a function checks before using it for this analysis's sink,
    /// by its text (`url`, `req.query.next`):
    /// - redirects and requests: a function named like a URL check
    ///   (`isLocalUrl(x)`, `isAllowedHost(x)`, `validateRedirect(x)`), and
    ///   `x.startsWith('/')`;
    /// - paths: one named like a path check (`isPathInside(x, root)`), and
    ///   `x.startsWith(root)`, `x.includes('..')`;
    /// - every sink: an allowlist, `['asc', 'desc'].includes(x)` or
    ///   `allowedHosts.has(x)`, and a whole-value pattern, `/^[a-z-]+$/.test(x)`.
    ///
    /// A check anywhere in the handler counts, not only one guarding the
    /// sink: precision before recall.
    fn checked_values(&self, function: Node) -> HashSet<String> {
        let words: &[&str] = match self.kind {
            SinkKind::Redirect | SinkKind::Ssrf => &[
                "url",
                "redirect",
                "local",
                "safe",
                "allowed",
                "valid",
                "trusted",
                "whitelist",
                "allowlist",
                "domain",
                "host",
                "origin",
            ],
            SinkKind::Path => &[
                "path", "within", "inside", "safe", "allowed", "valid", "sub",
            ],
            _ => &[],
        };
        let mut out = HashSet::new();
        let add = |n: Node, out: &mut HashSet<String>| {
            let mut stack = vec![n];
            while let Some(c) = stack.pop() {
                if matches!(
                    c.kind(),
                    "identifier" | "member_expression" | "call_expression"
                ) {
                    out.insert(self.text(c).to_string());
                }
                stack.extend(children(c));
            }
        };
        // An allowlist or a pattern checks the value it's given, as a whole:
        // `ok.includes(name.split('.').pop())` checks the extension, not
        // `name`. `new URL(u).hostname` is `u`'s host.
        let exact = |a: Node, out: &mut HashSet<String>| {
            let a = unwrap(a);
            out.insert(self.text(a).to_string());
            if a.kind() == "member_expression"
                && a.child_by_field_name("property")
                    .is_some_and(|p| matches!(self.text(p), "host" | "hostname" | "origin"))
                && let Some(object) = a.child_by_field_name("object").map(unwrap)
            {
                let url = if object.kind() == "new_expression" {
                    arguments(object).into_iter().next()
                } else {
                    Some(object)
                };
                out.extend(url.map(|u| self.text(unwrap(u)).to_string()));
            }
        };
        let mut stack = vec![function];
        while let Some(n) = stack.pop() {
            if n.kind() == "call_expression"
                && let Some(callee) = n.child_by_field_name("function").map(unwrap)
            {
                let (receiver, name) = match method(n) {
                    Some((r, m)) => (Some(unwrap(r)), self.text(m)),
                    None => (None, self.text(callee)),
                };
                let lower = name.to_ascii_lowercase();
                // `resolveLoginRedirect(x)` returns an allowed URL or throws;
                // `resolvePath` only joins.
                let resolves = self.kind == SinkKind::Redirect && lower.starts_with("resolve");
                let named_check = ([
                    "is", "validate", "assert", "check", "ensure", "verify", "sanitize",
                ]
                .iter()
                .any(|p| lower.starts_with(p))
                    || resolves)
                    && words.iter().any(|w| lower.contains(w));
                if named_check {
                    for a in arguments(n) {
                        add(a, &mut out);
                    }
                }
                if let Some(r) = receiver {
                    let receiver_name = self.text(r).to_ascii_lowercase();
                    let first = arguments(n).into_iter().next();
                    match name {
                        "startsWith" if !words.is_empty() => add(r, &mut out),
                        "includes" | "indexOf"
                            if self.kind == SinkKind::Path
                                && first.is_some_and(|a| {
                                    matches!(string_value(self.text(a)), ".." | "/" | "\\\\")
                                }) =>
                        {
                            add(r, &mut out);
                        }
                        _ => {}
                    }
                    match name {
                        // `['asc', 'desc'].includes(x)`, `allowedHosts.has(x)`.
                        "includes" | "has" | "indexOf" | "some"
                            if r.kind() == "array"
                                || ["allow", "white", "trusted", "permitted", "safe", "valid"]
                                    .iter()
                                    .any(|w| receiver_name.contains(w)) =>
                        {
                            for a in arguments(n) {
                                exact(a, &mut out);
                            }
                        }
                        // `/^[\w-]+$/.test(x)`, or a name set to such a pattern.
                        "test" if self.whole_value_pattern(r) => {
                            for a in arguments(n) {
                                exact(a, &mut out);
                            }
                        }
                        _ => {}
                    }
                }
            }
            stack.extend(children(n));
        }
        out
    }

    /// Values a sink's branch knows the text of: in
    /// `if (host === 'example.com') { … }` and `host === 'a' ? … : …`,
    /// `host` is that text in the branch taken when it's equal.
    fn equal_to_literal(&self, sink: Node) -> HashSet<String> {
        let mut out = HashSet::new();
        let mut child = sink;
        while let Some(p) = child.parent() {
            let (condition, branch) = match p.kind() {
                "if_statement" => (
                    p.child_by_field_name("condition"),
                    p.child_by_field_name("consequence"),
                ),
                "ternary_expression" => (
                    p.child_by_field_name("condition"),
                    p.child_by_field_name("consequence"),
                ),
                _ => (None, None),
            };
            if let (Some(c), Some(b)) = (condition, branch)
                && b.id() == child.id()
            {
                let mut terms = vec![unwrap(c)];
                while let Some(t) = terms.pop() {
                    let op = t.child_by_field_name("operator").map(|o| self.text(o));
                    match (t.kind(), op) {
                        ("binary_expression", Some("&&")) => {
                            terms.extend(t.child_by_field_name("left").map(unwrap));
                            terms.extend(t.child_by_field_name("right").map(unwrap));
                        }
                        ("binary_expression", Some("===" | "==")) => {
                            let (Some(l), Some(r)) = (
                                t.child_by_field_name("left").map(unwrap),
                                t.child_by_field_name("right").map(unwrap),
                            ) else {
                                continue;
                            };
                            if r.kind() == "string" {
                                out.insert(self.text(l).to_string());
                            } else if l.kind() == "string" {
                                out.insert(self.text(r).to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            child = p;
        }
        out
    }

    /// A regular expression that matches a whole value, `^…$`, or a name
    /// set to one.
    /// A name whose pattern this file can't see, imported or a parameter,
    /// counts by its name: `themeNamePattern`, `SLUG_RE`.
    fn whole_value_pattern(&self, n: Node) -> bool {
        let n = match n.kind() {
            "identifier" => match self
                .decl(n)
                .and_then(|d| self.m.decls[d].declarator)
                .and_then(|d| d.child_by_field_name("value"))
            {
                Some(v) if unwrap(v).kind() != "call_expression" => unwrap(v),
                _ => {
                    let name = self.text(n);
                    return ["Pattern", "Regex", "RegExp", "_RE", "Re"]
                        .iter()
                        .any(|w| name.ends_with(w))
                        || name.ends_with("_PATTERN")
                        || name.ends_with("_REGEX");
                }
            },
            _ => n,
        };
        n.kind() == "regex"
            && n.child_by_field_name("pattern").is_some_and(|p| {
                let t = self.text(p);
                t.starts_with('^') && t.ends_with('$') && !t.ends_with("\\$")
            })
    }
}

/// A variable whose path no later write replaces: a request's value. One
/// from another file's function's result gives way to a request's.
fn settled(state: &State, decl: DeclId) -> bool {
    state.tainted.get(&decl).is_some_and(|p| !from_call(p))
}

/// Whether `path` replaces what `decl` holds.
fn replaces(state: &State, decl: DeclId, path: &Path) -> bool {
    match state.tainted.get(&decl) {
        None => true,
        Some(old) => from_call(old) && !from_call(path),
    }
}

/// Whether `n` is inside `outer`.
fn within(n: Node, outer: Node) -> bool {
    outer.start_byte() <= n.start_byte() && n.end_byte() <= outer.end_byte()
}

/// A function's return values: its `return`s, not those of functions in
/// it, and an arrow's expression body.
fn return_values<'t>(f: Node<'t>, functions: &HashMap<usize, usize>) -> Vec<Node<'t>> {
    let Some(body) = f.child_by_field_name("body") else {
        return Vec::new();
    };
    if body.kind() != "statement_block" {
        return vec![body];
    }
    let mut out = Vec::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if functions.contains_key(&n.id()) {
            continue;
        }
        if n.kind() == "return_statement" {
            out.extend(n.named_child(0));
            continue;
        }
        stack.extend(children(n));
    }
    out
}

/// The type a parameter or field is declared with, when it's a name:
/// `users: UsersService`.
fn type_identifier(n: Node) -> Option<Node> {
    let t = n.child_by_field_name("type")?;
    children(t)
        .into_iter()
        .find(|c| c.kind() == "type_identifier")
        .or_else(|| (t.kind() == "type_identifier").then_some(t))
}

// ---------------------------------------------------------------- syntax

fn children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c)
        .filter(|c| c.kind() != "comment")
        .collect()
}

/// An expression without the parentheses, `await`, `!` and type
/// assertions around it.
fn unwrap(mut n: Node) -> Node {
    loop {
        match n.kind() {
            "parenthesized_expression"
            | "await_expression"
            | "non_null_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion" => match n
                .named_children(&mut n.walk())
                .find(|c| !c.kind().contains("type"))
            {
                Some(inner) => n = inner,
                None => return n,
            },
            _ => return n,
        }
    }
}

fn arguments(call: Node) -> Vec<Node> {
    call.child_by_field_name("arguments")
        .filter(|a| a.kind() == "arguments")
        .map(children)
        .unwrap_or_default()
}

/// A method call's receiver and name: `res.redirect(x)`, `a?.b(x)`.
fn method(call: Node) -> Option<(Node, Node)> {
    if !matches!(call.kind(), "call_expression" | "new_expression") {
        return None;
    }
    let f = unwrap(
        call.child_by_field_name("function")
            .or_else(|| call.child_by_field_name("constructor"))?,
    );
    if f.kind() != "member_expression" {
        return None;
    }
    Some((
        f.child_by_field_name("object")?,
        f.child_by_field_name("property")?,
    ))
}

/// `require('m')`'s module, and `await import('m')`'s.
fn require_of(n: Node, src: &[u8]) -> Option<String> {
    if n.kind() != "call_expression" {
        return None;
    }
    let f = n.child_by_field_name("function")?;
    let name = &src[f.byte_range()];
    if name != b"require" && f.kind() != "import" {
        return None;
    }
    let first = arguments(n).into_iter().next()?;
    (first.kind() == "string").then(|| {
        string_value(std::str::from_utf8(&src[first.byte_range()]).unwrap_or("")).to_string()
    })
}

/// A string literal's text without its quotes.
fn string_value(t: &str) -> &str {
    t.trim_matches(|c| c == '"' || c == '\'' || c == '`')
}

/// A parameter's name or pattern, without its type or default.
fn pattern_of(p: Node) -> Node {
    match p.kind() {
        "required_parameter" | "optional_parameter" => {
            p.child_by_field_name("pattern").unwrap_or(p)
        }
        "assignment_pattern" => p.child_by_field_name("left").unwrap_or(p),
        _ => p,
    }
}

/// A function's parameters, in order.
fn param_nodes(f: Node) -> Vec<Node> {
    if let Some(single) = f.child_by_field_name("parameter") {
        return vec![single];
    }
    f.child_by_field_name("parameters")
        .map(children)
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.kind() != "decorator")
        .collect()
}

/// A parameter's decorators' names: `@Query('id')` is `Query`.
fn decorators(p: Node) -> Vec<Node> {
    children(p)
        .into_iter()
        .filter(|c| c.kind() == "decorator")
        .filter_map(|d| d.named_child(0))
        .map(|e| {
            let e = if e.kind() == "call_expression" {
                e.child_by_field_name("function").unwrap_or(e)
            } else {
                e
            };
            if e.kind() == "member_expression" {
                e.child_by_field_name("property").unwrap_or(e)
            } else {
                e
            }
        })
        .collect()
}

/// The last name of a type: `express.Request<P>` is `Request`.
fn type_name(t: &str) -> &str {
    let t = t.trim_start_matches(':').trim();
    let t = t.split('<').next().unwrap_or(t);
    t.rsplit('.').next().unwrap_or(t).trim()
}

/// The names a pattern declares.
fn pattern_names(p: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut stack = vec![p];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" | "shorthand_property_identifier_pattern" => out.push(n),
            "pair_pattern" => stack.extend(n.child_by_field_name("value")),
            "object_assignment_pattern" | "assignment_pattern" => {
                stack.extend(n.child_by_field_name("left"))
            }
            _ => stack.extend(children(n)),
        }
    }
    out
}

/// The property of the destructured value a pattern's name comes from:
/// `{ id }` and `{ id: x = 1 }` read `id`, and `{ body: { name } }` reads
/// `body`, the outermost.
fn pattern_key(name: Node, src: &[u8]) -> Option<String> {
    let text =
        |n: Node| string_value(std::str::from_utf8(&src[n.byte_range()]).unwrap_or("")).to_string();
    let mut key = (name.kind() == "shorthand_property_identifier_pattern").then(|| text(name));
    let mut n = name;
    while let Some(parent) = n.parent() {
        match parent.kind() {
            "pair_pattern" => {
                if parent
                    .child_by_field_name("value")
                    .is_some_and(|v| v.id() == n.id())
                {
                    key = parent.child_by_field_name("key").map(text);
                }
            }
            "object_pattern" | "object_assignment_pattern" | "assignment_pattern" => {}
            "array_pattern" | "rest_pattern" => key = None,
            _ => break,
        }
        n = parent;
    }
    key
}

/// A concatenation's or template's parts, in order: its literal text and
/// the values put in it.
fn url_parts(n: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut stack = vec![unwrap(n)];
    while let Some(p) = stack.pop() {
        match p.kind() {
            "binary_expression" => {
                stack.extend(p.child_by_field_name("right").map(unwrap));
                stack.extend(p.child_by_field_name("left").map(unwrap));
            }
            "template_string" => {
                for c in children(p).into_iter().rev() {
                    match c.kind() {
                        "template_substitution" => stack.extend(c.named_child(0)),
                        "string_fragment" => stack.push(c),
                        _ => {}
                    }
                }
            }
            _ => out.push(p),
        }
    }
    out
}

/// Whether text of the program's own, before a request's value, already
/// ends the host: a path separator after it (`/groups/`, but not the
/// `//` that starts one), or a query or fragment.
fn separates_host(t: &str) -> bool {
    let b = t.as_bytes();
    t.contains(['?', '#'])
        || (0..b.len()).any(|i| {
            b[i] == b'/'
                && (i == 0 || b[i - 1] != b'/')
                && b.get(i + 1).is_some_and(|&c| c != b'/' && c != b'\\')
        })
}

/// A source read further, `req.params` then `req.params.theme`: the
/// source's step marks the whole read, which is what a check names.
fn deepen<'t>(mut path: Path<'t>, object: Node<'t>, n: Node<'t>) -> Path<'t> {
    if path.len() == 1 && path[0].node.id() == unwrap(object).id() {
        path[0].node = n;
    }
    path
}

/// A concatenation or a template with a value in it.
fn is_built(n: Node) -> bool {
    match n.kind() {
        "binary_expression" => true,
        "template_string" => children(n)
            .iter()
            .any(|c| c.kind() == "template_substitution"),
        _ => false,
    }
}

/// The outermost function around a node: the handler, for a callback in it.
fn outermost_function<'t>(n: Node<'t>, m: &Model<'t>) -> Option<Node<'t>> {
    let mut found = None;
    let mut cur = n.parent();
    while let Some(p) = cur {
        if m.functions.iter().any(|f| f.node.id() == p.id()) {
            found = Some(p);
        }
        cur = p.parent();
    }
    found
}

/// Whether text reads as SQL: a statement's keywords.
fn looks_like_sql(t: &str) -> bool {
    let t = t.to_ascii_lowercase();
    let has = |w: &str| t.contains(w);
    (has("select ") && has(" from"))
        || has("insert into")
        || has("delete from")
        || (has("update ") && has(" set "))
        || has(" where ")
        || has("order by ")
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::model::Issue;
    use crate::rules::RuleSet;

    fn issues_of(rule: &str, lang: Lang, src: &str) -> Vec<Issue> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let name = if lang == Lang::JavaScript {
            "t.js"
        } else {
            "t.ts"
        };
        let file = analyze(name, lang, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues.into_iter().filter(|i| i.rule == rule).collect()
    }

    fn js(rule: &str, src: &str) -> Vec<Issue> {
        issues_of(rule, Lang::JavaScript, src)
    }

    fn ts(rule: &str, src: &str) -> Vec<Issue> {
        issues_of(rule, Lang::TypeScript, src)
    }

    fn flow(i: &Issue) -> Vec<&str> {
        i.flow.iter().map(|s| s.message.as_str()).collect()
    }

    /// An Express route around `body`, with `db` and the modules it needs.
    fn route(head: &str, body: &str) -> String {
        format!("{head}\napp.get('/x', async (req, res) => {{\n{body}\n}});\n")
    }

    const SQL: &str = "js/sql-injection";
    const CMD: &str = "js/command-injection";
    const PATH: &str = "js/path-injection";
    const REDIRECT: &str = "js/open-redirect";
    const SSRF: &str = "js/ssrf";
    const CODE: &str = "js/code-injection";

    #[test]
    fn a_query_value_concatenated_into_sql_is_reported_with_its_path() {
        let src = route(
            "",
            "const q = \"SELECT * FROM o WHERE id = '\" + req.query.id + \"'\";\ndb.query(q);",
        );
        let found = js(SQL, &src);
        assert_eq!(found.len(), 1);
        assert_eq!(
            flow(&found[0]),
            [
                "the request's `query`",
                "concatenated into `q`",
                "passed to `query`"
            ]
        );
        assert_eq!(
            found[0].flow.iter().map(|s| s.line).collect::<Vec<_>>(),
            [3, 3, 4]
        );
        assert_eq!(found[0].line, 4, "the sink");
    }

    #[test]
    fn sql_through_templates_destructuring_and_arrays() {
        for body in [
            "db.query(`SELECT * FROM o WHERE id = ${req.params.id}`);",
            "const { id } = req.query; db.query('SELECT * FROM o WHERE id = ' + id);",
            "const { body: { name } } = req; db.execute(`DELETE FROM u WHERE name = '${name}'`);",
            "let q = 'SELECT * FROM o WHERE '; q += 'id = ' + req.body.id; pool.query(q);",
            "const w = []; w.push(`id = ${req.query.id}`); db.all('SELECT * FROM o WHERE ' + w.join(' AND '));",
            "const id = req.get('x-id').trim(); knex.raw('select ' + id);",
            "prisma.$queryRawUnsafe(req.body.sql);",
            "db.query(\"UPDATE u SET name = '\" + (req.body.name || 'x') + \"'\");",
            // A closure sees its handler's variables.
            "const id = req.query.id; db.connect(() => db.query('SELECT * FROM o WHERE id = ' + id));",
        ] {
            assert_eq!(js(SQL, &route("", body)).len(), 1, "{body}");
        }
    }

    #[test]
    fn parameterized_numeric_and_constant_sql_is_not() {
        for body in [
            "db.query('SELECT * FROM o WHERE id = ?', [req.query.id]);",
            "db.query('SELECT * FROM o WHERE id = $1', [req.params.id]);",
            "db.query(sql`SELECT * FROM o WHERE id = ${req.query.id}`);",
            "prisma.$queryRaw`SELECT * FROM o WHERE id = ${req.query.id}`;",
            "const n = parseInt(req.query.id, 10); db.query('SELECT * FROM o WHERE id = ' + n);",
            "db.query('SELECT * FROM o LIMIT ' + Number(req.query.limit));",
            "db.query('SELECT * FROM o WHERE n = ' + req.query.id.length);",
            "db.query('SELECT * FROM o WHERE id = ' + mysql.escape(req.query.id));",
            "const t = 'orders'; db.query('SELECT * FROM ' + t);",
            // Not SQL: other libraries' `get`, `exec` and `query`.
            "cache.get(req.query.key);",
            "/a(b)/.exec(req.query.s);",
            "const r = router.query(req.query.page);",
        ] {
            assert!(js(SQL, &route("", body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn the_request_is_only_a_handlers() {
        // No request: an ordinary function's parameter.
        assert!(
            js(
                SQL,
                "function f(id) { db.query('SELECT * FROM o WHERE id = ' + id); }"
            )
            .is_empty()
        );
        assert!(
            js(
                SQL,
                "function f(q) { db.query('SELECT * FROM o WHERE id = ' + q.query.id); }"
            )
            .is_empty()
        );
        // A cache's callback isn't a route.
        assert!(
            js(
                SQL,
                "cache.get('key', (req, x) => db.query('SELECT * FROM o WHERE id = ' + x.query));"
            )
            .is_empty()
        );
        // The request's other members aren't its sender's.
        assert!(
            js(
                SQL,
                &route("", "db.query('SELECT * FROM o WHERE u = ' + req.user.id);")
            )
            .is_empty()
        );
    }

    #[test]
    fn handlers_express_koa_fastify_next_and_nest() {
        let sink = "db.query('SELECT * FROM o WHERE id = ' + ";
        let cases = [
            // An Express controller, defined apart from its route.
            format!("export async function show(req, res) {{ {sink}req.params.id); }}"),
            format!("module.exports.show = (req, res, next) => {{ {sink}req.params.id); }};"),
            format!("router.route('/o').get((req, res) => {{ {sink}req.query.id); }});"),
            format!("app.use((req, res, next) => {{ {sink}req.headers['x-id']); }});"),
            format!("app.get('/o/:id', ({{ params }}, res) => {{ {sink}params.id); }});"),
            // Koa.
            format!("router.get('/o', async (ctx) => {{ {sink}ctx.query.id); }});"),
            format!(
                "router.post('/o', async (ctx) => {{ const {{ name }} = ctx.request.body; {sink}name); }});"
            ),
            // Fastify, and Node's server.
            format!("fastify.get('/o', async (request, reply) => {{ {sink}request.query.id); }});"),
            format!("http.createServer((req, res) => {{ {sink}req.url); }});"),
        ];
        for src in &cases {
            assert_eq!(js(SQL, src).len(), 1, "{src}");
        }
        let next = format!(
            "export async function GET(request: NextRequest, {{ params }}) {{\n\
             {sink}request.nextUrl.searchParams.get('id'));\n{sink}params.slug);\n}}"
        );
        assert_eq!(ts(SQL, &next).len(), 2);
        let body = format!(
            "export async function POST(request: Request) {{ const b = await request.json(); {sink}b.id); }}"
        );
        assert_eq!(ts(SQL, &body).len(), 1);
        let nest = format!(
            "@Controller('o') export class O {{\n\
             @Get(':id') find(@Param('id') id: string, @Query() q: Dto) {{ return this.db.query('SELECT * FROM o WHERE id = ' + id); }}\n\
             @Get() all(@Req() r: Request) {{ return this.db.query('SELECT * FROM o WHERE x = ' + r.query.x); }}\n\
             helper(id: string) {{ {sink}id); }}\n}}"
        );
        let found = ts(SQL, &nest);
        assert_eq!(found.len(), 2, "{nest}");
        assert_eq!(flow(&found[0])[0], "request parameter `id`");
    }

    #[test]
    fn commands_resolve_through_imports() {
        for head in [
            "const { exec } = require('child_process');",
            "import { exec } from 'node:child_process';",
            "import { exec as run } from 'child_process'; const exec = run;",
        ] {
            let src = route(head, "exec('ping ' + req.query.host);");
            assert_eq!(js(CMD, &src).len(), 1, "{head}");
        }
        for (head, body) in [
            (
                "const cp = require('child_process');",
                "cp.execSync(`ls ${req.query.dir}`);",
            ),
            (
                "import * as cp from 'child_process';",
                "cp.spawn(req.body.cmd);",
            ),
            ("", "require('child_process').exec(req.query.c);"),
            (
                "import { execa } from 'execa';",
                "await execa(req.query.c);",
            ),
        ] {
            assert_eq!(js(CMD, &route(head, body)).len(), 1, "{body}");
        }
        for (head, body) in [
            // A program of its own, with the value as an argument.
            (
                "const cp = require('child_process');",
                "cp.execFile('ping', ['-c', '1', req.query.host]);",
            ),
            // Some other `exec`.
            ("", "exec('ping ' + req.query.host);"),
            ("function exec(s) {}", "exec('ping ' + req.query.host);"),
            ("const cp = require('child_process');", "cp.exec('ls');"),
        ] {
            assert!(js(CMD, &route(head, body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn paths_and_their_checks() {
        let head = "const fs = require('fs'); const path = require('path');";
        for body in [
            "fs.readFile('/srv/' + req.query.name, () => {});",
            "fs.promises.unlink(path.join('/srv', req.params.name));",
            "res.sendFile(path.resolve(req.query.f));",
            "res.download(req.query.f);",
            "const p = path.join(__dirname, req.file.originalname); fs.writeFileSync(p, 'x');",
        ] {
            assert_eq!(js(PATH, &route(head, body)).len(), 1, "{body}");
        }
        assert_eq!(
            js(
                PATH,
                &route(
                    "import { readFile } from 'fs/promises';",
                    "await readFile(req.query.f);"
                )
            )
            .len(),
            1
        );
        for body in [
            "fs.readFile('/srv/' + path.basename(req.query.name), () => {});",
            "res.sendFile(req.params.name, { root: '/srv/public' });",
            "const p = path.resolve('/srv', req.query.f); if (!p.startsWith('/srv/')) return; fs.readFile(p, () => {});",
            "const f = req.query.f; if (f.includes('..')) return; fs.readFile('/srv/' + f, () => {});",
            "const f = req.query.f; if (!isSafePath(f)) return; fs.readFile(f, () => {});",
            "fs.readFile('/srv/static.txt', () => {});",
        ] {
            assert!(js(PATH, &route(head, body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn redirects_their_fixed_prefixes_and_checks() {
        for body in [
            "res.redirect(req.query.next);",
            "res.redirect(302, req.query.next);",
            "const u = req.query.next || '/'; return res.redirect(u);",
            "res.setHeader('Location', req.query.next); res.end();",
            "res.writeHead(302, { Location: req.query.next }); res.end();",
            "res.redirect('//' + req.query.host + '/x');",
        ] {
            assert_eq!(js(REDIRECT, &route("", body)).len(), 1, "{body}");
        }
        assert_eq!(
            js(
                REDIRECT,
                "router.get('/a', async (ctx) => { ctx.redirect(ctx.query.next); });"
            )
            .len(),
            1
        );
        let next = "import { redirect } from 'next/navigation';\n\
                    export async function GET(request) { redirect(request.nextUrl.searchParams.get('to')); }";
        assert_eq!(js(REDIRECT, next).len(), 1);
        for body in [
            "res.redirect('/orders/' + req.query.id);",
            "res.redirect(`/orders/${req.query.id}`);",
            "res.redirect('https://example.com/' + req.query.p);",
            "const base = '/app/'; res.redirect(base + req.query.p);",
            "const n = req.query.next; if (!isLocalUrl(n)) return; res.redirect(n);",
            "const n = req.query.next; if (n.startsWith('/') && !n.startsWith('//')) res.redirect(n);",
            "if (allowedUrls.includes(req.query.next)) res.redirect(req.query.next);",
        ] {
            assert!(js(REDIRECT, &route("", body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn server_side_requests() {
        for (head, body) in [
            ("", "await fetch(req.query.url);"),
            (
                "const axios = require('axios');",
                "await axios.get(req.body.url);",
            ),
            ("import axios from 'axios';", "await axios(req.body.url);"),
            (
                "import got from 'got';",
                "await got(`http://${req.query.host}/x`);",
            ),
            (
                "const https = require('https');",
                "https.get(req.query.u, () => {});",
            ),
            ("", "await fetch(new URL(req.query.u));"),
        ] {
            assert_eq!(js(SSRF, &route(head, body)).len(), 1, "{body}");
        }
        for (head, body) in [
            (
                "",
                "await fetch('https://api.example.com/users/' + req.query.id);",
            ),
            (
                "",
                "await fetch(`https://api.example.com/u?q=${encodeURIComponent(req.query.q)}`);",
            ),
            // An instance's base URL fixes the host.
            (
                "import axios from 'axios'; const api = axios.create({ baseURL: 'https://a.example' });",
                "await api.get('/users/' + req.query.id);",
            ),
            (
                "",
                "const u = req.query.url; if (!isAllowedUrl(u)) return; await fetch(u);",
            ),
            // A `fetch` of the program's own.
            ("function fetch(u) {}", "fetch(req.query.url);"),
        ] {
            assert!(js(SSRF, &route(head, body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn code_injection() {
        for (head, body) in [
            ("", "eval(req.body.expr);"),
            ("", "const f = new Function('a', req.body.code);"),
            (
                "const vm = require('vm');",
                "vm.runInNewContext(req.body.code, {});",
            ),
            ("", "setTimeout('run(' + req.query.x + ')', 10);"),
        ] {
            assert_eq!(js(CODE, &route(head, body)).len(), 1, "{body}");
        }
        for body in [
            "eval('1 + 1');",
            "setTimeout(() => run(req.query.x), 10);",
            "JSON.parse(req.body.expr);",
        ] {
            assert!(js(CODE, &route("", body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn a_value_reaching_several_arguments_of_one_sink_is_one_issue() {
        let src = route(
            "const fs = require('fs');",
            "fs.copyFileSync(req.query.a, req.query.b);",
        );
        assert_eq!(js(PATH, &src).len(), 1);
    }

    #[test]
    fn typescript_types_and_assertions_pass_the_value_through() {
        let src = "import { Request, Response } from 'express';\n\
                   export const show = async (req: Request, res: Response) => {\n\
                   const id = req.params.id as string;\n\
                   await db.query(`SELECT * FROM o WHERE id = ${id!}`);\n};";
        assert_eq!(ts(SQL, src).len(), 1);
    }

    #[test]
    fn test_files_are_not_analyzed() {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let src = route("", "eval(req.body.expr);");
        let file = analyze(
            "x.test.js",
            Lang::JavaScript,
            &src,
            &rules,
            &cfg,
            far_deadline(),
        )
        .unwrap();
        assert!(!file.issues.iter().any(|i| i.rule == CODE));
    }

    #[test]
    fn a_module_without_a_table_still_has_sql_methods() {
        let src = route(
            "import * as models from '../models';",
            "models.sequelize.query(`SELECT * FROM u WHERE email = '${req.body.email}'`);",
        );
        assert_eq!(js(SQL, &src).len(), 1);
    }

    #[test]
    fn origins_fixed_after_a_value_of_the_programs_own() {
        for body in [
            // A path after the program's base.
            "res.redirect(`${base}/admin/groups/${req.params.slug}`);",
            "res.redirect(base + '/assets' + req.path);",
            // Relative to this page.
            "res.redirect(303, `./callback?${new URLSearchParams(req.body)}`);",
            "res.redirect('original?' + req.url.split('?')[1]);",
            // A URL's parts after its host.
            "const to = new URL(target); to.pathname = req.path; res.redirect(to.toString());",
            // Rewritten to start with a path of this site.
            "res.redirect(req.path.replace(/^\\/share/, '/s'));",
            "res.redirect(req.originalUrl.replace(/^\\/+/, '/'));",
        ] {
            assert!(js(REDIRECT, &route("", body)).is_empty(), "{body}");
        }
        for body in [
            // The program's text doesn't end the host.
            "res.redirect(base + req.query.to);",
            "res.redirect(base + '/' + req.query.to);",
            "res.redirect('http://a' + req.query.to);",
            "res.redirect(req.path.replace(/x/, '/s'));",
        ] {
            assert_eq!(js(REDIRECT, &route("", body)).len(), 1, "{body}");
        }
    }

    #[test]
    fn allowlists_and_whole_value_patterns_check_any_sink() {
        let head = "const fs = require('fs');";
        for (rule, body) in [
            (
                SQL,
                "const o = req.query.order; if (!['asc', 'desc'].includes(o)) return; db.query('SELECT * FROM t ORDER BY id ' + o);",
            ),
            (
                PATH,
                "if (!/^[a-z-]+$/.test(req.params.theme)) throw new Error(); fs.readFile('/t/' + req.params.theme, () => {});",
            ),
            (
                PATH,
                "const re = /^[a-z-]+$/; const t = req.params.theme; if (!re.test(t)) return; fs.readFile('/t/' + t, () => {});",
            ),
            (
                PATH,
                "const f = req.query.f; if (f.includes('/')) return; fs.readFile('/srv/' + f, () => {});",
            ),
            (
                PATH,
                "const u = req.body.u; const ext = ['png', 'jpg'].includes(u.split('.').pop()) ? u.split('.').pop() : 'png'; fs.createWriteStream(`/up/${id}.${ext}`);",
            ),
        ] {
            assert!(js(rule, &route(head, body)).is_empty(), "{body}");
        }
        // The allowlist checked the extension, not the URL.
        let url = "const u = req.body.u; const ext = ['png'].includes(u.split('.').pop()) ? 'png' : 'jpg'; await fetch(u);";
        assert_eq!(js(SSRF, &route(head, url)).len(), 1);
        let host = "const u = req.body.u; if (!allowedHosts.has(new URL(u).hostname)) return; await fetch(u);";
        assert!(js(SSRF, &route(head, host)).is_empty());
        // A pattern that matches part of the value doesn't check it.
        let partial =
            "if (/[a-z]/.test(req.params.t)) fs.readFile('/t/' + req.params.t, () => {});";
        assert_eq!(js(PATH, &route(head, partial)).len(), 1);
    }

    #[test]
    fn checks_the_file_cant_see_count_by_their_names() {
        let head = "const fs = require('fs'); const { themeNamePattern } = require('./constants');";
        let body = "if (!themeNamePattern.test(req.params.theme)) throw new Error(); fs.readFile('/t/' + req.params.theme, () => {});";
        assert!(js(PATH, &route(head, body)).is_empty());
        // A redirect resolved to an allowed one, or an error.
        let body =
            "let r = req.body.RelayState; if (r) r = resolveLoginRedirect(r); res.redirect(r);";
        assert!(js(REDIRECT, &route("", body)).is_empty());
        // Resolving a path doesn't check it.
        let body = "fs.readFile(path.resolve('/srv', req.query.f), () => {});";
        let head = "const fs = require('fs'); const path = require('path');";
        assert_eq!(js(PATH, &route(head, body)).len(), 1);
    }

    #[test]
    fn controllers_taking_a_context() {
        let strapi = "module.exports = { async find(ctx) { db.query('SELECT * FROM t WHERE id = ' + ctx.query.id); } };";
        assert_eq!(js(SQL, strapi).len(), 1);
        let next = "export async function getServerSideProps(ctx) { await fetch(ctx.query.u); }";
        assert_eq!(js(SSRF, next).len(), 1);
        // A canvas's context has no request members.
        assert!(
            js(
                CODE,
                "function draw(ctx) { ctx.fillText(label, 0, 0); eval(ctx.font); }"
            )
            .is_empty()
        );
    }

    #[test]
    fn a_check_on_a_member_read_and_on_equality() {
        let head = "const fs = require('fs'); const path = require('path'); const { themeNamePattern } = require('./c');";
        let body = "if (!themeNamePattern.test(req.params.theme)) throw new Error();\n\
                    const dir = path.join('/t', req.params.theme); fs.readFile(path.join(dir, 'a.json'), () => {});";
        assert!(js(PATH, &route(head, body)).is_empty());
        let body = "if (req.headers.host === 'example.com') res.redirect(`https://www.${req.headers.host}/`);";
        assert!(js(REDIRECT, &route("", body)).is_empty());
        for body in [
            // Equal in the other branch only.
            "if (req.query.to === 'home') return; res.redirect(req.query.to);",
            "const to = req.query.to === 'undefined' ? '/' : req.query.to; res.redirect(to);",
        ] {
            assert_eq!(js(REDIRECT, &route("", body)).len(), 1, "{body}");
        }
    }

    // ------------------------------------------------------------ across files (T4)

    /// Each file analyzed, then the project pass: the issues of every file,
    /// as a scan reports them.
    fn project(files: &[(&str, &str)]) -> Vec<Issue> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<_> = files
            .iter()
            .map(|(path, src)| {
                let lang = if path.ends_with(".ts") {
                    Lang::TypeScript
                } else {
                    Lang::JavaScript
                };
                analyze(path, lang, src, &rules, &cfg, far_deadline()).unwrap()
            })
            .collect();
        crate::analysis::taint_project_rules(&mut analyzed, &rules);
        analyzed
            .into_iter()
            .flat_map(|f| f.issues)
            .filter(|i| i.rule.starts_with("js/") && !i.flow.is_empty())
            .collect()
    }

    fn files_of(i: &Issue) -> Vec<Option<&str>> {
        i.flow.iter().map(|s| s.path.as_deref()).collect()
    }

    #[test]
    fn a_request_value_passed_to_another_files_function_that_reaches_a_sink() {
        let found = project(&[
            (
                "src/routes.js",
                "const { findUser } = require('./users');\n\
                 app.get('/u', (req, res) => {\n  findUser(req.query.id);\n});\n",
            ),
            (
                "src/users.js",
                "exports.findUser = (id) => {\n  return db.query('SELECT * FROM u WHERE id = ' + id);\n};\n",
            ),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        let i = &found[0];
        assert_eq!((i.path.as_str(), i.rule, i.line), ("src/users.js", SQL, 2));
        assert_eq!(
            flow(i),
            [
                "the request's `query`",
                "passed to `findUser`",
                "`findUser`'s parameter `id`",
                "passed to `query`"
            ]
        );
        assert_eq!(
            files_of(i),
            [Some("src/routes.js"), Some("src/routes.js"), None, None]
        );
        assert_eq!(
            i.flow.iter().map(|s| s.line).collect::<Vec<_>>(),
            [3, 3, 1, 2]
        );
    }

    #[test]
    fn imports_of_every_kind_and_two_hops() {
        let service = "import { run } from './run';\nexport function ping(host) { return run('ping ' + host); }\n";
        let runner =
            "import { exec } from 'child_process';\nexport function run(cmd) { exec(cmd); }\n";
        for head in [
            "import { ping } from './service';",
            "import * as svc from './service'; const ping = (h) => svc.ping(h);",
        ] {
            let routes =
                format!("{head}\napp.get('/p', (req, res) => {{ ping(req.query.host); }});\n");
            let found = project(&[
                ("src/routes.ts", &routes),
                ("src/service.ts", service),
                ("src/run.ts", runner),
            ]);
            assert_eq!(found.len(), 1, "{head}: {found:?}");
            assert_eq!(found[0].path, "src/run.ts");
            assert!(flow(&found[0]).contains(&"`ping`'s parameter `host`"));
        }
        // A default export, and a default-exported object's member.
        for (head, call, callee) in [
            (
                "import save from './save';",
                "save(req.body.name)",
                "export default function (p) { fs.writeFileSync(p, 'x'); }",
            ),
            (
                "import store from './save';",
                "store.save(req.body.name)",
                "export default { save(p) { fs.writeFileSync(p, 'x'); } };",
            ),
            (
                "const store = require('./save');",
                "store.save(req.body.name)",
                "module.exports = { save: (p) => fs.writeFileSync(p, 'x') };",
            ),
        ] {
            let routes = format!("{head}\napp.post('/s', (req, res) => {{ {call}; }});\n");
            let callee = format!("const fs = require('fs');\n{callee}\n");
            let found = project(&[("src/routes.js", &routes), ("src/save.js", &callee)]);
            assert_eq!(found.len(), 1, "{call}: {found:?}");
            assert_eq!(found[0].rule, PATH);
        }
    }

    #[test]
    fn another_files_result_reaching_a_sink() {
        // A helper that builds the query from what it's given.
        let found = project(&[
            (
                "src/routes.js",
                "import { byId } from './sql';\napp.get('/o', (req, res) => {\n  db.query(byId(req.query.id));\n});\n",
            ),
            (
                "src/sql.js",
                "export const byId = (id) => 'SELECT * FROM o WHERE id = ' + id;\n",
            ),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            (found[0].path.as_str(), found[0].line),
            ("src/routes.js", 3)
        );
        assert_eq!(
            flow(&found[0]),
            [
                "the request's `query`",
                "passed to `byId`",
                "`byId`'s parameter `id`",
                "returned by `byId`",
                "passed to `query`"
            ]
        );
        assert_eq!(files_of(&found[0])[2], Some("src/sql.js"));
        // One that reads the request itself.
        let found = project(&[
            (
                "src/routes.js",
                "import { term } from './input';\napp.get('/s', (req, res) => {\n  db.query('SELECT * FROM p WHERE n = ' + term(req));\n});\n",
            ),
            (
                "src/input.js",
                "export function term(req) { return req.query.q; }\n",
            ),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(flow(&found[0])[0], "the request's `query`");
    }

    #[test]
    fn nest_services_injected_by_type() {
        let controller = "import { UsersService } from './users.service';\n\
                          @Controller('users') export class UsersController {\n\
                          constructor(private readonly users: UsersService) {}\n\
                          @Get(':id') find(@Param('id') id: string) { return this.users.findOne(id); }\n}\n";
        let service = "export class UsersService {\n\
                       findOne(id: string) { return this.db.query(`SELECT * FROM u WHERE id = ${id}`); }\n\
                       count() { return this.db.query('SELECT count(*) FROM u'); }\n}\n";
        let found = project(&[
            ("src/users.controller.ts", controller),
            ("src/users.service.ts", service),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "src/users.service.ts");
        assert_eq!(flow(&found[0])[1], "passed to `UsersService.findOne`");
    }

    #[test]
    fn helpers_of_the_same_file() {
        let src = route(
            "function find(id) { return db.query('SELECT * FROM o WHERE id = ' + id); }\n\
             const byName = (n) => 'SELECT * FROM u WHERE name = ' + n;",
            "find(req.query.id);\ndb.query(byName(req.query.name));",
        );
        let found = js(SQL, &src);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().any(|i| flow(i).contains(&"passed to `find`")));
        assert!(
            found
                .iter()
                .any(|i| flow(i).contains(&"returned by `byName`"))
        );
        // A helper that parses its parameter, and recursion, end safely.
        let src = route(
            "function n(id) { return parseInt(id, 10); }\nfunction r(x) { return r(x); }",
            "db.query('SELECT * FROM o WHERE id = ' + n(req.query.id));\ndb.query('SELECT ' + r(1));",
        );
        assert!(js(SQL, &src).is_empty());
    }

    #[test]
    fn what_doesnt_cross_files() {
        let routes = "import { findUser } from './users';\nimport { q } from 'some-package';\n\
                      app.get('/u', (req, res) => { findUser(req.query.id); q(req.query.id); });\n";
        for users in [
            // Parsed before the query.
            "export function findUser(id) { return db.query('SELECT * FROM u WHERE id = ' + Number(id)); }",
            // Not exported.
            "function findUser(id) { return db.query('SELECT * FROM u WHERE id = ' + id); }",
            // The sink's line suppresses the rule.
            "export function findUser(id) { return db.query('SELECT * FROM u WHERE id = ' + id); } // NOSONAR",
        ] {
            assert!(
                project(&[("src/routes.js", routes), ("src/users.js", users)]).is_empty(),
                "{users}"
            );
        }
    }

    #[test]
    fn uploads_and_checks_before_a_helper() {
        let head = "const fs = require('fs'); const path = require('path');";
        // Where multer stored the upload is the server's.
        let stored = "const del = (f) => fs.unlinkSync(f.path);\napp.post('/u', (req, res) => { del(req.file); });";
        assert!(js(PATH, &format!("{head}\n{stored}")).is_empty());
        let named = route(
            head,
            "fs.writeFileSync('/up/' + req.file.originalname, 'x');",
        );
        assert_eq!(js(PATH, &named).len(), 1);
        assert_eq!(
            flow(&js(PATH, &named)[0])[0],
            "the uploaded file's `originalname`"
        );
        // Checked before it's passed to a helper.
        let src = format!(
            "{head}\nfunction list(dir) {{ return fs.readdirSync(dir); }}\n\
             app.get('/f', (req, res) => {{\n\
             const d = path.join('/up', req.query.dir);\n\
             if (!isPathInside('/up', d)) return;\n list(d);\n}});"
        );
        assert!(js(PATH, &src).is_empty());
    }
}
