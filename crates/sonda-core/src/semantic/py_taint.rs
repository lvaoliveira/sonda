//! Taint analysis for Python (ADR-0027): which values that came from a
//! request reach a sink, and by what path.
//!
//! Like JavaScript's (T2), it's **flow-insensitive**, over the scopes of
//! Python's binder (S1): a variable that is ever assigned a request's value
//! holds it everywhere, and the whole file is one fixed point over its
//! writes. A function of the file is followed through its summary (T3).
//!
//! Precision before recall, as the ADR says:
//! - a call this module doesn't know returns an untainted value, so a
//!   program's own escaping helper sanitizes;
//! - a number can't inject: `int(x)`, `len(x)`, arithmetic and comparisons
//!   give untainted values;
//! - the request object itself isn't tainted, only its members.
//!
//! Sources are a request's members, in Flask (`request.args`), Django
//! (`request.GET`) and Starlette and FastAPI (`request.query_params`), and
//! the parameters a framework fills from the request: a Flask route's, a
//! Django view's after its `request`, a FastAPI path operation's.

use super::taint::{
    CallFact, Callee, Facts, Finding, Key, ReturnFact, SinkKind, Step, SummaryFact, TaintResult,
    cap,
};
use super::{DeclId, Model};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

type Path<'t> = Vec<Step<'t>>;

/// A path that starts at another file's function's result: a request's
/// value only if that function returns one, which the project pass
/// decides (T4). Its first step is the call, with this message.
const FROM_CALL: &str = "\u{1}";

fn from_call(path: &Path) -> bool {
    path.first().is_some_and(|s| s.message == FROM_CALL)
}

/// Modules that are libraries, whose functions the tables model or that
/// return nothing of a request's: no other file of the project.
const LIBRARIES: &[&str] = &[
    "os",
    "sys",
    "re",
    "json",
    "subprocess",
    "shutil",
    "pathlib",
    "requests",
    "httpx",
    "urllib",
    "urllib3",
    "aiohttp",
    "flask",
    "django",
    "fastapi",
    "starlette",
    "sqlalchemy",
    "lxml",
    "ldap",
    "ldap3",
    "typing",
    "logging",
    "datetime",
    "time",
    "base64",
    "hashlib",
    "html",
    "shlex",
    "collections",
    "itertools",
    "functools",
    "math",
    "random",
    "uuid",
    "io",
    "tempfile",
    "werkzeug",
    "pydantic",
    "asyncio",
];

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
        needs_sql: bool,
    },
}

/// Rounds of the fixed point; past it, the file reports nothing.
const MAX_ROUNDS: usize = 64;
/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;
/// How deep an expression is followed for its taint.
const MAX_DEPTH: u32 = 64;
/// Functions summarized per file, at most.
const MAX_SUMMARIES: usize = 256;
/// Expressions followed for their taint in one file, at most: past it,
/// what's left is untainted, so a pathological file costs a bounded time.
const MAX_EVALUATIONS: u64 = 5_000_000;

// ---------------------------------------------------------------- tables

/// A request's members that hold what its sender chose: Flask's, Django's
/// and Starlette's.
const REQUEST_MEMBERS: &[&str] = &[
    // Flask
    "args",
    "form",
    "values",
    "json",
    "data",
    "cookies",
    "headers",
    "view_args",
    "query_string",
    "path",
    "full_path",
    "url",
    "base_url",
    "url_root",
    "stream",
    // Django
    "GET",
    "POST",
    "COOKIES",
    "META",
    "body",
    "path_info",
    // Starlette
    "query_params",
    "path_params",
    // aiohttp
    "query",
    "match_info",
    "rel_url",
];

/// A request's methods that return what its sender chose.
const REQUEST_METHODS: &[&str] = &[
    "post",
    "text",
    "get_json",
    "get_data",
    "json",
    "form",
    "body",
    "get_full_path",
    "read",
];

/// A request's own path, which a redirect to stays on this site.
const OWN_PATH: &[&str] = &["path", "path_info", "full_path", "get_full_path"];

/// An upload's members its sender chose: Flask's and Django's file name.
const UPLOAD_NAMES: &[&str] = &["filename", "name"];

/// Decorators' methods that register a route: Flask's `route`, FastAPI's
/// and Flask 2's `get`, `post`…
const ROUTE_DECORATORS: &[&str] = &[
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "api_route",
];

/// Types a FastAPI parameter can have that carry no text, or that aren't
/// the request's values.
const NOT_VALUES: &[&str] = &[
    "int",
    "float",
    "bool",
    "UUID",
    "uuid.UUID",
    "datetime",
    "date",
    "time",
    "Decimal",
    "Response",
    "BackgroundTasks",
    "WebSocket",
    "Session",
    "AsyncSession",
    "SecurityScopes",
];

/// The types of a request object.
const REQUEST_TYPES: &[&str] = &["Request", "HttpRequest", "WSGIRequest", "ASGIRequest"];

/// Methods whose result carries their receiver's value.
const PROPAGATING_METHODS: &[&str] = &[
    "get",
    "getlist",
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "title",
    "capitalize",
    "casefold",
    "replace",
    "split",
    "rsplit",
    "splitlines",
    "encode",
    "decode",
    "format",
    "join",
    "values",
    "items",
    "copy",
    "pop",
    "to_dict",
    "dict",
    "model_dump",
    "joinpath",
    "with_name",
    "with_suffix",
    "resolve",
    "absolute",
    "expanduser",
];

/// Builtins whose result carries their arguments' value.
const PROPAGATING_BUILTINS: &[&str] = &[
    "str",
    "repr",
    "bytes",
    "bytearray",
    "list",
    "tuple",
    "dict",
    "format",
];

/// Modules whose functions' results carry their arguments' value, and
/// those of their functions that sanitize for a sink instead.
const PROPAGATING_MODULES: &[&str] = &[
    "os.path",
    "posixpath",
    "ntpath",
    "urllib.parse",
    "json",
    "base64",
    "shlex",
    "html",
    "pathlib",
];

/// A path object's methods that use the file it names: sinks for a path
/// from the request.
const PATH_METHODS: &[&str] = &[
    "open",
    "read_text",
    "read_bytes",
    "write_text",
    "write_bytes",
    "unlink",
    "rmdir",
    "mkdir",
    "touch",
    "rename",
    "replace",
    "iterdir",
    "symlink_to",
    "hardlink_to",
    "chmod",
];

/// SQL text methods: with text that reads as SQL, a value reaching them is
/// a finding.
const SQL_EXECUTE: &[&str] = &["execute", "executemany", "executescript", "exec_driver_sql"];
/// Methods and functions that take SQL text as such.
const SQL_RAW: &[&str] = &["raw", "RawSQL", "text", "literal_column", "from_statement"];

/// Which arguments of a sink take the value.
#[derive(Clone, Copy)]
enum Args {
    First,
    Second,
    FirstTwo,
    Third,
}

/// A module's functions that are sinks: `(module, names, kind, args)`.
const MODULE_SINKS: &[(&str, &[&str], SinkKind, Args)] = &[
    (
        "os",
        &[
            "system",
            "popen",
            "execl",
            "execle",
            "execlp",
            "execlpe",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
            "startfile",
        ],
        SinkKind::Command,
        Args::First,
    ),
    (
        "subprocess",
        &[
            "run",
            "call",
            "check_call",
            "check_output",
            "Popen",
            "getoutput",
            "getstatusoutput",
        ],
        SinkKind::Command,
        Args::First,
    ),
    (
        "os",
        &[
            "remove",
            "unlink",
            "rmdir",
            "removedirs",
            "mkdir",
            "makedirs",
            "listdir",
            "scandir",
            "chmod",
            "chown",
            "walk",
            "open",
            "truncate",
        ],
        SinkKind::Path,
        Args::First,
    ),
    (
        "os",
        &["rename", "replace", "link", "symlink"],
        SinkKind::Path,
        Args::FirstTwo,
    ),
    (
        "shutil",
        &["copy", "copy2", "copyfile", "copytree", "move", "rmtree"],
        SinkKind::Path,
        Args::FirstTwo,
    ),
    ("flask", &["send_file"], SinkKind::Path, Args::First),
    ("flask", &["redirect"], SinkKind::Redirect, Args::First),
    (
        "django.shortcuts",
        &["redirect"],
        SinkKind::Redirect,
        Args::First,
    ),
    (
        "django.http",
        &["HttpResponseRedirect", "HttpResponsePermanentRedirect"],
        SinkKind::Redirect,
        Args::First,
    ),
    (
        "fastapi.responses",
        &["RedirectResponse"],
        SinkKind::Redirect,
        Args::First,
    ),
    (
        "starlette.responses",
        &["RedirectResponse"],
        SinkKind::Redirect,
        Args::First,
    ),
    (
        "fastapi",
        &["RedirectResponse"],
        SinkKind::Redirect,
        Args::First,
    ),
    (
        "requests",
        &["get", "post", "put", "patch", "delete", "head", "options"],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("requests", &["request"], SinkKind::Ssrf, Args::Second),
    (
        "httpx",
        &[
            "get", "post", "put", "patch", "delete", "head", "options", "stream",
        ],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("httpx", &["request"], SinkKind::Ssrf, Args::Second),
    (
        "urllib.request",
        &["urlopen", "Request", "urlretrieve"],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("urllib3", &["request"], SinkKind::Ssrf, Args::Second),
    (
        "sqlalchemy",
        &["text", "literal_column"],
        SinkKind::Sql,
        Args::First,
    ),
    (
        "django.db.models.expressions",
        &["RawSQL"],
        SinkKind::Sql,
        Args::First,
    ),
    ("django.db.models", &["RawSQL"], SinkKind::Sql, Args::First),
    ("lxml.etree", &["XPath"], SinkKind::XPath, Args::First),
];

/// Builtins that are sinks.
const BUILTIN_SINKS: &[(&str, SinkKind, Args)] = &[
    ("eval", SinkKind::Code, Args::First),
    ("exec", SinkKind::Code, Args::First),
    ("open", SinkKind::Path, Args::First),
];

/// Methods of a module's instances that are sinks: a `requests.Session()`'s
/// `get`, an `httpx.Client()`'s.
const INSTANCE_SINKS: &[(&str, &[&str], SinkKind, Args)] = &[
    (
        "requests",
        &["get", "post", "put", "patch", "delete", "head", "options"],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("requests", &["request"], SinkKind::Ssrf, Args::Second),
    (
        "httpx",
        &[
            "get", "post", "put", "patch", "delete", "head", "options", "stream",
        ],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("httpx", &["request"], SinkKind::Ssrf, Args::Second),
    (
        "aiohttp",
        &["get", "post", "put", "patch", "delete", "head", "options"],
        SinkKind::Ssrf,
        Args::First,
    ),
    ("aiohttp", &["request"], SinkKind::Ssrf, Args::Second),
    (
        "urllib3",
        &["request", "urlopen"],
        SinkKind::Ssrf,
        Args::Second,
    ),
];

/// Calls that make an instance of their module: `requests.Session()`.
const INSTANCE_MAKERS: &[&str] = &[
    "Session",
    "Client",
    "AsyncClient",
    "ClientSession",
    "PoolManager",
];

// ---------------------------------------------------------------- entry

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    // A file without a sink can still pass a value on to another file's
    // function, or define one another file calls.
    let has = |n: &[u8]| src.windows(n.len()).any(|w| w == n);
    let sinks = might_have_sinks(src, kind);
    // A request's value: Django's, Flask's, Starlette's `request`, and the
    // parameters of a route a decorator registers.
    // `request.args`, `def view(request, …)`, `request: Request`; not
    // `requests` or `request_id`.
    let sources = [
        b"request.".as_slice(),
        b"request,",
        b"request)",
        b"request:",
    ]
    .iter()
    .any(|n| has(n))
        || has(b".route(")
        || has(b"api_route")
        || [b"@app.".as_slice(), b"@router.", b"@bp.", b"@blueprint."]
            .iter()
            .any(|d| has(d));
    if !sinks && !sources && !has(b"import") && !has(b"def ") {
        return TaintResult::default();
    }
    let Some(root) = m.root else {
        return TaintResult::default();
    };
    let Some(cx) = Cx::new(m, src, kind, root) else {
        return TaintResult::default();
    };
    // Neither a sink nor a request: only what its functions pass straight
    // on to other modules matters, read from the syntax. Analyzing every
    // such file costs a large project seconds.
    if !sinks && !sources {
        return TaintResult {
            findings: Vec::new(),
            facts: Facts {
                summaries: cx.passed_on_summaries(),
                ..Facts::default()
            },
        };
    }
    let mut start = cx.initial.clone();
    start.from_calls = true;
    let Some(state) = cx.run(start, None) else {
        return TaintResult::default();
    };
    let mut findings: Vec<Finding<'t>> = Vec::new();
    let mut facts = Facts::default();
    for r in cx.reached(None, &state) {
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
                    let args = positional(call)
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
    // Without a sink of its own, a file's functions pass values on at
    // most, which the syntax shows more cheaply than a summary per function.
    facts.summaries = if sinks {
        cx.exported_summaries(&state)
    } else {
        cx.passed_on_summaries()
    };
    TaintResult { findings, facts }
}

/// Whether the file can have a sink of this kind: the modules and names
/// the sink tables use, as written.
fn might_have_sinks(src: &[u8], kind: SinkKind) -> bool {
    let has = |n: &[u8]| src.windows(n.len()).any(|w| w == n);
    let os = || has(b"import os") || has(b"from os");
    let words: &[&[u8]] = match kind {
        SinkKind::Sql => &[
            b"execute",
            b".raw(",
            b"RawSQL",
            b"sqlalchemy",
            b"literal_column",
            b"from_statement",
        ],
        SinkKind::Command => return os() || has(b"subprocess"),
        SinkKind::Path => {
            return os()
                || [b"open(".as_slice(), b"shutil", b"pathlib", b"send_file"]
                    .iter()
                    .any(|w| has(w));
        }
        SinkKind::Redirect => &[b"redirect", b"Redirect"],
        SinkKind::Ssrf => &[b"requests", b"httpx", b"urllib", b"aiohttp"],
        SinkKind::Code => &[b"eval(", b"exec("],
        SinkKind::XPath => &[b"xpath", b"XPath"],
        SinkKind::Ldap => &[b"ldap"],
    };
    words.iter().any(|w| has(w))
}

// ---------------------------------------------------------------- the file

/// What a name imported from a module is: the module (`os.path`), and the
/// name imported from it (`join`), or None for the module itself.
struct Import {
    module: String,
    member: Option<String>,
}

/// A write of a value into a target.
struct Write<'t> {
    target: Node<'t>,
    value: Node<'t>,
    /// `q += x`, `parts.append(x)`: the target keeps what it had.
    adds: bool,
}

#[derive(Clone, Default)]
struct State<'t> {
    tainted: HashMap<DeclId, Path<'t>>,
    requests: HashSet<DeclId>,
    /// Variables holding an upload: `f = request.files['doc']`.
    uploads: HashSet<DeclId>,
    /// Whether other files' functions' results count, as paths that start
    /// at the call: for the file's own run, not a summary's.
    from_calls: bool,
}

/// What a function's parameters reach, each analyzed alone.
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
    by_node: HashMap<usize, DeclId>,
    imports: HashMap<DeclId, Import>,
    /// Instances of a module: `s = requests.Session()`.
    instances: HashMap<DeclId, String>,
    initial: State<'t>,
    writes: Vec<Write<'t>>,
    calls: Vec<Node<'t>>,
    fn_index: HashMap<usize, usize>,
    summaries: RefCell<HashMap<usize, Rc<FnSummary<'t>>>>,
    busy: RefCell<HashSet<usize>>,
    checks: RefCell<HashMap<usize, Rc<HashSet<String>>>>,
    evaluations: Cell<u64>,
    /// The writes' indices by their target's position (and the calls,
    /// sorted by position), so a function's are a range, not the file's.
    writes_by_start: Vec<usize>,
    /// Per call and per function, computed once: what a call calls in
    /// this file, its sink, and a function's return values.
    local_calls: RefCell<HashMap<usize, Option<usize>>>,
    sink_calls: RefCell<HashMap<usize, Option<SinkCall<'t>>>>,
    returns: RefCell<HashMap<usize, Rc<Vec<Node<'t>>>>>,
}

/// A sink's name, and the arguments that take the value.
type SinkCall<'t> = (String, Vec<Node<'t>>);

impl<'a, 't> Cx<'a, 't> {
    fn new(m: &'a Model<'t>, src: &'a [u8], kind: SinkKind, root: Node<'t>) -> Option<Self> {
        let mut cx = Cx {
            m,
            src,
            kind,
            by_node: m
                .decls
                .iter()
                .enumerate()
                .map(|(i, d)| (d.node.id(), i))
                .collect(),
            imports: HashMap::new(),
            instances: HashMap::new(),
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
            checks: RefCell::new(HashMap::new()),
            evaluations: Cell::new(0),
            writes_by_start: Vec::new(),
            local_calls: RefCell::new(HashMap::new()),
            sink_calls: RefCell::new(HashMap::new()),
            returns: RefCell::new(HashMap::new()),
        };
        cx.walk(root)?;
        cx.calls.sort_by_key(|c| c.start_byte());
        let mut by_start: Vec<usize> = (0..cx.writes.len()).collect();
        by_start.sort_by_key(|&i| cx.writes[i].target.start_byte());
        cx.writes_by_start = by_start;
        for (i, f) in m.functions.iter().enumerate() {
            cx.handler(i, f.node);
        }
        // `request` imported from Flask, wherever it's used.
        for (d, import) in &cx.imports {
            if import.module == "flask" && import.member.as_deref() == Some("request") {
                cx.initial.requests.insert(*d);
            }
        }
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        std::str::from_utf8(&self.src[n.byte_range()]).unwrap_or("")
    }

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
            let field = |f: &str| n.child_by_field_name(f);
            match n.kind() {
                "import_statement" | "import_from_statement" => self.import(n),
                "assignment" | "augmented_assignment" => {
                    if let (Some(left), Some(right)) = (field("left"), field("right")) {
                        self.instance(left, right);
                        self.writes.push(Write {
                            target: left,
                            value: right,
                            adds: n.kind() == "augmented_assignment",
                        });
                    }
                }
                "for_statement" | "for_in_clause" => {
                    if let (Some(left), Some(right)) = (field("left"), field("right")) {
                        self.writes.push(Write {
                            target: left,
                            value: right,
                            adds: false,
                        });
                    }
                }
                "named_expression" => {
                    if let (Some(name), Some(value)) = (field("name"), field("value")) {
                        self.writes.push(Write {
                            target: name,
                            value,
                            adds: false,
                        });
                    }
                }
                // `with open(p) as f`, `async with ClientSession() as s`.
                "as_pattern" => {
                    let value = children(n)
                        .into_iter()
                        .find(|c| c.kind() != "as_pattern_target");
                    let target = children(n)
                        .into_iter()
                        .find(|c| c.kind() == "as_pattern_target");
                    if let (Some(value), Some(target)) = (value, target) {
                        let target = target.named_child(0).unwrap_or(target);
                        self.instance(target, value);
                        self.writes.push(Write {
                            target,
                            value,
                            adds: false,
                        });
                    }
                }
                "call" => {
                    self.calls.push(n);
                    // `parts.append(x)`: the list holds it.
                    if let Some((receiver, name)) = method(n)
                        && matches!(
                            self.text(name),
                            "append" | "extend" | "insert" | "add" | "update"
                        )
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
        let from = n
            .child_by_field_name("module_name")
            .map(|m| self.text(m).to_string());
        for c in children(n) {
            if Some(c) == n.child_by_field_name("module_name") {
                continue;
            }
            let (name, alias) = match c.kind() {
                "aliased_import" => (
                    c.child_by_field_name("name"),
                    c.child_by_field_name("alias"),
                ),
                "dotted_name" => (Some(c), None),
                _ => continue,
            };
            let Some(name) = name else { continue };
            let dotted = self.text(name).to_string();
            let (local, import) = match &from {
                // `from os import path as p`: `p` is `os`'s `path`.
                // The binder declares the name's identifier, not the
                // `dotted_name` around it.
                Some(module) => (
                    alias.unwrap_or_else(|| name.named_child(0).unwrap_or(name)),
                    Import {
                        module: module.clone(),
                        member: Some(dotted),
                    },
                ),
                // `import os.path as p` is `os.path`; `import os.path` binds
                // `os`, the module itself.
                None => match alias {
                    Some(a) => (
                        a,
                        Import {
                            module: dotted,
                            member: None,
                        },
                    ),
                    None => {
                        let Some(first) = name.named_child(0) else {
                            continue;
                        };
                        (
                            first,
                            Import {
                                module: self.text(first).to_string(),
                                member: None,
                            },
                        )
                    }
                },
            };
            if let Some(d) = self.decl(local) {
                self.imports.insert(d, import);
            }
        }
    }

    /// `s = requests.Session()`: `s` is an instance of `requests`.
    fn instance(&mut self, target: Node<'t>, value: Node<'t>) {
        if target.kind() != "identifier" || value.kind() != "call" {
            return;
        }
        let Some(callee) = value.child_by_field_name("function") else {
            return;
        };
        let Some((module, name)) = self.qualified(callee) else {
            return;
        };
        let last = name.rsplit('.').next().unwrap_or(&name);
        if INSTANCE_MAKERS.contains(&last)
            && let Some(d) = self.decl(target)
        {
            let base = module.split('.').next().unwrap_or(&module).to_string();
            self.instances.insert(d, base);
        }
    }

    /// What a callee names in a module: `os.path.join` is `("os.path",
    /// "join")`; `join` imported from `os.path` too; `subprocess.run`.
    fn qualified(&self, callee: Node) -> Option<(String, String)> {
        let mut parts: Vec<&str> = Vec::new();
        let mut n = callee;
        while n.kind() == "attribute" {
            parts.push(self.text(n.child_by_field_name("attribute")?));
            n = n.child_by_field_name("object")?;
        }
        if n.kind() != "identifier" {
            return None;
        }
        let decl = self.decl(n)?;
        // Flask's `request` is imported, but it's no module.
        if self.initial.requests.contains(&decl) {
            return None;
        }
        let import = self.imports.get(&decl)?;
        parts.reverse();
        let mut full: Vec<String> = import.module.split('.').map(str::to_string).collect();
        full.extend(import.member.iter().cloned());
        full.extend(parts.iter().map(|p| p.to_string()));
        let name = full.pop()?;
        Some((full.join("."), name))
    }

    // ------------------------------------------------------------ sources

    /// Whether function `i` is a handler, and what its parameters hold.
    fn handler(&mut self, i: usize, f: Node<'t>) {
        let params = &self.m.functions[i].params;
        let nodes: Vec<Node<'t>> = f
            .child_by_field_name("parameters")
            .map(children)
            .unwrap_or_default();
        // A parameter named `request`, or typed as one: Django's and
        // Starlette's request.
        let mut request_at = None;
        for (k, p) in nodes.iter().enumerate() {
            let name = param_name(*p).map(|n| self.text(n));
            let typed = p
                .child_by_field_name("type")
                .is_some_and(|t| REQUEST_TYPES.contains(&last_name(self.text(t))));
            if name == Some("request") || typed {
                if let Some(decls) = params.get(k) {
                    self.initial.requests.extend(decls.iter().copied());
                }
                request_at.get_or_insert(k);
            }
        }
        let route = self.route_of(f);
        // A route's parameters, and a Django view's after its request.
        let first_value = match (&route, request_at) {
            (Some(_), _) => 0,
            (None, Some(k)) if k <= 1 => k + 1,
            _ => return,
        };
        for (k, p) in nodes.iter().enumerate().skip(first_value) {
            let Some(name) = param_name(*p) else { continue };
            let text = self.text(name);
            if matches!(text, "self" | "cls" | "request") || Some(k) == request_at {
                continue;
            }
            // A number, a dependency or a framework object isn't a value.
            if p.child_by_field_name("type")
                .is_some_and(|t| NOT_VALUES.contains(&last_name(self.text(t))))
                || p.child_by_field_name("value").is_some_and(|v| {
                    let v = self.text(v);
                    v.starts_with("Depends(") || v.starts_with("Security(")
                })
                || route.as_deref().is_some_and(|r| numeric_converter(r, text))
            {
                continue;
            }
            for d in params.get(k).into_iter().flatten() {
                self.initial.tainted.insert(
                    *d,
                    vec![Step {
                        node: name,
                        message: format!("request parameter `{text}`"),
                    }],
                );
            }
        }
    }

    /// The route a function is decorated with: `@app.route('/u/<id>')`,
    /// `@router.get('/items/{id}')`. Its path, or "" without one.
    fn route_of(&self, f: Node) -> Option<String> {
        let decorated = f.parent().filter(|p| p.kind() == "decorated_definition")?;
        for d in children(decorated)
            .into_iter()
            .filter(|c| c.kind() == "decorator")
        {
            let Some(call) = d.named_child(0).filter(|c| c.kind() == "call") else {
                continue;
            };
            let Some(callee) = call.child_by_field_name("function") else {
                continue;
            };
            if callee.kind() != "attribute" {
                continue;
            }
            let name = callee
                .child_by_field_name("attribute")
                .map_or("", |a| self.text(a));
            if ROUTE_DECORATORS.contains(&name) {
                let path = arguments(call)
                    .into_iter()
                    .find(|a| a.kind() == "string")
                    .map_or(String::new(), |a| self.text(a).to_string());
                return Some(path);
            }
        }
        None
    }

    // ------------------------------------------------------------ fixed point

    /// The fixed point from `state`, over the writes in `scope` (a function,
    /// for a summary), or the whole file's.
    fn run(&self, mut state: State<'t>, scope: Option<Node>) -> Option<State<'t>> {
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

    fn bind(&self, w: &Write<'t>, state: &mut State<'t>) -> bool {
        let target = w.target;
        match target.kind() {
            "identifier" => {
                let Some(decl) = self.decl(target) else {
                    return false;
                };
                if !w.adds && self.is_request(w.value, state) {
                    return state.requests.insert(decl);
                }
                if !w.adds && self.is_upload(w.value, state) {
                    return state.uploads.insert(decl);
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
                let message = if w.adds
                    && w.target
                        .parent()
                        .is_some_and(|p| p.kind() == "argument_list")
                {
                    format!("added to `{name}`")
                } else if w.adds || is_built(w.value) {
                    format!("concatenated into `{name}`")
                } else {
                    format!("assigned to `{name}`")
                };
                path.push(Step {
                    node: target,
                    message,
                });
                state.tainted.insert(decl, cap(path));
                true
            }
            // `a, b = request.args['a'], …`: each name gets the value.
            "pattern_list" | "tuple_pattern" | "list_pattern" | "tuple" | "list" => {
                let Some(path) = self.taint(w.value, state, 0) else {
                    return false;
                };
                let mut changed = false;
                for name in names_in(target) {
                    let Some(decl) = self.decl(name) else {
                        continue;
                    };
                    if state.tainted.contains_key(&decl) {
                        continue;
                    }
                    let mut p = path.clone();
                    p.push(Step {
                        node: name,
                        message: format!("read into `{}`", self.text(name)),
                    });
                    state.tainted.insert(decl, cap(p));
                    changed = true;
                }
                changed
            }
            // `params['q'] = x`, `options.url = x`: the object holds it.
            "subscript" | "attribute" => {
                let object = target
                    .child_by_field_name("value")
                    .or_else(|| target.child_by_field_name("object"));
                let Some(object) = object.filter(|o| o.kind() == "identifier") else {
                    return false;
                };
                let Some(decl) = self.decl(object) else {
                    return false;
                };
                if state.tainted.contains_key(&decl) || state.requests.contains(&decl) {
                    return false;
                }
                let Some(mut path) = self.taint(w.value, state, 0) else {
                    return false;
                };
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

    /// A request object: a handler's, Flask's imported one, or `flask.request`.
    fn is_request(&self, n: Node, state: &State) -> bool {
        let n = unwrap(n);
        match n.kind() {
            "identifier" => self.decl(n).is_some_and(|d| state.requests.contains(&d)),
            "attribute" => {
                n.child_by_field_name("attribute")
                    .is_some_and(|a| self.text(a) == "request")
                    && n.child_by_field_name("object").is_some_and(|o| {
                        o.kind() == "identifier"
                            && self
                                .decl(o)
                                .and_then(|d| self.imports.get(&d))
                                .is_some_and(|i| i.module == "flask" && i.member.is_none())
                    })
            }
            _ => false,
        }
    }

    /// A `pathlib` path: `Path(p)`, a path's method's result (`joinpath`,
    /// `resolve`), `base / name` from one, or a name set to one of those.
    /// Its methods share names with a string's (`replace`, `open`).
    fn is_path_object(&self, n: Node) -> bool {
        self.path_object_at(n, 3)
    }

    fn path_object_at(&self, n: Node, depth: u8) -> bool {
        let n = unwrap(n);
        match n.kind() {
            "call" => {
                if let Some((receiver, m)) = method(n)
                    && matches!(
                        self.text(m),
                        "joinpath"
                            | "resolve"
                            | "absolute"
                            | "expanduser"
                            | "with_name"
                            | "with_suffix"
                            | "relative_to"
                    )
                {
                    return self.path_object_at(receiver, depth);
                }
                n.child_by_field_name("function")
                    .and_then(|f| self.qualified(f))
                    .is_some_and(|(m, name)| m == "pathlib" && name.ends_with("Path"))
            }
            "binary_operator" => {
                n.child_by_field_name("operator")
                    .is_some_and(|o| self.text(o) == "/")
                    && n.child_by_field_name("left")
                        .is_some_and(|l| self.path_object_at(l, depth))
            }
            "parenthesized_expression" => n
                .named_child(0)
                .is_some_and(|c| self.path_object_at(c, depth)),
            "identifier" if depth > 0 => self.decl(n).is_some_and(|d| {
                self.writes.iter().any(|w| {
                    w.target.kind() == "identifier"
                        && self.decl(w.target) == Some(d)
                        && self.path_object_at(w.value, depth - 1)
                })
            }),
            _ => false,
        }
    }

    /// An upload: `request.files['f']`, `request.FILES.get('f')`.
    fn is_upload(&self, n: Node, state: &State) -> bool {
        let mut n = unwrap(n);
        loop {
            match n.kind() {
                "identifier" => return self.decl(n).is_some_and(|d| state.uploads.contains(&d)),
                "subscript" => {
                    n = match n.child_by_field_name("value") {
                        Some(v) => unwrap(v),
                        None => return false,
                    }
                }
                "call" => match method(n) {
                    Some((receiver, name)) if matches!(self.text(name), "get" | "getlist") => {
                        n = unwrap(receiver)
                    }
                    _ => return false,
                },
                "attribute" => {
                    let property = n.child_by_field_name("attribute").map(|a| self.text(a));
                    let object = n.child_by_field_name("object");
                    return matches!(property, Some("files" | "FILES"))
                        && object.is_some_and(|o| self.is_request(o, state));
                }
                _ => return false,
            }
        }
    }

    /// The path of the first request's value an expression carries.
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
            "parenthesized_expression" | "await" | "expression_statement" => {
                n.named_child(0).and_then(|c| self.taint(c, state, d))
            }
            "attribute" => {
                let object = n.child_by_field_name("object")?;
                let property = self.text(n.child_by_field_name("attribute")?);
                if self.is_request(object, state) {
                    // The request's own path: its route matched it, and a
                    // redirect to it stays on this site.
                    if self.kind == SinkKind::Redirect && OWN_PATH.contains(&property) {
                        return None;
                    }
                    return REQUEST_MEMBERS.contains(&property).then(|| {
                        vec![Step {
                            node: n,
                            message: format!("the request's `{property}`"),
                        }]
                    });
                }
                if self.kind == SinkKind::Path
                    && matches!(property, "name" | "stem" | "suffix")
                    && self.is_path_object(object)
                {
                    return None;
                }
                if UPLOAD_NAMES.contains(&property) && self.is_upload(object, state) {
                    return Some(vec![Step {
                        node: n,
                        message: format!("the uploaded file's `{property}`"),
                    }]);
                }
                self.taint(object, state, d).map(|p| deepen(p, object, n))
            }
            "subscript" => {
                let value = n.child_by_field_name("value")?;
                if self.is_request(value, state) || self.is_upload(value, state) {
                    return None;
                }
                self.taint(value, state, d).map(|p| deepen(p, value, n))
            }
            "binary_operator" => {
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
                    // `base / name`: a path built from both.
                    Some("/") if self.kind == SinkKind::Path => self
                        .taint(left, state, d)
                        .or_else(|| self.taint(right, state, d)),
                    // `"… %s" % x`: string formatting, when the left is text.
                    Some("%") if is_text(left) => {
                        if self.fixes_origin(n, state, d) {
                            return None;
                        }
                        self.taint(right, state, d)
                    }
                    _ => None,
                }
            }
            "boolean_operator" => n
                .child_by_field_name("left")
                .and_then(|l| self.taint(l, state, d))
                .or_else(|| {
                    n.child_by_field_name("right")
                        .and_then(|r| self.taint(r, state, d))
                }),
            "conditional_expression" => {
                let parts = children(n);
                // `a if c else b`: a or b, not the condition.
                [parts.first(), parts.get(2)]
                    .into_iter()
                    .flatten()
                    .find_map(|p| self.taint(*p, state, d))
            }
            "string" => {
                if self.fixes_origin(n, state, d) {
                    return None;
                }
                children(n)
                    .into_iter()
                    .filter(|c| c.kind() == "interpolation")
                    .filter_map(|c| c.named_child(0))
                    .find_map(|e| self.taint(e, state, d))
            }
            "concatenated_string" | "list" | "tuple" | "set" | "expression_list" => children(n)
                .into_iter()
                .find_map(|c| self.taint(c, state, d)),
            "dictionary" => children(n)
                .into_iter()
                .filter_map(|p| p.child_by_field_name("value"))
                .find_map(|v| self.taint(v, state, d)),
            "list_comprehension" | "set_comprehension" | "generator_expression" => n
                .child_by_field_name("body")
                .and_then(|b| self.taint(b, state, d)),
            "call" => self.call_taint(n, state, d),
            _ => None,
        }
    }

    fn call_taint(&self, call: Node<'t>, state: &State<'t>, d: u32) -> Option<Path<'t>> {
        let any_arg = || {
            arguments(call)
                .into_iter()
                .find_map(|a| self.taint(a, state, d))
        };
        if let Some(j) = self.local_function(call) {
            return self.through_local(call, j, state, d);
        }
        let callee = call.child_by_field_name("function")?;
        if callee.kind() == "identifier" && self.decl(callee).is_none() {
            let name = self.text(callee);
            return PROPAGATING_BUILTINS.contains(&name).then(any_arg).flatten();
        }
        if state.from_calls
            && self.callee_of(call).is_some()
            && !self
                .qualified(callee)
                .is_some_and(|(m, _)| PROPAGATING_MODULES.contains(&m.as_str()))
        {
            return Some(vec![Step {
                node: call,
                message: FROM_CALL.to_string(),
            }]);
        }
        if let Some((module, name)) = self.qualified(callee) {
            // `os.path.basename` and `secure_filename` keep a file name.
            let sanitizes = match self.kind {
                SinkKind::Path => name == "basename" || name == "secure_filename",
                SinkKind::Redirect | SinkKind::Ssrf => {
                    module == "urllib.parse" && name.starts_with("quote")
                }
                SinkKind::Command => module == "shlex" && name == "quote",
                SinkKind::Code | SinkKind::Sql | SinkKind::XPath | SinkKind::Ldap => false,
            };
            let propagates = PROPAGATING_MODULES.contains(&module.as_str())
                || (module == "os" && name == "fspath");
            return (propagates && !sanitizes).then(any_arg).flatten();
        }
        let (receiver, method_name) = method(call)?;
        let name = self.text(method_name);
        if self.is_request(receiver, state) {
            if self.kind == SinkKind::Redirect && OWN_PATH.contains(&name) {
                return None;
            }
            return REQUEST_METHODS.contains(&name).then(|| {
                vec![Step {
                    node: call,
                    message: format!("the request's `{name}`"),
                }]
            });
        }
        if !PROPAGATING_METHODS.contains(&name) {
            return None;
        }
        // `"… {}".format(x)`, `", ".join(names)`: the arguments too.
        self.taint(receiver, state, d)
            .or_else(|| matches!(name, "format" | "join").then(any_arg).flatten())
    }

    /// For a request (SSRF) or a redirect: a URL whose text before the
    /// request's value fixes where it goes.
    fn fixes_origin(&self, n: Node<'t>, state: &State<'t>, d: u32) -> bool {
        if !matches!(self.kind, SinkKind::Ssrf | SinkKind::Redirect) {
            return false;
        }
        let mut before = String::new();
        for part in url_parts(n) {
            match part.kind() {
                "string_content" => before.push_str(self.text(part)),
                "string" => {
                    for c in children(part) {
                        if c.kind() == "string_content" {
                            before.push_str(self.text(c));
                        } else if c.kind() == "interpolation" {
                            let Some(e) = c.named_child(0) else { continue };
                            if self.taint(e, state, d + 1).is_some() {
                                return fixed(&before);
                            }
                            if before.is_empty() && self.site_url(e) {
                                return true;
                            }
                        }
                    }
                }
                _ if self.taint(part, state, d + 1).is_some() => break,
                // `url = url_for(…)`, then `f"{url}&{params}"`: a URL of
                // this site, where nothing has been written yet.
                _ if before.is_empty() && self.site_url(part) => return true,
                _ => {}
            }
        }
        fixed(&before)
    }

    /// A URL of this site: `url_for(…)`, Django's `reverse(…)`, or a name
    /// set to one.
    fn site_url(&self, n: Node) -> bool {
        let n = unwrap(n);
        let call = match n.kind() {
            "call" => Some(n),
            "identifier" => self
                .decl(n)
                .and_then(|d| self.m.decls[d].declarator)
                .and_then(|a| a.child_by_field_name("right"))
                .filter(|v| v.kind() == "call"),
            _ => None,
        };
        call.and_then(|c| c.child_by_field_name("function"))
            .is_some_and(|f| {
                let name = self.text(f);
                let name = name.rsplit('.').next().unwrap_or(name);
                matches!(name, "url_for" | "reverse" | "reverse_lazy" | "resolve_url")
            })
    }

    // ------------------------------------------------------------ sinks

    /// What the request's values reach from the calls in `scope`, or the
    /// whole file's: sinks, this file's helpers' sinks, and other files'
    /// functions.
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
            if let Some((name, args)) = self.sink(call) {
                for arg in args {
                    let Some(mut path) = self.taint(arg, state, 0) else {
                        continue;
                    };
                    let needs_sql = self.kind == SinkKind::Sql
                        && SQL_EXECUTE.contains(&name.as_str())
                        && !self.reads_as_sql(arg, 3);
                    if needs_sql && !from_call(&path) {
                        continue;
                    }
                    if self.is_checked(call, arg, &path) {
                        continue;
                    }
                    path.push(Step {
                        node: call,
                        message: format!("passed to `{name}`"),
                    });
                    out.push(reach_sink(path, call, needs_sql));
                    break;
                }
                continue;
            }
            // A helper of this file whose parameter reaches a sink, or
            // another file's function.
            if let Some(j) = self.local_function(call) {
                let summary = self.summary(j);
                if summary.to_sink.is_empty() && summary.to_call.is_empty() {
                    continue;
                }
                let fname = self.function_name(j);
                let params: HashSet<usize> = summary
                    .to_sink
                    .iter()
                    .map(|t| t.0)
                    .chain(summary.to_call.iter().map(|t| t.0))
                    .collect();
                for p in params {
                    let Some(arg) = self.argument_for(call, j, p) else {
                        continue;
                    };
                    let Some(path) = self.taint(arg, state, 0) else {
                        continue;
                    };
                    if self.is_checked(call, arg, &path) {
                        continue;
                    }
                    let into = |inner: &Path<'t>| {
                        let mut path = path.clone();
                        path.push(Step {
                            node: call,
                            message: format!("passed to `{fname}`"),
                        });
                        path.extend(inner.iter().cloned());
                        path
                    };
                    for (_, inner, sink) in summary.to_sink.iter().filter(|t| t.0 == p) {
                        out.push(reach_sink(into(inner), *sink, false));
                    }
                    if !from_call(&path) {
                        for (_, inner, callee, a) in summary.to_call.iter().filter(|t| t.0 == p) {
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
                for (i, arg) in positional(call).into_iter().enumerate() {
                    if let Some(path) = self
                        .taint(arg, state, 0)
                        .filter(|p| !from_call(p) && !self.is_checked(call, arg, p))
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

    /// Another file's function a call calls: imported from a module of the
    /// project (`from .db import query`), through a module (`db.query`), or
    /// an instance of an imported class (`svc = UserService()`).
    fn callee_of(&self, call: Node<'t>) -> Option<Callee> {
        let callee = call.child_by_field_name("function")?;
        let project = |i: &Import| {
            let root = i
                .module
                .trim_start_matches('.')
                .split('.')
                .next()
                .unwrap_or("");
            i.module.starts_with('.') || !LIBRARIES.contains(&root)
        };
        let import_of = |n: Node| {
            (n.kind() == "identifier")
                .then(|| self.decl(n))
                .flatten()
                .filter(|d| !self.initial.requests.contains(d))
                .and_then(|d| self.imports.get(&d))
                .filter(|i| project(i))
        };
        if callee.kind() == "identifier" {
            let import = import_of(callee)?;
            return Some(Callee::Py {
                module: import.module.clone(),
                name: import.member.clone(),
                member: None,
            });
        }
        let (receiver, member) = method(call)?;
        let member = Some(self.text(member).to_string());
        if let Some(import) = import_of(receiver) {
            return Some(Callee::Py {
                module: import.module.clone(),
                name: import.member.clone(),
                member,
            });
        }
        // `svc = UserService(…)`, with `UserService` imported.
        if receiver.kind() == "identifier"
            && let Some(class) = self
                .decl(receiver)
                .and_then(|d| self.m.decls[d].declarator)
                .and_then(|a| a.child_by_field_name("right"))
                .filter(|v| v.kind() == "call")
                .and_then(|v| v.child_by_field_name("function"))
            && let Some(import) = import_of(class)
        {
            return Some(Callee::Py {
                module: import.module.clone(),
                name: import
                    .member
                    .clone()
                    .or_else(|| Some(self.text(class).to_string())),
                member,
            });
        }
        None
    }

    /// Function `j`'s return values, computed once.
    fn returns_of(&self, j: usize) -> Rc<Vec<Node<'t>>> {
        if let Some(r) = self.returns.borrow().get(&j) {
            return r.clone();
        }
        let r = Rc::new(return_values(self.m.functions[j].node, &self.fn_index));
        self.returns.borrow_mut().insert(j, r.clone());
        r
    }

    /// Whether function `j` can have anything to summarize, read from the
    /// syntax: a sink, a call to a helper of the file or to another file's
    /// function with a parameter in its arguments, or a parameter in what
    /// it returns. Most functions have none, and a summary analyzes the
    /// function once per parameter.
    fn worth_summarizing(&self, j: usize) -> bool {
        let f = &self.m.functions[j];
        let params: Vec<&str> = f
            .params
            .iter()
            .flatten()
            .map(|d| self.m.decls[*d].name.as_str())
            .filter(|n| !matches!(*n, "self" | "cls"))
            .collect();
        if params.is_empty() {
            // It may still return a request's value it reads itself.
            return true;
        }
        let mentions = |n: Node| {
            let mut stack = vec![n];
            while let Some(c) = stack.pop() {
                if c.kind() == "identifier" && params.contains(&self.text(c)) {
                    return true;
                }
                stack.extend(children(c));
            }
            false
        };
        let lo = self
            .calls
            .partition_point(|c| c.start_byte() < f.node.start_byte());
        let hi = self
            .calls
            .partition_point(|c| c.start_byte() < f.node.end_byte());
        self.calls[lo..hi].iter().any(|&c| {
            self.sink(c).is_some()
                || ((self.local_function(c).is_some() || self.callee_of(c).is_some())
                    && arguments(c).into_iter().any(mentions))
        }) || self.returns_of(j).iter().any(|r| mentions(*r))
    }

    /// The key other modules import function `j` by: a module's function
    /// by its name, a module's class's method by class and method.
    fn export_key(&self, j: usize) -> Option<Key> {
        let f = self.m.functions[j].node;
        if f.kind() != "function_definition" {
            return None;
        }
        let name = self.text(f.child_by_field_name("name")?).to_string();
        let mut owner = f.parent();
        if owner.is_some_and(|o| o.kind() == "decorated_definition") {
            owner = owner.and_then(|o| o.parent());
        }
        match owner?.kind() {
            "module" => Some(Key {
                export: name,
                member: None,
            }),
            "block" => {
                let class = owner?.parent().filter(|c| c.kind() == "class_definition")?;
                let parent = class.parent()?;
                let at_top = parent.kind() == "module"
                    || (parent.kind() == "decorated_definition"
                        && parent.parent().is_some_and(|g| g.kind() == "module"));
                at_top.then(|| Key {
                    export: self
                        .text(class.child_by_field_name("name").unwrap_or(class))
                        .to_string(),
                    member: Some(name),
                })
            }
            _ => None,
        }
    }

    /// For a module with neither a sink nor a request: its functions'
    /// parameters passed straight on to other modules' functions, as the
    /// argument, a member of it, or in a concatenation, a `%` or an
    /// f-string, not through another call, which may sanitize it.
    fn passed_on_summaries(&self) -> Vec<SummaryFact<'t>> {
        let mut out = Vec::new();
        for (j, f) in self.m.functions.iter().enumerate() {
            let Some(key) = self.export_key(j) else {
                continue;
            };
            let fname = self.function_name(j);
            let first_is_self = f
                .params
                .first()
                .and_then(|d| d.first())
                .is_some_and(|d| matches!(self.m.decls[*d].name.as_str(), "self" | "cls"));
            let shift = usize::from(key.member.is_some() && first_is_self);
            let lo = self
                .calls
                .partition_point(|c| c.start_byte() < f.node.start_byte());
            let hi = self
                .calls
                .partition_point(|c| c.start_byte() < f.node.end_byte());
            let mut to_call = Vec::new();
            for &call in &self.calls[lo..hi] {
                let positional = positional(call);
                if positional.is_empty() {
                    continue;
                }
                for (p, decls) in f.params.iter().enumerate().skip(shift) {
                    for &d in decls {
                        let decl = &self.m.decls[d];
                        let Some(k) = positional
                            .iter()
                            .position(|a| passes_directly(*a, &decl.name, self.src))
                        else {
                            continue;
                        };
                        let Some(callee) = self.callee_of(call) else {
                            continue;
                        };
                        to_call.push((
                            p - shift,
                            vec![
                                Step {
                                    node: decl.node,
                                    message: format!("`{fname}`'s parameter `{}`", decl.name),
                                },
                                Step {
                                    node: call,
                                    message: format!("passed to `{}`", callee.display()),
                                },
                            ],
                            callee,
                            k,
                        ));
                    }
                }
            }
            // A value it returns built straight from a parameter: a query
            // builder's.
            let returns = self.returns_of(j);
            let mut to_return = Vec::new();
            for (p, decls) in f.params.iter().enumerate().skip(shift) {
                for &d in decls {
                    let decl = &self.m.decls[d];
                    if returns
                        .iter()
                        .any(|r| passes_directly(*r, &decl.name, self.src))
                    {
                        to_return.push((
                            p - shift,
                            vec![Step {
                                node: decl.node,
                                message: format!("`{fname}`'s parameter `{}`", decl.name),
                            }],
                        ));
                    }
                }
            }
            if !to_call.is_empty() || !to_return.is_empty() {
                out.push(SummaryFact {
                    key,
                    returns_sql: self.kind == SinkKind::Sql
                        && returns.iter().any(|r| self.reads_as_sql(*r, 3)),
                    to_sink: Vec::new(),
                    to_return,
                    returns_source: None,
                    to_call,
                });
            }
        }
        out
    }

    /// The summaries of the functions other modules can import: the
    /// module's functions, by name, and its classes' methods, by class and
    /// method, their parameters counted after `self`.
    fn exported_summaries(&self, state: &State<'t>) -> Vec<SummaryFact<'t>> {
        let mut out = Vec::new();
        for (j, f) in self.m.functions.iter().enumerate() {
            if out.len() >= MAX_SUMMARIES {
                continue;
            }
            let Some(key) = self.export_key(j) else {
                continue;
            };
            if !self.worth_summarizing(j) {
                continue;
            }
            let summary = self.summary(j);
            let returns_source = self
                .returns_of(j)
                .iter()
                .find_map(|r| self.taint(*r, state, 0).filter(|p| !from_call(p)))
                .map(cap);
            if summary.to_sink.is_empty()
                && summary.to_return.is_empty()
                && summary.to_call.is_empty()
                && returns_source.is_none()
            {
                continue;
            }
            // A method's `self` isn't one of its call's arguments.
            let first_is_self = f
                .params
                .first()
                .and_then(|d| d.first())
                .is_some_and(|d| matches!(self.m.decls[*d].name.as_str(), "self" | "cls"));
            let shift = |p: usize| {
                if key.member.is_some() && first_is_self {
                    p.checked_sub(1)
                } else {
                    Some(p)
                }
            };
            out.push(SummaryFact {
                returns_sql: summary.returns_sql,
                to_sink: summary
                    .to_sink
                    .iter()
                    .filter_map(|(p, path, sink)| Some((shift(*p)?, path.clone(), *sink)))
                    .collect(),
                to_return: summary
                    .to_return
                    .iter()
                    .filter_map(|(p, path)| Some((shift(*p)?, path.clone())))
                    .collect(),
                returns_source,
                to_call: summary
                    .to_call
                    .iter()
                    .filter_map(|(p, path, c, a)| Some((shift(*p)?, path.clone(), c.clone(), *a)))
                    .collect(),
                key,
            });
        }
        out
    }

    /// The sink a call is for this analysis's kind: its name, and the
    /// arguments that take the value.
    fn sink(&self, call: Node<'t>) -> Option<SinkCall<'t>> {
        if let Some(found) = self.sink_calls.borrow().get(&call.id()) {
            return found.clone();
        }
        let found = self.resolve_sink(call);
        self.sink_calls
            .borrow_mut()
            .insert(call.id(), found.clone());
        found
    }

    fn resolve_sink(&self, call: Node<'t>) -> Option<SinkCall<'t>> {
        let callee = call.child_by_field_name("function")?;
        let positional = arguments(call)
            .into_iter()
            .filter(|a| a.kind() != "keyword_argument")
            .collect::<Vec<_>>();
        let keyword = |k: &str| {
            arguments(call)
                .into_iter()
                .filter(|a| a.kind() == "keyword_argument")
                .find(|a| {
                    a.child_by_field_name("name")
                        .is_some_and(|n| self.text(n) == k)
                })
                .and_then(|a| a.child_by_field_name("value"))
        };
        let pick = |spec: Args| -> Vec<Node<'t>> {
            match spec {
                Args::First => positional.iter().take(1).copied().collect(),
                Args::Second => positional.iter().skip(1).take(1).copied().collect(),
                Args::FirstTwo => positional.iter().take(2).copied().collect(),
                Args::Third => positional.iter().skip(2).take(1).copied().collect(),
            }
        };
        // `eval(x)`, `open(p)`: builtins, when nothing in the file shadows them.
        if callee.kind() == "identifier" && self.decl(callee).is_none() {
            let name = self.text(callee);
            return BUILTIN_SINKS
                .iter()
                .find(|(b, k, _)| *b == name && *k == self.kind)
                .map(|(_, _, spec)| (name.to_string(), pick(*spec)));
        }
        if let Some((module, name)) = self.qualified(callee) {
            let found = MODULE_SINKS.iter().find(|(m, names, k, _)| {
                *k == self.kind
                    && names.contains(&name.as_str())
                    && (*m == module || module.starts_with(&format!("{m}.")))
            });
            if let Some((_, _, _, spec)) = found {
                let mut args = pick(*spec);
                // `subprocess.run([prog, arg])`: without a shell, only the
                // program is a command; `args=` and `url=` too.
                if self.kind == SinkKind::Command {
                    if args.is_empty() {
                        args.extend(keyword("args"));
                    }
                    let shell = keyword("shell").is_some_and(|v| self.text(v) == "True");
                    if !shell && module == "subprocess" {
                        args = args
                            .into_iter()
                            .map(|a| match a.kind() {
                                "list" | "tuple" => children(a).into_iter().next().unwrap_or(a),
                                _ => a,
                            })
                            .collect();
                    }
                }
                if self.kind == SinkKind::Ssrf && args.is_empty() {
                    args.extend(keyword("url"));
                }
                return Some((name, args));
            }
            if self.kind == SinkKind::Sql
                && SQL_RAW.contains(&name.as_str())
                && module.starts_with("sqlalchemy")
            {
                return Some((name, pick(Args::First)));
            }
            return None;
        }
        let (receiver, method_name) = method(call)?;
        let name = self.text(method_name).to_string();
        // An instance of a module: `session.get(url)`.
        if receiver.kind() == "identifier"
            && let Some(module) = self.decl(receiver).and_then(|d| self.instances.get(&d))
        {
            return INSTANCE_SINKS
                .iter()
                .find(|(m, names, k, _)| {
                    *k == self.kind && m == module && names.contains(&name.as_str())
                })
                .map(|(_, _, _, spec)| {
                    let mut args = pick(*spec);
                    if args.is_empty() {
                        args.extend(keyword("url"));
                    }
                    (name.clone(), args)
                });
        }
        match self.kind {
            // `Path(p).read_text()`: the path object is what's used.
            SinkKind::Path
                if PATH_METHODS.contains(&name.as_str()) && self.is_path_object(receiver) =>
            {
                Some((name, vec![receiver]))
            }
            SinkKind::Sql
                if SQL_EXECUTE.contains(&name.as_str()) || SQL_RAW.contains(&name.as_str()) =>
            {
                Some((name, pick(Args::First)))
            }
            SinkKind::XPath if name == "xpath" => Some((name, pick(Args::First))),
            // python-ldap's `search_s(base, scope, filter)`, ldap3's
            // `search(base, filter)`, in a file that imports them.
            SinkKind::Ldap if self.imports_module("ldap") && name.starts_with("search") => {
                Some((name, pick(Args::Third)))
            }
            SinkKind::Ldap if self.imports_module("ldap3") && name == "search" => {
                Some((name, pick(Args::Second)))
            }
            _ => None,
        }
    }

    fn imports_module(&self, module: &str) -> bool {
        self.imports.values().any(|i| i.module == module)
    }

    /// Whether the text a query was built from reads as SQL.
    fn reads_as_sql(&self, n: Node<'t>, depth: u8) -> bool {
        let mut text = String::new();
        let mut names = Vec::new();
        let mut stack = vec![n];
        while let Some(c) = stack.pop() {
            match c.kind() {
                "string_content" => text.push_str(self.text(c)),
                "identifier" => names.push(c),
                // A helper of this file: what it returns.
                "call" if depth > 0 && self.local_function(c).is_some() => {
                    if let Some(j) = self.local_function(c)
                        && self
                            .returns_of(j)
                            .iter()
                            .any(|r| self.reads_as_sql(*r, depth - 1))
                    {
                        return true;
                    }
                }
                _ => stack.extend(children(c)),
            }
        }
        if looks_like_sql(&text) {
            return true;
        }
        depth > 0
            && names.iter().filter_map(|i| self.decl(*i)).any(|d| {
                self.writes.iter().any(|w| {
                    w.target.kind() == "identifier"
                        && self.decl(w.target) == Some(d)
                        && self.reads_as_sql(w.value, depth - 1)
                })
            })
    }

    // ------------------------------------------------------------ checks

    /// Whether the function around a sink checked the value first.
    fn is_checked(&self, call: Node<'t>, arg: Node<'t>, path: &Path<'t>) -> bool {
        let scope = outermost_function(call, self.m);
        let key = scope.map_or(0, |s| s.id());
        let checked = self
            .checks
            .borrow_mut()
            .entry(key)
            .or_insert_with(|| Rc::new(scope.map(|s| self.checked_values(s)).unwrap_or_default()))
            .clone();
        let mut mentioned = vec![arg];
        let mut stack = children(arg);
        while let Some(c) = stack.pop() {
            if matches!(c.kind(), "identifier" | "attribute" | "subscript") {
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

    /// What a function checks before using it for this analysis's sink:
    /// - redirects and requests: Django's `url_has_allowed_host_and_scheme`,
    ///   functions named like a URL check (`is_safe_url`), `startswith`;
    /// - paths: functions named like a path check, `startswith`,
    ///   `is_relative_to`, `'..' in p`;
    /// - every sink: an allowlist (`x in ALLOWED`, `x in ('a', 'b')`) and a
    ///   whole-value pattern (`re.fullmatch(p, x)`).
    fn checked_values(&self, function: Node) -> HashSet<String> {
        let words: &[&str] = match self.kind {
            SinkKind::Redirect | SinkKind::Ssrf => &[
                "url", "redirect", "host", "safe", "allowed", "valid", "trusted", "domain",
                "origin",
            ],
            SinkKind::Path => &[
                "path", "within", "inside", "safe", "allowed", "valid", "sub",
            ],
            _ => &[],
        };
        let mut out = HashSet::new();
        let add_all = |n: Node, out: &mut HashSet<String>| {
            let mut stack = vec![n];
            while let Some(c) = stack.pop() {
                if matches!(c.kind(), "identifier" | "attribute" | "subscript" | "call") {
                    out.insert(self.text(c).to_string());
                }
                stack.extend(children(c));
            }
        };
        let mut stack = vec![function];
        while let Some(n) = stack.pop() {
            stack.extend(children(n));
            match n.kind() {
                // `x in ALLOWED`, `x in ('asc', 'desc')`.
                "comparison_operator" => {
                    let ops: Vec<&str> = (0..n.child_count())
                        .filter_map(|i| n.child(i))
                        .filter(|c| !c.is_named())
                        .map(|c| self.text(c))
                        .collect();
                    let parts = children(n);
                    let membership = ops.iter().any(|o| matches!(*o, "in" | "not in"));
                    if membership && let (Some(value), Some(set)) = (parts.first(), parts.get(1)) {
                        let allowlist = matches!(set.kind(), "list" | "tuple" | "set")
                            || ["allow", "white", "trusted", "permitted", "safe", "valid"]
                                .iter()
                                .any(|w| self.text(*set).to_ascii_lowercase().contains(w));
                        if allowlist {
                            out.insert(self.text(*value).to_string());
                        }
                    }
                    // `'..' in p`
                    if self.kind == SinkKind::Path
                        && matches!(ops.first(), Some(&"in") | Some(&"not in"))
                        && parts
                            .first()
                            .is_some_and(|v| string_value(self.text(*v)) == "..")
                        && let Some(p) = parts.get(1)
                    {
                        add_all(*p, &mut out);
                    }
                }
                "call" => {
                    let Some(callee) = n.child_by_field_name("function") else {
                        continue;
                    };
                    let (receiver, name) = match method(n) {
                        Some((r, m)) => (Some(r), self.text(m)),
                        None => (None, self.text(callee)),
                    };
                    let lower = name.trim_start_matches('_').to_ascii_lowercase();
                    let named_check = [
                        "is_", "validate", "assert", "check", "ensure", "verify", "sanitize",
                        "allow", "safe", "can_", "has_",
                    ]
                    .iter()
                    .any(|p| lower.starts_with(p))
                        && words.iter().any(|w| lower.contains(w));
                    let django = name == "url_has_allowed_host_and_scheme";
                    if named_check || django {
                        for a in arguments(n) {
                            add_all(a, &mut out);
                        }
                    }
                    if let Some(r) = receiver {
                        if !words.is_empty() && matches!(name, "startswith" | "is_relative_to") {
                            add_all(r, &mut out);
                        }
                        // `re.fullmatch(p, x)`, `PATTERN.fullmatch(x)`, and
                        // `re.match(r"^[a-z_]+$", x)`: a whole value.
                        let args = arguments(n);
                        let anchored = |pattern: Option<&Node>| {
                            pattern.is_some_and(|p| {
                                let t = string_value(self.text(*p));
                                t.starts_with('^') && (t.ends_with('$') || t.ends_with("\\Z"))
                            })
                        };
                        let whole = name == "fullmatch"
                            || (matches!(name, "match" | "search")
                                && (anchored(args.first().filter(|_| args.len() >= 2))
                                    || self.compiled_anchored(r)));
                        if whole && let Some(last) = args.last() {
                            out.insert(self.text(*last).to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// A name set to `re.compile(r"^…$")`.
    fn compiled_anchored(&self, n: Node) -> bool {
        n.kind() == "identifier"
            && self
                .decl(n)
                .and_then(|d| self.m.decls[d].declarator)
                .and_then(|a| a.child_by_field_name("right"))
                .filter(|v| v.kind() == "call")
                .and_then(|c| arguments(c).into_iter().next())
                .is_some_and(|p| {
                    let t = string_value(self.text(p));
                    t.starts_with('^') && (t.ends_with('$') || t.ends_with("\\Z"))
                })
    }

    /// Values a sink's branch knows the text of: `if host == 'a.com': …`.
    fn equal_to_literal(&self, sink: Node) -> HashSet<String> {
        let mut out = HashSet::new();
        let mut child = sink;
        while let Some(p) = child.parent() {
            let (condition, branch) = match p.kind() {
                "if_statement" | "elif_clause" => (
                    p.child_by_field_name("condition"),
                    p.child_by_field_name("consequence"),
                ),
                _ => (None, None),
            };
            if let (Some(c), Some(b)) = (condition, branch)
                && b.id() == child.id()
            {
                let mut terms = vec![c];
                while let Some(t) = terms.pop() {
                    match t.kind() {
                        "boolean_operator" => terms.extend(children(t)),
                        "comparison_operator" => {
                            let parts = children(t);
                            let op = (0..t.child_count())
                                .filter_map(|i| t.child(i))
                                .find(|c| !c.is_named())
                                .map(|c| self.text(c));
                            if op == Some("==")
                                && let (Some(l), Some(r)) = (parts.first(), parts.get(1))
                            {
                                if r.kind() == "string" {
                                    out.insert(self.text(*l).to_string());
                                } else if l.kind() == "string" {
                                    out.insert(self.text(*r).to_string());
                                }
                            }
                            // `if plugin in plugins:`: one of a collection's
                            // values, not a substring of a text.
                            if op == Some("in")
                                && let (Some(l), Some(r)) = (parts.first(), parts.get(1))
                                && r.kind() != "string"
                            {
                                out.insert(self.text(*l).to_string());
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

    // ------------------------------------------------------------ helpers (T3)

    /// The function of this file a call calls: `build(x)`, or a method of
    /// the same class through `self.build(x)`.
    fn local_function(&self, call: Node<'t>) -> Option<usize> {
        if let Some(j) = self.local_calls.borrow().get(&call.id()) {
            return *j;
        }
        let j = self.resolve_local(call);
        self.local_calls.borrow_mut().insert(call.id(), j);
        j
    }

    fn resolve_local(&self, call: Node<'t>) -> Option<usize> {
        let callee = call.child_by_field_name("function")?;
        let function = match callee.kind() {
            "identifier" => {
                let decl = &self.m.decls[self.decl(callee)?];
                decl.node
                    .parent()
                    .filter(|p| p.kind() == "function_definition")?
            }
            "attribute" => {
                let object = callee.child_by_field_name("object")?;
                if !matches!(self.text(object), "self" | "cls") {
                    return None;
                }
                let name = self.text(callee.child_by_field_name("attribute")?);
                let class = std::iter::successors(call.parent(), |p| p.parent())
                    .find(|p| p.kind() == "class_definition")?;
                let body = class.child_by_field_name("body")?;
                children(body)
                    .into_iter()
                    .map(|c| {
                        if c.kind() == "decorated_definition" {
                            c.child_by_field_name("definition").unwrap_or(c)
                        } else {
                            c
                        }
                    })
                    .find(|c| {
                        c.kind() == "function_definition"
                            && c.child_by_field_name("name")
                                .is_some_and(|n| self.text(n) == name)
                    })?
            }
            _ => return None,
        };
        self.fn_index.get(&function.id()).copied()
    }

    /// The argument a call passes to parameter `p` of function `j`: by
    /// keyword, else by position, after `self` for a method.
    fn argument_for(&self, call: Node<'t>, j: usize, p: usize) -> Option<Node<'t>> {
        let f = self.m.functions[j].node;
        let names: Vec<&str> = f
            .child_by_field_name("parameters")
            .map(children)
            .unwrap_or_default()
            .into_iter()
            .map(|n| param_name(n).map_or("", |x| self.text(x)))
            .collect();
        let name = *names.get(p)?;
        let args = arguments(call);
        if let Some(k) = args.iter().find(|a| {
            a.kind() == "keyword_argument"
                && a.child_by_field_name("name")
                    .is_some_and(|n| self.text(n) == name)
        }) {
            return k.child_by_field_name("value");
        }
        let through_self = call
            .child_by_field_name("function")
            .is_some_and(|c| c.kind() == "attribute");
        let offset =
            usize::from(through_self && matches!(names.first(), Some(&"self") | Some(&"cls")));
        let index = p.checked_sub(offset)?;
        args.into_iter()
            .filter(|a| a.kind() != "keyword_argument")
            .nth(index)
    }

    fn function_name(&self, j: usize) -> String {
        self.m.functions[j]
            .node
            .child_by_field_name("name")
            .map_or_else(|| "lambda".to_string(), |n| self.text(n).to_string())
    }

    fn through_local(
        &self,
        call: Node<'t>,
        j: usize,
        state: &State<'t>,
        d: u32,
    ) -> Option<Path<'t>> {
        let summary = self.summary(j);
        let name = self.function_name(j);
        summary.to_return.iter().find_map(|(p, inner)| {
            let mut path = self.taint(self.argument_for(call, j, *p)?, state, d)?;
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
        let returns = self.returns_of(j);
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
                .filter(|&&d| !matches!(self.m.decls[d].name.as_str(), "self" | "cls"))
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
                .collect::<HashMap<_, _>>();
            if tainted.is_empty() {
                continue;
            }
            let start = State {
                tainted,
                requests: self.initial.requests.clone(),
                uploads: HashSet::new(),
                from_calls: false,
            };
            let Some(state) = self.run(start, Some(f.node)) else {
                continue;
            };
            // A value the helper checked before returning it, such as a
            // path it made sure stays in its directory, is safe.
            if let Some(path) = returns.iter().find_map(|r| {
                self.taint(*r, &state, 0)
                    .filter(|path| !self.is_checked(*r, *r, path))
            }) {
                summary.to_return.push((p, cap(path)));
            }
            let from_param = |path: &Path<'t>| {
                path.first().is_some_and(|s| {
                    decls
                        .iter()
                        .any(|d| self.m.decls[*d].node.id() == s.node.id())
                })
            };
            for r in self.reached(Some(f.node), &state) {
                match r {
                    Reach::Sink { path, sink } if from_param(&path) => {
                        summary.to_sink.push((p, cap(path), sink));
                    }
                    Reach::Open {
                        mut path,
                        callee,
                        arg,
                        call,
                    } if from_param(&path) => {
                        path.push(Step {
                            node: call,
                            message: format!("passed to `{}`", callee.display()),
                        });
                        summary.to_call.push((p, cap(path), callee, arg));
                    }
                    _ => {}
                }
            }
        }
        summary
    }
}

/// A sink reached: by a request's value, or by another file's function's
/// result, which the project pass follows.
fn reach_sink<'t>(path: Path<'t>, sink: Node<'t>, needs_sql: bool) -> Reach<'t> {
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

/// A variable whose path no later write replaces: a request's value.
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

/// Whether `name` reaches an argument as it is: the argument itself, a
/// member of it (`user.id`), or a part of a concatenation, a `%` or an
/// f-string, not inside another call.
fn passes_directly(arg: Node, name: &str, src: &[u8]) -> bool {
    let text = |n: Node| n.utf8_text(src).unwrap_or_default();
    let mut stack = vec![arg];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" if text(n) == name => return true,
            "attribute" | "subscript" => stack.extend(n.named_child(0)),
            "binary_operator"
            | "string"
            | "interpolation"
            | "parenthesized_expression"
            | "concatenated_string" => stack.extend(children(n)),
            _ => {}
        }
    }
    false
}

/// A call's positional arguments.
fn positional(call: Node) -> Vec<Node> {
    arguments(call)
        .into_iter()
        .filter(|a| {
            !matches!(
                a.kind(),
                "keyword_argument" | "dictionary_splat" | "list_splat"
            )
        })
        .collect()
}

// ---------------------------------------------------------------- syntax

fn children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c)
        .filter(|c| c.kind() != "comment")
        .collect()
}

fn unwrap(mut n: Node) -> Node {
    while matches!(n.kind(), "parenthesized_expression" | "await") {
        match n.named_child(0) {
            Some(c) => n = c,
            None => break,
        }
    }
    n
}

fn arguments(call: Node) -> Vec<Node> {
    call.child_by_field_name("arguments")
        .filter(|a| a.kind() == "argument_list")
        .map(children)
        .unwrap_or_default()
}

/// A method call's receiver and name: `cursor.execute(q)`.
fn method(call: Node) -> Option<(Node, Node)> {
    let f = call.child_by_field_name("function")?;
    if f.kind() != "attribute" {
        return None;
    }
    Some((
        f.child_by_field_name("object")?,
        f.child_by_field_name("attribute")?,
    ))
}

/// A parameter's name: `x`, `x: str`, `x=1`, `*args`.
fn param_name(p: Node) -> Option<Node> {
    match p.kind() {
        "identifier" => Some(p),
        "default_parameter" | "typed_default_parameter" => p.child_by_field_name("name"),
        "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => {
            children(p).into_iter().find(|c| c.kind() == "identifier")
        }
        _ => None,
    }
}

/// The last name of a type: `fastapi.Request` is `Request`.
fn last_name(t: &str) -> &str {
    let t = t.split('[').next().unwrap_or(t).trim();
    t.rsplit('.').next().unwrap_or(t)
}

/// Whether a route's path converts a parameter to a number:
/// `<int:id>`, `{id:int}`.
fn numeric_converter(route: &str, name: &str) -> bool {
    ["int", "float", "uuid"].iter().any(|c| {
        route.contains(&format!("<{c}:{name}>")) || route.contains(&format!("{{{name}:{c}}}"))
    })
}

fn names_in(p: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut stack = vec![p];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => out.push(n),
            "pattern_list"
            | "tuple_pattern"
            | "list_pattern"
            | "tuple"
            | "list"
            | "list_splat_pattern"
            | "parenthesized_expression" => stack.extend(children(n)),
            _ => {}
        }
    }
    out
}

/// A string literal's text without its quotes and prefix.
fn string_value(t: &str) -> &str {
    let t = t.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    t.trim_matches(|c| c == '"' || c == '\'')
}

fn is_text(n: Node) -> bool {
    matches!(n.kind(), "string" | "concatenated_string")
}

/// A concatenation, a formatting or an f-string with a value in it.
fn is_built(n: Node) -> bool {
    match n.kind() {
        "binary_operator" => true,
        "string" => children(n).iter().any(|c| c.kind() == "interpolation"),
        _ => false,
    }
}

/// A concatenation's or f-string's parts, in order.
fn url_parts(n: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut stack = vec![n];
    while let Some(p) = stack.pop() {
        match p.kind() {
            "binary_operator" => {
                stack.extend(p.child_by_field_name("right"));
                stack.extend(p.child_by_field_name("left"));
            }
            "parenthesized_expression" => stack.extend(p.named_child(0)),
            _ => out.push(p),
        }
    }
    out
}

/// Whether text of the program's own, before a request's value, fixes a
/// URL's host: an absolute URL with a host, a local path, or a path
/// separator, query or fragment after the start.
fn fixed(before: &str) -> bool {
    let absolute = before.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
            && rest.find('/').is_some_and(|slash| slash > 0)
    });
    let b = before.as_bytes();
    let separated = before.contains(['?', '#'])
        || (0..b.len()).any(|i| {
            b[i] == b'/'
                && (i == 0 || b[i - 1] != b'/')
                && b.get(i + 1).is_some_and(|&c| c != b'/' && c != b'\\')
        });
    absolute || separated
}

fn within(n: Node, outer: Node) -> bool {
    outer.start_byte() <= n.start_byte() && n.end_byte() <= outer.end_byte()
}

/// A source read further, `request.args` then `request.args['q']`.
fn deepen<'t>(mut path: Path<'t>, object: Node<'t>, n: Node<'t>) -> Path<'t> {
    if path.len() == 1 && path[0].node.id() == object.id() {
        path[0].node = n;
    }
    path
}

/// A function's return values: its `return`s, not nested functions', and
/// a lambda's body.
fn return_values<'t>(f: Node<'t>, functions: &HashMap<usize, usize>) -> Vec<Node<'t>> {
    let Some(body) = f.child_by_field_name("body") else {
        return Vec::new();
    };
    if f.kind() == "lambda" {
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

/// The outermost function around a node: the handler.
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

    fn py(rule: &str, src: &str) -> Vec<Issue> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("app.py", Lang::Python, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues.into_iter().filter(|i| i.rule == rule).collect()
    }

    fn flow(i: &Issue) -> Vec<&str> {
        i.flow.iter().map(|s| s.message.as_str()).collect()
    }

    const FLASK: &str =
        "from flask import Flask, request, redirect, send_file\napp = Flask(__name__)\n";

    /// A Flask route around `body`, indented.
    fn route(head: &str, body: &str) -> String {
        let body: String = body.lines().map(|l| format!("    {l}\n")).collect();
        format!("{head}\n{FLASK}@app.route('/x')\ndef view():\n{body}")
    }

    const SQL: &str = "py/sql-injection";
    const CMD: &str = "py/command-injection";
    const PATH: &str = "py/path-injection";
    const REDIRECT: &str = "py/open-redirect";
    const SSRF: &str = "py/ssrf";
    const CODE: &str = "py/code-injection";

    #[test]
    fn a_request_value_formatted_into_sql_is_reported_with_its_path() {
        let src = route(
            "",
            "q = \"SELECT * FROM o WHERE id = '%s'\" % request.args['id']\ncursor.execute(q)",
        );
        let found = py(SQL, &src);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            flow(&found[0]),
            [
                "the request's `args`",
                "concatenated into `q`",
                "passed to `execute`"
            ]
        );
        assert_eq!(
            found[0].flow.iter().map(|s| s.line).collect::<Vec<_>>(),
            [6, 6, 7]
        );
    }

    #[test]
    fn sql_built_every_way() {
        for body in [
            "cursor.execute(f\"SELECT * FROM o WHERE id = {request.args['id']}\")",
            "cursor.execute(\"SELECT * FROM o WHERE id = {}\".format(request.form['id']))",
            "cursor.execute('SELECT * FROM o WHERE id = ' + request.values.get('id'))",
            "name = request.json['name'].strip()\ncursor.execute('DELETE FROM u WHERE name = %s' % name)",
            "w = []\nw.append('id = ' + request.args['id'])\ncursor.execute('SELECT * FROM o WHERE ' + ' AND '.join(w))",
            "User.objects.raw('SELECT * FROM u WHERE n = ' + request.args['n'])",
        ] {
            assert_eq!(py(SQL, &route("", body)).len(), 1, "{body}");
        }
        let alchemy = route(
            "from sqlalchemy import text",
            "db.execute(text('SELECT * FROM o WHERE id = ' + request.args['id']))",
        );
        assert_eq!(py(SQL, &alchemy).len(), 1);
    }

    #[test]
    fn parameterized_numeric_and_constant_sql_is_not() {
        for body in [
            "cursor.execute('SELECT * FROM o WHERE id = %s', (request.args['id'],))",
            "cursor.execute('SELECT * FROM o WHERE id = %s' % int(request.args['id']))",
            "cursor.execute('SELECT * FROM o LIMIT %d' % len(request.args['q']))",
            "t = 'orders'\ncursor.execute('SELECT * FROM ' + t)",
            // Not SQL text.
            "cache.execute(request.args['k'])",
        ] {
            assert!(py(SQL, &route("", body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn frameworks_sources() {
        let sink = "cursor.execute('SELECT * FROM o WHERE id = ' + ";
        let cases = [
            // Flask's route parameter, and `flask.request`.
            format!(
                "import flask\napp = flask.Flask(__name__)\n@app.route('/o/<oid>')\ndef show(oid):\n    {sink}oid)\n"
            ),
            format!(
                "import flask\n@app.route('/o')\ndef show():\n    {sink}flask.request.args['id'])\n"
            ),
            // Django: the request's members, and a URL parameter.
            format!("def detail(request, slug):\n    {sink}request.GET['id'])\n"),
            format!("def detail(request, slug):\n    {sink}slug)\n"),
            format!(
                "class V(View):\n    def get(self, request, slug):\n        {sink}request.POST.get('id'))\n"
            ),
            // FastAPI: a path operation's parameters, and its request.
            format!(
                "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/items/{{item_id}}')\nasync def item(item_id: str, q: str = None):\n    {sink}q)\n"
            ),
            format!(
                "from fastapi import Request\n@router.post('/x')\nasync def x(request: Request):\n    body = await request.json()\n    {sink}body['id'])\n"
            ),
            // aiohttp.
            format!("async def handler(request):\n    {sink}request.match_info['id'])\n"),
        ];
        for src in &cases {
            assert_eq!(py(SQL, src).len(), 1, "{src}");
        }
        for src in [
            // A numeric converter, a number, and a dependency.
            format!(
                "from flask import Flask\napp = Flask(__name__)\n@app.route('/o/<int:oid>')\ndef show(oid):\n    {sink}oid)\n"
            ),
            format!(
                "@app.get('/items/{{item_id}}')\nasync def item(item_id: int):\n    {sink}item_id)\n"
            ),
            format!("@app.get('/items')\nasync def item(db = Depends(get_db)):\n    {sink}db)\n"),
            // An ordinary function.
            format!("def helper(slug):\n    {sink}slug)\n"),
        ] {
            assert!(py(SQL, &src).is_empty(), "{src}");
        }
    }

    #[test]
    fn commands() {
        for (head, body) in [
            ("import os", "os.system('ping ' + request.args['h'])"),
            ("import os", "os.popen(f\"ls {request.args['d']}\")"),
            (
                "import subprocess",
                "subprocess.run('ls ' + request.args['d'], shell=True)",
            ),
            (
                "import subprocess",
                "subprocess.Popen([request.args['prog'], '-v'])",
            ),
            (
                "from subprocess import check_output",
                "check_output(request.args['c'], shell=True)",
            ),
        ] {
            assert_eq!(py(CMD, &route(head, body)).len(), 1, "{body}");
        }
        for (head, body) in [
            // An argument of a fixed program, without a shell.
            (
                "import subprocess",
                "subprocess.run(['ping', '-c', '1', request.args['h']])",
            ),
            (
                "import subprocess, shlex",
                "subprocess.run('ls ' + shlex.quote(request.args['d']), shell=True)",
            ),
            ("", "system('ping ' + request.args['h'])"),
        ] {
            assert!(py(CMD, &route(head, body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn paths_and_their_checks() {
        for (head, body) in [
            ("", "open('/srv/' + request.args['f'])"),
            (
                "import os",
                "os.remove(os.path.join('/srv', request.args['f']))",
            ),
            ("import shutil", "shutil.rmtree(request.form['d'])"),
            (
                "from pathlib import Path",
                "Path('/srv') / request.args['f']\nPath(request.args['f']).read_text()",
            ),
            ("", "send_file(request.args['f'])"),
            (
                "",
                "f = request.files['doc']\nopen('/up/' + f.filename, 'wb')",
            ),
        ] {
            assert_eq!(py(PATH, &route(head, body)).len(), 1, "{body}");
        }
        for (head, body) in [
            (
                "import os",
                "open('/srv/' + os.path.basename(request.args['f']))",
            ),
            (
                "from werkzeug.utils import secure_filename",
                "open('/up/' + secure_filename(request.files['doc'].filename), 'wb')",
            ),
            (
                "import os",
                "p = os.path.realpath(os.path.join('/srv', request.args['f']))\nif not p.startswith('/srv/'):\n    return\nopen(p)",
            ),
            (
                "",
                "f = request.args['f']\nif '..' in f:\n    return\nopen('/srv/' + f)",
            ),
            // Where the upload was stored is the server's.
            (
                "",
                "f = request.files['doc']\nf.save('/up/x')\nopen(f.stream.name)",
            ),
        ] {
            assert!(py(PATH, &route(head, body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn redirects_their_fixed_prefixes_and_checks() {
        for body in [
            "return redirect(request.args['next'])",
            "return redirect(request.args.get('next') or '/')",
            "return redirect('//' + request.args['h'])",
        ] {
            assert_eq!(py(REDIRECT, &route("", body)).len(), 1, "{body}");
        }
        let django = "from django.http import HttpResponseRedirect\ndef v(request):\n    return HttpResponseRedirect(request.GET['next'])\n";
        assert_eq!(py(REDIRECT, django).len(), 1);
        for body in [
            "return redirect('/orders/' + request.args['id'])",
            "return redirect(f\"/orders/{request.args['id']}\")",
            "return redirect('https://example.com/' + request.args['p'])",
            "n = request.args['next']\nif n in ALLOWED_URLS:\n    return redirect(n)",
            "n = request.args['next']\nif not is_safe_url(n):\n    return\nreturn redirect(n)",
        ] {
            assert!(py(REDIRECT, &route("", body)).is_empty(), "{body}");
        }
        let checked = "from django.shortcuts import redirect\nfrom django.utils.http import url_has_allowed_host_and_scheme\n\
                       def v(request):\n    n = request.GET['next']\n    \
                       if url_has_allowed_host_and_scheme(n, allowed_hosts={request.get_host()}):\n        return redirect(n)\n";
        assert!(py(REDIRECT, checked).is_empty());
    }

    #[test]
    fn server_side_requests() {
        for (head, body) in [
            ("import requests", "requests.get(request.args['url'])"),
            (
                "import requests",
                "requests.request('GET', request.args['url'])",
            ),
            (
                "import httpx",
                "httpx.post(f\"http://{request.args['host']}/x\")",
            ),
            (
                "import urllib.request",
                "urllib.request.urlopen(request.args['u'])",
            ),
            (
                "import requests",
                "s = requests.Session()\ns.get(request.args['u'])",
            ),
        ] {
            assert_eq!(py(SSRF, &route(head, body)).len(), 1, "{body}");
        }
        for (head, body) in [
            (
                "import requests",
                "requests.get('https://api.example.com/users/' + request.args['id'])",
            ),
            (
                "import requests",
                "requests.get(f\"https://api.example.com/u?q={request.args['q']}\")",
            ),
            (
                "import requests",
                "u = request.args['u']\nif u in ALLOWED_HOSTS:\n    requests.get(u)",
            ),
        ] {
            assert!(py(SSRF, &route(head, body)).is_empty(), "{body}");
        }
    }

    #[test]
    fn code_injection() {
        assert_eq!(py(CODE, &route("", "eval(request.form['expr'])")).len(), 1);
        assert_eq!(
            py(CODE, &route("", "exec('x = ' + request.args['v'])")).len(),
            1
        );
        assert!(
            py(
                CODE,
                &route("import ast", "ast.literal_eval(request.form['expr'])")
            )
            .is_empty()
        );
        assert!(py(CODE, &route("", "eval('1 + 1')")).is_empty());
    }

    #[test]
    fn helpers_of_the_same_file() {
        let src = format!(
            "{FLASK}def find(oid):\n    cursor.execute('SELECT * FROM o WHERE id = ' + oid)\n\n\
             def by_name(n):\n    return 'SELECT * FROM u WHERE name = ' + n\n\n\
             @app.route('/x')\ndef view():\n    find(request.args['id'])\n    cursor.execute(by_name(request.args['n']))\n"
        );
        let found = py(SQL, &src);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().any(|i| flow(i).contains(&"passed to `find`")));
        assert!(
            found
                .iter()
                .any(|i| flow(i).contains(&"returned by `by_name`"))
        );
        // A method of the same class, through `self`.
        let class = "class V(View):\n    def get(self, request):\n        self.run(request.GET['id'])\n\n    \
                     def run(self, oid):\n        cursor.execute('SELECT * FROM o WHERE id = ' + oid)\n";
        assert_eq!(py(SQL, class).len(), 1);
    }

    #[test]
    fn test_files_are_not_analyzed() {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let src = route("", "eval(request.form['expr'])");
        let file = analyze(
            "tests/test_app.py",
            Lang::Python,
            &src,
            &rules,
            &cfg,
            far_deadline(),
        )
        .unwrap();
        assert!(!file.issues.iter().any(|i| i.rule == CODE));
    }

    #[test]
    fn what_the_corpus_taught() {
        // `Path(p)` names a file; reading it is the sink, its name isn't.
        assert_eq!(
            py(
                PATH,
                &route(
                    "from pathlib import Path",
                    "Path('/srv', request.args['f']).read_text()"
                )
            )
            .len(),
            1
        );
        assert_eq!(
            py(
                PATH,
                &route(
                    "from pathlib import Path",
                    "p = Path('/srv') / request.args['f']\np.unlink()"
                )
            )
            .len(),
            1
        );
        for body in [
            "name = Path(request.args['f']).name\nopen('/up/' + name, 'wb')",
            "dest = Path('/up').joinpath(Path(request.args['f']).stem + '.zip')\ndest.open('wb')",
            "shutil.copyfileobj(request.files['f'], out)",
        ] {
            let head = "from pathlib import Path\nimport shutil";
            assert!(py(PATH, &route(head, body)).is_empty(), "{body}");
        }
        // Membership in its branch checks the value.
        let plugins = "import os\nplugins = os.listdir('/p')\nif request.args['p'] in plugins:\n    open(os.path.join('/p', request.args['p']))";
        assert!(py(PATH, &route("", plugins)).is_empty());
        // Check names: `_allow_redirect`, `safe_for_redirect`.
        for check in ["_allow_redirect(n)", "safe_for_redirect(n)"] {
            let body =
                format!("n = request.args['next']\nif n and {check}:\n    return redirect(n)");
            assert!(py(REDIRECT, &route("", &body)).is_empty(), "{check}");
        }
        // A redirect to the request's own path, or after a URL of this site.
        for body in [
            "return redirect(request.path)",
            "url = url_for('home')\nurl = f\"{url}&{request.query_string.decode()}\"\nreturn redirect(url)",
        ] {
            assert!(
                py(REDIRECT, &route("from flask import url_for", body)).is_empty(),
                "{body}"
            );
        }
        // The request's full URL is its sender's Host header.
        assert_eq!(
            py(REDIRECT, &route("", "return redirect(request.url)")).len(),
            1
        );
    }

    #[test]
    fn a_strings_replace_is_no_paths() {
        let body = "q = request.args['q']\nq = q.replace('a', 'b')\nreturn q";
        assert!(py(PATH, &route("", body)).is_empty());
        let body = "p = Path('/srv') / request.args['f']\np.replace('/tmp/x')";
        assert_eq!(py(PATH, &route("from pathlib import Path", body)).len(), 1);
    }

    #[test]
    fn checks_from_the_corpus() {
        let head = "import re\nfrom pathlib import Path\nNAME = re.compile(r'^[a-z_]+$')";
        for body in [
            "doc = request.args['doc']\nif not re.match(r'^[0-9a-z_]+$', doc):\n    return\nopen('/docs/' + doc)",
            "doc = request.args['doc']\nif not NAME.match(doc):\n    return\nopen('/docs/' + doc)",
            "ext = request.args['ext']\nif ext not in ALLOWED_EXTENSIONS:\n    return\nopen('/a/x.' + ext)",
        ] {
            assert!(py(PATH, &route(head, body)).is_empty(), "{body}");
        }
        // A pattern that matches part of the value doesn't check it.
        let partial =
            "doc = request.args['doc']\nif re.match(r'[a-z]', doc):\n    open('/docs/' + doc)";
        assert_eq!(py(PATH, &route(head, partial)).len(), 1);
        // A helper that makes sure its path stays in its directory.
        let src = format!(
            "from pathlib import Path\n{FLASK}def safe(name):\n    c = (Path('/b') / name).resolve()\n    \
             if not c.is_relative_to(Path('/b')):\n        raise ValueError()\n    return c\n\n\
             @app.route('/x')\ndef view():\n    safe(request.args['f']).unlink()\n"
        );
        assert!(py(PATH, &src).is_empty(), "{src}");
    }

    // ------------------------------------------------------------ across files (T4)

    fn project(files: &[(&str, &str)]) -> Vec<Issue> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<_> = files
            .iter()
            .map(|(path, src)| {
                analyze(path, Lang::Python, src, &rules, &cfg, far_deadline()).unwrap()
            })
            .collect();
        crate::analysis::taint_project_rules(&mut analyzed, &rules);
        analyzed
            .into_iter()
            .flat_map(|f| f.issues)
            .filter(|i| i.rule.starts_with("py/") && !i.flow.is_empty())
            .collect()
    }

    const VIEWS: &str = "from flask import Flask, request\napp = Flask(__name__)\n";

    #[test]
    fn a_request_value_into_another_modules_function() {
        let dao = "def find_student(sid):\n    cursor.execute(\"SELECT * FROM s WHERE id = '%s'\" % sid)\n";
        // The step names the callee as the import does: `dao.find_student`
        // when `dao` is the name imported from the package.
        for (import, call, shown) in [
            (
                "from .dao import find_student",
                "find_student",
                "find_student",
            ),
            (
                "from app.dao import find_student",
                "find_student",
                "find_student",
            ),
            ("from . import dao", "dao.find_student", "dao.find_student"),
            ("import app.dao as dao", "dao.find_student", "find_student"),
        ] {
            let views = format!(
                "{VIEWS}{import}\n@app.route('/s')\ndef show():\n    {call}(request.args['id'])\n"
            );
            let found = project(&[("app/views.py", &views), ("app/dao.py", dao)]);
            assert_eq!(found.len(), 1, "{import}: {found:?}");
            assert_eq!(found[0].path, "app/dao.py");
            assert_eq!(
                flow(&found[0]),
                [
                    "the request's `args`",
                    &*format!("passed to `{shown}`"),
                    "`find_student`'s parameter `sid`",
                    "passed to `execute`"
                ],
                "{import}"
            );
            assert_eq!(found[0].flow[0].path.as_deref(), Some("app/views.py"));
        }
    }

    #[test]
    fn methods_returns_and_hops() {
        // A class's method through an instance; `self` isn't an argument.
        let svc = "class UserService:\n    def find(self, uid):\n        cursor.execute('SELECT * FROM u WHERE id = ' + uid)\n";
        let views = format!(
            "{VIEWS}from .services import UserService\n@app.route('/u')\ndef show():\n    \
             svc = UserService()\n    svc.find(request.args['id'])\n"
        );
        let found = project(&[("app/views.py", &views), ("app/services.py", svc)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "app/services.py");
        // A query built in another module and run here.
        let sql = "def by_id(i):\n    return 'SELECT * FROM t WHERE id = ' + i\n";
        let views = format!(
            "{VIEWS}from .sql import by_id\n@app.route('/t')\ndef show():\n    cursor.execute(by_id(request.args['id']))\n"
        );
        let found = project(&[("app/views.py", &views), ("app/sql.py", sql)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "app/views.py");
        assert!(flow(&found[0]).contains(&"returned by `by_id`"));
        // Two hops: views, service, repository.
        let service = "from .repo import fetch\ndef lookup(key):\n    return fetch(key)\n";
        let repo = "def fetch(k):\n    cursor.execute(f\"SELECT * FROM t WHERE k = '{k}'\")\n";
        let views = format!(
            "{VIEWS}from .service import lookup\n@app.route('/k')\ndef show():\n    lookup(request.args['k'])\n"
        );
        let found = project(&[
            ("app/views.py", &views),
            ("app/service.py", service),
            ("app/repo.py", repo),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "app/repo.py");
    }

    #[test]
    fn what_doesnt_cross_python_files() {
        let views = format!(
            "{VIEWS}from .dao import find\nimport requests\n@app.route('/s')\ndef show():\n    find(request.args['id'])\n"
        );
        for dao in [
            "def find(sid):\n    cursor.execute('SELECT * FROM s WHERE id = %d' % int(sid))\n",
            "def find(sid):\n    cursor.execute('SELECT * FROM s WHERE id = %s', (sid,))\n",
            "def find(sid):\n    cursor.execute('SELECT * FROM s WHERE id = ' + sid)  # NOSONAR\n",
        ] {
            assert!(
                project(&[("app/views.py", &views), ("app/dao.py", dao)]).is_empty(),
                "{dao}"
            );
        }
    }

    #[test]
    fn a_service_without_sinks_passes_values_on() {
        // The service has neither a sink nor a request: its summary is read
        // from the syntax.
        let service = "from .repo import fetch\n\ndef lookup(key):\n    return fetch('k:' + key)\n";
        let repo = "def fetch(k):\n    cursor.execute(f\"SELECT * FROM t WHERE k = '{k}'\")\n";
        let views = format!(
            "{VIEWS}from .service import lookup\n@app.route('/k')\ndef show():\n    lookup(request.args['k'])\n"
        );
        let found = project(&[
            ("app/views.py", &views),
            ("app/service.py", service),
            ("app/repo.py", repo),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        // Through another call, which may sanitize it: no.
        let service = "from .repo import fetch\n\ndef lookup(key):\n    return fetch(int(key))\n";
        let found = project(&[
            ("app/views.py", &views),
            ("app/service.py", service),
            ("app/repo.py", repo),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }
}
