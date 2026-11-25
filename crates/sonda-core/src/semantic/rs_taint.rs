//! Taint analysis for Rust, phases T2 and T3 (ADR-0027): which values that
//! came from a request reach a sink, and by what path.
//!
//! Like the other languages', it's **flow-insensitive** over the scopes of
//! Rust's binder (S1): a variable that is ever assigned a request's value holds
//! it wherever the binding is visible, and the whole file is one fixed point
//! over its writes. A function of the file is followed through its summary
//! (T3), per parameter.
//!
//! Precision before recall, as the ADR says:
//! - a call this module doesn't know returns an untainted value, so a
//!   program's own escaping helper sanitizes, and `parse::<u32>()`, `len()` and
//!   the like are numbers, which can't inject;
//! - a field of a request's struct is as inert as its type in the file says
//!   (`page: u32`);
//! - a value that's tested in the file by a call that reads as a check
//!   (`starts_with`, `contains`, `canonicalize`, ...) is taken as validated;
//! - the request object itself isn't tainted, only what it returns.
//!
//! Sources are the parameters of a web handler, extracted from the request
//! (axum's and actix-web's `Query`, `Path`, `Json`, `Form`, ...), those of a
//! function with a route attribute (`#[get("/<id>")]`), and what a request
//! object's methods return (`req.query_string()`, `req.headers()`).
//!
//! Values are followed through other files (T4), in both directions: into
//! another file's function, and out of it, when it returns one.

use super::taint::{Callee, Facts, Finding, Key, ReturnFact, SinkKind, Step, TaintResult};
use super::taint_core::{
    Exports, Flow, How, Path, Reaches, Summaries, Write, at_sinks, best, calls_in, checked_names,
    decl_index, exports_for, finish, flow_for, from_call, held, inside, maybe_path, outcome,
    record_return_at_sink, return_values, short, sinks_in, sure_path, through_returns,
    through_sinks, tick, walk,
};
use super::{DeclId, Model};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;
/// Summaries per file, at most: past it, calls to other functions give nothing.
const MAX_SUMMARIES: usize = 256;

/// Crates a call into is no call to the project's own modules.
const LIBRARY_CRATES: &[&str] = &[
    "std",
    "core",
    "alloc",
    "tokio",
    "serde",
    "serde_json",
    "axum",
    "actix_web",
    "actix",
    "actix_files",
    "reqwest",
    "sqlx",
    "diesel",
    "rusqlite",
    "tokio_postgres",
    "postgres",
    "anyhow",
    "thiserror",
    "tracing",
    "log",
    "futures",
    "chrono",
    "uuid",
    "regex",
    "url",
    "http",
    "hyper",
    "tower",
    "tower_http",
    "bytes",
    "rand",
    "once_cell",
    "itertools",
    "clap",
    "rocket",
    "warp",
    "tide",
    "ureq",
    "surf",
    "isahc",
    "mysql",
    "sea_orm",
    "async_trait",
    "parking_lot",
    "dashmap",
    "time",
    "base64",
    "sha2",
    "hex",
    "tempfile",
    "walkdir",
    "glob",
    "ignore",
];

// ---------------------------------------------------------------- tables

/// Extractors that fill a handler's parameter from the request.
const EXTRACTORS: &[&str] = &["Query", "Path", "Json", "Form", "TypedHeader"];

/// Extractors without type arguments: only next to the others, or in a
/// routed function, since `Bytes` and `Uri` are everywhere else too.
const PLAIN_EXTRACTORS: &[&str] = &[
    "Multipart",
    "Bytes",
    "Payload",
    "RawQuery",
    "RawForm",
    "Host",
    "OriginalUri",
    "Uri",
];

/// Types of the request object itself.
const REQUEST_TYPES: &[&str] = &[
    "HttpRequest",
    "Request",
    "HeaderMap",
    "Parts",
    "ServiceRequest",
];

/// Methods of a request that return a value from it.
const REQUEST_METHODS: &[&str] = &[
    "query_string",
    "path",
    "uri",
    "headers",
    "match_info",
    "param",
    "params",
    "query",
    "cookie",
    "cookies",
    "peer_addr",
    "body",
    "body_string",
    "body_bytes",
    "body_json",
    "body_form",
    "url",
    "host",
];

/// Types a request's values can't inject through.
const INERT_TYPES: &[&str] = &[
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "f32",
    "f64",
    "bool",
    "char",
    "Uuid",
    "NaiveDate",
    "NaiveDateTime",
    "DateTime",
    "Utc",
    "Duration",
    "Ulid",
    "IpAddr",
    "Ipv4Addr",
    "Ipv6Addr",
    "SocketAddr",
    "Option",
    "Vec",
    "mut",
    "std",
    "uuid",
];

/// Methods that return their receiver's text, or part of it, changed: a
/// tainted receiver gives a tainted result.
const PROPAGATING_METHODS: &[&str] = &[
    "to_string",
    "to_owned",
    "clone",
    "as_str",
    "as_ref",
    "as_bytes",
    "as_deref",
    "borrow",
    "deref",
    "into",
    "into_owned",
    "to_str",
    "to_string_lossy",
    "trim",
    "trim_start",
    "trim_end",
    "trim_matches",
    "trim_start_matches",
    "trim_end_matches",
    "to_lowercase",
    "to_uppercase",
    "to_ascii_lowercase",
    "to_ascii_uppercase",
    "replace",
    "replacen",
    "unwrap",
    "unwrap_or",
    "unwrap_or_default",
    "unwrap_or_else",
    "expect",
    "ok",
    "ok_or",
    "ok_or_else",
    "cloned",
    "copied",
    "iter",
    "into_iter",
    "collect",
    "concat",
    "get",
    "first",
    "last",
    "next",
    "split",
    "splitn",
    "rsplit",
    "split_once",
    "rsplit_once",
    "lines",
    "strip_prefix",
    "strip_suffix",
    "to_path_buf",
    "as_path",
    "into_string",
    "map",
    "and_then",
    "filter",
    "values",
    "keys",
    "remove",
    "take",
    "get_one",
    "get_all",
    "form",
    "text",
    "to_vec",
    "into_bytes",
    "escape_default",
    "chars",
];

/// Methods that add their arguments to their receiver.
const BUILDER_METHODS: &[&str] = &[
    "push_str",
    "push",
    "extend",
    "insert",
    "insert_str",
    "push_back",
    "push_front",
    "append",
    "add",
];

/// Associated functions and constructors whose result holds their arguments:
/// the last two segments of the path.
const PROPAGATING_CALLS: &[(&str, &str)] = &[
    ("String", "from"),
    ("String", "from_utf8"),
    ("String", "from_utf8_lossy"),
    ("PathBuf", "from"),
    ("Path", "new"),
    ("OsStr", "new"),
    ("OsString", "from"),
    ("Cow", "from"),
    ("Box", "new"),
    ("Rc", "new"),
    ("Arc", "new"),
    ("Url", "parse"),
    ("Url", "from_str"),
    ("Uri", "from_str"),
    ("Uri", "try_from"),
    ("Vec", "from"),
    ("Some", ""),
    ("Ok", ""),
    ("Err", ""),
];

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ash",
    "cmd",
    "cmd.exe",
    "powershell",
    "pwsh",
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/env",
];

const SQL_METHODS: &[&str] = &[
    "execute",
    "query",
    "query_one",
    "query_opt",
    "query_row",
    "query_map",
    "query_and_then",
    "query_drop",
    "query_iter",
    "query_first",
    "prepare",
    "prepare_cached",
    "batch_execute",
    "simple_query",
    "execute_batch",
    "exec",
    "exec_drop",
    "exec_first",
    "exec_iter",
    "raw_sql",
];

const SQL_FUNCTIONS: &[&str] = &[
    "query",
    "query_as",
    "query_scalar",
    "query_unchecked",
    "raw_sql",
    "sql_query",
];

const PATH_FUNCTIONS: &[(&str, &[&str])] = &[
    ("File", &["open", "create", "create_new", "options"]),
    (
        "fs",
        &[
            "read",
            "read_to_string",
            "read_dir",
            "write",
            "remove_file",
            "remove_dir",
            "remove_dir_all",
            "create_dir",
            "create_dir_all",
            "copy",
            "rename",
            "metadata",
            "symlink_metadata",
            "read_link",
            "hard_link",
            "set_permissions",
        ],
    ),
    ("NamedFile", &["open", "open_async"]),
    ("ServeFile", &["new"]),
];

const REDIRECT_FUNCTIONS: &[&str] = &[
    "to",
    "temporary",
    "permanent",
    "found",
    "see_other",
    "moved_permanently",
    "temporary_redirect",
    "permanent_redirect",
];

const SSRF_CRATES: &[&str] = &["reqwest", "ureq", "surf", "isahc", "attohttpc", "minreq"];
const HTTP_VERBS: &[&str] = &["get", "post", "put", "delete", "patch", "head", "options"];

/// What the file must contain for the kind's sinks to be in it.
fn might_have_sinks(src: &[u8], kind: SinkKind) -> bool {
    let lower = src.to_ascii_lowercase();
    let has = |n: &[u8]| {
        let n = n.to_ascii_lowercase();
        lower.windows(n.len()).any(|w| w == n.as_slice())
    };
    let words: &[&[u8]] = match kind {
        SinkKind::Sql => &[
            b"sqlx",
            b"rusqlite",
            b"postgres",
            b"mysql",
            b"diesel",
            b"sea_orm",
            b"libsql",
            b"sqlite",
            b"duckdb",
            b"sql_query",
        ],
        SinkKind::Command => &[b"Command"],
        SinkKind::Path => &[
            b"File::",
            b"fs::",
            b"NamedFile",
            b"ServeFile",
            b"OpenOptions",
        ],
        SinkKind::Redirect => &[b"Redirect", b"location"],
        SinkKind::Ssrf => &[
            b"reqwest",
            b"ureq",
            b"surf",
            b"isahc",
            b"attohttpc",
            b"minreq",
            b"hyper",
            b"client",
        ],
        SinkKind::XPath | SinkKind::Ldap | SinkKind::Code | SinkKind::Format => return false,
    };
    words.iter().any(|w| has(w))
}

/// Calls that, with a value as argument or receiver, read as checking it.
fn check_words(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Path => &[
            "starts_with",
            "canonicalize",
            "strip_prefix",
            "contains",
            "is_absolute",
            "is_match",
            "matches",
        ],
        SinkKind::Redirect | SinkKind::Ssrf => &[
            "starts_with",
            "ends_with",
            "contains",
            "is_match",
            "matches",
            "validate",
            "host_str",
        ],
        _ => &[
            "contains",
            "is_match",
            "matches",
            "all",
            "validate",
            "is_numeric",
            "is_alphanumeric",
            "is_ascii_digit",
        ],
    }
}

// ---------------------------------------------------------------- entry

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    // A file with neither a sink nor a request can still define a function
    // that other files' values reach, or pass one on: any file with functions.
    if !might_have_sinks(src, kind) && !src.windows(3).any(|w| w == b"fn ") {
        return TaintResult::default();
    }
    let Some(root) = m.root else {
        return TaintResult::default();
    };
    let Some(cx) = Cx::new(m, src, kind, root) else {
        return TaintResult::default();
    };
    let Some(tainted) = cx.run() else {
        return TaintResult::default();
    };
    let findings = finish(cx.reached(&tainted));
    let facts = Facts {
        summaries: cx.exported_summaries(),
        calls: cx.passed_to_other_files(&tainted),
        returns: cx.return_facts.take(),
    };
    TaintResult { findings, facts }
}

// ---------------------------------------------------------------- the file

/// What a request's value does inside a function of the file, for one of its
/// parameters.
#[derive(Default)]
struct Summary<'t> {
    returns: Option<Path<'t>>,
    sinks: Vec<(Path<'t>, Node<'t>)>,
    /// The other files' functions the value is passed on to: the path to the
    /// call, the callee and its argument.
    calls: Vec<(Path<'t>, Callee, usize)>,
}

impl<'t> Reaches<'t> for Summary<'t> {
    fn sinks(&self) -> &[(Path<'t>, Node<'t>)] {
        &self.sinks
    }

    fn calls(&self) -> &[(Path<'t>, Callee, usize)] {
        &self.calls
    }
}

type SummaryKey = (usize, Option<usize>);

struct Cx<'a, 't> {
    m: &'a Model<'t>,
    src: &'a [u8],
    kind: SinkKind,
    by_node: HashMap<usize, DeclId>,
    /// Variables that hold a request object.
    requests: HashSet<DeclId>,
    /// Parameters a handler gets from the request, each with its path.
    initial: HashMap<DeclId, Path<'t>>,
    /// Variables a check reads as validating, for this kind of sink.
    checked: HashSet<DeclId>,
    /// The structs of the file: name, then field and type as written.
    structs: HashMap<String, HashMap<String, String>>,
    /// The names a format string captures, by the string's node.
    captures: HashMap<usize, Vec<DeclId>>,
    /// What the file's `use`s name.
    uses: HashMap<String, Vec<String>>,
    /// The module a `use m::*;` brings in, when the file has just one.
    glob: Option<Vec<String>>,
    writes: Vec<Write<'t>>,
    calls: Vec<Node<'t>>,
    /// Each function's name, to its index, and each method's by name.
    functions: HashMap<usize, usize>,
    methods: HashMap<String, Vec<usize>>,
    evaluations: Cell<u64>,
    summaries: Summaries<SummaryKey, Summary<'t>>,
    /// Whether another file's function's result counts as maybe holding a
    /// request's value: for the file's own run, not for a summary.
    from_calls: Cell<bool>,
    /// Another file's function's result reaching a sink here.
    return_facts: RefCell<Vec<ReturnFact<'t>>>,
}

impl<'a, 't> Cx<'a, 't> {
    fn new(m: &'a Model<'t>, src: &'a [u8], kind: SinkKind, root: Node<'t>) -> Option<Self> {
        let mut cx = Cx {
            m,
            src,
            kind,
            by_node: decl_index(m),
            requests: HashSet::new(),
            initial: HashMap::new(),
            checked: HashSet::new(),
            structs: HashMap::new(),
            captures: HashMap::new(),
            uses: HashMap::new(),
            glob: None,
            writes: Vec::new(),
            calls: Vec::new(),
            functions: HashMap::new(),
            methods: HashMap::new(),
            evaluations: Cell::new(0),
            summaries: Summaries::new(MAX_SUMMARIES),
            from_calls: Cell::new(false),
            return_facts: RefCell::new(Vec::new()),
        };
        cx.index();
        cx.uses = cx.uses(root);
        cx.glob = cx.glob(root);
        cx.collect(root)?;
        cx.sources();
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// The structs, the functions and the methods of the file, and the names
    /// its format strings capture.
    fn index(&mut self) {
        for (j, f) in self.m.functions.iter().enumerate() {
            if f.node.kind() != "function_item" {
                continue;
            }
            let Some(name) = f.node.child_by_field_name("name") else {
                continue;
            };
            self.functions.insert(name.id(), j);
            if f.node.parent().is_some_and(|b| {
                b.kind() == "declaration_list"
                    && b.parent().is_some_and(|i| i.kind() == "impl_item")
            }) {
                self.methods
                    .entry(self.text(name).to_string())
                    .or_default()
                    .push(j);
            }
        }
        for r in &self.m.refs {
            if r.node.kind() == "string_literal"
                && let Some(d) = r.decl
            {
                self.captures.entry(r.node.id()).or_default().push(d);
            }
        }
    }

    /// Walks the file once, in source order, for its writes, calls, structs
    /// and checks. None past a limit.
    fn collect(&mut self, root: Node<'t>) -> Option<()> {
        let mut checks: Vec<Node<'t>> = Vec::new();
        let words = check_words(self.kind);
        walk(root, |n| {
            self.visit(n, words, &mut checks);
            self.writes.len() <= MAX_WRITES
        })?;
        // A variable named as a check's receiver or argument is validated.
        let named = checked_names(checks, arguments, ("field_expression", "value"), |n| {
            self.decl_of(unwrap(n))
        });
        self.checked.extend(named);
        Some(())
    }

    /// Records what one node writes, calls or checks.
    fn visit(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        match n.kind() {
            "let_declaration" => self.bind_value(n, How::Assigned),
            "let_condition" | "for_expression" => self.bind_value(n, How::Read),
            "match_expression" => self.match_arms(n),
            "assignment_expression" => self.assignment(n, How::Assigned),
            "compound_assignment_expr" => self.assignment(n, How::Added),
            "call_expression" => self.call(n, words, checks),
            "struct_item" => self.struct_item(n),
            "binary_expression" => self.comparison(n),
            _ => {}
        }
    }

    /// `let p = v;`, `if let p = v`, `for p in v`: the pattern's names get the
    /// value.
    fn bind_value(&mut self, n: Node<'t>, how: How) {
        if let (Some(p), Some(v)) = (
            n.child_by_field_name("pattern"),
            n.child_by_field_name("value"),
        ) {
            self.write_pattern(p, v, how);
        }
    }

    /// `x == "..."`: a comparison tests the value.
    fn comparison(&mut self, n: Node<'t>) {
        if !matches!(self.operator(n), "==" | "!=") || matches!(self.kind, SinkKind::Sql) {
            return;
        }
        for side in ["left", "right"] {
            if let Some(d) = n
                .child_by_field_name(side)
                .and_then(|s| self.decl_of(unwrap(s)))
            {
                self.checked.insert(d);
            }
        }
    }

    fn operator(&self, n: Node) -> &'a str {
        n.child_by_field_name("operator")
            .map_or("", |o| self.text(o))
    }

    /// Records `pattern = value` for each name the pattern binds.
    fn write_pattern(&mut self, pattern: Node<'t>, value: Node<'t>, how: How) {
        // `let (a, b) = (x, y);`: each name gets its own element.
        let tuple = unwrap(value);
        if pattern.kind() == "tuple_pattern" && tuple.kind() == "tuple_expression" {
            let (mut c, mut d) = (pattern.walk(), tuple.walk());
            let names: Vec<Node<'t>> = pattern.named_children(&mut c).collect();
            let items: Vec<Node<'t>> = tuple.named_children(&mut d).collect();
            if names.len() == items.len() {
                for (name, item) in names.into_iter().zip(items) {
                    self.write_pattern(name, item, how);
                }
                return;
            }
        }
        for b in super::rs::pattern_bindings(pattern, self.src) {
            if let Some(&target) = self.by_node.get(&b.id()) {
                self.writes.push(Write {
                    target,
                    target_node: b,
                    value,
                    how,
                });
            }
        }
    }

    /// `match value { Some(x) => .., }`: each arm's names get the value.
    fn match_arms(&mut self, n: Node<'t>) {
        let (Some(value), Some(body)) = (
            n.child_by_field_name("value"),
            n.child_by_field_name("body"),
        ) else {
            return;
        };
        let mut c = body.walk();
        let arms: Vec<Node<'t>> = body
            .named_children(&mut c)
            .filter(|a| a.kind() == "match_arm")
            .collect();
        for arm in arms {
            let Some(p) = arm.child_by_field_name("pattern") else {
                continue;
            };
            let guard = p.child_by_field_name("condition").map(|g| g.id());
            let mut k = p.walk();
            let pats: Vec<Node<'t>> = p
                .named_children(&mut k)
                .filter(|x| Some(x.id()) != guard)
                .collect();
            for pat in pats {
                self.write_pattern(pat, value, How::Read);
            }
        }
    }

    /// `x = v`, `x += v`.
    fn assignment(&mut self, n: Node<'t>, how: How) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        if let Some(target) = self.decl_of(left) {
            self.writes.push(Write {
                target,
                target_node: left,
                value: right,
                how,
            });
        }
    }

    /// A call: a possible sink, a builder, a check.
    fn call(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        self.calls.push(n);
        // `path_is_valid(&name)`, `sanitize(x)`: a helper that reads as a check.
        let called = self
            .path_of(n)
            .and_then(|s| s.last().copied())
            .or_else(|| self.method_of(n).map(|(_, m)| m));
        if called.is_some_and(is_a_check_by_name) {
            checks.push(n);
        }
        let Some((receiver, name)) = self.method_of(n) else {
            return;
        };
        if BUILDER_METHODS.contains(&name)
            && let Some(target) = self.decl_of(unwrap(receiver))
        {
            for a in arguments(n) {
                self.writes.push(Write {
                    target,
                    target_node: unwrap(receiver),
                    value: a,
                    how: How::Added,
                });
            }
        }
        if words.contains(&name) {
            checks.push(n);
        }
    }

    /// The receiver and the name of a method call: `a.b(..)`, through a
    /// turbofish (`a.parse::<T>()`).
    fn method_of(&self, call: Node<'t>) -> Option<(Node<'t>, &'a str)> {
        let f = call.child_by_field_name("function")?;
        let f = if f.kind() == "generic_function" {
            f.child_by_field_name("function")?
        } else {
            f
        };
        if f.kind() != "field_expression" {
            return None;
        }
        let name = self.text(f.child_by_field_name("field")?);
        Some((f.child_by_field_name("value")?, name))
    }

    /// The segments of the path a call names: `std::fs::read` is
    /// `["std", "fs", "read"]`. None for a method call.
    fn path_of(&self, call: Node<'t>) -> Option<Vec<&'a str>> {
        let f = call.child_by_field_name("function")?;
        let f = if f.kind() == "generic_function" {
            f.child_by_field_name("function")?
        } else {
            f
        };
        if !matches!(f.kind(), "identifier" | "scoped_identifier") {
            return None;
        }
        Some(self.text(f).split("::").map(str::trim).collect())
    }

    /// The fields of a struct, with their types as written.
    fn struct_item(&mut self, n: Node<'t>) {
        let (Some(name), Some(body)) =
            (n.child_by_field_name("name"), n.child_by_field_name("body"))
        else {
            return;
        };
        let mut fields = HashMap::new();
        let mut c = body.walk();
        for f in body
            .named_children(&mut c)
            .filter(|f| f.kind() == "field_declaration")
        {
            if let (Some(fname), Some(ty)) =
                (f.child_by_field_name("name"), f.child_by_field_name("type"))
            {
                fields.insert(self.text(fname).to_string(), self.text(ty).to_string());
            }
        }
        self.structs.insert(self.text(name).to_string(), fields);
    }

    /// The declaration `n` names, as a declaration or as a reference.
    fn decl_of(&self, n: Node<'t>) -> Option<DeclId> {
        if n.kind() != "identifier" {
            return None;
        }
        self.by_node
            .get(&n.id())
            .copied()
            .or_else(|| self.m.decl_id_of(n))
    }

    // ------------------------------------------------------------ sources

    /// The parameters of a web handler: tainted from the start.
    fn sources(&mut self) {
        let mut found: Vec<(DeclId, Path<'t>)> = Vec::new();
        for f in &self.m.functions {
            if f.node.kind() == "function_item" {
                found.extend(self.handler_sources(f.node));
            }
        }
        self.initial.extend(found);
    }

    /// The parameters of `function` that a request fills, and the request
    /// objects among them (recorded).
    fn handler_sources(&mut self, function: Node<'t>) -> Vec<(DeclId, Path<'t>)> {
        let Some(list) = function.child_by_field_name("parameters") else {
            return Vec::new();
        };
        let mut c = list.walk();
        let params: Vec<Node<'t>> = list
            .named_children(&mut c)
            .filter(|p| p.kind() == "parameter")
            .collect();
        let routed = self.has_route_attribute(function);
        // `Path<T>` is axum's; a bare `Path` (or `&Path`) is `std::path`'s.
        let extracts = params.iter().any(|p| {
            p.child_by_field_name("type")
                .is_some_and(|t| self.is_generic_extractor(t))
        });
        let mut found = Vec::new();
        for p in params {
            let (Some(pat), Some(ty)) = (
                p.child_by_field_name("pattern"),
                p.child_by_field_name("type"),
            ) else {
                continue;
            };
            let names = super::rs::pattern_bindings(pat, self.src);
            if REQUEST_TYPES.contains(&self.outer_type(ty).as_str()) {
                let ids: Vec<DeclId> = names
                    .iter()
                    .filter_map(|b| self.by_node.get(&b.id()).copied())
                    .collect();
                self.requests.extend(ids);
            } else if self.fills_from_request(ty, routed || extracts) {
                for b in names {
                    if let Some(&d) = self.by_node.get(&b.id()) {
                        let message = format!("request parameter `{}`", self.text(b));
                        found.push((d, vec![Step { node: b, message }]));
                    }
                }
            }
        }
        found
    }

    /// Whether a parameter of type `ty` holds what a request puts in. In a
    /// handler (routed, or with extractors), a plain `String` or `&str` is a
    /// path segment or a body.
    fn fills_from_request(&self, ty: Node<'t>, in_a_handler: bool) -> bool {
        if self.is_generic_extractor(ty) {
            return !self.is_inert(&self.inner_type(ty));
        }
        if PLAIN_EXTRACTORS.contains(&self.outer_type(ty).as_str()) {
            return in_a_handler;
        }
        in_a_handler && self.is_text(ty)
    }

    /// A function with `#[get("/")]`, `#[post(..)]` and the like.
    fn has_route_attribute(&self, function: Node<'t>) -> bool {
        let mut prev = function.prev_named_sibling();
        while let Some(p) = prev {
            if p.kind() != "attribute_item" {
                break;
            }
            let t = self.text(p);
            if [
                "get", "post", "put", "delete", "patch", "head", "options", "route",
            ]
            .iter()
            .any(|v| t.starts_with(&format!("#[{v}(")) || t.contains(&format!("::{v}(")))
            {
                return true;
            }
            prev = p.prev_named_sibling();
        }
        false
    }

    /// `Query<P>`, `web::Json<T>`: an extractor, which has type arguments.
    fn is_generic_extractor(&self, ty: Node) -> bool {
        self.text(ty).contains('<') && EXTRACTORS.contains(&self.outer_type(ty).as_str())
    }

    /// A type without its path and its arguments: `web::Query<P>` is `Query`.
    fn outer_type(&self, ty: Node) -> String {
        let t = self.text(ty).trim_start_matches('&').trim();
        let t = t.split('<').next().unwrap_or(t);
        t.rsplit("::").next().unwrap_or(t).trim().to_string()
    }

    /// What's between a type's angle brackets.
    fn inner_type(&self, ty: Node) -> String {
        let t = self.text(ty);
        match (t.find('<'), t.rfind('>')) {
            (Some(a), Some(b)) if a < b => t[a + 1..b].to_string(),
            _ => String::new(),
        }
    }

    /// Whether a type is only numbers, ids and the like. A struct of the file
    /// isn't: its fields say.
    fn is_inert(&self, ty: &str) -> bool {
        let words: Vec<&str> = ty
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty())
            .collect();
        !words.is_empty() && words.iter().all(|w| INERT_TYPES.contains(w))
    }

    /// `String`, `&str`, `Bytes`: text a request puts in.
    fn is_text(&self, ty: Node) -> bool {
        let t = self.text(ty);
        let t = t.trim_start_matches('&').trim_start_matches("mut ").trim();
        matches!(t, "String" | "str" | "Bytes") || t.starts_with("Vec<u8>")
    }

    // ------------------------------------------------------------ the fixed point

    /// The variables that hold a request's value, each with its path, or None
    /// if the file is past a limit.
    fn run(&self) -> Option<HashMap<DeclId, Path<'t>>> {
        let mut tainted = self.initial.clone();
        self.from_calls.set(true);
        self.propagate(None, &mut tainted)?;
        Some(tainted)
    }

    // ------------------------------------------------------------ expressions

    /// The path a request's value takes to `n`, if `n` holds one.
    fn taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        if !tick(&self.evaluations, depth) {
            return None;
        }
        let next = depth + 1;
        match n.kind() {
            "identifier" => held(self.decl_of(n), &self.checked, state),
            "parenthesized_expression" | "try_expression" | "await_expression" => {
                self.taint(n.named_child(0)?, state, next)
            }
            "reference_expression" => self.taint(n.child_by_field_name("value")?, state, next),
            "unary_expression" => {
                // `*x` is the value; `!x` and `-x` are numbers and booleans.
                if self.text(n).starts_with('*') {
                    self.taint(n.named_child(0)?, state, next)
                } else {
                    None
                }
            }
            "binary_expression" => {
                if self.operator(n) != "+" {
                    return None;
                }
                if self.starts_the_text(self.kind) {
                    return self.after_a_start(n, state, next);
                }
                self.either(n, &["left", "right"], state, next)
            }
            "field_expression" => self.field_taint(n, state, next),
            "index_expression" => self.taint(n.named_child(0)?, state, next),
            "tuple_expression" | "array_expression" => self.items_taint(n, state, next),
            "macro_invocation" => self.macro_taint(n, state, next),
            "call_expression" => self.call_taint(n, state, next),
            "if_expression" | "match_expression" | "block" | "unsafe_block" => best(
                tail_values(n)
                    .into_iter()
                    .map(|v| self.taint(v, state, next)),
            ),
            "string_literal" => {
                // `"{id}"` with an inline name; it matters inside `format!`.
                let names = self.captures.get(&n.id())?;
                names.iter().find_map(|d| {
                    if self.checked.contains(d) {
                        None
                    } else {
                        state.get(d).cloned()
                    }
                })
            }
            _ => None,
        }
    }

    /// A tuple's or an array's items: any of them.
    fn items_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let mut c = n.walk();
        let items: Vec<Node<'t>> = n.named_children(&mut c).collect();
        best(items.into_iter().map(|i| self.taint(i, state, depth)))
    }

    /// The path of the first of `n`'s `fields` that holds a request's value.
    fn either(
        &self,
        n: Node<'t>,
        fields: &[&str],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        best(
            fields
                .iter()
                .filter_map(|f| n.child_by_field_name(f))
                .map(|o| self.taint(o, state, depth)),
        )
    }

    /// `a.b`: `a`'s value, unless the field's type, in a struct of the file,
    /// is a number or the like.
    fn field_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let value = n.child_by_field_name("value")?;
        let field = self.text(n.child_by_field_name("field")?);
        if self.inert_field(unwrap(value), field) {
            return None;
        }
        self.taint(value, state, depth)
    }

    /// Whether `field` of the variable `value` is a number or the like, by
    /// the struct its declared type names in this file.
    fn inert_field(&self, value: Node<'t>, field: &str) -> bool {
        self.decl_of(value)
            .and_then(|d| self.m.decls[d].ty)
            .and_then(|ty| self.field_type(self.text(ty), field))
            .is_some_and(|fty| self.is_inert(&fty))
    }

    /// The type of `field` in the struct a declared type names, if the file
    /// declares it: `Query<Pagination>`, `Json<Order>`, `&Order`.
    fn field_type(&self, declared: &str, field: &str) -> Option<String> {
        declared
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .find_map(|w| self.structs.get(w).and_then(|f| f.get(field)).cloned())
    }

    /// For an address (a redirect, a request), only its start can change where
    /// it goes.
    fn starts_the_text(&self, kind: SinkKind) -> bool {
        matches!(kind, SinkKind::Redirect | SinkKind::Ssrf)
    }

    /// `"/orders/" + id`, `base + id`: a value after a start that fixes the
    /// origin can't change the host; after another start it can.
    fn after_a_start(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let (left, right) = (
            n.child_by_field_name("left")?,
            n.child_by_field_name("right")?,
        );
        if let Some(p) = self.taint(left, state, depth) {
            return Some(p);
        }
        match self.literal_start(left) {
            Some(text) if !fixes_origin(text) => self.taint(right, state, depth),
            _ => None,
        }
    }

    /// The text of a string written out: `"/p/"`, `"/p/".to_string()`,
    /// `String::from("/p/")`.
    fn literal_start(&self, n: Node<'t>) -> Option<&'a str> {
        let n = unwrap(n);
        match n.kind() {
            "string_literal" => Some(self.string_content(n)),
            "call_expression" => {
                if let Some((receiver, name)) = self.method_of(n) {
                    return matches!(name, "to_string" | "to_owned" | "into")
                        .then(|| self.literal_start(receiver))
                        .flatten();
                }
                let segments = self.path_of(n)?;
                (segments.ends_with(&["String", "from"]))
                    .then(|| arguments(n).first().and_then(|a| self.literal_start(*a)))
                    .flatten()
            }
            _ => None,
        }
    }

    /// A string literal's text, without its quotes.
    fn string_content(&self, literal: Node<'t>) -> &'a str {
        self.text(literal)
            .trim_start_matches(['r', '#'])
            .trim_matches(['"', '#'])
    }

    /// `format!(..)` and friends: the text of the tokens they're built from.
    fn macro_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let name = self.text(n.child_by_field_name("macro")?);
        let name = name.rsplit("::").next().unwrap_or(name);
        if !matches!(
            name,
            "format" | "format_args" | "concat" | "write" | "writeln" | "vec"
        ) {
            return None;
        }
        let tree = n
            .named_children(&mut n.walk())
            .find(|c| c.kind() == "token_tree")?;
        if self.starts_the_text(self.kind) && matches!(name, "format" | "format_args") {
            return self.start_of_format(tree, state, depth);
        }
        let mut stack = vec![tree];
        let mut paths = Vec::new();
        while let Some(t) = stack.pop() {
            let mut c = t.walk();
            let tokens: Vec<Node<'t>> = t.children(&mut c).collect();
            for (i, tok) in tokens.iter().enumerate() {
                match tok.kind() {
                    "identifier" => {
                        // `p.page`: tokens, not a field expression.
                        let field = tokens
                            .get(i + 1)
                            .filter(|d| self.text(**d) == ".")
                            .and_then(|_| tokens.get(i + 2))
                            .filter(|f| f.kind() == "identifier");
                        if field.is_some_and(|f| self.inert_field(*tok, self.text(*f))) {
                            continue;
                        }
                        paths.push(self.taint(*tok, state, depth));
                    }
                    "string_literal" => paths.push(self.taint(*tok, state, depth)),
                    "token_tree" => stack.push(*tok),
                    _ => {}
                }
            }
        }
        best(paths.into_iter())
    }

    /// `format!("{base}/x?{q}", ..)` as an address: what its start says. A start
    /// that fixes the origin leaves the rest no say; a name or an argument
    /// there is the value that sets where it goes.
    fn start_of_format(
        &self,
        tree: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let mut c = tree.walk();
        let tokens: Vec<Node<'t>> = tree.named_children(&mut c).collect();
        let literal = *tokens.first().filter(|t| t.kind() == "string_literal")?;
        let content = self.string_content(literal);
        if !content.starts_with('{') || content.starts_with("{{") {
            let prefix = content.split('{').next().unwrap_or("");
            if fixes_origin(prefix) {
                return None;
            }
            // Another literal start: any of it that's tainted.
            return best(tokens.iter().map(|t| self.taint(*t, state, depth)));
        }
        let first = content[1..].split(['}', ':']).next().unwrap_or("").trim();
        if first.is_empty() || first.chars().all(|ch| ch.is_ascii_digit()) {
            // `{}` or `{0}`: the first argument after the string.
            let arg = tokens.iter().skip(1).find(|t| t.kind() == "identifier")?;
            return self.taint(*arg, state, depth);
        }
        // `{name}`: the variable the string names.
        self.taint(literal, state, depth).filter(|_| {
            self.captures.get(&literal.id()).is_some_and(|ds| {
                ds.iter()
                    .any(|d| state.contains_key(d) && self.m.decls[*d].name == first)
            })
        })
    }

    /// What a call returns: a request's value for a request's accessor, the
    /// result of a function of the file that returns one, and the text of a
    /// tainted receiver or argument for the calls that change text.
    fn call_taint(
        &self,
        call: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let args = arguments(call);
        if let Some(path) = self.through_function(call, &args, state, depth) {
            return Some(path);
        }
        if let Some(segments) = self.path_of(call) {
            return self
                .path_call_taint(&segments, &args, state, depth)
                .or_else(|| self.maybe_from(call));
        }
        let (receiver, name) = self.method_of(call)?;
        if let Some(path) = self.request_value(call, receiver, name) {
            return Some(path);
        }
        if BUILDER_METHODS.contains(&name) {
            return best(
                std::iter::once(self.taint(receiver, state, depth))
                    .chain(args.into_iter().map(|a| self.taint(a, state, depth))),
            );
        }
        if name == "join" {
            // `base.join(user)`, `parts.join(",")`: either side's text.
            return best(
                std::iter::once(self.taint(receiver, state, depth))
                    .chain(args.into_iter().map(|a| self.taint(a, state, depth))),
            );
        }
        if name == "parse" {
            // A number can't inject; text, a URL or a path can.
            let target = call
                .child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("type_arguments"))
                .map(|t| self.text(t))
                .unwrap_or_default();
            if self.is_inert(target.trim_matches(['<', '>'])) {
                return None;
            }
        }
        let Some(tainted) = self.taint(receiver, state, depth) else {
            return self.maybe_from(call);
        };
        PROPAGATING_METHODS.contains(&name).then_some(tainted)
    }

    /// What another file's function's result may hold: a request's value, if
    /// that function returns one. The project pass decides.
    fn maybe_from(&self, call: Node<'t>) -> Option<Path<'t>> {
        maybe_path(self.from_calls.get(), call, || {
            self.external_callee(call).is_some()
        })
    }

    /// `String::from(x)`, `PathBuf::from(x)`, `Some(x)`: the text of an
    /// argument.
    fn path_call_taint(
        &self,
        segments: &[&str],
        args: &[Node<'t>],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let last = *segments.last()?;
        let before = if segments.len() >= 2 {
            segments[segments.len() - 2]
        } else {
            ""
        };
        let propagates = PROPAGATING_CALLS.iter().any(|(t, f)| {
            (*t == before && *f == last) || (segments.len() == 1 && *t == last && f.is_empty())
        });
        propagates
            .then(|| best(args.iter().map(|a| self.taint(*a, state, depth))))
            .flatten()
    }

    /// A request object's accessor: `req.query_string()`. Its path starts here.
    fn request_value(&self, call: Node<'t>, object: Node<'t>, name: &str) -> Option<Path<'t>> {
        if !REQUEST_METHODS.contains(&name) {
            return None;
        }
        let object = unwrap(object);
        let is_request = match object.kind() {
            "identifier" => self
                .decl_of(object)
                .is_some_and(|d| self.requests.contains(&d)),
            // `req.match_info().get("id")`, `req.headers().get(..)`: the inner
            // call is the request's.
            "call_expression" => self
                .method_of(object)
                .is_some_and(|(r, n)| REQUEST_METHODS.contains(&n) && self.is_a_request(r)),
            _ => false,
        };
        (is_request || self.is_a_request(object)).then(|| {
            vec![Step {
                node: call,
                message: format!("request value `{}`", short(self.text(call))),
            }]
        })
    }

    fn is_a_request(&self, n: Node<'t>) -> bool {
        let n = unwrap(n);
        n.kind() == "identifier" && self.decl_of(n).is_some_and(|d| self.requests.contains(&d))
    }

    // ------------------------------------------------------------ sinks

    /// Every sink a tainted value reaches, with its path.
    fn reached(&self, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let mut out = at_sinks(
            &self.calls,
            |c| self.sink_call(c),
            |a| {
                sure_path(self.taint(a, state, 0), |path| {
                    self.record_return(a, path, state)
                })
            },
        );
        out.extend(self.reached_through_functions(state));
        out
    }

    /// The sink a call is, for this kind, and the arguments that take the
    /// value.
    fn sink_call(&self, call: Node<'t>) -> Option<(String, Vec<Node<'t>>)> {
        let args = arguments(call);
        if let Some(segments) = self.path_of(call) {
            let last = *segments.last()?;
            let before = if segments.len() >= 2 {
                segments[segments.len() - 2]
            } else {
                ""
            };
            return self.function_sink(&segments, before, last, args);
        }
        let (receiver, name) = self.method_of(call)?;
        self.method_sink(receiver, name, args)
    }

    fn function_sink(
        &self,
        segments: &[&str],
        before: &str,
        last: &str,
        args: Vec<Node<'t>>,
    ) -> Option<(String, Vec<Node<'t>>)> {
        let shown = format!(
            "{before}{}{last}",
            if before.is_empty() { "" } else { "::" }
        );
        let first = |a: Vec<Node<'t>>| a.into_iter().take(1).collect::<Vec<_>>();
        match self.kind {
            SinkKind::Sql
                if SQL_FUNCTIONS.contains(&last) && (segments.len() > 1 || self.has(b"sqlx")) =>
            {
                Some((shown, first(args)))
            }
            SinkKind::Command if before == "Command" && last == "new" => Some((shown, first(args))),
            SinkKind::Path
                if PATH_FUNCTIONS
                    .iter()
                    .any(|(t, fs)| *t == before && fs.contains(&last)) =>
            {
                // `fs::write(path, contents)`: the contents aren't a path.
                Some((shown, if last == "write" { first(args) } else { args }))
            }
            SinkKind::Redirect if before == "Redirect" && REDIRECT_FUNCTIONS.contains(&last) => {
                Some((shown, first(args)))
            }
            SinkKind::Ssrf
                if segments.len() >= 2
                    && SSRF_CRATES.contains(&segments[0])
                    && (HTTP_VERBS.contains(&last) || last == "request") =>
            {
                Some((shown, args.into_iter().last().into_iter().collect()))
            }
            _ => None,
        }
    }

    fn method_sink(
        &self,
        receiver: Node<'t>,
        name: &str,
        args: Vec<Node<'t>>,
    ) -> Option<(String, Vec<Node<'t>>)> {
        let shown = name.to_string();
        let first = |a: Vec<Node<'t>>| a.into_iter().take(1).collect::<Vec<_>>();
        match self.kind {
            SinkKind::Sql if SQL_METHODS.contains(&name) => Some((shown, first(args))),
            // `Command::new("sh").arg("-c").arg(x)`: the shell runs it.
            SinkKind::Command if matches!(name, "arg" | "args") && self.shell_root(receiver) => {
                Some((shown, args))
            }
            SinkKind::Path if name == "open" && self.text(receiver).contains("OpenOptions") => {
                Some((shown, args))
            }
            SinkKind::Redirect
                if matches!(
                    name,
                    "header" | "insert_header" | "append_header" | "set_header"
                ) =>
            {
                self.location_value(&args).map(|v| (shown, vec![v]))
            }
            SinkKind::Ssrf if HTTP_VERBS.contains(&name) && self.is_http_client(receiver) => {
                Some((shown, first(args)))
            }
            SinkKind::Ssrf if name == "request" && self.is_http_client(receiver) => {
                Some((shown, args.into_iter().last().into_iter().collect()))
            }
            SinkKind::Ssrf if name == "uri" && self.text(receiver).contains("Request") => {
                Some((shown, first(args)))
            }
            _ => None,
        }
    }

    fn has(&self, word: &[u8]) -> bool {
        self.src.windows(word.len()).any(|w| w == word)
    }

    /// Whether the call chain starts with `Command::new("sh")` or the like.
    fn shell_root(&self, receiver: Node<'t>) -> bool {
        let mut n = unwrap(receiver);
        loop {
            if n.kind() != "call_expression" {
                return false;
            }
            if self.path_of(n).is_some_and(|s| {
                s.len() >= 2 && s[s.len() - 2] == "Command" && s[s.len() - 1] == "new"
            }) {
                return arguments(n)
                    .first()
                    .is_some_and(|a| SHELLS.contains(&self.text(*a).trim_matches('"')));
            }
            match self.method_of(n) {
                Some((r, _)) => n = unwrap(r),
                None => return false,
            }
        }
    }

    /// The value of a `Location` header given as `("Location", x)` or
    /// `LOCATION, x`.
    fn location_value(&self, args: &[Node<'t>]) -> Option<Node<'t>> {
        let (name, value) = match args {
            [t] if t.kind() == "tuple_expression" => {
                let mut c = t.walk();
                let items: Vec<Node<'t>> = t.named_children(&mut c).collect();
                (*items.first()?, *items.get(1)?)
            }
            [a, b] => (*a, *b),
            _ => return None,
        };
        self.text(name)
            .to_ascii_lowercase()
            .contains("location")
            .then_some(value)
    }

    /// Whether a method's receiver reads as an HTTP client: its text says so,
    /// or its declared type does.
    fn is_http_client(&self, receiver: Node<'t>) -> bool {
        let r = unwrap(receiver);
        let mut texts = vec![self.text(r).to_ascii_lowercase()];
        if let Some(d) = self.decl_of(r)
            && let Some(ty) = self.m.decls[d].ty
        {
            texts.push(self.text(ty).to_ascii_lowercase());
        }
        texts.iter().any(|t| {
            ["client", "http", "agent", "reqwest", "ureq", "session"]
                .iter()
                .any(|w| t.contains(w))
        })
    }
}

// ---------------------------------------------------------------- functions of the file (T3)

impl<'a, 't> Cx<'a, 't> {
    /// The function of this file a call calls, when it's unambiguous: a path
    /// call to a function, `Self::f` or `Type::f`, or `self.f(..)` and
    /// `x.f(..)` with one method of that name and arity.
    fn local_callee(&self, call: Node<'t>) -> Option<usize> {
        let arity = arguments(call).len();
        if let Some(segments) = self.path_of(call) {
            let f = call.child_by_field_name("function")?;
            let f = if f.kind() == "generic_function" {
                f.child_by_field_name("function")?
            } else {
                f
            };
            if segments.len() == 1 {
                let d = self.decl_of(f)?;
                return self
                    .functions
                    .get(&self.m.decls[d].node.id())
                    .copied()
                    .filter(|&j| self.m.functions[j].params.len() == arity);
            }
            let name = *segments.last()?;
            let owner = segments[segments.len() - 2];
            let candidates: Vec<usize> = self
                .methods
                .get(name)?
                .iter()
                .copied()
                .filter(|&j| {
                    self.m.functions[j].params.len() == arity
                        && (owner == "Self" || self.impl_type(j).as_deref() == Some(owner))
                })
                .collect();
            return match candidates.as_slice() {
                [only] => Some(*only),
                _ => None,
            };
        }
        let (receiver, name) = self.method_of(call)?;
        let candidates: Vec<usize> = self
            .methods
            .get(name)?
            .iter()
            .copied()
            .filter(|&j| self.m.functions[j].params.len() == arity)
            .filter(|&j| {
                // `self.f(..)` is in the same impl; another receiver needs to
                // be the only method of that name.
                let r = unwrap(receiver);
                r.kind() != "self" || self.same_impl(j, call)
            })
            .collect();
        match candidates.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// The type an `impl` block of method `j` is for.
    fn impl_type(&self, j: usize) -> Option<String> {
        let imp = self.m.functions[j].node.parent()?.parent()?;
        let ty = imp.child_by_field_name("type")?;
        Some(self.outer_type(ty))
    }

    /// Whether `call` is inside the `impl` that holds method `j`.
    fn same_impl(&self, j: usize, call: Node<'t>) -> bool {
        let Some(imp) = self.m.functions[j].node.parent().and_then(|b| b.parent()) else {
            return false;
        };
        inside(call, imp)
    }

    /// What a call to a function of the file returns: the value of a tainted
    /// argument that reaches its result, or one it reads itself.
    fn through_function(
        &self,
        call: Node<'t>,
        args: &[Node<'t>],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let j = self.local_callee(call)?;
        through_returns(
            call,
            self.function_name(j),
            self.summary(j, None).returns.clone(),
            args,
            |a| self.taint(a, state, depth),
            |i| self.summary(j, Some(i)).returns.clone(),
        )
    }

    fn function_name(&self, j: usize) -> &'a str {
        self.m.functions[j]
            .node
            .child_by_field_name("name")
            .map_or("function", |n| self.text(n))
    }

    /// The sinks a request's value reaches inside the functions of the file
    /// that the calls with a tainted argument call.
    fn reached_through_functions(&self, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let mut out = Vec::new();
        for &call in &self.calls {
            out.extend(self.sinks_through(call, state));
        }
        out
    }

    fn sinks_through(&self, call: Node<'t>, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let Some(j) = self.local_callee(call) else {
            return Vec::new();
        };
        through_sinks(
            call,
            self.function_name(j),
            arguments(call),
            |a| self.taint(a, state, 0).filter(|p| !from_call(p)),
            |i| self.summary(j, Some(i)).sinks.clone(),
        )
    }

    /// What a request's value does in function `j`, for its parameter `p` (or
    /// for nothing but what the function reads itself).
    fn summary(&self, j: usize, p: Option<usize>) -> Rc<Summary<'t>> {
        self.summaries.get((j, p), || self.summarize(j, p))
    }

    fn summarize(&self, j: usize, p: Option<usize>) -> Option<Summary<'t>> {
        let f = &self.m.functions[j];
        let mut state: HashMap<DeclId, Path<'t>> = HashMap::new();
        if let Some(p) = p {
            for &d in f.params.get(p)? {
                let decl = &self.m.decls[d];
                if decl.ty.is_some_and(|t| self.is_inert(self.text(t))) {
                    return Some(Summary::default());
                }
                state.insert(
                    d,
                    vec![Step {
                        node: decl.node,
                        message: format!("`{}`'s parameter `{}`", self.function_name(j), decl.name),
                    }],
                );
            }
        }
        self.propagate(Some(f.node), &mut state)?;
        let body = f.node.child_by_field_name("body");
        let mut values = body.map(tail_values).unwrap_or_default();
        values.extend(return_values(
            f.node,
            &["function_item", "closure_expression"],
            "return_expression",
        ));
        let sinks = p.is_some().then(|| {
            sinks_in(
                &self.calls,
                f.node,
                |c| self.sink_call(c),
                |a| self.taint(a, &state, 0),
                |c| self.sinks_through(c, &state),
            )
        });
        let (returns, sinks) = outcome(values, |v| self.taint(v, &state, 0), sinks);
        let calls = if p.is_some() {
            calls_in(self, &self.calls, f.node, &state)
        } else {
            Vec::new()
        };
        Some(Summary {
            returns,
            sinks,
            calls,
        })
    }

    // ------------------------------------------------------------ other files (T4)

    /// What the file's `use`s name: each name to the path it stands for.
    fn uses(&self, root: Node<'t>) -> HashMap<String, Vec<String>> {
        let mut out = HashMap::new();
        let mut c = root.walk();
        for u in root
            .named_children(&mut c)
            .filter(|n| n.kind() == "use_declaration")
        {
            if let Some(arg) = u.child_by_field_name("argument") {
                self.collect_use(arg, &[], &mut out);
            }
        }
        // `mod db;` is a child module, which `db::find` names.
        let mut c = root.walk();
        for m in root
            .named_children(&mut c)
            .filter(|n| n.kind() == "mod_item" && n.child_by_field_name("body").is_none())
        {
            if let Some(name) = m.child_by_field_name("name") {
                let name = self.text(name).to_string();
                out.entry(name.clone())
                    .or_insert_with(|| vec!["self".into(), name]);
            }
        }
        out
    }

    /// The module of the file's only `use m::*;`: with two, a bare name could
    /// be either's, so none is followed.
    fn glob(&self, root: Node<'t>) -> Option<Vec<String>> {
        let mut c = root.walk();
        let mut globs = root
            .named_children(&mut c)
            .filter(|n| n.kind() == "use_declaration")
            .filter_map(|u| u.child_by_field_name("argument"))
            .filter(|a| a.kind() == "use_wildcard")
            .filter_map(|a| a.named_child(0))
            .map(|m| {
                self.text(m)
                    .split("::")
                    .map(|w| w.trim().to_string())
                    .collect::<Vec<_>>()
            });
        let only = globs.next()?;
        globs.next().is_none().then_some(only)
    }

    fn collect_use(&self, n: Node<'t>, prefix: &[String], out: &mut HashMap<String, Vec<String>>) {
        let words = |t: &str| {
            t.split("::")
                .map(|w| w.trim().to_string())
                .collect::<Vec<_>>()
        };
        match n.kind() {
            "identifier" | "scoped_identifier" | "crate" | "self" | "super" => {
                let mut path = prefix.to_vec();
                path.extend(words(self.text(n)));
                // `use a::{self, b}`: `a` itself.
                if path.last().is_some_and(|l| l == "self") {
                    path.pop();
                }
                if let Some(alias) = path.last().cloned() {
                    out.insert(alias, path);
                }
            }
            "use_as_clause" => {
                if let (Some(p), Some(a)) = (
                    n.child_by_field_name("path"),
                    n.child_by_field_name("alias"),
                ) {
                    let mut path = prefix.to_vec();
                    path.extend(words(self.text(p)));
                    out.insert(self.text(a).to_string(), path);
                }
            }
            "scoped_use_list" => {
                let mut base = prefix.to_vec();
                if let Some(p) = n.child_by_field_name("path") {
                    base.extend(words(self.text(p)));
                }
                if let Some(list) = n.child_by_field_name("list") {
                    self.collect_use(list, &base, out);
                }
            }
            "use_list" => {
                let mut c = n.walk();
                for child in n.named_children(&mut c) {
                    self.collect_use(child, prefix, out);
                }
            }
            _ => {}
        }
    }

    /// `segments` with its first name taken through the file's `use`s. None
    /// for a name that doesn't come from one of the project's modules: a
    /// library's (`std`, a crate this analysis models), or no import at all.
    fn through_uses(&self, segments: &[&str]) -> Option<Vec<String>> {
        let first = *segments.first()?;
        let mut full: Vec<String> = match self.uses.get(first) {
            Some(path) => path.clone(),
            None if matches!(first, "crate" | "self" | "super") => vec![first.to_string()],
            // `store::db::find(..)`: a crate or a module written out.
            None if segments.len() >= 2 && first.starts_with(char::is_lowercase) => {
                vec![first.to_string()]
            }
            // `use crate::db::*;` brought in `find` and `Repo`.
            None => {
                let mut path = self.glob.clone()?;
                path.push(first.to_string());
                path
            }
        };
        full.extend(segments[1..].iter().map(|s| s.to_string()));
        let root = full.first()?.as_str();
        (!LIBRARY_CRATES.contains(&root)).then_some(full)
    }

    /// The other file's function a call calls, as this file writes it.
    fn external_callee(&self, call: Node<'t>) -> Option<Callee> {
        if self.local_callee(call).is_some() {
            return None;
        }
        if let Some(segments) = self.path_of(call) {
            // `f(x)` with `f` a local (a closure) isn't any module's function.
            let local = segments.len() == 1
                && call
                    .child_by_field_name("function")
                    .is_some_and(|f| self.decl_of(f).is_some());
            let path = self.through_uses(&segments).filter(|_| !local)?;
            return (path.len() >= 2).then_some(Callee::Rs { path, method: None });
        }
        let (receiver, name) = self.method_of(call)?;
        let ty = self.receiver_type(unwrap(receiver))?;
        let path = self.through_uses(&ty.iter().map(String::as_str).collect::<Vec<_>>())?;
        Some(Callee::Rs {
            path,
            method: Some(name.to_string()),
        })
    }

    /// The path of a receiver's declared type: a variable's, or a field of
    /// `self`'s (`self.repo`), with `&`, `Arc<..>` and the like peeled off.
    fn receiver_type(&self, receiver: Node<'t>) -> Option<Vec<String>> {
        let declared = match receiver.kind() {
            "identifier" => self
                .text(self.m.decls[self.decl_of(receiver)?].ty?)
                .to_string(),
            "field_expression" => {
                let (value, field) = (
                    receiver.child_by_field_name("value")?,
                    receiver.child_by_field_name("field")?,
                );
                if value.kind() != "self" {
                    return None;
                }
                let imp = self.enclosing_impl_type(receiver)?;
                self.structs.get(&imp)?.get(self.text(field))?.clone()
            }
            _ => return None,
        };
        let mut t = declared.as_str();
        // Peel wrappers: `&mut Arc<UserRepo>`, `Option<Box<dyn Store>>`.
        loop {
            let trimmed = t
                .trim()
                .trim_start_matches('&')
                .trim_start_matches("mut ")
                .trim_start_matches("dyn ")
                .trim_start_matches("impl ")
                .trim();
            // `Arc<T>` or `std::sync::Arc<T>`: the type argument.
            let inner = trimmed.split_once('<').and_then(|(head, rest)| {
                let wrapper = head.rsplit("::").next().unwrap_or(head);
                (["Arc", "Rc", "Box", "Option", "RefCell", "Mutex", "RwLock"].contains(&wrapper))
                    .then(|| rest.strip_suffix('>'))
                    .flatten()
            });
            match inner {
                Some(i) => t = i,
                None => {
                    t = trimmed;
                    break;
                }
            }
        }
        let t = t.split('<').next().unwrap_or(t);
        Some(t.split("::").map(|w| w.trim().to_string()).collect())
    }

    /// The name of the type of the `impl` a node is in.
    fn enclosing_impl_type(&self, n: Node<'t>) -> Option<String> {
        let mut p = n.parent();
        while let Some(x) = p {
            if x.kind() == "impl_item" {
                return Some(self.outer_type(x.child_by_field_name("type")?));
            }
            p = x.parent();
        }
        None
    }

    /// Another file's function's result reaching a sink through the argument
    /// `arg` of the sink call: the call, the request's values in its
    /// arguments, and the path after it.
    fn record_return(
        &self,
        sink_arg: Node<'t>,
        path: &Path<'t>,
        state: &HashMap<DeclId, Path<'t>>,
    ) {
        record_return_at_sink(
            &self.return_facts,
            &self.calls,
            |c| self.sink_call(c),
            |c| Some((self.external_callee(c)?, arguments(c))),
            sink_arg,
            path,
            |a| self.taint(a, state, 0),
        );
    }

    /// What other files call function `j` by: its name, or its type and its name
    /// for a method.
    fn function_key(&self, j: usize) -> Option<Key> {
        let f = &self.m.functions[j];
        if f.node.kind() != "function_item" {
            return None;
        }
        let name = self.text(f.node.child_by_field_name("name")?).to_string();
        match self.impl_type(j) {
            Some(ty) => Some(Key {
                export: ty,
                member: Some(name),
            }),
            None => {
                // A function inside another function isn't one a file can name.
                let nested = f
                    .node
                    .parent()
                    .is_some_and(|b| b.parent().is_some_and(|p| p.kind() == "function_item"));
                (!nested).then_some(Key {
                    export: name,
                    member: None,
                })
            }
        }
    }
}

flow_for!(Cx, from_call);
exports_for!(Cx);

// ---------------------------------------------------------------- syntax

/// The arguments of a call.
fn arguments(call: Node) -> Vec<Node> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|a| !matches!(a.kind(), "line_comment" | "block_comment"))
        .collect()
}

/// An expression without the parentheses and references around it.
fn unwrap(mut n: Node) -> Node {
    loop {
        match n.kind() {
            "parenthesized_expression" => match n.named_child(0) {
                Some(inner) => n = inner,
                None => return n,
            },
            "reference_expression" => match n.child_by_field_name("value") {
                Some(inner) => n = inner,
                None => return n,
            },
            _ => return n,
        }
    }
}

/// The values an expression can end in: a block's tail, the branches of an
/// `if` or a `match`; the expression itself otherwise.
fn tail_values(n: Node) -> Vec<Node> {
    match n.kind() {
        "block" | "unsafe_block" => {
            let mut c = n.walk();
            let last = n
                .named_children(&mut c)
                .filter(|x| !matches!(x.kind(), "line_comment" | "block_comment"))
                .last();
            match last {
                Some(l) if is_expression_tail(l) => tail_values(l),
                _ => Vec::new(),
            }
        }
        "if_expression" => {
            let mut out = n
                .child_by_field_name("consequence")
                .map(tail_values)
                .unwrap_or_default();
            if let Some(alt) = n
                .child_by_field_name("alternative")
                .and_then(|e| e.named_child(0))
            {
                out.extend(tail_values(alt));
            }
            out
        }
        "match_expression" => {
            let Some(body) = n.child_by_field_name("body") else {
                return Vec::new();
            };
            let mut c = body.walk();
            body.named_children(&mut c)
                .filter(|a| a.kind() == "match_arm")
                .filter_map(|a| a.child_by_field_name("value"))
                .flat_map(tail_values)
                .collect()
        }
        _ => vec![n],
    }
}

/// Whether a block's last child is its value (an expression without `;`).
fn is_expression_tail(n: Node) -> bool {
    !matches!(
        n.kind(),
        "expression_statement"
            | "let_declaration"
            | "empty_statement"
            | "function_item"
            | "struct_item"
            | "enum_item"
            | "impl_item"
            | "use_declaration"
            | "const_item"
            | "static_item"
            | "mod_item"
            | "attribute_item"
    )
}

/// Whether text, as the start of an address, fixes where it goes: a path on
/// this site (`/orders/`, not `//host`), or a scheme and host with a path.
fn fixes_origin(prefix: &str) -> bool {
    let absolute = prefix.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
            && rest.find('/').is_some_and(|slash| slash > 0)
    });
    let local =
        prefix.starts_with('/') && prefix.chars().nth(1).is_some_and(|c| c != '/' && c != '\\');
    absolute || local
}

/// A function whose name says it checks its argument.
fn is_a_check_by_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "valid",
        "safe",
        "sanitiz",
        "allowed",
        "within",
        "inside",
        "verify",
        "authorized",
    ]
    .iter()
    .any(|w| n.contains(w))
}

/// Text built by concatenation or formatting, which the path says.
fn is_built(n: Node) -> bool {
    matches!(n.kind(), "binary_expression" | "macro_invocation")
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    /// The lines `rule` flags in `src`.
    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("main.rs", Lang::Rust, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn a_query_value_in_a_query_through_format() {
        let src = "async fn orders(Query(p): Query<Params>, State(db): State<Db>) -> String {\n    let q = format!(\"SELECT * FROM o WHERE name = '{}'\", p.name);\n    sqlx::query(&q).fetch_all(&db.pool).await.unwrap();\n    String::new()\n}\nstruct Params { name: String, page: u32 }";
        assert_eq!(flagged("rs/sql-injection", src), [3]);
    }

    #[test]
    fn inline_names_numbers_and_parameters_are_told_apart() {
        let src = "struct Params { name: String, page: u32 }\nasync fn a(Query(p): Query<Params>) {\n    let name = p.name;\n    sqlx::query(&format!(\"SELECT * FROM o WHERE n = '{name}'\")).fetch_all(&pool).await;\n}\nasync fn b(Query(p): Query<Params>) {\n    sqlx::query(&format!(\"SELECT * FROM o LIMIT {}\", p.page)).fetch_all(&pool).await;\n}\nasync fn c(Query(p): Query<Params>) {\n    sqlx::query(\"SELECT * FROM o WHERE n = $1\").bind(p.name).fetch_all(&pool).await;\n}";
        assert_eq!(flagged("rs/sql-injection", src), [4]);
    }

    #[test]
    fn a_routed_functions_path_segment_and_the_shadowing_trim() {
        let src = "use rusqlite::Connection;\n#[get(\"/user/<name>\")]\nfn user(name: &str) -> String {\n    let name = name.trim();\n    let conn = open();\n    conn.execute(&format!(\"DELETE FROM u WHERE n = '{}'\", name), []).unwrap();\n    String::new()\n}";
        assert_eq!(flagged("rs/sql-injection", src), [6]);
    }

    #[test]
    fn a_shell_command_but_not_a_fixed_program() {
        let src = "async fn a(Query(p): Query<P>) {\n    Command::new(\"sh\").arg(\"-c\").arg(format!(\"ping {}\", p.host)).output();\n}\nasync fn b(Query(p): Query<P>) {\n    Command::new(\"ping\").arg(p.host).output();\n}\nasync fn c(Query(p): Query<P>) {\n    Command::new(p.prog).output();\n}";
        assert_eq!(flagged("rs/command-injection", src), [2, 8]);
    }

    #[test]
    fn paths_redirects_and_requests() {
        let src = "async fn f(Path(name): Path<String>) -> Vec<u8> {\n    let p = std::path::Path::new(\"/srv\").join(&name);\n    std::fs::read(p).unwrap()\n}\nasync fn g(Query(q): Query<R>) -> Redirect {\n    Redirect::to(&q.next)\n}\nasync fn h(Query(q): Query<R>) {\n    reqwest::get(&q.url).await.unwrap();\n}";
        assert_eq!(flagged("rs/path-injection", src), [3]);
        assert_eq!(flagged("rs/open-redirect", src), [6]);
        assert_eq!(flagged("rs/ssrf", src), [9]);
    }

    #[test]
    fn a_tuple_pattern_takes_its_elements_one_by_one() {
        let src = "use rusqlite::Connection;\nasync fn f(Query(p): Query<P>, cfg: Config) {\n    let (table, name) = (cfg.table.clone(), p.name);\n    let c = Connection::open(\"x\").unwrap();\n    c.execute(&format!(\"DELETE FROM {table} WHERE n = '{name}'\"), []).unwrap();\n    c.execute(&format!(\"DELETE FROM {table}\"), []).unwrap();\n}";
        assert_eq!(flagged("rs/sql-injection", src), [5]);
    }

    #[test]
    fn checked_and_numeric_values_are_left_alone() {
        let src = "async fn f(Path(name): Path<String>) {\n    if name.contains(\"..\") { return; }\n    std::fs::read(&name).unwrap();\n}\nasync fn g(Path(id): Path<u64>) {\n    std::fs::read(format!(\"/srv/{id}\")).unwrap();\n}\nasync fn h(Path(n): Path<String>) {\n    let id: u64 = n.parse().unwrap();\n    std::fs::read(format!(\"/srv/{}\", id)).unwrap();\n}";
        assert_eq!(flagged("rs/path-injection", src), Vec::<usize>::new());
    }

    #[test]
    fn a_value_through_the_functions_of_the_file() {
        let src = "use rusqlite::Connection;\nasync fn handler(Query(p): Query<P>) {\n    let q = build(&p.name);\n    run(&q);\n    fetch(&p.name);\n}\nfn build(n: &str) -> String {\n    format!(\"SELECT * FROM o WHERE n = '{}'\", n)\n}\nfn run(sql: &str) {\n    conn().execute(sql, []).unwrap();\n}\nfn fetch(n: &str) {\n    conn().execute(&format!(\"DELETE FROM o WHERE n = '{n}'\"), []).unwrap();\n}\nfn safe(n: &str) -> String {\n    String::from(\"constant\")\n}";
        assert_eq!(flagged("rs/sql-injection", src), [11, 14]);
    }

    #[test]
    fn an_actix_request_object() {
        let src = "use tokio_postgres::Client;\nasync fn f(req: HttpRequest) -> HttpResponse {\n    let id = req.match_info().get(\"id\").unwrap();\n    let sql = format!(\"SELECT * FROM t WHERE id = {}\", id);\n    client.query(&sql, &[]).await.unwrap();\n    HttpResponse::Ok().finish()\n}";
        assert_eq!(flagged("rs/sql-injection", src), [5]);
    }

    #[test]
    fn only_the_start_of_an_address_sets_where_it_goes() {
        let src = "async fn a(Query(q): Query<R>) -> Redirect {\n    Redirect::to(&format!(\"/orders/{}\", q.id))\n}\nasync fn b(Query(q): Query<R>) -> Redirect {\n    let base = \"/home\";\n    Redirect::to(&format!(\"{base}?next={}\", q.next))\n}\nasync fn c(Query(q): Query<R>) -> Redirect {\n    Redirect::to(&format!(\"{}?x=1\", q.next))\n}\nasync fn d(Query(q): Query<R>) -> Redirect {\n    Redirect::to(&(\"/p/\".to_string() + &q.page))\n}\nasync fn e(Query(q): Query<R>) -> Redirect {\n    Redirect::to(&(String::from(\"//\") + &q.host))\n}";
        assert_eq!(flagged("rs/open-redirect", src), [9, 15]);
    }

    // ------------------------------------------------------------ across files (T4)

    /// The Rust taint issues of a project of files, `(path, source)`.
    fn project(files: &[(&str, &str)]) -> Vec<crate::model::Issue> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<_> = files
            .iter()
            .map(|(path, src)| {
                analyze(path, Lang::Rust, src, &rules, &cfg, far_deadline()).unwrap()
            })
            .collect();
        crate::analysis::taint_project_rules(&mut analyzed, &rules);
        analyzed
            .into_iter()
            .flat_map(|f| f.issues)
            .filter(|i| i.rule.starts_with("rs/") && !i.flow.is_empty())
            .collect()
    }

    const DB: &str = "use rusqlite::Connection;\npub fn find(name: &str) {\n    let c = Connection::open(\"x\").unwrap();\n    c.execute(&format!(\"DELETE FROM u WHERE n = '{name}'\"), []).unwrap();\n}\npub fn count() {\n    let c = Connection::open(\"x\").unwrap();\n    c.execute(\"DELETE FROM u\", []).unwrap();\n}\n";

    #[test]
    fn a_value_into_a_function_of_another_module() {
        for (use_line, call) in [
            ("use crate::db;", "db::find(&p.name)"),
            ("use crate::db::find;", "find(&p.name)"),
            ("use crate::db::find as lookup;", "lookup(&p.name)"),
            ("use crate::db::{self, count};", "db::find(&p.name)"),
            ("", "crate::db::find(&p.name)"),
        ] {
            let main = format!(
                "use axum::extract::Query;\n{use_line}\nasync fn h(Query(p): Query<P>) {{\n    {call};\n}}\n"
            );
            for db_path in ["src/db.rs", "src/db/mod.rs"] {
                let found = project(&[("src/main.rs", &main), (db_path, DB)]);
                assert_eq!(found.len(), 1, "{use_line} {call} {db_path}: {found:?}");
                assert_eq!(found[0].path, db_path);
                let flow: Vec<&str> = found[0].flow.iter().map(|s| s.message.as_str()).collect();
                assert_eq!(flow.first().copied(), Some("request parameter `p`"));
                assert!(
                    flow.iter().any(|m| m.starts_with("passed to `")),
                    "{flow:?}"
                );
            }
        }
        // Another function of that module, and a value that isn't the request's.
        let main = "use crate::db;\nuse axum::extract::Query;\nasync fn h(Query(p): Query<P>) {\n    db::count();\n    db::find(\"constant\");\n}\n";
        assert!(project(&[("src/main.rs", main), ("src/db.rs", DB)]).is_empty());
    }

    #[test]
    fn super_a_child_module_a_workspace_crate_and_a_library() {
        let handler =
            "use axum::extract::Query;\nmod db;\nasync fn h(Query(p): Query<P>) {\n    CALL;\n}\n";
        for (path, call, db) in [
            ("src/web/mod.rs", "super::db::find(&p.name)", "src/db.rs"),
            ("src/lib.rs", "db::find(&p.name)", "src/db.rs"),
            (
                "crates/web/src/lib.rs",
                "store::db::find(&p.name)",
                "crates/store/src/db.rs",
            ),
        ] {
            let found = project(&[(path, &handler.replace("CALL", call)), (db, DB)]);
            assert_eq!(found.len(), 1, "{path} {call}: {found:?}");
        }
        // A library's function isn't a module of the project.
        let lib = "use axum::extract::Query;\nuse std::fs;\nasync fn h(Query(p): Query<P>) {\n    fs::remove_file(&p.name);\n}\n";
        // (The call is a sink itself, in the file; the module of that name isn't
        // reached.)
        let found = project(&[("src/main.rs", lib), ("src/fs.rs", DB)]);
        assert!(found.iter().all(|i| i.path != "src/fs.rs"), "{found:?}");
    }

    #[test]
    fn a_method_of_a_type_another_file_declares() {
        let repo = "use rusqlite::Connection;\npub struct UserRepo { conn: Connection }\nimpl UserRepo {\n    pub fn find(&self, name: &str) {\n        self.conn.execute(&format!(\"DELETE FROM u WHERE n = '{name}'\"), []).unwrap();\n    }\n}\n";
        let by_param = "use crate::repo::UserRepo;\nuse axum::extract::Query;\nasync fn h(State(repo): State<UserRepo>, Query(p): Query<P>, r: UserRepo) {\n    r.find(&p.name);\n}\n";
        let by_field = "use crate::repo::UserRepo;\nuse axum::extract::Query;\nstruct Service { repo: std::sync::Arc<UserRepo> }\nimpl Service {\n    async fn h(&self, Query(p): Query<P>) {\n        self.repo.find(&p.name);\n    }\n}\n";
        for main in [by_param, by_field] {
            let found = project(&[("src/main.rs", main), ("src/repo.rs", repo)]);
            assert_eq!(found.len(), 1, "{main}: {found:?}");
            assert_eq!(found[0].path, "src/repo.rs");
        }
    }

    #[test]
    fn through_a_second_module() {
        let service = "use crate::db;\npub fn run(name: &str) {\n    db::find(name);\n}\n";
        let main = "use crate::service;\nuse axum::extract::Query;\nasync fn h(Query(p): Query<P>) {\n    service::run(&p.name);\n}\n";
        let found = project(&[
            ("src/main.rs", main),
            ("src/service.rs", service),
            ("src/db.rs", DB),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "src/db.rs");
        let files: Vec<Option<&str>> = found[0].flow.iter().map(|s| s.path.as_deref()).collect();
        assert!(files.contains(&Some("src/service.rs")), "{files:?}");
    }

    #[test]
    fn what_is_written_is_not_the_path() {
        let src = "async fn f(Query(q): Query<R>) {\n    std::fs::write(\"/srv/out\", q.text).unwrap();\n    std::fs::write(&q.name, \"x\").unwrap();\n}";
        assert_eq!(flagged("rs/path-injection", src), [3]);
    }

    #[test]
    fn another_modules_result_reaching_a_sink() {
        let sink = "use rusqlite::Connection;\nuse crate::text;\nuse axum::extract::Query;\nasync fn h(Query(p): Query<P>) {\n    let n = text::wrap(&p.name);\n    let c = Connection::open(\"x\").unwrap();\n    c.execute(&format!(\"DELETE FROM u WHERE n = '{n}'\"), []).unwrap();\n}\n";
        // The helper hands back what it was given.
        let wrap = "pub fn wrap(x: &str) -> String {\n    format!(\"<{x}>\")\n}\n";
        let found = project(&[("src/main.rs", sink), ("src/text.rs", wrap)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "src/main.rs");
        let flow: Vec<&str> = found[0].flow.iter().map(|s| s.message.as_str()).collect();
        assert!(
            flow.iter().any(|m| m.starts_with("returned by")),
            "{flow:?}"
        );
        // A helper that returns a constant clears it.
        let constant = "pub fn wrap(x: &str) -> String {\n    String::from(\"fixed\")\n}\n";
        assert!(project(&[("src/main.rs", sink), ("src/text.rs", constant)]).is_empty());
        // The call's own result is no request's value when nothing reaches it.
        let alone = "use rusqlite::Connection;\nuse crate::text;\nfn f() {\n    let n = text::wrap(\"a\");\n    let c = Connection::open(\"x\").unwrap();\n    c.execute(&format!(\"DELETE FROM u WHERE n = '{n}'\"), []).unwrap();\n}\n";
        assert!(project(&[("src/main.rs", alone), ("src/text.rs", wrap)]).is_empty());
    }

    #[test]
    fn another_modules_function_that_reads_the_request_itself() {
        let main = "use rusqlite::Connection;\nuse crate::input;\nasync fn h(req: HttpRequest) {\n    let id = input::id(&req);\n    let c = Connection::open(\"x\").unwrap();\n    c.execute(&format!(\"DELETE FROM u WHERE id = {id}\"), []).unwrap();\n}\n";
        let input =
            "pub fn id(req: &HttpRequest) -> String {\n    req.query_string().to_string()\n}\n";
        let found = project(&[("src/main.rs", main), ("src/input.rs", input)]);
        assert_eq!(found.len(), 1, "{found:?}");
        // A method of a type another file declares.
        let main = "use rusqlite::Connection;\nuse crate::input::Reader;\nasync fn h(req: HttpRequest, r: Reader) {\n    let id = r.read(&req);\n    let c = Connection::open(\"x\").unwrap();\n    c.execute(&format!(\"DELETE FROM u WHERE id = {id}\"), []).unwrap();\n}\n";
        let reader = "pub struct Reader;\nimpl Reader {\n    pub fn read(&self, req: &HttpRequest) -> String {\n        req.query_string().to_string()\n    }\n}\n";
        let found = project(&[("src/main.rs", main), ("src/input.rs", reader)]);
        assert_eq!(found.len(), 1, "{found:?}");
    }

    #[test]
    fn a_glob_import_names_the_functions_of_its_module() {
        let closure = "use crate::db::*;\nuse axum::extract::Query;\nasync fn h(Query(p): Query<P>) {\n    let find = |x: &str| x.len();\n    find(&p.name);\n}\n";
        assert!(project(&[("src/main.rs", closure), ("src/db.rs", DB)]).is_empty());
        let main = |use_line: &str| {
            format!(
                "use axum::extract::Query;\n{use_line}\nasync fn h(Query(p): Query<P>) {{\n    find(&p.name);\n}}\n"
            )
        };
        let found = project(&[
            ("src/main.rs", &main("use crate::db::*;")),
            ("src/db.rs", DB),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "src/db.rs");
        // Two globs: a bare name could be either's.
        let two = main("use crate::db::*;\nuse crate::other::*;");
        assert!(project(&[("src/main.rs", &two), ("src/db.rs", DB)]).is_empty());
        // A library's glob names no module of the project.
        let lib = main("use std::fs::*;");
        assert!(project(&[("src/main.rs", &lib), ("src/db.rs", DB)]).is_empty());
        // A type from a glob, and its method.
        let repo = "use rusqlite::Connection;\npub struct UserRepo { conn: Connection }\nimpl UserRepo {\n    pub fn find(&self, name: &str) {\n        self.conn.execute(&format!(\"DELETE FROM u WHERE n = '{name}'\"), []).unwrap();\n    }\n}\n";
        let by_type = "use crate::repo::*;\nuse axum::extract::Query;\nasync fn h(Query(p): Query<P>, r: UserRepo) {\n    r.find(&p.name);\n}\n";
        let found = project(&[("src/main.rs", by_type), ("src/repo.rs", repo)]);
        assert_eq!(found.len(), 1, "{found:?}");
    }
}
