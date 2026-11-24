//! Taint analysis for C and C++, phases T2 and T3 (ADR-0027): which values
//! that came from a request reach a sink, and by what path.
//!
//! Like the other languages', it's **flow-insensitive** over the scopes of the
//! C/C++ binder (S1): a variable that is ever written a request's value holds
//! it wherever the binding is visible, and the whole file is one fixed point
//! over its writes. A function of the file is followed through its summary
//! (T3), per parameter.
//!
//! Precision before recall, as the ADR says:
//! - the command line, standard input and the environment are the program's
//!   own: a value is a request's only when it comes from a web framework's
//!   request (cpp-httplib, Crow, Drogon, Pistache), a socket (`recv`) or a
//!   CGI variable (`getenv("QUERY_STRING")`);
//! - a call this module doesn't know returns an untainted value, so a
//!   program's own escaping helper sanitizes, and `atoi` and `strlen` give
//!   numbers, which can't inject;
//! - a value that's tested in the file by a call that reads as a check
//!   (`strstr`, `starts_with`, `realpath`, ...) is taken as validated;
//! - the request object itself isn't tainted, only what it returns.
//!
//! C has no return values for the functions that build text: `snprintf`,
//! `strcat` and `memcpy` write into an argument, so a call like that is a
//! write of its source arguments into its destination.

use super::taint::{Callee, Facts, Finding, SinkKind, Step, TaintResult};
use super::taint_core::{
    Flow, How, Path, Reaches, Summaries, Write, at_sinks, best, checked_names, decl_index, finish,
    flow_for, held, inside, outcome, return_values, sinks_in, through_returns, through_sinks, tick,
    walk,
};
use super::{DeclId, DeclKind, Model};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;
/// Summaries per file, at most: past it, calls to other functions give nothing.
const MAX_SUMMARIES: usize = 256;

/// What a file names when it handles a web framework's requests.
const FRAMEWORKS: &[&str] = &["httplib", "crow", "drogon", "pistache"];

/// Types of a request object, by their last name.
const REQUEST_TYPES: &[&str] = &["Request", "request", "HttpRequest", "HttpRequestPtr"];

/// What a request object has that a client chooses: methods and fields.
const REQUEST_MEMBERS: &[&str] = &[
    "get_param_value",
    "get_header_value",
    "getParameter",
    "getParameters",
    "getBody",
    "getHeader",
    "getCookie",
    "getPath",
    "getQuery",
    "body",
    "query",
    "path",
    "param",
    "params",
    "path_params",
    "resource",
    "header",
    "headers",
    "cookies",
    "target",
    "url",
    "raw_url",
    "url_params",
];

/// Methods whose result is, or holds, their receiver's text.
const PROPAGATING_METHODS: &[&str] = &[
    "c_str",
    "data",
    "str",
    "string",
    "substr",
    "get",
    "value",
    "value_or",
    "as",
    "find",
    "at",
    "toStdString",
    "toUtf8",
    "toLocal8Bit",
    "toLatin1",
    "constData",
    "u8string",
    "native",
    "generic_string",
];

/// Functions whose result is their first argument's text, or part of it.
const PROPAGATING_CALLS: &[&str] = &[
    "strdup",
    "strndup",
    "strtok",
    "strtok_r",
    "string",
    "string_view",
    "path",
    "move",
    "forward",
    "fromStdString",
    "fromUtf8",
    "fromLatin1",
    "fromLocal8Bit",
    "QString",
    "QByteArray",
];

/// Types that hold text, by their last name: a constructor call with a value
/// writes it into the variable.
const TEXT_TYPES: &[&str] = &[
    "string",
    "string_view",
    "wstring",
    "path",
    "QString",
    "QByteArray",
    "ostringstream",
    "stringstream",
];

/// Types of numbers and the like, which can't inject.
const NUMERIC_TYPES: &[&str] = &[
    "int",
    "long",
    "short",
    "char",
    "float",
    "double",
    "bool",
    "unsigned",
    "signed",
    "size_t",
    "ssize_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uint",
    "intptr_t",
    "uintptr_t",
    "ptrdiff_t",
    "time_t",
    "off_t",
    "socklen_t",
    "SOCKET",
    "DWORD",
];

/// CGI variables a client chooses (and every `HTTP_*`).
const CGI_VARIABLES: &[&str] = &[
    "QUERY_STRING",
    "PATH_INFO",
    "PATH_TRANSLATED",
    "REQUEST_URI",
    "SCRIPT_NAME",
    "CONTENT_TYPE",
];

/// What the file must contain for the kind's sinks to be in it.
fn might_have_sinks(src: &[u8], kind: SinkKind) -> bool {
    let words: &[&[u8]] = match kind {
        SinkKind::Sql => &[
            b"sqlite3_",
            b"mysql_",
            b"pqexec",
            b"pqsend",
            b"pqprepare",
            b"sqlexec",
            b"sqlprepare",
            b"qsqlquery",
            b"sqlite::",
            b"pqxx",
            b"sql::",
        ],
        SinkKind::Command => &[
            b"system",
            b"popen",
            b"exec",
            b"createprocess",
            b"shellexecute",
            b"winexec",
            b"qprocess",
            b"g_spawn",
        ],
        SinkKind::Path => &[
            b"fopen",
            b"open",
            b"fstream",
            b"filesystem",
            b"unlink",
            b"remove",
            b"rename",
            b"mkdir",
            b"createfile",
            b"qfile",
            b"qdir",
            b"stat",
            b"access",
            b"chdir",
        ],
        SinkKind::Redirect => &[b"redirect", b"location"],
        SinkKind::Ssrf => &[b"curlopt_url", b"httplib"],
        SinkKind::Format => &[b"printf", b"syslog", b"err(", b"errx(", b"warn(", b"warnx("],
        SinkKind::XPath | SinkKind::Ldap | SinkKind::Code => return false,
    };
    contains_any(src, words)
}

/// What the file must contain for a request's value to be in it.
fn might_have_sources(src: &[u8]) -> bool {
    let words: &[&[u8]] = &[
        b"httplib",
        b"crow",
        b"drogon",
        b"pistache",
        b"recv",
        b"ssl_read",
        b"getenv",
        b"fcgx_getparam",
    ];
    contains_any(src, words)
}

fn contains_any(src: &[u8], words: &[&[u8]]) -> bool {
    let lower = src.to_ascii_lowercase();
    words
        .iter()
        .any(|w| lower.windows(w.len()).any(|x| x == *w))
}

/// Calls that, with a value as argument or receiver, read as checking it.
fn check_words(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Path | SinkKind::Redirect | SinkKind::Ssrf => &[
            "strstr",
            "strchr",
            "strrchr",
            "strcmp",
            "strncmp",
            "strcasecmp",
            "strncasecmp",
            "compare",
            "starts_with",
            "ends_with",
            "contains",
            "find",
            "rfind",
            "realpath",
            "canonical",
            "weakly_canonical",
            "lexically_normal",
            "is_absolute",
            "is_relative",
            "has_root_path",
            "regex_match",
            "regex_search",
            "startsWith",
            "endsWith",
            "indexOf",
        ],
        _ => &[
            "strcmp",
            "strncmp",
            "strcasecmp",
            "strncasecmp",
            "compare",
            "regex_match",
            "regex_search",
            "isalnum",
            "isdigit",
            "isalpha",
            "isxdigit",
        ],
    }
}

// ---------------------------------------------------------------- entry

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    if !might_have_sinks(src, kind) || !might_have_sources(src) {
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
    TaintResult {
        findings: finish(cx.reached(&tainted)),
        facts: Facts::default(),
    }
}

// ---------------------------------------------------------------- the file

/// What a request's value does inside a function of the file, for one of its
/// parameters.
#[derive(Default)]
struct Summary<'t> {
    returns: Option<Path<'t>>,
    sinks: Vec<(Path<'t>, Node<'t>)>,
    /// Never filled until values cross files (T4).
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
    /// The file handles a web framework's requests.
    framework: bool,
    by_node: HashMap<usize, DeclId>,
    /// Variables that hold a request object.
    requests: HashSet<DeclId>,
    /// What is a request's value from the start, each with its path.
    initial: HashMap<DeclId, Path<'t>>,
    /// Variables a check reads as validating, for this kind of sink.
    checked: HashSet<DeclId>,
    writes: Vec<Write<'t>>,
    /// The calls of the file, and the declarations that construct an object.
    calls: Vec<Node<'t>>,
    /// Each function's name, by its index (empty for a lambda), and the
    /// functions by name.
    names: Vec<&'a str>,
    by_name: HashMap<&'a str, Vec<usize>>,
    evaluations: Cell<u64>,
    summaries: Summaries<SummaryKey, Summary<'t>>,
}

impl<'a, 't> Cx<'a, 't> {
    fn new(m: &'a Model<'t>, src: &'a [u8], kind: SinkKind, root: Node<'t>) -> Option<Self> {
        let lower = src.to_ascii_lowercase();
        let framework = FRAMEWORKS
            .iter()
            .any(|w| lower.windows(w.len()).any(|x| x == w.as_bytes()));
        let mut cx = Cx {
            m,
            src,
            kind,
            framework,
            by_node: decl_index(m),
            requests: HashSet::new(),
            initial: HashMap::new(),
            checked: HashSet::new(),
            writes: Vec::new(),
            calls: Vec::new(),
            names: Vec::new(),
            by_name: HashMap::new(),
            evaluations: Cell::new(0),
            summaries: Summaries::new(MAX_SUMMARIES),
        };
        cx.index();
        cx.collect(root)?;
        cx.sources();
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// The functions of the file by name, and the variables that hold a
    /// request object.
    fn index(&mut self) {
        for (j, f) in self.m.functions.iter().enumerate() {
            let name = function_name(f.node).map_or("", |n| self.text(n));
            self.names.push(name);
            if !name.is_empty() {
                self.by_name.entry(name).or_default().push(j);
            }
        }
        if !self.framework {
            return;
        }
        for (d, decl) in self.m.decls.iter().enumerate() {
            if decl.kind == DeclKind::Param
                && decl
                    .ty
                    .is_some_and(|t| REQUEST_TYPES.contains(&last_name(self.text(t)).as_str()))
            {
                self.requests.insert(d);
            }
        }
    }

    /// Walks the file once, in source order, for its writes, calls and
    /// checks. None past a limit.
    fn collect(&mut self, root: Node<'t>) -> Option<()> {
        let mut checks: Vec<Node<'t>> = Vec::new();
        let words = check_words(self.kind);
        walk(root, |n| {
            self.visit(n, words, &mut checks);
            self.writes.len() <= MAX_WRITES
        })?;
        // A variable named as a check's receiver or argument is validated.
        let named = checked_names(checks, arguments, ("field_expression", "argument"), |n| {
            self.decl_of(unwrap(n))
        });
        self.checked.extend(named);
        Some(())
    }

    /// Records what one node writes, calls or checks.
    fn visit(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        match n.kind() {
            "init_declarator" => self.initialization(n),
            "assignment_expression" => self.assignment(n),
            "for_range_loop" => self.range_loop(n),
            "call_expression" => self.call(n, words, checks),
            "binary_expression" => self.binary(n),
            _ => {}
        }
    }

    /// `T x = v;`, `T x(v);`, `T x{v};`: the variable gets the value.
    fn initialization(&mut self, n: Node<'t>) {
        let (Some(d), Some(v)) = (
            n.child_by_field_name("declarator"),
            n.child_by_field_name("value"),
        ) else {
            return;
        };
        let Some(name) = declared_name(d) else {
            return;
        };
        let Some(target) = self.decl_of(name) else {
            return;
        };
        if matches!(v.kind(), "argument_list" | "initializer_list") {
            // A constructor call: it's a call, and for a type that holds
            // text, its first argument is the value.
            if self.is_constructor_sink_type(n) {
                self.calls.push(n);
            }
            let holds_text = self
                .declared_type(n)
                .is_some_and(|t| TEXT_TYPES.contains(&t.as_str()));
            if holds_text && let Some(first) = v.named_child(0) {
                self.write(target, name, first, How::Assigned);
            }
            return;
        }
        self.write(target, name, v, How::Assigned);
    }

    /// `x = v;`, `x += v;`, `buf[i] = v;`.
    fn assignment(&mut self, n: Node<'t>) {
        let (Some(l), Some(r)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        let how = match n
            .child_by_field_name("operator")
            .map_or("", |o| self.text(o))
        {
            "=" => How::Assigned,
            "+=" => How::Added,
            _ => return,
        };
        let (target, how) = match l.kind() {
            "identifier" => (l, how),
            "subscript_expression" => (l, How::Added),
            _ => return,
        };
        if let Some((d, node)) = self.base_of(target) {
            self.write(d, node, r, how);
        }
    }

    /// `for (auto c : v)`: the variable holds a part of the value.
    fn range_loop(&mut self, n: Node<'t>) {
        let (Some(d), Some(v)) = (
            n.child_by_field_name("declarator"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        if let Some(name) = declared_name(d)
            && let Some(target) = self.decl_of(name)
        {
            self.write(target, name, v, How::Read);
        }
    }

    /// `x == "..."` tests the value; `out << v` writes a stream.
    fn binary(&mut self, n: Node<'t>) {
        let op = n
            .child_by_field_name("operator")
            .map_or("", |o| self.text(o));
        match op {
            "==" | "!=" if !matches!(self.kind, SinkKind::Sql) => {
                for side in ["left", "right"] {
                    if let Some(d) = n
                        .child_by_field_name(side)
                        .and_then(|s| self.decl_of(unwrap(s)))
                    {
                        self.checked.insert(d);
                    }
                }
            }
            "<<" => {
                // `oss << a << b` is `(oss << a) << b`: the stream is the
                // leftmost operand.
                let (Some(l), Some(r)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) else {
                    return;
                };
                let mut stream = l;
                while stream.kind() == "binary_expression" {
                    match stream.child_by_field_name("left") {
                        Some(next) => stream = next,
                        None => return,
                    }
                }
                if stream.kind() == "identifier"
                    && let Some(d) = self.decl_of(stream)
                    && self.m.decls[d]
                        .ty
                        .is_some_and(|t| self.text(t).contains("stringstream"))
                {
                    self.write(d, stream, r, How::Added);
                }
            }
            _ => {}
        }
    }

    fn write(&mut self, target: DeclId, target_node: Node<'t>, value: Node<'t>, how: How) {
        if self.is_inert(target) {
            return;
        }
        self.writes.push(Write {
            target,
            target_node,
            value,
            how,
        });
    }

    /// A call: the check it may be, what it writes into its arguments, and a
    /// sink or a function it may be.
    fn call(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        self.calls.push(n);
        let Some((segments, receiver)) = self.parts(n) else {
            return;
        };
        let Some(&name) = segments.last() else {
            return;
        };
        if words.contains(&name) || is_a_check_by_name(name) {
            checks.push(n);
        }
        let args = arguments(n);
        if let Some(receiver) = receiver {
            self.method_writes(receiver, name, &args);
        } else {
            self.argument_writes(name, &args);
        }
    }

    /// `snprintf(buf, n, fmt, v)`, `strcat(d, s)`, `memcpy(d, s, n)`: the
    /// destination gets the values.
    fn argument_writes(&mut self, name: &str, args: &[Node<'t>]) {
        let from = match name {
            "snprintf" | "snprintf_s" | "sprintf_s" | "swprintf" => 2,
            "sprintf" | "strcpy" | "strcat" | "stpcpy" | "wcscpy" | "wcscat" | "strncpy"
            | "strncat" | "memcpy" | "memmove" | "stpncpy" | "wcsncpy" => 1,
            _ => return,
        };
        let sources: &[Node<'t>] = if from == 1 && name != "sprintf" {
            args.get(1..2).unwrap_or_default()
        } else {
            args.get(from..).unwrap_or_default()
        };
        let Some((d, node)) = args.first().and_then(|a| self.base_of(*a)) else {
            return;
        };
        for v in sources {
            self.write(d, node, *v, How::Added);
        }
    }

    /// `s.append(v)`: the string holds the value.
    fn method_writes(&mut self, receiver: Node<'t>, name: &str, args: &[Node<'t>]) {
        if !matches!(name, "append" | "assign" | "insert" | "replace") {
            return;
        }
        let Some((d, node)) = self.base_of(receiver) else {
            return;
        };
        for v in args {
            self.write(d, node, *v, How::Added);
        }
    }

    /// The variable an argument writes into, and the node that names it:
    /// through casts, `&x`, `x + n`, `x[i]` and `x.data()`.
    fn base_of(&self, n: Node<'t>) -> Option<(DeclId, Node<'t>)> {
        let mut n = n;
        for _ in 0..16 {
            match n.kind() {
                "identifier" => return Some((self.decl_of(n)?, n)),
                "cast_expression" => n = n.child_by_field_name("value")?,
                "parenthesized_expression" => n = n.named_child(0)?,
                "pointer_expression" => n = n.child_by_field_name("argument")?,
                "binary_expression" => n = n.child_by_field_name("left")?,
                "subscript_expression" => n = n.child_by_field_name("argument")?,
                "field_expression" => n = n.child_by_field_name("argument")?,
                "call_expression" => {
                    let f = n.child_by_field_name("function")?;
                    if f.kind() != "field_expression" {
                        return None;
                    }
                    n = f.child_by_field_name("argument")?;
                }
                _ => return None,
            }
        }
        None
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

    /// A variable of a number's type, which can't hold what injects. An
    /// array or a pointer of them is text.
    fn is_inert(&self, d: DeclId) -> bool {
        let decl = &self.m.decls[d];
        let Some(ty) = decl.ty else {
            return false;
        };
        let plain = decl.node.parent().is_some_and(|p| {
            matches!(
                p.kind(),
                "declaration" | "init_declarator" | "parameter_declaration"
            )
        });
        plain && NUMERIC_TYPES.contains(&last_name(self.text(ty)).as_str())
    }

    /// The type a declaration or a variable is declared with, by its last
    /// name.
    fn declared_type(&self, init: Node<'t>) -> Option<String> {
        let ty = init.parent()?.child_by_field_name("type")?;
        Some(last_name(self.text(ty)))
    }

    /// The type of a variable named by `n`, as written.
    fn type_of(&self, n: Node<'t>) -> Option<&'a str> {
        let d = self.decl_of(unwrap(n))?;
        self.m.decls[d].ty.map(|t| self.text(t))
    }

    // ------------------------------------------------------------ sources

    /// A web handler's path parameters, and what a socket's `recv` fills.
    fn sources(&mut self) {
        let mut found = self.route_parameters();
        found.extend(self.socket_buffers());
        for (d, path) in found {
            self.initial.entry(d).or_insert(path);
        }
    }

    /// The text parameters of a Crow route's handler.
    fn route_parameters(&self) -> Vec<(DeclId, Path<'t>)> {
        let mut found = Vec::new();
        for f in self
            .m
            .functions
            .iter()
            .filter(|f| self.is_crow_route(f.node))
        {
            for &d in f.params.iter().flatten() {
                let decl = &self.m.decls[d];
                let text = decl.ty.is_some_and(|t| {
                    let t = self.text(t);
                    t.contains("string") || t.contains("char") || t.contains("QString")
                });
                if decl.kind == DeclKind::Param
                    && text
                    && !self.requests.contains(&d)
                    && !self.is_inert(d)
                {
                    found.push((
                        d,
                        vec![Step {
                            node: decl.node,
                            message: format!("route parameter `{}`", decl.name),
                        }],
                    ));
                }
            }
        }
        found
    }

    /// The buffers `recv(s, buf, ..)` fills.
    fn socket_buffers(&self) -> Vec<(DeclId, Path<'t>)> {
        let mut found = Vec::new();
        for &call in self.calls.iter().filter(|c| c.kind() == "call_expression") {
            let Some((segments, None)) = self.parts(call) else {
                continue;
            };
            let name = *segments.last().unwrap_or(&"");
            if !matches!(name, "recv" | "recvfrom" | "SSL_read") {
                continue;
            }
            if let Some((d, _)) = arguments(call).get(1).and_then(|a| self.base_of(*a))
                && !self.is_inert(d)
            {
                found.push((
                    d,
                    vec![Step {
                        node: call,
                        message: format!("received from a socket by `{name}`"),
                    }],
                ));
            }
        }
        found
    }

    /// A lambda that `CROW_ROUTE(app, "/x/<string>")` takes as its handler.
    fn is_crow_route(&self, function: Node<'t>) -> bool {
        if function.kind() != "lambda_expression" {
            return false;
        }
        let Some(call) = function
            .parent()
            .filter(|p| p.kind() == "argument_list")
            .and_then(|a| a.parent())
            .filter(|c| c.kind() == "call_expression")
        else {
            return false;
        };
        call.child_by_field_name("function")
            .filter(|f| f.kind() == "call_expression")
            .and_then(|f| f.child_by_field_name("function"))
            .is_some_and(|name| self.text(name).starts_with("CROW_"))
    }

    // ------------------------------------------------------------ calls

    /// A call's callee: its names, `std::filesystem::remove` as three, and
    /// the receiver of a method call.
    fn parts(&self, call: Node<'t>) -> Option<(Vec<&'a str>, Option<Node<'t>>)> {
        let f = call.child_by_field_name("function")?;
        match f.kind() {
            "identifier" => Some((vec![self.text(f)], None)),
            "qualified_identifier" => Some((
                self.text(f)
                    .split("::")
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect(),
                None,
            )),
            "field_expression" => {
                let name = f.child_by_field_name("field")?;
                if name.kind() != "field_identifier" {
                    return None;
                }
                Some((vec![self.text(name)], f.child_by_field_name("argument")))
            }
            _ => None,
        }
    }

    /// Whether the file defines a function of this name: then a call to it
    /// is that function, not a library's.
    fn defined_here(&self, name: &str) -> bool {
        self.by_name.contains_key(name)
    }

    /// Whether the type a declaration declares has a constructor that is a
    /// sink for some kind.
    fn is_constructor_sink_type(&self, init: Node<'t>) -> bool {
        self.declared_type(init)
            .is_some_and(|t| constructor_sink(self.kind, &t).is_some())
    }

    // ------------------------------------------------------------ evaluation

    fn run(&self) -> Option<HashMap<DeclId, Path<'t>>> {
        let mut tainted = self.initial.clone();
        self.propagate(None, &mut tainted)?;
        Some(tainted)
    }

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
            "parenthesized_expression" => self.taint(n.named_child(0)?, state, next),
            "cast_expression" => self.taint(n.child_by_field_name("value")?, state, next),
            "pointer_expression" | "subscript_expression" => {
                self.taint(n.child_by_field_name("argument")?, state, next)
            }
            "binary_expression" => {
                let op = n
                    .child_by_field_name("operator")
                    .map_or("", |o| self.text(o));
                if op != "+" {
                    return None;
                }
                best(
                    ["left", "right"]
                        .into_iter()
                        .filter_map(|s| n.child_by_field_name(s))
                        .map(|c| self.taint(c, state, next)),
                )
            }
            "conditional_expression" => best(
                ["consequence", "alternative"]
                    .into_iter()
                    .filter_map(|s| n.child_by_field_name(s))
                    .map(|c| self.taint(c, state, next)),
            ),
            "assignment_expression" => self.taint(n.child_by_field_name("right")?, state, next),
            "field_expression" => self.field_taint(n, state, next),
            "call_expression" => self.call_taint(n, state, next),
            _ => None,
        }
    }

    /// `req.body`, `req.url_params`; a field of a tainted value.
    fn field_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let object = n.child_by_field_name("argument")?;
        let field = self.text(n.child_by_field_name("field")?);
        if self.is_a_request(object) && REQUEST_MEMBERS.contains(&field) {
            return Some(vec![Step {
                node: n,
                message: format!(
                    "read from the request: `{}`",
                    super::taint_core::short(self.text(n))
                ),
            }]);
        }
        self.taint(object, state, depth)
    }

    /// Whether `n` is a request object, or a part of one (`req.headers`).
    fn is_a_request(&self, n: Node<'t>) -> bool {
        let mut n = n;
        for _ in 0..16 {
            match n.kind() {
                "identifier" => return self.decl_of(n).is_some_and(|d| self.requests.contains(&d)),
                "field_expression" => match n.child_by_field_name("argument") {
                    Some(a) => n = a,
                    None => return false,
                },
                "call_expression" => match n
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "field_expression")
                    .and_then(|f| f.child_by_field_name("argument"))
                {
                    Some(a) => n = a,
                    None => return false,
                },
                "parenthesized_expression" | "pointer_expression" => match n.named_child(0) {
                    Some(a) => n = a,
                    None => return false,
                },
                _ => return false,
            }
        }
        false
    }

    fn call_taint(
        &self,
        call: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let (segments, receiver) = self.parts(call)?;
        let name = *segments.last()?;
        let args = arguments(call);
        if let Some(receiver) = receiver {
            if self.is_a_request(receiver) && REQUEST_MEMBERS.contains(&name) {
                return Some(vec![Step {
                    node: call,
                    message: format!("read from the request by `{name}`"),
                }]);
            }
            if PROPAGATING_METHODS.contains(&name) && !self.defined_here(name) {
                return self.taint(receiver, state, depth);
            }
            return self.through_function(call, &args, state, depth);
        }
        if let Some(variable) = self.cgi_variable(name, &args) {
            return Some(vec![Step {
                node: call,
                message: format!("read from the CGI variable `{variable}`"),
            }]);
        }
        if PROPAGATING_CALLS.contains(&name) && !self.defined_here(name) {
            return self.taint(*args.first()?, state, depth);
        }
        self.through_function(call, &args, state, depth)
    }

    /// `getenv("QUERY_STRING")`: the CGI variable a client chooses.
    fn cgi_variable(&self, name: &str, args: &[Node<'t>]) -> Option<&'a str> {
        if !matches!(name, "getenv" | "secure_getenv" | "FCGX_GetParam") {
            return None;
        }
        let literal = args.first().filter(|a| a.kind() == "string_literal")?;
        let variable = self.text(*literal).trim_matches('"');
        (CGI_VARIABLES.contains(&variable) || variable.starts_with("HTTP_")).then_some(variable)
    }

    // ------------------------------------------------------------ sinks

    fn reached(&self, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let mut out = at_sinks(
            &self.calls,
            |c| self.sink_call(c),
            |a| self.taint(a, state, 0),
        );
        for &call in &self.calls {
            out.extend(self.sinks_through(call, state));
        }
        out
    }

    /// The sink a call is, for this kind, and the arguments that take the
    /// value.
    fn sink_call(&self, call: Node<'t>) -> Option<(String, Vec<Node<'t>>)> {
        if call.kind() == "init_declarator" {
            let ty = self.declared_type(call)?;
            let at = constructor_sink(self.kind, &ty)?;
            let args = arguments(call);
            return Some((ty, args.get(at).copied().into_iter().collect()));
        }
        let args = arguments(call);
        let (segments, receiver) = self.parts(call)?;
        let name = *segments.last()?;
        let before = if segments.len() >= 2 {
            segments[segments.len() - 2]
        } else {
            ""
        };
        let at = match receiver {
            None => {
                if self.defined_here(name) && segments.len() == 1 {
                    return None;
                }
                function_sink(self.kind, name, before, &args, self)?
            }
            Some(r) => self.method_sink(r, name, &args)?,
        };
        let taking = at
            .into_iter()
            .filter_map(|i| args.get(i).copied())
            .collect();
        Some((name.to_string(), taking))
    }

    fn method_sink(&self, receiver: Node<'t>, name: &str, args: &[Node<'t>]) -> Option<Vec<usize>> {
        let ty = self.type_of(receiver).unwrap_or_default();
        match self.kind {
            SinkKind::Command
                if ty.contains("QProcess") && matches!(name, "start" | "startDetached") =>
            {
                Some(vec![0])
            }
            SinkKind::Path if ty.contains("fstream") && name == "open" => Some(vec![0]),
            SinkKind::Sql
                if (ty.contains("QSqlQuery") && matches!(name, "exec" | "prepare"))
                    || ((ty.contains("SQLite::") || ty.contains("pqxx"))
                        && matches!(
                            name,
                            "exec" | "exec0" | "exec1" | "query" | "query_value" | "execAndGet"
                        ))
                    || (ty.contains("sql::")
                        && matches!(
                            name,
                            "execute" | "executeQuery" | "executeUpdate" | "prepareStatement"
                        )) =>
            {
                Some(vec![0])
            }
            SinkKind::Redirect if self.framework => match name {
                "set_redirect" | "redirect" | "redirect_permanent" => Some(vec![0]),
                "set_header" | "add_header" | "addHeader" | "append_header"
                    if args.first().is_some_and(|a| self.is_location(*a)) =>
                {
                    Some(vec![1])
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether `a` is the string `"Location"`.
    fn is_location(&self, a: Node<'t>) -> bool {
        a.kind() == "string_literal"
            && self
                .text(a)
                .trim_matches('"')
                .eq_ignore_ascii_case("location")
    }

    /// Whether `a` is a literal that starts a CGI redirect: `"Location: ..."`.
    fn starts_a_location(&self, a: Node<'t>) -> bool {
        a.kind() == "string_literal"
            && self
                .text(a)
                .trim_matches('"')
                .to_ascii_lowercase()
                .starts_with("location:")
    }
}

/// The sink a type's constructor is, for a kind: the argument that takes the
/// value.
fn constructor_sink(kind: SinkKind, ty: &str) -> Option<usize> {
    match (kind, ty) {
        (
            SinkKind::Path,
            "ifstream" | "ofstream" | "fstream" | "wifstream" | "wofstream" | "QFile",
        ) => Some(0),
        (SinkKind::Sql, "QSqlQuery") => Some(0),
        (SinkKind::Ssrf, "Client") => Some(0),
        _ => None,
    }
}

/// Which arguments of a call to the function `name` take a value for this
/// kind of sink. `before` is the name before it in a qualified call.
fn function_sink<'t>(
    kind: SinkKind,
    name: &str,
    before: &str,
    args: &[Node<'t>],
    cx: &Cx<'_, 't>,
) -> Option<Vec<usize>> {
    match kind {
        SinkKind::Command => command_sink(name, before, args, cx),
        SinkKind::Path => path_sink(name, before),
        SinkKind::Sql => sql_sink(name),
        SinkKind::Redirect => redirect_sink(name, before, args, cx),
        SinkKind::Ssrf => ssrf_sink(name, before, args, cx),
        SinkKind::Format => format_sink(name, before),
        SinkKind::XPath | SinkKind::Ldap | SinkKind::Code => None,
    }
}

/// Whether a call is to the library's function of that name, not a method
/// or another namespace's.
fn is_library(before: &str) -> bool {
    matches!(before, "" | "std" | "filesystem" | "fs")
}

fn command_sink<'t>(
    name: &str,
    before: &str,
    args: &[Node<'t>],
    cx: &Cx<'_, 't>,
) -> Option<Vec<usize>> {
    match name {
        "system"
        | "popen"
        | "_popen"
        | "_wsystem"
        | "wsystem"
        | "WinExec"
        | "g_spawn_command_line_sync"
        | "g_spawn_command_line_async"
            if is_library(before) =>
        {
            Some(vec![0])
        }
        "execl" | "execlp" | "execle" | "execv" | "execvp" | "execvpe" | "_execl" | "_execlp"
        | "_execv" | "_execvp" => {
            // A shell takes the whole command line, whatever its argument.
            let shell = args.first().is_some_and(|a| {
                let t = cx.text(*a).trim_matches('"');
                t.ends_with("sh") || t.ends_with("cmd.exe") || t == "cmd"
            });
            Some(if shell {
                (0..args.len()).collect()
            } else {
                vec![0]
            })
        }
        "CreateProcessA" | "CreateProcessW" | "CreateProcess" => Some(vec![0, 1]),
        "ShellExecuteA" | "ShellExecuteW" | "ShellExecute" => Some(vec![2, 3]),
        "execute" | "startDetached" if before == "QProcess" => Some(vec![0]),
        _ => None,
    }
}

fn path_sink(name: &str, before: &str) -> Option<Vec<usize>> {
    let library = is_library(before);
    match name {
        "fopen" | "freopen" | "open" | "open64" | "creat" | "unlink" | "remove" | "rmdir"
        | "mkdir" | "chdir" | "chmod" | "chown" | "access" | "stat" | "lstat" | "opendir"
        | "readlink" | "truncate" | "_wfopen" | "_open" | "CreateFileA" | "CreateFileW"
        | "CreateFile" | "DeleteFileA" | "DeleteFileW" | "remove_all" | "create_directory"
        | "create_directories" | "directory_iterator" | "ifstream" | "ofstream" | "fstream"
            if library =>
        {
            Some(vec![0])
        }
        "fopen_s" | "openat" => Some(vec![1]),
        "rename" | "link" | "symlink" | "copy" | "copy_file" | "CopyFileA" | "CopyFileW"
            if library =>
        {
            Some(vec![0, 1])
        }
        _ => None,
    }
}

fn sql_sink(name: &str) -> Option<Vec<usize>> {
    match name {
        "sqlite3_exec" | "sqlite3_prepare" | "sqlite3_prepare_v2" | "sqlite3_prepare_v3"
        | "sqlite3_prepare16" | "sqlite3_get_table" | "mysql_query" | "mysql_real_query"
        | "mysql_send_query" | "PQexec" | "PQsendQuery" | "PQexecParams" | "SQLExecDirect"
        | "SQLExecDirectA" | "SQLExecDirectW" | "SQLPrepare" | "SQLPrepareA" | "SQLPrepareW" => {
            Some(vec![1])
        }
        "PQprepare" => Some(vec![2]),
        _ => None,
    }
}

fn redirect_sink<'t>(
    name: &str,
    before: &str,
    args: &[Node<'t>],
    cx: &Cx<'_, 't>,
) -> Option<Vec<usize>> {
    match name {
        "newRedirectionResponse" if before == "HttpResponse" => Some(vec![0]),
        // A CGI program redirects by printing a `Location:` header.
        "printf" | "puts" | "fputs" => cx
            .starts_a_location(*args.first()?)
            .then(|| (1..args.len()).collect()),
        "fprintf" => cx
            .starts_a_location(*args.get(1)?)
            .then(|| (2..args.len()).collect()),
        _ => None,
    }
}

fn ssrf_sink<'t>(
    name: &str,
    before: &str,
    args: &[Node<'t>],
    cx: &Cx<'_, 't>,
) -> Option<Vec<usize>> {
    match name {
        "curl_easy_setopt" => (cx.text(*args.get(1)?) == "CURLOPT_URL").then(|| vec![2]),
        "Client" if before == "httplib" => Some(vec![0]),
        _ => None,
    }
}

/// The argument that is the format of a `printf` family function.
fn format_sink(name: &str, before: &str) -> Option<Vec<usize>> {
    if !is_library(before) {
        return None;
    }
    match name {
        "printf" | "vprintf" | "wprintf" | "vwprintf" | "warn" | "warnx" | "vwarn" | "vwarnx" => {
            Some(vec![0])
        }
        "fprintf" | "vfprintf" | "dprintf" | "vdprintf" | "sprintf" | "vsprintf" | "syslog"
        | "vsyslog" | "err" | "errx" | "verr" | "verrx" | "fwprintf" | "vfwprintf" => Some(vec![1]),
        "snprintf" | "vsnprintf" | "swprintf" | "vswprintf" | "sprintf_s" | "snprintf_s" => {
            Some(vec![2])
        }
        _ => None,
    }
}

// ---------------------------------------------------------------- functions (T3)

impl<'a, 't> Cx<'a, 't> {
    /// The function of this file a call calls, when it's unambiguous: the only
    /// one of that name with that many parameters.
    fn local_callee(&self, call: Node<'t>) -> Option<usize> {
        let (segments, receiver) = self.parts(call)?;
        let name = *segments.last()?;
        if receiver.is_none()
            && segments.len() == 1
            && let Some(d) = call
                .child_by_field_name("function")
                .and_then(|f| self.decl_of(f))
            && !matches!(self.m.decls[d].kind, DeclKind::Function | DeclKind::Method)
        {
            return None;
        }
        let arity = arguments(call).len();
        let candidates: Vec<usize> = self
            .by_name
            .get(name)?
            .iter()
            .copied()
            .filter(|&j| {
                self.m.functions[j].params.len() == arity
                    && self.m.functions[j].node.kind() == "function_definition"
            })
            .collect();
        match candidates.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
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
            self.names[j],
            self.summary(j, None).returns.clone(),
            args,
            |a| self.taint(a, state, depth),
            |i| self.summary(j, Some(i)).returns.clone(),
        )
    }

    fn sinks_through(&self, call: Node<'t>, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let Some(j) = self.local_callee(call) else {
            return Vec::new();
        };
        let reached = |i: usize| self.summary(j, Some(i)).sinks.clone();
        let name = self.names[j];
        through_sinks(
            call,
            name,
            arguments(call),
            |a| self.taint(a, state, 0),
            reached,
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
                if self.is_inert(d) {
                    return Some(Summary::default());
                }
                state.insert(
                    d,
                    vec![Step {
                        node: decl.node,
                        message: format!("`{}`'s parameter `{}`", self.names[j], decl.name),
                    }],
                );
            }
        } else {
            // What the function reads itself: its own sources.
            for (d, path) in &self.initial {
                if inside(self.m.decls[*d].node, f.node) {
                    state.insert(*d, path.clone());
                }
            }
        }
        self.propagate(Some(f.node), &mut state)?;
        let values = return_values(
            f.node,
            &["function_definition", "lambda_expression"],
            "return_statement",
        );
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
        Some(Summary {
            returns,
            sinks,
            calls: Vec::new(),
        })
    }

    /// Another file's function a call calls: none until values cross files.
    fn external_callee(&self, _call: Node<'t>) -> Option<Callee> {
        None
    }
}

flow_for!(Cx);

// ---------------------------------------------------------------- syntax

/// A call's arguments, or a constructor's: `T x(a, b)`, `T x{a, b}`.
fn arguments(call: Node) -> Vec<Node> {
    let list = match call.kind() {
        "init_declarator" => call
            .child_by_field_name("value")
            .filter(|v| matches!(v.kind(), "argument_list" | "initializer_list")),
        _ => call.child_by_field_name("arguments"),
    };
    let Some(list) = list else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|a| a.kind() != "comment")
        .collect()
}

/// An expression without the parentheses and casts around it.
fn unwrap(mut n: Node) -> Node {
    loop {
        match n.kind() {
            "parenthesized_expression" => match n.named_child(0) {
                Some(inner) => n = inner,
                None => return n,
            },
            "cast_expression" => match n.child_by_field_name("value") {
                Some(inner) => n = inner,
                None => return n,
            },
            "pointer_expression" => match n.child_by_field_name("argument") {
                Some(inner) => n = inner,
                None => return n,
            },
            _ => return n,
        }
    }
}

/// The name a declarator declares, through pointers, references and arrays.
fn declared_name(d: Node) -> Option<Node> {
    let mut d = d;
    for _ in 0..16 {
        match d.kind() {
            "identifier" => return Some(d),
            "pointer_declarator"
            | "reference_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "init_declarator" => {
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| d.named_child(0))?;
            }
            _ => return None,
        }
    }
    None
}

/// The node that names a function a definition defines, if it has a plain
/// name: `f`, a method's `f`, `C::f`. None for a constructor-like or operator.
fn function_name(function: Node) -> Option<Node> {
    if function.kind() != "function_definition" {
        return None;
    }
    let mut d = function.child_by_field_name("declarator")?;
    for _ in 0..16 {
        match d.kind() {
            "function_declarator" => {
                d = d.child_by_field_name("declarator")?;
                break;
            }
            "pointer_declarator"
            | "reference_declarator"
            | "parenthesized_declarator"
            | "attributed_declarator" => {
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| d.named_child(0))?;
            }
            _ => return None,
        }
    }
    for _ in 0..16 {
        match d.kind() {
            "identifier" | "field_identifier" => return Some(d),
            "qualified_identifier" => d = d.child_by_field_name("name")?,
            _ => return None,
        }
    }
    None
}

/// A type's last name, without qualifiers, template arguments, references
/// and pointers: `const std::string &` is `string`.
fn last_name(ty: &str) -> String {
    let no_templates = match ty.find('<') {
        Some(i) => &ty[..i],
        None => ty,
    };
    let last = no_templates.rsplit("::").next().unwrap_or(no_templates);
    last.split_whitespace()
        .filter(|w| {
            !matches!(
                *w,
                "const" | "volatile" | "struct" | "class" | "unsigned" | "signed"
            )
        })
        .collect::<Vec<_>>()
        .join("")
        .trim_matches(|c| c == '&' || c == '*')
        .to_string()
}

/// A function whose name says it checks its argument.
fn is_a_check_by_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "valid",
        "safe",
        "sanitiz",
        "allowed",
        "whitelist",
        "allowlist",
        "within",
        "inside",
        "verify",
        "authorized",
    ]
    .iter()
    .any(|w| n.contains(w))
}

/// Text built by concatenation, which the path says.
fn is_built(n: Node) -> bool {
    n.kind() == "binary_expression"
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
        flagged_in(rule, src, Lang::Cpp, "main.cpp")
    }

    fn flagged_in(rule: &str, src: &str, lang: Lang, path: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze(path, lang, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn a_request_value_in_a_shell_command() {
        let src = "#include <httplib.h>\nvoid ping(const httplib::Request& req, httplib::Response& res) {\n    std::string host = req.get_param_value(\"host\");\n    std::string cmd = \"ping -c 1 \" + host;\n    system(cmd.c_str());\n}\nvoid fixed(const httplib::Request& req) {\n    system(\"uptime\");\n}\n";
        assert_eq!(flagged("c/command-injection", src), [5]);
    }

    #[test]
    fn a_socket_read_through_snprintf_and_strcat() {
        let src = "void f(int s) {\n    char data[100];\n    char cmd[200];\n    recv(s, data, 99, 0);\n    snprintf(cmd, sizeof(cmd), \"cat %s\", data);\n    system(cmd);\n}\nvoid g(int s) {\n    char data[100];\n    char cmd[200] = \"ls \";\n    recv(s, data, 99, 0);\n    strcat(cmd, data);\n    popen(cmd, \"r\");\n}\nvoid h() {\n    char cmd[200];\n    snprintf(cmd, sizeof(cmd), \"cat %s\", \"file\");\n    system(cmd);\n}\n";
        assert_eq!(
            flagged_in("c/command-injection", src, Lang::C, "main.c"),
            [6, 13]
        );
    }

    #[test]
    fn the_command_line_and_the_environment_are_the_programs_own() {
        let src = "int main(int argc, char** argv) {\n    char cmd[100];\n    snprintf(cmd, 100, \"ls %s\", argv[1]);\n    system(cmd);\n    system(getenv(\"HOME\"));\n    return 0;\n}\nvoid cgi() {\n    system(getenv(\"QUERY_STRING\"));\n}\n";
        assert_eq!(
            flagged_in("c/command-injection", src, Lang::C, "main.c"),
            [9]
        );
    }

    #[test]
    fn paths_through_the_file_functions_and_streams() {
        let src = "#include <httplib.h>\n#include <fstream>\nvoid a(const httplib::Request& req) {\n    std::string name = req.get_param_value(\"f\");\n    std::ifstream in(\"/srv/\" + name);\n}\nvoid b(const httplib::Request& req) {\n    std::string name = req.path;\n    if (name.find(\"..\") != std::string::npos) return;\n    FILE* f = fopen(name.c_str(), \"r\");\n}\nstd::string join(const std::string& n) { return \"/srv/\" + n; }\nvoid c(const httplib::Request& req) {\n    FILE* f = fopen(join(req.body).c_str(), \"r\");\n}\n";
        assert_eq!(flagged("c/path-injection", src), [5, 14]);
    }

    #[test]
    fn a_query_a_redirect_and_a_format() {
        let src = "#include <httplib.h>\nvoid a(const httplib::Request& req, sqlite3* db) {\n    std::string q = \"SELECT * FROM u WHERE n = '\" + req.get_param_value(\"n\") + \"'\";\n    sqlite3_exec(db, q.c_str(), 0, 0, 0);\n}\nvoid b(const httplib::Request& req, httplib::Response& res) {\n    res.set_redirect(req.get_param_value(\"next\"));\n}\nvoid c(int s) {\n    char buf[100];\n    recv(s, buf, 99, 0);\n    printf(buf);\n    printf(\"%s\", buf);\n}\n";
        assert_eq!(flagged("c/sql-injection", src), [4]);
        assert_eq!(flagged("c/open-redirect", src), [7]);
        assert_eq!(flagged("c/format-string", src), [12]);
    }

    #[test]
    fn a_crow_route_parameter() {
        let src = "#include \"crow.h\"\nint main() {\n    crow::SimpleApp app;\n    CROW_ROUTE(app, \"/run/<string>\")([](const std::string& name) {\n        system((\"./job \" + name).c_str());\n        return \"ok\";\n    });\n}\n";
        assert_eq!(flagged("c/command-injection", src), [5]);
    }
}
