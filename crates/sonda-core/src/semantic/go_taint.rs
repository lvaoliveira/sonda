//! Taint analysis for Go, phases T2 and T3 (ADR-0027): which values that
//! came from a request reach a sink, and by what path.
//!
//! Like the other languages', it's **flow-insensitive** over the scopes of the
//! Go binder: a variable that is ever written a request's value holds it
//! wherever the binding is visible, and the whole file is one fixed point
//! over its writes. A function or a method of the file is followed through
//! its summary, per parameter.
//!
//! Precision before recall, as the ADR says:
//! - a value is a request's only when it comes from a web framework's request
//!   object (`net/http`'s `*http.Request`, gin's and echo's `Context`,
//!   fiber's `Ctx`) or chi's and gorilla/mux's route parameters: not the
//!   command line, the environment or a file;
//! - a call this module doesn't know returns an untainted value, so a
//!   program's own escaping helper sanitizes, and `strconv.Atoi` gives a
//!   number, which can't inject;
//! - a value that's tested in the file by a call that reads as a check
//!   (`strings.HasPrefix`, `filepath.IsLocal`, a regexp's `MatchString`) or
//!   compared with `==` is taken as validated;
//! - the request object itself isn't tainted, only what it returns.
//!
//! A call is matched by what its package was imported as (`exec.Command` is
//! `os/exec`'s only if the file imports it), and a method of the file by its
//! name, its number of arguments and the type of its receiver.

use super::taint::{Callee, Facts, Finding, SinkKind, Step, TaintResult};
use super::taint_core::{
    Flow, How, Path, Summaries, Summary, SummaryKey, Write, at_sinks, best, best_of, checked_names,
    decl_index, finish, fixes_origin, flow_for, held, outcome, return_values, sinks_in,
    sinks_local, through_local, tick, walk,
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

// ---------------------------------------------------------------- entry

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    if !might_have_sources(src) || !might_have_sinks(src, kind) {
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

fn contains_any(src: &[u8], words: &[&[u8]]) -> bool {
    words
        .iter()
        .any(|w| !w.is_empty() && src.windows(w.len()).any(|x| x == *w))
}

fn might_have_sources(src: &[u8]) -> bool {
    contains_any(
        src,
        &[
            b"http.Request",
            b"gin.Context",
            b"echo.Context",
            b"fiber.Ctx",
            b"chi.URLParam",
            b"mux.Vars",
        ],
    )
}

fn might_have_sinks(src: &[u8], kind: SinkKind) -> bool {
    let words: &[&[u8]] = match kind {
        SinkKind::Sql => &[
            b"Query", b"Exec", b"Raw(", b"Prepare", b"Where(", b"Select(", b"Get(",
        ],
        SinkKind::Command => &[b"exec.", b"StartProcess", b"syscall."],
        SinkKind::Path => &[
            b"os.",
            b"ioutil.",
            b"ServeFile",
            b".File(",
            b"SendFile",
            b"Attachment",
            b"filepath.Walk",
            b"Download",
            b"Inline",
        ],
        SinkKind::Redirect => &[b"Redirect"],
        SinkKind::Ssrf => &[b"http.", b"Client", b"client", b"NewRequest"],
        SinkKind::XPath | SinkKind::Ldap | SinkKind::Code | SinkKind::Format => return false,
    };
    contains_any(src, words)
}

// ---------------------------------------------------------------- tables

/// What a request object is, by its type as written: the framework it
/// belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Http,
    Gin,
    Echo,
    Fiber,
}

fn request_kind(ty: &str) -> Option<Kind> {
    match ty.trim().trim_start_matches(['*', '&']) {
        "http.Request" => Some(Kind::Http),
        "gin.Context" => Some(Kind::Gin),
        "echo.Context" => Some(Kind::Echo),
        "fiber.Ctx" => Some(Kind::Fiber),
        _ => None,
    }
}

/// Methods of a request object, or a part of one, whose result is what a
/// client sent.
const REQUEST_METHODS: &[&str] = &[
    "FormValue",
    "PostFormValue",
    "Referer",
    "UserAgent",
    "Cookie",
    "Cookies",
    "Query",
    "DefaultQuery",
    "QueryParam",
    "QueryParams",
    "QueryArray",
    "QueryMap",
    "Param",
    "Params",
    "AllParams",
    "PostForm",
    "DefaultPostForm",
    "PostFormArray",
    "FormParams",
    "GetHeader",
    "GetRawData",
    "Body",
    "OriginalURL",
    "BaseURL",
    "Hostname",
    "Path",
    "BindJSON",
    "BindQuery",
    "BindUri",
    "BindXML",
    "BindYAML",
    "Bind",
    "ShouldBind",
    "ShouldBindJSON",
    "ShouldBindQuery",
    "ShouldBindUri",
    "ShouldBindXML",
    "ShouldBindYAML",
    "BodyParser",
    "QueryParser",
    "ParamsParser",
];

/// Of those, the ones that fill the value their first argument points at
/// instead of returning one.
const BINDING_METHODS: &[&str] = &[
    "BindJSON",
    "BindQuery",
    "BindUri",
    "BindXML",
    "BindYAML",
    "Bind",
    "ShouldBind",
    "ShouldBindJSON",
    "ShouldBindQuery",
    "ShouldBindUri",
    "ShouldBindXML",
    "ShouldBindYAML",
    "BodyParser",
    "QueryParser",
    "ParamsParser",
];

/// Fields of a request object that hold what a client sent.
const REQUEST_FIELDS: &[&str] = &[
    "URL",
    "Header",
    "Form",
    "PostForm",
    "Body",
    "MultipartForm",
    "Host",
    "RequestURI",
    "Params",
    "Trailer",
    "Cookies",
];

/// Methods whose result holds, or is part of, their receiver's text.
const PROPAGATING_METHODS: &[&str] = &[
    "String",
    "Get",
    "Query",
    "Bytes",
    "Value",
    "Values",
    "Path",
    "EscapedPath",
    "Host",
    "Hostname",
    "Port",
    "Trim",
    "TrimSpace",
    "TrimLeft",
    "TrimRight",
    "TrimPrefix",
    "TrimSuffix",
    "ToLower",
    "ToUpper",
    "Title",
    "Fields",
    "Split",
    "Replace",
    "ReplaceAll",
    "Clean",
    "Join",
    "Base",
    "Ext",
    "Dir",
    "Header",
    "Cookie",
    "Slice",
    "ReadString",
    "ReadBytes",
    "ReadLine",
    "Text",
    "Sprintf",
];

/// Package functions whose result is made of their arguments' text: the
/// import path, and the functions.
const PROPAGATING_CALLS: &[(&str, &[&str])] = &[
    (
        "fmt",
        &[
            "Sprintf", "Sprint", "Sprintln", "Errorf", "Append", "Appendf",
        ],
    ),
    (
        "strings",
        &[
            "ToLower",
            "ToUpper",
            "Title",
            "TrimSpace",
            "Trim",
            "TrimLeft",
            "TrimRight",
            "TrimPrefix",
            "TrimSuffix",
            "TrimFunc",
            "Replace",
            "ReplaceAll",
            "Join",
            "Repeat",
            "Split",
            "SplitN",
            "Fields",
            "Map",
            "NewReader",
            "NewReplacer",
        ],
    ),
    (
        "path/filepath",
        &["Join", "Clean", "Abs", "FromSlash", "ToSlash", "Dir", "Ext"],
    ),
    ("path", &["Join", "Clean", "Dir", "Ext"]),
    (
        "net/url",
        &[
            "Parse",
            "ParseRequestURI",
            "QueryUnescape",
            "PathUnescape",
            "JoinPath",
        ],
    ),
    ("io", &["ReadAll"]),
    ("io/ioutil", &["ReadAll"]),
    (
        "bytes",
        &[
            "NewBufferString",
            "NewBuffer",
            "NewReader",
            "TrimSpace",
            "ToLower",
            "ToUpper",
        ],
    ),
    ("encoding/json", &["NewDecoder", "Unmarshal"]),
    ("encoding/xml", &["NewDecoder"]),
    ("encoding/base64", &[]),
    ("html", &["UnescapeString"]),
    ("bufio", &["NewReader", "NewScanner"]),
    ("strconv", &["Quote", "QuoteToASCII", "Unquote"]),
];

/// Numbers and booleans: they can't carry what injects.
const NUMERIC_TYPES: &[&str] = &[
    "bool",
    "byte",
    "rune",
    "int",
    "int8",
    "int16",
    "int32",
    "int64",
    "uint",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uintptr",
    "float32",
    "float64",
    "complex64",
    "complex128",
    "time.Duration",
    "time.Time",
];

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "/bin/sh",
    "/bin/bash",
    "cmd",
    "powershell",
];
const SHELL_FLAGS: &[&str] = &["-c", "/c", "-Command", "-command"];

/// Calls that test a value, by kind: what they say about it makes it
/// validated.
fn check_names(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Path | SinkKind::Redirect | SinkKind::Ssrf => &[
            "HasPrefix",
            "HasSuffix",
            "Contains",
            "ContainsAny",
            "ContainsRune",
            "Index",
            "EqualFold",
            "IsLocal",
            "IsAbs",
            "Match",
            "MatchString",
            "Rel",
            "EvalSymlinks",
        ],
        _ => &["Match", "MatchString", "EqualFold", "IsDigit", "IsLetter"],
    }
}

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

// ---------------------------------------------------------------- the file

/// What a call calls, as the file writes it.
enum Target<'a, 't> {
    /// `f(x)`: a name of the file, or a builtin.
    Func(&'a str),
    /// `exec.Command(x)`: a package's function, by its import path.
    Package(String, &'a str),
    /// `r.FormValue(x)`: a method, and what it's called on.
    Method(Node<'t>, &'a str),
}

struct Cx<'a, 't> {
    m: &'a Model<'t>,
    src: &'a [u8],
    kind: SinkKind,
    by_node: HashMap<usize, DeclId>,
    /// Variables that hold a request object, and its framework.
    requests: HashMap<DeclId, Kind>,
    /// The import path each imported name stands for.
    imports: HashMap<DeclId, String>,
    /// Variables a check reads as validating, for this kind of sink.
    checked: HashSet<DeclId>,
    writes: Vec<Write<'t>>,
    calls: Vec<Node<'t>>,
    /// Each function's name and its receiver's type, by its index (the name
    /// is empty for a literal), and the functions by name.
    names: Vec<&'a str>,
    receivers: Vec<&'a str>,
    by_name: HashMap<&'a str, Vec<usize>>,
    evaluations: Cell<u64>,
    summaries: Summaries<SummaryKey, Summary<'t>>,
}

impl<'a, 't> Cx<'a, 't> {
    fn new(m: &'a Model<'t>, src: &'a [u8], kind: SinkKind, root: Node<'t>) -> Option<Self> {
        let mut cx = Cx {
            m,
            src,
            kind,
            by_node: decl_index(m),
            requests: HashMap::new(),
            imports: HashMap::new(),
            checked: HashSet::new(),
            writes: Vec::new(),
            calls: Vec::new(),
            names: Vec::new(),
            receivers: Vec::new(),
            by_name: HashMap::new(),
            evaluations: Cell::new(0),
            summaries: Summaries::new(MAX_SUMMARIES),
        };
        cx.index();
        cx.collect(root)?;
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// The functions of the file by name, the variables that hold a request
    /// object, and what each import is.
    fn index(&mut self) {
        for f in &self.m.functions {
            let name = f
                .node
                .child_by_field_name("name")
                .map_or("", |n| self.text(n));
            self.names.push(name);
            self.receivers.push(
                f.node
                    .child_by_field_name("receiver")
                    .map_or("", |r| self.receiver_type(r)),
            );
        }
        for (j, name) in self.names.iter().enumerate() {
            if !name.is_empty() {
                self.by_name.entry(*name).or_default().push(j);
            }
        }
        for (d, decl) in self.m.decls.iter().enumerate() {
            if decl.kind == DeclKind::Import {
                if let Some(path) = decl
                    .node
                    .parent()
                    .filter(|p| p.kind() == "import_spec")
                    .and_then(|p| p.child_by_field_name("path"))
                {
                    self.imports
                        .insert(d, self.text(path).trim_matches(['"', '`']).to_string());
                }
            } else if let Some(k) = decl.ty.and_then(|t| request_kind(self.text(t))) {
                self.requests.insert(d, k);
            }
        }
    }

    /// The name of a method's receiver type, without `*` and type arguments.
    fn receiver_type(&self, list: Node<'t>) -> &'a str {
        let ty = list
            .named_child(0)
            .and_then(|p| p.child_by_field_name("type"))
            .map_or("", |t| self.text(t));
        let ty = ty.trim_start_matches('*');
        ty.split('[').next().unwrap_or(ty).trim()
    }

    /// Walks the file once, in source order, for its writes, calls and
    /// checks. None past a limit.
    fn collect(&mut self, root: Node<'t>) -> Option<()> {
        let mut checks: Vec<Node<'t>> = Vec::new();
        let words = check_names(self.kind);
        walk(root, |n| {
            self.visit(n, words, &mut checks);
            self.writes.len() <= MAX_WRITES
        })?;
        // A variable named as a check's argument or receiver is validated.
        let named = checked_names(checks, arguments, ("selector_expression", "operand"), |n| {
            self.decl_of(unwrap(n))
        });
        self.checked.extend(named);
        Some(())
    }

    /// Records what one node writes, calls or checks.
    fn visit(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        match n.kind() {
            "short_var_declaration" | "assignment_statement" => self.assignment(n),
            "var_spec" => self.variable(n),
            "range_clause" => self.range(n),
            "call_expression" => self.call(n, words, checks),
            "binary_expression" => self.comparison(n),
            _ => {}
        }
    }

    // ------------------------------------------------------------ writes

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

    /// `a := v`, `a, b = f()`, `s += v`, `m[k] = v`: each variable gets its
    /// value; a call with several results gives each the call's value,
    /// except the `err` and `ok` that come with it.
    fn assignment(&mut self, n: Node<'t>) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        let how = match n
            .child_by_field_name("operator")
            .map_or("=", |o| self.text(o))
        {
            "=" | ":=" => How::Assigned,
            "+=" => How::Added,
            _ => return,
        };
        self.pairs(left, right, how);
    }

    fn variable(&mut self, n: Node<'t>) {
        let Some(value) = n.child_by_field_name("value") else {
            return;
        };
        let mut c = n.walk();
        let names: Vec<Node<'t>> = n.children_by_field_name("name", &mut c).collect();
        let targets: Vec<(Node<'t>, Node<'t>)> = pair_up(&names, &named_children(value));
        for (name, v) in targets {
            self.write_to(name, v, How::Assigned);
        }
    }

    fn pairs(&mut self, left: Node<'t>, right: Node<'t>, how: How) {
        let (l, r) = (named_children(left), named_children(right));
        if r.len() == 1 && l.len() > 1 {
            for target in &l {
                if !matches!(self.text(*target), "err" | "ok" | "_") {
                    self.write_to(*target, r[0], how);
                }
            }
            return;
        }
        for (target, value) in pair_up(&l, &r) {
            self.write_to(target, value, how);
        }
    }

    /// Writes `value` into the variable `target` names: a variable, or the
    /// collection an element of it is set in.
    fn write_to(&mut self, target: Node<'t>, value: Node<'t>, how: How) {
        let (target, how) = match target.kind() {
            "identifier" => (target, how),
            "index_expression" => (target, How::Added),
            _ => return,
        };
        if let Some((d, node)) = self.base_of(target) {
            self.write(d, node, value, how);
        }
    }

    /// `for k, v := range xs`: `v` holds a part of the value.
    fn range(&mut self, n: Node<'t>) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        let names = named_children(left);
        if let [_, value] = names.as_slice()
            && let Some(d) = self.decl_of(*value)
        {
            self.write(d, *value, right, How::Read);
        }
    }

    /// `x == "..."` tests the value.
    fn comparison(&mut self, n: Node<'t>) {
        let op = n
            .child_by_field_name("operator")
            .map_or("", |o| self.text(o));
        if !matches!(op, "==" | "!=") || matches!(self.kind, SinkKind::Sql) {
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

    /// A call: the check it may be, and what it writes into its arguments.
    fn call(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        self.calls.push(n);
        let Some(function) = n.child_by_field_name("function") else {
            return;
        };
        let name = match function.kind() {
            "identifier" => self.text(function),
            "selector_expression" => function
                .child_by_field_name("field")
                .map_or("", |f| self.text(f)),
            _ => return,
        };
        if words.contains(&name) || is_a_check_by_name(name) {
            checks.push(n);
        }
        let args = arguments(n);
        match self.target(n) {
            Some(Target::Method(receiver, method)) => {
                self.method_writes(n, receiver, method, &args)
            }
            Some(Target::Package(path, f)) => self.package_writes(&path, f, &args),
            Some(Target::Func("copy")) => {
                if let (Some(dst), Some(src)) = (args.first(), args.get(1))
                    && let Some((d, node)) = self.base_of(*dst)
                {
                    self.write(d, node, *src, How::Added);
                }
            }
            _ => {}
        }
    }

    /// `c.ShouldBindJSON(&x)`, `dec.Decode(&x)`, `sb.WriteString(v)`: the
    /// variable gets the value.
    fn method_writes(&mut self, call: Node<'t>, receiver: Node<'t>, name: &str, args: &[Node<'t>]) {
        if BINDING_METHODS.contains(&name) && self.is_request(receiver) {
            if let Some((d, node)) = args.first().and_then(|a| self.base_of(*a)) {
                self.write(d, node, call, How::Assigned);
            }
            return;
        }
        match name {
            // `json.NewDecoder(r.Body).Decode(&x)`
            "Decode" => {
                if let Some((d, node)) = args.first().and_then(|a| self.base_of(*a)) {
                    self.write(d, node, receiver, How::Assigned);
                }
            }
            // `sb.WriteString(v)`, `q.Set("k", v)`
            "WriteString" | "Write" | "WriteRune" | "WriteByte" | "Add" | "Set" => {
                if let (Some((d, node)), Some(v)) = (self.base_of(receiver), args.last()) {
                    self.write(d, node, *v, How::Added);
                }
            }
            _ => {}
        }
    }

    /// `json.Unmarshal(data, &x)`, `fmt.Fprintf(&sb, f, v)`, `io.Copy(dst, src)`.
    fn package_writes(&mut self, path: &str, name: &str, args: &[Node<'t>]) {
        match (path, name) {
            ("encoding/json" | "encoding/xml", "Unmarshal") => {
                if let (Some(data), Some((d, node))) =
                    (args.first(), args.get(1).and_then(|a| self.base_of(*a)))
                {
                    self.write(d, node, *data, How::Assigned);
                }
            }
            ("fmt", "Fprintf" | "Fprint" | "Fprintln") => {
                if let Some((d, node)) = args.first().and_then(|a| self.base_of(*a)) {
                    for v in args.iter().skip(1) {
                        self.write(d, node, *v, How::Added);
                    }
                }
            }
            ("io", "Copy" | "CopyN") => {
                if let (Some((d, node)), Some(src)) =
                    (args.first().and_then(|a| self.base_of(*a)), args.get(1))
                {
                    self.write(d, node, *src, How::Added);
                }
            }
            _ => {}
        }
    }

    /// The variable an expression names, and the node that names it: through
    /// `&x`, `x[i]`, `x.f` and `x.m()`.
    fn base_of(&self, n: Node<'t>) -> Option<(DeclId, Node<'t>)> {
        let mut n = n;
        for _ in 0..16 {
            match n.kind() {
                "identifier" => return Some((self.decl_of(n)?, n)),
                "parenthesized_expression" => n = n.named_child(0)?,
                "unary_expression" => n = n.child_by_field_name("operand")?,
                "index_expression" | "slice_expression" => n = n.child_by_field_name("operand")?,
                "selector_expression" => n = n.child_by_field_name("operand")?,
                "call_expression" => {
                    let f = n.child_by_field_name("function")?;
                    if f.kind() != "selector_expression" {
                        return None;
                    }
                    n = f.child_by_field_name("operand")?;
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

    /// A variable of a number's type, which can't hold what injects.
    fn is_inert(&self, d: DeclId) -> bool {
        self.m.decls[d]
            .ty
            .is_some_and(|t| NUMERIC_TYPES.contains(&self.text(t)))
    }

    // ------------------------------------------------------------ calls

    /// What a call calls.
    fn target(&self, call: Node<'t>) -> Option<Target<'a, 't>> {
        let function = call.child_by_field_name("function")?;
        match function.kind() {
            "identifier" => Some(Target::Func(self.text(function))),
            "selector_expression" => {
                let operand = function.child_by_field_name("operand")?;
                let field = self.text(function.child_by_field_name("field")?);
                if operand.kind() == "identifier"
                    && let Some(path) = self.decl_of(operand).and_then(|d| self.imports.get(&d))
                {
                    return Some(Target::Package(path.clone(), field));
                }
                Some(Target::Method(operand, field))
            }
            _ => None,
        }
    }

    /// Whether `n` is a request object, or a part of one (`r.URL`, `c.Request`).
    fn is_request(&self, n: Node<'t>) -> bool {
        self.request_of(n).is_some()
    }

    /// The framework of the request object `n` is, or is a part of.
    fn request_of(&self, n: Node<'t>) -> Option<Kind> {
        let mut n = n;
        for _ in 0..16 {
            match n.kind() {
                "identifier" => return self.requests.get(&self.decl_of(n)?).copied(),
                "parenthesized_expression" => n = n.named_child(0)?,
                "selector_expression" => {
                    let field = self.text(n.child_by_field_name("field")?);
                    let operand = n.child_by_field_name("operand")?;
                    if field != "Request" && !REQUEST_FIELDS.contains(&field) {
                        return None;
                    }
                    n = operand;
                }
                // `c.Request()`, echo's.
                "call_expression" => {
                    let f = n.child_by_field_name("function")?;
                    if f.kind() != "selector_expression"
                        || self.text(f.child_by_field_name("field")?) != "Request"
                    {
                        return None;
                    }
                    n = f.child_by_field_name("operand")?;
                }
                _ => return None,
            }
        }
        None
    }

    // ------------------------------------------------------------ evaluation

    fn run(&self) -> Option<HashMap<DeclId, Path<'t>>> {
        let mut tainted = HashMap::new();
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
        if tick(&self.evaluations, depth) {
            self.expression(n, state, depth + 1)
        } else {
            None
        }
    }

    /// What `n`'s kind of expression holds, `next` levels down.
    fn expression(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        next: u32,
    ) -> Option<Path<'t>> {
        match n.kind() {
            "identifier" => held(self.decl_of(n), &self.checked, state),
            "parenthesized_expression" | "variadic_argument" => {
                self.taint(n.named_child(0)?, state, next)
            }
            "expression_list" | "literal_value" => best(
                named_children(n)
                    .into_iter()
                    .map(|c| self.taint(c, state, next)),
            ),
            "literal_element" => self.taint(n.named_child(0)?, state, next),
            "keyed_element" => self.taint(n.child_by_field_name("value")?, state, next),
            "composite_literal" => self.taint(n.child_by_field_name("body")?, state, next),
            "binary_expression" => {
                let op = n
                    .child_by_field_name("operator")
                    .map_or("", |o| self.text(o));
                if op != "+" {
                    return None;
                }
                if self.starts_the_text() {
                    return self.address_taint(n, state, next);
                }
                best_of(n, &["left", "right"], |c| self.taint(c, state, next))
            }
            "unary_expression"
            | "index_expression"
            | "slice_expression"
            | "type_assertion_expression" => {
                let operand = n
                    .child_by_field_name("operand")
                    .or_else(|| n.named_child(0))?;
                self.taint(operand, state, next)
            }
            "selector_expression" => self.field_taint(n, state, next),
            "call_expression" => self.call_taint(n, state, next),
            _ => None,
        }
    }

    /// `r.URL`, `c.Request`; a field of a tainted value.
    fn field_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let operand = n.child_by_field_name("operand")?;
        let field = self.text(n.child_by_field_name("field")?);
        if self.is_request(operand)
            && REQUEST_FIELDS.contains(&field)
            && !self.names_the_host(field)
        {
            return Some(vec![Step {
                node: n,
                message: format!(
                    "read from the request: `{}`",
                    super::taint_core::short(self.text(n))
                ),
            }]);
        }
        self.taint(operand, state, depth)
    }

    fn call_taint(
        &self,
        call: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let args = arguments(call);
        let function = call.child_by_field_name("function")?;
        // `[]byte(x)`, `string(x)`: the same text.
        if matches!(function.kind(), "slice_type" | "array_type") {
            return self.taint(*args.first()?, state, depth);
        }
        match self.target(call)? {
            Target::Func(name) => match name {
                "string" | "append" => best(args.iter().map(|a| self.taint(*a, state, depth))),
                _ => self.through_function(call, &args, state, depth),
            },
            Target::Package(path, name) => {
                self.package_taint(call, (&path, name), &args, state, depth)
            }
            Target::Method(receiver, name) => {
                self.method_taint(call, receiver, name, &args, state, depth)
            }
        }
    }

    /// What `pkg.F(..)` returns: a route parameter, or the text of an
    /// argument for the functions that change text.
    fn package_taint(
        &self,
        call: Node<'t>,
        (path, name): (&str, &str),
        args: &[Node<'t>],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        if matches!(
            (path, name),
            (
                "github.com/go-chi/chi" | "github.com/go-chi/chi/v5",
                "URLParam"
            ) | ("github.com/gorilla/mux", "Vars")
        ) {
            return Some(source_step(call, name));
        }
        if self.starts_the_text() && path == "fmt" && name == "Sprintf" {
            return self.format_taint(args, state, depth);
        }
        PROPAGATING_CALLS
            .iter()
            .any(|(p, fs)| *p == path && fs.contains(&name))
            .then(|| best(args.iter().map(|a| self.taint(*a, state, depth))))
            .flatten()
    }

    /// What `x.M(..)` returns: what a request's accessor gives, the text of
    /// a tainted receiver for the methods that pass it on, or what a method
    /// of the file returns.
    fn method_taint(
        &self,
        call: Node<'t>,
        receiver: Node<'t>,
        name: &str,
        args: &[Node<'t>],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        if self.is_request(receiver)
            && REQUEST_METHODS.contains(&name)
            && !self.names_the_host(name)
        {
            return Some(source_step(call, name));
        }
        if PROPAGATING_METHODS.contains(&name) && self.local_callee(call).is_none() {
            return self.taint(receiver, state, depth);
        }
        self.through_function(call, args, state, depth)
    }

    /// For an address (a redirect, a request), only its start can change
    /// where it goes.
    fn starts_the_text(&self) -> bool {
        matches!(self.kind, SinkKind::Redirect | SinkKind::Ssrf)
    }

    /// `"/orders/" + id`, `"https://" + host + path`: the operands of a
    /// concatenation, from the first. Text that fixes the origin leaves the
    /// rest no say; a scheme leaves it to the next operand, the host; any
    /// other start, or none, to every operand.
    fn address_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let mut operands = Vec::new();
        concatenation(n, self.src, &mut operands);
        let deciding = match operands.first().and_then(|o| self.literal(*o)) {
            Some(start) if fixes_origin(start) => 0,
            Some(start) if start.ends_with("://") || start == "//" => 2,
            Some(_) => operands.len(),
            // A variable first, as in `base + id`: it sets where the rest goes.
            None => 1,
        };
        best(
            operands
                .iter()
                .take(deciding)
                .map(|o| self.taint(*o, state, depth)),
        )
    }

    /// `fmt.Sprintf("https://%s%s", host, path)` as an address: the same,
    /// by what the format says before its first verb.
    fn format_taint(
        &self,
        args: &[Node<'t>],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let format = args.first().and_then(|f| self.literal(*f));
        let prefix = format.map(|f| f.split('%').next().unwrap_or(f));
        let deciding = match prefix {
            Some(start) if fixes_origin(start) => 0,
            Some(start) if start.is_empty() || start.ends_with("://") || start == "//" => 2,
            _ => args.len(),
        };
        best(
            args.iter()
                .take(deciding)
                .map(|a| self.taint(*a, state, depth)),
        )
    }

    /// The text of a string literal written out.
    fn literal(&self, n: Node<'t>) -> Option<&'a str> {
        matches!(
            unwrap(n).kind(),
            "interpreted_string_literal" | "raw_string_literal"
        )
        .then(|| self.text(unwrap(n)).trim_matches(['"', '`']))
    }

    /// Whether a request's field or method gives the `Host` the client wrote
    /// (`r.Host`, fiber's `Hostname` and `BaseURL`), which a redirect to
    /// `https://` + host, the usual way to move to HTTPS, rightly builds on: a
    /// victim's browser can't be made to send another one.
    fn names_the_host(&self, name: &str) -> bool {
        matches!(self.kind, SinkKind::Redirect) && matches!(name, "Host" | "Hostname" | "BaseURL")
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
        let args = arguments(call);
        let (name, at) = match self.target(call)? {
            Target::Package(path, f) => {
                let at = self.package_sink(&path, f, &args)?;
                (
                    format!("{}.{f}", path.rsplit('/').next().unwrap_or(&path)),
                    at,
                )
            }
            Target::Method(receiver, f) => {
                let at = self.method_sink(receiver, f, &args)?;
                (f.to_string(), at)
            }
            Target::Func(_) => return None,
        };
        let taking = at
            .into_iter()
            .filter_map(|i| args.get(i).copied())
            .collect();
        Some((name, taking))
    }

    /// The positions of the arguments of a package function that take the
    /// value, if it's a sink of this kind.
    fn package_sink(&self, path: &str, name: &str, args: &[Node<'t>]) -> Option<Vec<usize>> {
        match (self.kind, path, name) {
            (SinkKind::Command, "os/exec", "Command") => Some(self.shell_args(args, 0)),
            (SinkKind::Command, "os/exec", "CommandContext") => Some(self.shell_args(args, 1)),
            (SinkKind::Command, "os", "StartProcess") | (SinkKind::Command, "syscall", "Exec") => {
                Some(vec![0])
            }
            (
                SinkKind::Path,
                "os",
                "Open" | "OpenFile" | "Create" | "ReadFile" | "WriteFile" | "Remove" | "RemoveAll"
                | "Mkdir" | "MkdirAll" | "Stat" | "Lstat" | "ReadDir" | "Chdir" | "Truncate"
                | "Chmod" | "Chown" | "Readlink",
            )
            | (SinkKind::Path, "io/ioutil", "ReadFile" | "WriteFile" | "ReadDir")
            | (SinkKind::Path, "path/filepath", "Walk" | "WalkDir") => Some(vec![0]),
            (SinkKind::Path, "os", "Rename" | "Symlink" | "Link") => Some(vec![0, 1]),
            (SinkKind::Path, "net/http", "ServeFile") => Some(vec![2]),
            (SinkKind::Redirect, "net/http", "Redirect") => Some(vec![2]),
            (SinkKind::Ssrf, "net/http", "Get" | "Head" | "Post" | "PostForm") => Some(vec![0]),
            (SinkKind::Ssrf, "net/http", "NewRequest") => Some(vec![1]),
            (SinkKind::Ssrf, "net/http", "NewRequestWithContext") => Some(vec![2]),
            _ => None,
        }
    }

    /// `exec.Command(name, args...)`: the program, and the script of a shell
    /// run with `-c`; `from` is where the name is.
    fn shell_args(&self, args: &[Node<'t>], from: usize) -> Vec<usize> {
        let mut at = vec![from];
        let literal = |i: usize| {
            args.get(i)
                .filter(|a| a.kind() == "interpreted_string_literal")
                .map(|a| self.text(*a).trim_matches('"'))
        };
        if literal(from).is_some_and(|s| SHELLS.contains(&s))
            && literal(from + 1).is_some_and(|s| SHELL_FLAGS.contains(&s))
        {
            at.push(from + 2);
        }
        at
    }

    /// The positions of the arguments of a method that take the value, if
    /// it's a sink of this kind.
    fn method_sink(&self, receiver: Node<'t>, name: &str, args: &[Node<'t>]) -> Option<Vec<usize>> {
        if let Some(framework) = self.request_of(receiver) {
            return match (self.kind, framework, name) {
                (
                    SinkKind::Path,
                    Kind::Gin | Kind::Echo,
                    "File" | "FileAttachment" | "Attachment" | "Inline",
                )
                | (SinkKind::Path, Kind::Fiber, "SendFile" | "Download") => Some(vec![0]),
                (SinkKind::Redirect, Kind::Gin | Kind::Echo, "Redirect") => Some(vec![1]),
                (SinkKind::Redirect, Kind::Fiber, "Redirect") => Some(vec![0]),
                _ => None,
            };
        }
        match self.kind {
            SinkKind::Sql => sql_position(name, args),
            SinkKind::Ssrf => (matches!(name, "Get" | "Head" | "Post" | "PostForm")
                && self.is_client(receiver))
            .then(|| vec![0]),
            _ => None,
        }
    }

    /// Whether a receiver reads as an HTTP client: declared as one, or
    /// called one.
    fn is_client(&self, receiver: Node<'t>) -> bool {
        let named = self.text(receiver).to_ascii_lowercase().contains("client");
        let typed = self
            .decl_of(unwrap(receiver))
            .and_then(|d| self.m.decls[d].ty)
            .is_some_and(|t| self.text(t).contains("Client"));
        named || typed
    }

    // ------------------------------------------------------------ functions (T3)

    /// The function or method of this file a call calls, when it's
    /// unambiguous: the only one of that name with that many parameters,
    /// and for a method, on a receiver of its type.
    fn local_callee(&self, call: Node<'t>) -> Option<usize> {
        let arity = arguments(call).len();
        let (name, receiver) = match self.target(call)? {
            Target::Func(name) => (name, None),
            Target::Method(receiver, name) => (name, Some(receiver)),
            Target::Package(..) => return None,
        };
        let candidates: Vec<usize> = self
            .by_name
            .get(name)?
            .iter()
            .copied()
            .filter(|&j| {
                let f = &self.m.functions[j];
                let variadic = f.node.child_by_field_name("parameters").is_some_and(|p| {
                    p.named_children(&mut p.walk())
                        .any(|c| c.kind() == "variadic_parameter_declaration")
                });
                f.params.len() == arity
                    && !variadic
                    && match receiver {
                        None => f.node.kind() == "function_declaration",
                        Some(r) => {
                            f.node.kind() == "method_declaration"
                                && self.receiver_matches(r, self.receivers[j])
                        }
                    }
            })
            .collect();
        match candidates.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// Whether the value a method is called on is of the receiver type: a
    /// variable declared with it.
    fn receiver_matches(&self, receiver: Node<'t>, ty: &str) -> bool {
        let Some(d) = self.decl_of(unwrap(receiver)) else {
            return false;
        };
        let declared = self.m.decls[d].ty.map_or("", |t| self.text(t));
        let declared = declared.trim_start_matches('*');
        declared.split('[').next().unwrap_or(declared).trim() == ty
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
        through_local(
            call,
            self.names[j],
            args,
            |p| self.summary(j, p),
            |a| self.taint(a, state, depth),
        )
    }

    fn sinks_through(&self, call: Node<'t>, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let Some(j) = self.local_callee(call) else {
            return Vec::new();
        };
        sinks_local(
            call,
            self.names[j],
            arguments(call),
            |p| self.summary(j, p),
            |a| self.taint(a, state, 0),
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
                if self.is_inert(d) || self.requests.contains_key(&d) {
                    return Some(Summary::default());
                }
                let decl = &self.m.decls[d];
                state.insert(
                    d,
                    vec![Step {
                        node: decl.node,
                        message: format!("`{}`'s parameter `{}`", self.names[j], decl.name),
                    }],
                );
            }
        }
        self.propagate(Some(f.node), &mut state)?;
        let values = return_values(
            f.node,
            &["function_declaration", "method_declaration", "func_literal"],
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

/// A step for a value a request's call returns.
fn source_step<'t>(call: Node<'t>, name: &str) -> Path<'t> {
    vec![Step {
        node: call,
        message: format!("read from the request by `{name}`"),
    }]
}

/// The positions of the query argument of a `database/sql`-style method, and
/// nothing for a method of that name that isn't one: `Get` and `Select` are
/// sqlx's only with a destination (`&x`) before the query.
fn sql_position(name: &str, args: &[Node]) -> Option<Vec<usize>> {
    let takes_destination = |n: usize| {
        args.len() > n
            && args
                .first()
                .is_some_and(|a| a.kind() == "unary_expression" || a.kind() == "identifier")
    };
    match name {
        "Query" | "QueryRow" | "Exec" | "Prepare" | "NamedQuery" | "NamedExec" | "MustExec"
        | "Raw" | "Where" | "Order" => Some(vec![0]),
        "QueryContext" | "QueryRowContext" | "ExecContext" | "PrepareContext"
        | "NamedQueryContext" | "NamedExecContext" => Some(vec![1]),
        "Get" | "Select" if takes_destination(2) => Some(vec![1]),
        "GetContext" | "SelectContext" if takes_destination(3) => Some(vec![2]),
        _ => None,
    }
}

/// The operands of a chain of `+`, left to right.
fn concatenation<'t>(n: Node<'t>, src: &[u8], out: &mut Vec<Node<'t>>) {
    let is_plus = n.kind() == "binary_expression"
        && n.child_by_field_name("operator")
            .is_some_and(|o| &src[o.byte_range()] == b"+");
    match (
        is_plus,
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
    ) {
        (true, Some(l), Some(r)) => {
            concatenation(l, src, out);
            out.push(r);
        }
        _ => out.push(n),
    }
}

/// A call's arguments.
fn arguments(call: Node) -> Vec<Node> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    named_children(list)
        .into_iter()
        .filter(|a| a.kind() != "comment")
        .collect()
}

fn named_children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// Names and values in order, when there are as many of one as the other.
fn pair_up<'t>(names: &[Node<'t>], values: &[Node<'t>]) -> Vec<(Node<'t>, Node<'t>)> {
    if names.len() == values.len() {
        names.iter().copied().zip(values.iter().copied()).collect()
    } else {
        Vec::new()
    }
}

/// An expression without the parentheses and `&` and `*` around it.
fn unwrap(mut n: Node) -> Node {
    loop {
        match n.kind() {
            "parenthesized_expression" => match n.named_child(0) {
                Some(inner) => n = inner,
                None => return n,
            },
            "unary_expression" => match n.child_by_field_name("operand") {
                Some(inner) => n = inner,
                None => return n,
            },
            _ => return n,
        }
    }
}

fn is_built(n: Node) -> bool {
    n.kind() == "binary_expression"
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::flagged_go as flagged;

    #[test]
    fn a_form_value_in_a_query_a_command_and_a_path() {
        let src = "import (\n\t\"database/sql\"\n\t\"net/http\"\n\t\"os\"\n\t\"os/exec\"\n)\n\nfunc h(db *sql.DB, w http.ResponseWriter, r *http.Request) {\n\tid := r.FormValue(\"id\")\n\tdb.Query(\"SELECT * FROM t WHERE id = '\" + id + \"'\")\n\tdb.Query(\"SELECT * FROM t WHERE id = ?\", id)\n\texec.Command(\"sh\", \"-c\", \"ls \"+id)\n\texec.Command(\"ls\", \"-l\", id)\n\tos.Open(\"/srv/\" + id)\n\tos.Open(\"/srv/fixed\")\n}\n";
        assert_eq!(flagged("go/sql-injection", src), [10]);
        assert_eq!(flagged("go/command-injection", src), [12]);
        assert_eq!(flagged("go/path-injection", src), [14]);
    }

    #[test]
    fn what_a_url_and_its_query_hold() {
        let src = "import (\n\t\"net/http\"\n\t\"os\"\n)\n\nfunc h(r *http.Request) {\n\tos.Open(r.URL.Path)\n\tos.Open(r.URL.Query().Get(\"f\"))\n\tos.Open(r.Header.Get(\"X-File\"))\n\tos.Open(r.Method)\n}\n";
        assert_eq!(flagged("go/path-injection", src), [7, 8, 9]);
    }

    #[test]
    fn gin_echo_and_fiber_contexts() {
        let gin = "import (\n\t\"net/http\"\n\n\t\"github.com/gin-gonic/gin\"\n)\n\nfunc h(c *gin.Context) {\n\tc.Redirect(http.StatusFound, c.Query(\"next\"))\n\tc.Redirect(http.StatusFound, \"/home\")\n\tc.File(c.Param(\"name\"))\n}\n";
        assert_eq!(flagged("go/open-redirect", gin), [8]);
        assert_eq!(flagged("go/path-injection", gin), [10]);
        let echo = "import \"github.com/labstack/echo/v4\"\n\nfunc h(c echo.Context) error {\n\treturn c.Redirect(302, c.QueryParam(\"to\"))\n}\n";
        assert_eq!(flagged("go/open-redirect", echo), [4]);
        let fiber = "import \"github.com/gofiber/fiber/v2\"\n\nfunc h(c *fiber.Ctx) error {\n\treturn c.Redirect(c.Query(\"to\"))\n}\n";
        assert_eq!(flagged("go/open-redirect", fiber), [4]);
    }

    #[test]
    fn values_bound_into_a_struct_and_decoded_from_a_body() {
        let src = "import (\n\t\"encoding/json\"\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tvar in string\n\tjson.NewDecoder(r.Body).Decode(&in)\n\texec.Command(in)\n}\n";
        assert_eq!(flagged("go/command-injection", src), [10]);
    }

    #[test]
    fn a_context_of_the_standard_library_is_not_a_request() {
        let src = "import (\n\t\"context\"\n\t\"os\"\n)\n\nfunc h(ctx context.Context) {\n\tos.Open(ctx.Value(\"f\").(string))\n}\n";
        assert!(flagged("go/path-injection", src).is_empty());
    }

    #[test]
    fn a_number_a_check_and_a_comparison_clear_the_value() {
        let src = "import (\n\t\"net/http\"\n\t\"os\"\n\t\"strconv\"\n\t\"strings\"\n)\n\nfunc h(r *http.Request) {\n\tn, _ := strconv.Atoi(r.FormValue(\"n\"))\n\tos.Open(strconv.Itoa(n))\n\tname := r.FormValue(\"f\")\n\tif strings.HasPrefix(name, \"public/\") {\n\t\tos.Open(name)\n\t}\n\tkind := r.FormValue(\"k\")\n\tif kind == \"a\" {\n\t\tos.Open(kind)\n\t}\n}\n";
        assert!(flagged("go/path-injection", src).is_empty());
    }

    #[test]
    fn through_the_functions_and_methods_of_the_file() {
        let src = "import (\n\t\"database/sql\"\n\t\"net/http\"\n)\n\ntype Store struct{ db *sql.DB }\n\nfunc (s *Store) find(name string) {\n\ts.db.Query(\"SELECT * FROM u WHERE n = '\" + name + \"'\")\n}\n\nfunc clean(x string) string { return x }\n\nfunc h(s *Store, r *http.Request) {\n\ts.find(clean(r.FormValue(\"n\")))\n}\n";
        assert_eq!(flagged("go/sql-injection", src), [9]);
    }

    #[test]
    fn the_host_header_is_the_way_to_move_to_https_not_an_open_redirect() {
        let src = "import \"net/http\"\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\thttp.Redirect(w, r, \"https://\"+r.Host+\"/home\", http.StatusFound)\n\thttp.Redirect(w, r, r.RequestURI, http.StatusFound)\n}\n";
        // `RequestURI` can be `//evil.example`, which is another site.
        assert_eq!(flagged("go/open-redirect", src), [5]);
    }

    #[test]
    fn only_the_start_of_an_address_sets_where_it_goes() {
        let src = "import (\n\t\"fmt\"\n\t\"net/http\"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request, base string) {\n\tid := r.FormValue(\"id\")\n\thost := r.FormValue(\"host\")\n\thttp.Redirect(w, r, \"/orders/\"+id, 302)\n\thttp.Redirect(w, r, base+id, 302)\n\thttp.Redirect(w, r, fmt.Sprintf(\"https://%s%s\", base, r.RequestURI), 302)\n\thttp.Redirect(w, r, \"https://\"+base+id, 302)\n\thttp.Redirect(w, r, \"https://\"+host+\"/x\", 302)\n\thttp.Redirect(w, r, fmt.Sprintf(\"https://%s/p\", host), 302)\n\thttp.Redirect(w, r, \"//\"+host, 302)\n\thttp.Redirect(w, r, id, 302)\n\thttp.Redirect(w, r, fmt.Sprintf(\"%s/x\", host), 302)\n}\n";
        assert_eq!(flagged("go/open-redirect", src), [13, 14, 15, 16, 17]);
    }

    #[test]
    fn chi_and_mux_route_parameters_and_a_client() {
        let chi = "import (\n\t\"net/http\"\n\n\t\"github.com/go-chi/chi/v5\"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\thttp.Get(chi.URLParam(r, \"url\"))\n}\n";
        assert_eq!(flagged("go/ssrf", chi), [8]);
        let mux = "import (\n\t\"net/http\"\n\n\t\"github.com/gorilla/mux\"\n)\n\nfunc h(client *http.Client, r *http.Request) {\n\tclient.Get(mux.Vars(r)[\"u\"])\n\tcache.Get(mux.Vars(r)[\"k\"])\n}\n";
        assert_eq!(flagged("go/ssrf", mux), [8]);
    }
}
