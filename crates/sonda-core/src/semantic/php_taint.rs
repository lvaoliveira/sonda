//! Taint analysis for PHP (ADR-0027): which values that came from a request
//! reach a sink, and by what path, within a file and across the project's.
//!
//! Like the other languages', it's **flow-insensitive** over the scopes of
//! the PHP binder: a variable that is ever written a request's value holds it
//! wherever the function reads it, and the whole file is one fixed point over
//! its writes. A function or a method of the file is followed through its
//! summary, per parameter.
//!
//! Precision before recall, as the ADR says:
//! - a value is a request's only when it comes from a superglobal a client
//!   fills (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, a few
//!   `$_SERVER` keys), the body (`php://input`), the headers, or a request
//!   object (Laravel's and Symfony's `Request`, PSR-7's
//!   `ServerRequestInterface`) the file's functions take;
//! - a call this module doesn't know returns an untainted value, so
//!   `htmlspecialchars`, `intval`, `basename` and `escapeshellarg` sanitize,
//!   and the program's own escaping helper does too;
//! - a value that's tested in the file by a call that reads as a check
//!   (`in_array`, `preg_match`, `ctype_digit`, a function called
//!   `validate...`) or compared with `==` is taken as validated;
//! - the request object itself isn't tainted, only what it returns.
//!
//! A function is matched by its name, which PHP reads without regard to case,
//! and a method by its name and its class: `$this`, `self::`, a variable
//! declared with the class or made by `new`.

use super::taint::{Callee, Key, ReturnFact, SinkKind, Step, TaintResult};
use super::taint_core::{
    Exports, Flow, How, Path, Summaries, Summary, SummaryKey, Write, address_path, best, best_of,
    checked_names, contains_any, decl_index, evaluation_for, exports_for, externals_for, flow_for,
    from_call, function_keys_for, held, locals_for, names_a_check, summarize_for, walk,
};
use super::{Decl, DeclId, Model};
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;
/// Summaries per file, at most: past it, calls to other functions give nothing.
const MAX_SUMMARIES: usize = 256;

// ---------------------------------------------------------------- entry

/// The fact a PHP file's classes are in, for the project pass.
pub(crate) const FACT: &str = "php-classes";

/// A class, trait or enum a file declares: what it extends and uses, and the
/// methods it defines, all lowercase: where a call to a method it inherits
/// goes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct ClassFact {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) parents: Vec<String>,
    #[serde(default)]
    pub(crate) methods: Vec<String>,
}

/// The classes of a file.
pub(crate) fn classes(root: Node, src: &[u8]) -> Vec<ClassFact> {
    let mut out = Vec::new();
    let _ = walk(root, |n| {
        out.extend(class_fact(n, src));
        out.len() <= MAX_WRITES
    });
    out
}

/// What a class, trait or enum declaration extends, uses and defines.
fn class_fact(n: Node, src: &[u8]) -> Option<ClassFact> {
    if !matches!(
        n.kind(),
        "class_declaration" | "trait_declaration" | "enum_declaration"
    ) {
        return None;
    }
    let text = |n: Node| n.utf8_text(src).unwrap_or_default().to_ascii_lowercase();
    let mut fact = ClassFact {
        name: text(n.child_by_field_name("name")?),
        ..ClassFact::default()
    };
    for part in named_children(n) {
        if part.kind() == "base_clause" {
            fact.parents.extend(
                named_children(part)
                    .into_iter()
                    .map(|c| last_name(&text(c)).to_string()),
            );
        }
    }
    let body = n.child_by_field_name("body");
    for member in body.map(named_children).unwrap_or_default() {
        match member.kind() {
            "use_declaration" => fact.parents.extend(
                named_children(member)
                    .into_iter()
                    .filter(|c| matches!(c.kind(), "name" | "qualified_name"))
                    .map(|c| last_name(&text(c)).to_string()),
            ),
            "method_declaration" => fact
                .methods
                .extend(member.child_by_field_name("name").map(text)),
            _ => {}
        }
    }
    Some(fact)
}

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    // A file with neither a request nor a sink can still define a function
    // other files' values reach, or pass one on: any file with functions.
    if !(might_have_sources(src)
        || might_have_sinks(src, kind)
        || contains_any(src, &[b"function"]))
    {
        return TaintResult::default();
    }
    Cx::file_result(m, src, kind).unwrap_or_default()
}

fn might_have_sources(src: &[u8]) -> bool {
    contains_any(
        src,
        &[
            b"$_GET",
            b"$_POST",
            b"$_REQUEST",
            b"$_COOKIE",
            b"$_FILES",
            b"$_SERVER",
            b"php://input",
            b"getallheaders",
            b"apache_request_headers",
            b"filter_input",
            b"Request",
            b"HTTP_RAW_POST_DATA",
        ],
    )
}

fn might_have_sinks(src: &[u8], kind: SinkKind) -> bool {
    let words: &[&[u8]] = match kind {
        SinkKind::Sql => &[
            b"query",
            b"Query",
            b"exec",
            b"prepare",
            b"mysql",
            b"pg_",
            b"sqlite",
            b"odbc",
            b"sqlsrv",
            b"DB::",
            b"Raw(",
            b"wpdb",
            b"get_results",
            b"get_row",
            b"get_var",
        ],
        SinkKind::Command => &[
            b"system",
            b"exec",
            b"passthru",
            b"popen",
            b"proc_open",
            b"pcntl_exec",
            b"`",
        ],
        SinkKind::Path => &[
            b"include",
            b"require",
            b"fopen",
            b"file_",
            b"readfile",
            b"unlink",
            b"rename",
            b"copy",
            b"mkdir",
            b"rmdir",
            b"move_uploaded_file",
            b"highlight_file",
            b"show_source",
            b"scandir",
            b"opendir",
            b"parse_ini_file",
            b"simplexml_load_file",
            b"SplFileObject",
            b"fpassthru",
            b"touch",
        ],
        SinkKind::Redirect => &[b"Location", b"redirect", b"Redirect"],
        SinkKind::Ssrf => &[
            b"curl_",
            b"file_get_contents",
            b"fopen",
            b"get_headers",
            b"Client",
            b"client",
            b"wp_remote",
            b"SoapClient",
            b"readfile",
        ],
        SinkKind::Code => &[b"eval", b"assert", b"create_function", b"call_user_func"],
        SinkKind::Html => &[b"echo", b"print", b"<?=", b"die", b"exit"],
        SinkKind::XPath | SinkKind::Ldap | SinkKind::Format => return false,
    };
    contains_any(src, words)
}

// ---------------------------------------------------------------- tables

/// Types of a request object, by their last name.
const REQUEST_TYPES: &[&str] = &[
    "Request",
    "FormRequest",
    "ServerRequestInterface",
    "ServerRequest",
    "RequestInterface",
];

/// Methods of a request object, or of a part of one (`$request->query`),
/// whose result is what a client sent.
const REQUEST_METHODS: &[&str] = &[
    "get",
    "input",
    "query",
    "post",
    "all",
    "only",
    "except",
    "cookie",
    "header",
    "file",
    "files",
    "json",
    "string",
    "param",
    "params",
    "getcontent",
    "getqueryparams",
    "getparsedbody",
    "getbody",
    "getheaderline",
    "getheader",
    "getheaders",
    "getcookieparams",
    "getuploadedfiles",
    "getattribute",
    "getattributes",
    "getparam",
    "getpost",
    "getget",
    "getrequesturi",
    "getpathinfo",
    "getquerystring",
    "bearertoken",
    "path",
    "fullurl",
    "url",
    "getbody",
];

/// Properties of a request object that hold what a client sent.
const REQUEST_PARTS: &[&str] = &[
    "query",
    "request",
    "cookies",
    "headers",
    "files",
    "attributes",
    "server",
];

/// The superglobals a client fills.
const REQUEST_ARRAYS: &[&str] = &["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"];

/// The `$_SERVER` keys a client chooses.
fn is_client_server_key(key: &str) -> bool {
    key.starts_with("HTTP_")
        || matches!(
            key,
            "REQUEST_URI"
                | "QUERY_STRING"
                | "PATH_INFO"
                | "PHP_SELF"
                | "ORIG_PATH_INFO"
                | "PATH_TRANSLATED"
        )
}

/// Functions whose result is made of their arguments' text.
const PROPAGATING_FUNCTIONS: &[&str] = &[
    "sprintf",
    "vsprintf",
    "implode",
    "join",
    "str_replace",
    "str_ireplace",
    "substr_replace",
    "preg_replace",
    "preg_replace_callback",
    "trim",
    "ltrim",
    "rtrim",
    "chop",
    "strtolower",
    "strtoupper",
    "ucfirst",
    "ucwords",
    "lcfirst",
    "substr",
    "mb_substr",
    "mb_strtolower",
    "mb_strtoupper",
    "str_pad",
    "str_repeat",
    "strrev",
    "wordwrap",
    "urldecode",
    "rawurldecode",
    "base64_decode",
    "base64_encode",
    "html_entity_decode",
    "htmlspecialchars_decode",
    "stripslashes",
    "stripcslashes",
    "strtr",
    "strval",
    "array_merge",
    "array_values",
    "array_slice",
    "array_unique",
    "array_filter",
    "array_reverse",
    "array_map",
    "array_pop",
    "array_shift",
    "array_column",
    "current",
    "reset",
    "end",
    "next",
    "prev",
    "json_decode",
    "unserialize",
    "explode",
    "str_split",
    "preg_split",
    "nl2br",
    "strip_tags",
    "trim_all",
    "mb_convert_encoding",
    "iconv",
    "utf8_decode",
    "utf8_encode",
];

/// Numbers and booleans: they can't carry what injects.
const NUMERIC_TYPES: &[&str] = &["int", "float", "bool", "integer", "double", "boolean"];

/// Calls that test a value, by kind: what they say about it makes it
/// validated.
fn check_names(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Path | SinkKind::Redirect | SinkKind::Ssrf => &[
            "strpos",
            "stripos",
            "strstr",
            "stristr",
            "str_starts_with",
            "str_ends_with",
            "str_contains",
            "in_array",
            "preg_match",
            "ctype_alnum",
            "ctype_alpha",
            "ctype_digit",
            "is_numeric",
            "filter_var",
            "realpath",
            "array_key_exists",
            "is_int",
        ],
        _ => &[
            "in_array",
            "preg_match",
            "ctype_alnum",
            "ctype_alpha",
            "ctype_digit",
            "ctype_xdigit",
            "is_numeric",
            "is_int",
            "filter_var",
            "array_key_exists",
        ],
    }
}

/// A function whose name says it checks its argument.
fn is_a_check_by_name(name: &str) -> bool {
    names_a_check(
        name,
        &["valid", "safe", "allowed", "sanitized", "verified"],
        &["sanitiz", "allowlist", "whitelist"],
    )
}

/// The functions that make a value safe for where it goes, by kind: the
/// ones a variable is passed through, `$v = esc($v)`.
fn sanitizers(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Sql => &[
            "intval",
            "floatval",
            "doubleval",
            "absint",
            "mysqli_real_escape_string",
            "mysql_real_escape_string",
            "mysqli_escape_string",
            "mysql_escape_string",
            "pg_escape_string",
            "pg_escape_literal",
            "pg_escape_identifier",
            "addslashes",
            "esc_sql",
            "quote",
            "real_escape_string",
            "escape_string",
            "escapestring",
            "sqlite_escape_string",
        ],
        SinkKind::Command => &["intval", "escapeshellarg", "escapeshellcmd"],
        SinkKind::Path => &["intval", "basename", "realpath", "sanitize_file_name"],
        SinkKind::Redirect | SinkKind::Ssrf => &[
            "intval",
            "wp_validate_redirect",
            "esc_url",
            "esc_url_raw",
            "filter_var",
        ],
        SinkKind::Html => &[
            "intval",
            "absint",
            "htmlspecialchars",
            "htmlentities",
            "strip_tags",
            "esc_html",
            "esc_attr",
            "esc_textarea",
            "wp_kses",
            "wp_kses_post",
        ],
        SinkKind::Code | SinkKind::XPath | SinkKind::Ldap | SinkKind::Format => &["intval"],
    }
}

/// Functions the language has, which no file of the project defines: a call
/// to one is never to another file's function.
const BUILTIN_PREFIXES: &[&str] = &[
    "str",
    "array_",
    "preg_",
    "mb_",
    "is_",
    "ctype_",
    "json_",
    "file_",
    "mysqli_",
    "mysql_",
    "pg_",
    "curl_",
    "date",
    "html",
    "url",
    "base64_",
    "ob_",
    "session_",
    "header",
    "http_",
    "ini_",
    "get_",
    "set_",
    "spl_",
    "iterator_",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "unlink",
    "mkdir",
    "intval",
    "floatval",
    "boolval",
    "count",
    "isset",
    "empty",
    "define",
    "defined",
    "in_array",
    "implode",
    "explode",
    "sprintf",
    "printf",
    "trim",
    "ltrim",
    "rtrim",
    "md5",
    "sha1",
    "crc32",
    "hash",
    "password_",
    "random_",
    "rand",
    "mt_",
    "uniqid",
    "time",
    "microtime",
    "sleep",
    "usleep",
    "abs",
    "ceil",
    "floor",
    "round",
    "max",
    "min",
    "sort",
    "usort",
    "rsort",
    "ksort",
    "krsort",
    "asort",
    "range",
    "compact",
    "extract",
    "func_",
    "call_user_func",
    "function_exists",
    "class_exists",
    "method_exists",
    "property_exists",
    "var_",
    "print_r",
    "error_log",
    "trigger_error",
    "exit",
    "die",
    "eval",
    "include",
    "require",
    "unserialize",
    "serialize",
    "gettype",
    "settype",
    "basename",
    "dirname",
    "pathinfo",
    "realpath",
    "glob",
    "scandir",
    "touch",
    "copy",
    "rename",
    "chmod",
    "escapeshell",
    "shell_exec",
    "system",
    "exec",
    "passthru",
    "popen",
    "proc_",
    "filter_",
    "libxml_",
    "simplexml_",
    "xml",
    "iconv",
    "utf8_",
    "nl2br",
    "wordwrap",
    "chunk_split",
    "lcfirst",
    "ucfirst",
    "ucwords",
    "number_format",
    "money_",
    "setlocale",
    "gc_",
    "memory_",
    "sys_",
    "php",
    "zend_",
    "stream_",
    "socket_",
    "fsockopen",
    "gethost",
    "ip2long",
    "long2ip",
    "inet_",
    "mail",
    "move_uploaded_file",
    "is_uploaded_file",
    "readfile",
    "fpassthru",
    "tempnam",
    "tmpfile",
];

fn is_builtin(name: &str) -> bool {
    BUILTIN_PREFIXES.iter().any(|p| name.starts_with(p))
}

// ---------------------------------------------------------------- the file

/// What a call calls, as the file writes it.
enum Target<'t> {
    /// `f(x)`: a function, by its lowercase name.
    Function(String),
    /// `$obj->m(x)`: a method, by its receiver and its lowercase name.
    Method(Node<'t>, String),
    /// `Class::m(x)`, `self::m(x)`: a static method, by the class as
    /// written and its lowercase name.
    Static(String, String),
    /// `new Class(x)`: a constructor, by the class as written.
    New(String),
}

struct Cx<'a, 't> {
    m: &'a Model<'t>,
    src: &'a [u8],
    kind: SinkKind,
    by_node: HashMap<usize, DeclId>,
    /// The variable each version of one stands for: a reassignment that
    /// always runs before a later read gets an id past the declarations'.
    versions: Vec<Option<DeclId>>,
    /// Each class's `$this->name`, as a variable of its own, and the ones that
    /// hold a request object.
    props: HashMap<(String, String), DeclId>,
    request_props: HashSet<DeclId>,
    /// The property each `$this->name` node is.
    property_nodes: HashMap<usize, DeclId>,
    /// Variables that hold a request object.
    requests: HashSet<DeclId>,
    /// Variables a check reads as validating, for this kind of sink.
    checked: HashSet<DeclId>,
    writes: Vec<Write<'t>>,
    calls: Vec<Node<'t>>,
    /// Each function's lowercase name and its class's, by its index (the
    /// name is empty for a closure), and the functions by name.
    names: Vec<String>,
    classes: Vec<String>,
    by_name: HashMap<String, Vec<usize>>,
    /// Where each class is in the file: its range and its lowercase name.
    class_ranges: Vec<(usize, usize, String)>,
    /// What each class of the file extends and uses, and the classes that
    /// define each method.
    parents: HashMap<String, Vec<String>>,
    evaluations: Cell<u64>,
    summaries: Summaries<SummaryKey, Summary<'t>>,
    /// Whether a call to another file's function may return a request's value
    /// (the project pass decides); set once the fixed point starts.
    from_calls: Cell<bool>,
    return_facts: RefCell<Vec<ReturnFact<'t>>>,
    /// What other files call each function by, worked out once.
    keys: OnceCell<Vec<Option<Key>>>,
    /// The other file's function each call calls, worked out once per call.
    callees: RefCell<HashMap<usize, Option<Callee>>>,
}

impl<'a, 't> Cx<'a, 't> {
    fn new(m: &'a Model<'t>, src: &'a [u8], kind: SinkKind, root: Node<'t>) -> Option<Self> {
        let mut cx = Cx {
            m,
            src,
            kind,
            by_node: decl_index(m),
            versions: Vec::new(),
            props: HashMap::new(),
            request_props: HashSet::new(),
            property_nodes: HashMap::new(),
            requests: HashSet::new(),
            checked: HashSet::new(),
            writes: Vec::new(),
            calls: Vec::new(),
            names: Vec::new(),
            classes: Vec::new(),
            by_name: HashMap::new(),
            class_ranges: Vec::new(),
            parents: HashMap::new(),
            evaluations: Cell::new(0),
            summaries: Summaries::new(MAX_SUMMARIES),
            from_calls: Cell::new(false),
            return_facts: RefCell::new(Vec::new()),
            keys: OnceCell::new(),
            callees: RefCell::new(HashMap::new()),
        };
        if might_have_sources(src) {
            cx.prepare(root);
        }
        cx.collect(root)?;
        cx.index();
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// The functions of the file by name, and the variables that hold a
    /// request object.
    fn index(&mut self) {
        for f in &self.m.functions {
            let name = f
                .node
                .child_by_field_name("name")
                .map_or(String::new(), |n| self.text(n).to_ascii_lowercase());
            self.classes.push(self.class_at(f.node).to_string());
            self.names.push(name);
        }
        for (j, name) in self.names.iter().enumerate() {
            if !name.is_empty() {
                self.by_name.entry(name.clone()).or_default().push(j);
            }
        }
        for (d, decl) in self.m.decls.iter().enumerate() {
            if decl
                .ty
                .is_some_and(|t| REQUEST_TYPES.contains(&last_name(self.text(t))))
            {
                self.requests.insert(d);
            }
        }
    }

    /// The class a node is in: the innermost whose range holds it.
    fn class_at(&self, n: Node) -> &str {
        self.class_ranges
            .iter()
            .filter(|(s, e, _)| *s <= n.start_byte() && n.end_byte() <= *e)
            .min_by_key(|(s, e, _)| e - s)
            .map_or("", |(_, _, name)| name.as_str())
    }

    /// Walks the file once, in source order, for its writes, calls, classes
    /// and checks. None past a limit.
    fn collect(&mut self, root: Node<'t>) -> Option<()> {
        let mut checks: Vec<Node<'t>> = Vec::new();
        let words = check_names(self.kind);
        walk(root, |n| {
            self.visit(n, words, &mut checks);
            self.writes.len() <= MAX_WRITES
        })?;
        // A variable named as a check's argument or receiver is validated.
        let named = checked_names(
            checks,
            arguments,
            ("member_call_expression", "object"),
            |n| self.checked_variable(n),
        );
        for d in named {
            self.validate(d);
        }
        Some(())
    }

    /// Records what one node writes, calls or checks.
    fn visit(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        match n.kind() {
            "class_declaration"
            | "trait_declaration"
            | "enum_declaration"
            | "interface_declaration" => {
                if let Some(c) = class_fact(n, self.src) {
                    self.parents.insert(c.name, c.parents);
                }
                if let Some(name) = n.child_by_field_name("name") {
                    self.class_ranges.push((
                        n.start_byte(),
                        n.end_byte(),
                        self.text(name).to_ascii_lowercase(),
                    ));
                }
            }
            "assignment_expression" => self.assignment(n, How::Assigned),
            "augmented_assignment_expression" => self.augmented(n),
            "foreach_statement" => self.foreach(n),
            "binary_expression" => self.comparison(n),
            "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression"
            | "object_creation_expression" => self.call(n, words, checks),
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression"
            | "echo_statement"
            | "print_intrinsic"
            | "exit_statement" => {
                self.calls.push(n);
            }
            "expression_statement" if self.is_short_echo(n) => self.calls.push(n),
            _ => {}
        }
    }

    /// `<?= $x ?>`: an expression that is printed.
    fn is_short_echo(&self, n: Node<'t>) -> bool {
        // The tag is the node before it, or the last of what a closing tag and
        // the text after it made.
        let tag = |p: Node<'t>| p.kind() == "php_tag" && self.text(p) == "<?=";
        n.prev_sibling().is_some_and(|p| {
            tag(p)
                || (p.kind() == "text_interpolation"
                    && p.child(p.child_count().saturating_sub(1)).is_some_and(tag))
        })
    }

    // ------------------------------------------------------------ writes

    fn write(&mut self, target: DeclId, target_node: Node<'t>, value: Node<'t>, how: How) {
        if self.is_inert(target) {
            return;
        }
        // A version's writes are also the writes of every version it
        // replaced, for the reads past the block it's in.
        let mut id = Some(target);
        while let Some(t) = id {
            self.writes.push(Write {
                target: t,
                target_node,
                value,
                how,
            });
            id = self.replaced(t);
        }
    }

    /// The variable a version replaced, None for a declaration.
    fn replaced(&self, d: DeclId) -> Option<DeclId> {
        d.checked_sub(self.m.decls.len())
            .and_then(|i| self.versions.get(i).copied().flatten())
    }

    /// The declaration a variable, or a version of one, is.
    fn decl(&self, d: DeclId) -> &Decl<'t> {
        &self.m.decls[self.origin(d)]
    }

    fn origin(&self, d: DeclId) -> DeclId {
        let mut d = d;
        while let Some(r) = self.replaced(d) {
            d = r;
        }
        d
    }

    /// A variable a check or a sanitizing assignment validates, and the
    /// versions it replaced: the read past the block gets no other.
    fn validate(&mut self, d: DeclId) {
        let mut id = Some(d);
        while let Some(t) = id {
            self.checked.insert(t);
            id = self.replaced(t);
        }
    }

    // -------------------------------------------------------- properties

    /// A variable for each property a class names through `$this`, and which
    /// are declared to hold a request object: a method writes it, another
    /// reads it.
    fn prepare(&mut self, root: Node<'t>) {
        let this = contains_any(self.src, &[b"$this"]);
        let mut found: Vec<(Node<'t>, bool)> = Vec::new();
        let mut blocks: Vec<Node<'t>> = Vec::new();
        each_node(root, |n| {
            match n.kind() {
                "member_access_expression" | "nullsafe_member_access_expression" if this => {
                    found.push((n, false));
                }
                "property_element" | "property_promotion_parameter" if this => {
                    found.push((n, true));
                }
                "compound_statement" | "program" => blocks.push(n),
                _ => {}
            }
            found.len() + blocks.len() <= MAX_WRITES
        });
        self.properties(found);
        self.version(blocks);
    }

    fn properties(&mut self, found: Vec<(Node<'t>, bool)>) {
        for (n, declared) in found {
            let key = if declared {
                self.declared_property(n)
            } else {
                self.this_property(n)
            };
            let Some(key) = key else { continue };
            let next = self.m.decls.len() + self.versions.len();
            let id = *self.props.entry(key).or_insert(next);
            if id == next {
                self.versions.push(None);
            }
            self.property_nodes.insert(n.id(), id);
            if declared && self.declared_request(n) {
                self.request_props.insert(id);
            }
        }
    }

    /// The class and name of a property a declaration or a promoted
    /// parameter introduces.
    fn declared_property(&self, n: Node<'t>) -> Option<(String, String)> {
        let name = n.child_by_field_name("name")?;
        let class = enclosing_class(n, self.src)?;
        Some((class, self.text(name).trim_start_matches('$').to_string()))
    }

    /// Whether the declaration's type is a request's.
    fn declared_request(&self, n: Node<'t>) -> bool {
        let holder = if n.kind() == "property_element" {
            n.parent()
        } else {
            Some(n)
        };
        holder
            .and_then(|h| h.child_by_field_name("type"))
            .is_some_and(|t| {
                REQUEST_TYPES.contains(&last_name(self.text(t).trim_start_matches('?')))
            })
    }

    /// The class and name of `$this->name`.
    fn this_property(&self, n: Node<'t>) -> Option<(String, String)> {
        if !matches!(
            n.kind(),
            "member_access_expression" | "nullsafe_member_access_expression"
        ) {
            return None;
        }
        let object = n.child_by_field_name("object")?;
        let name = n.child_by_field_name("name")?;
        if self.text(object) != "$this" || name.kind() != "name" {
            return None;
        }
        Some((enclosing_class(n, self.src)?, self.text(name).to_string()))
    }

    /// The variable `$this->name` is, if the file has one for it.
    fn property_id(&self, n: Node<'t>) -> Option<DeclId> {
        self.property_nodes.get(&n.id()).copied()
    }

    /// `$this->name` or `$this->name['k']`.
    fn written_property(&self, n: Node<'t>) -> Option<DeclId> {
        let mut n = n;
        while n.kind() == "subscript_expression" {
            n = n.named_child(0)?;
        }
        self.property_id(n)
    }

    // ---------------------------------------------------------- versions

    /// `$x = v;` as a statement of a block (not in a loop) kills what `$x`
    /// held before, for what the block reads after it: those reads get a
    /// version of their own. The flow-insensitive model alone would keep
    /// `$ip = $_GET['ip']` tainting `$ip = $octet[0] . '.' . $octet[1]`.
    fn version(&mut self, blocks: Vec<Node<'t>>) {
        for block in blocks {
            if !in_loop(block) {
                self.version_block(block);
            }
        }
    }

    fn version_block(&mut self, block: Node<'t>) {
        // Only a reassignment of a variable declared before has anything to
        // kill: most blocks have none.
        let kills = |cx: &Self, s: Node<'t>| {
            let left = cx.killer(s)?;
            let d = cx.decl_of(left)?;
            (cx.decl(d).node.start_byte() < s.start_byte()).then_some(left)
        };
        let wanted: HashSet<DeclId> = named_children(block)
            .into_iter()
            .filter_map(|s| kills(self, s))
            .filter_map(|left| self.decl_of(left))
            .collect();
        if wanted.is_empty() {
            return;
        }
        let mut reads: HashMap<DeclId, Vec<Node<'t>>> = HashMap::new();
        each_node(block, |n| {
            if n.kind() == "variable_name"
                && let Some(d) = self.decl_of(n).filter(|d| wanted.contains(d))
            {
                reads.entry(d).or_default().push(n);
            }
            true
        });
        for s in named_children(block) {
            let Some(left) = self.killer(s) else {
                continue;
            };
            let Some(d) = self.decl_of(left) else {
                continue;
            };
            // The first assignment declares; there's nothing to kill.
            if self.decl(d).node.start_byte() >= s.start_byte() {
                continue;
            }
            let id = self.m.decls.len() + self.versions.len();
            self.versions.push(Some(d));
            let after = s.end_byte();
            let mut moved = Vec::new();
            if let Some(nodes) = reads.get_mut(&d) {
                let (later, rest): (Vec<_>, Vec<_>) = std::mem::take(nodes)
                    .into_iter()
                    .partition(|v| v.start_byte() >= after || v.id() == left.id());
                *nodes = rest;
                moved = later;
            }
            for v in &moved {
                self.by_node.insert(v.id(), id);
            }
            reads.insert(id, moved);
        }
    }

    /// The variable `s` is `$x = v;` for.
    fn killer(&self, s: Node<'t>) -> Option<Node<'t>> {
        let a = (s.kind() == "expression_statement")
            .then(|| s.named_child(0))
            .flatten()
            .filter(|a| a.kind() == "assignment_expression")?;
        let left = a.child_by_field_name("left")?;
        (left.kind() == "variable_name").then_some(left)
    }

    /// `$a = v`, `$a[] = v`, `[$a, $b] = f()`: each variable gets the value.
    fn assignment(&mut self, n: Node<'t>, how: How) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        self.sanitizes_itself(left, right);
        self.write_to(left, right, how);
    }

    /// `$s .= v` adds to a string; `??=` and `=`-like operators set it; a
    /// number's `+=` is no text.
    fn augmented(&mut self, n: Node<'t>) {
        let how = match n
            .child_by_field_name("operator")
            .map_or("", |o| self.text(o))
        {
            ".=" => How::Added,
            "??=" => How::Assigned,
            _ => return,
        };
        self.assignment(n, how);
    }

    fn write_to(&mut self, target: Node<'t>, value: Node<'t>, how: How) {
        match target.kind() {
            "variable_name" => {
                if let Some(d) = self.decl_of(target) {
                    self.write(d, target, value, how);
                }
            }
            // `$this->p = v`: the class's property holds the value.
            "member_access_expression" | "nullsafe_member_access_expression" => {
                if let Some(d) = self.property_id(target) {
                    self.write(d, target, value, how);
                }
            }
            // `$a['k'] = v`, `$a[] = v`: the collection holds the value.
            "subscript_expression" => {
                if let Some(d) = self.written_property(target) {
                    self.write(d, target, value, How::Added);
                } else if let Some((d, node)) = self.base_of(target) {
                    self.write(d, node, value, How::Added);
                }
            }
            // `[$a, $b] = $row`: each holds a part of it.
            "list_literal" | "array_creation_expression" => {
                for v in variables(target) {
                    if let Some(d) = self.decl_of(v) {
                        self.write(d, v, value, How::Read);
                    }
                }
            }
            _ => {}
        }
    }

    /// `foreach ($xs as $k => $v)`: the variables hold a part of the value.
    fn foreach(&mut self, n: Node<'t>) {
        let body = n.child_by_field_name("body");
        let mut c = n.walk();
        let parts: Vec<Node<'t>> = n
            .named_children(&mut c)
            .filter(|k| body.is_none_or(|b| b.id() != k.id()) && k.kind() != "comment")
            .collect();
        let Some((iterated, bindings)) = parts.split_first() else {
            return;
        };
        for b in bindings {
            for v in variables(*b) {
                if let Some(d) = self.decl_of(v) {
                    self.write(d, v, *iterated, How::Read);
                }
            }
        }
    }

    /// `$x == "..."` tests the value.
    fn comparison(&mut self, n: Node<'t>) {
        let op = n
            .child_by_field_name("operator")
            .map_or("", |o| self.text(o));
        if !matches!(op, "==" | "===" | "!=" | "!==") || matches!(self.kind, SinkKind::Sql) {
            return;
        }
        for side in ["left", "right"] {
            if let Some(d) = n
                .child_by_field_name(side)
                .and_then(|s| self.checked_variable(s))
            {
                self.validate(d);
            }
        }
    }

    /// The variable a test is about: `$x` in `is_numeric($x)`,
    /// `$octet[0]`, `strtolower($ext) == 'jpg'` and `(int) $n`.
    fn checked_variable(&self, n: Node<'t>) -> Option<DeclId> {
        let mut n = unwrap(n);
        for _ in 0..8 {
            match n.kind() {
                "variable_name" => return self.decl_of(n),
                "member_access_expression" | "nullsafe_member_access_expression" => {
                    return self.property_id(n);
                }
                "subscript_expression" | "parenthesized_expression" => n = n.named_child(0)?,
                "cast_expression" => n = n.child_by_field_name("value")?,
                "function_call_expression"
                    if call_name(n, self.src)
                        .is_some_and(|f| PROPAGATING_FUNCTIONS.contains(&f.as_str())) =>
                {
                    n = *arguments(n).first()?
                }
                _ => return None,
            }
        }
        None
    }

    /// `$v = esc($v)`: a variable the program passes through what makes it
    /// safe for where it goes is taken as validated, wherever it's read:
    /// the flow-insensitive model can't tell the line before from the line
    /// after, and this is how PHP code writes it.
    fn sanitizes_itself(&mut self, left: Node<'t>, right: Node<'t>) {
        let Some(d) = self.decl_of(left) else {
            return;
        };
        let mut sanitized = false;
        walk_nodes(right, &mut |c| {
            // `$n = (int) $n`
            if c.kind() == "cast_expression"
                && c.child_by_field_name("type")
                    .is_some_and(|t| NUMERIC_TYPES.contains(&self.text(t).trim()))
                && variables(c).into_iter().any(|v| self.same(v, d))
            {
                sanitized = true;
            }
            let name = match c.kind() {
                "function_call_expression" => call_name(c, self.src),
                "member_call_expression" | "nullsafe_member_call_expression" => c
                    .child_by_field_name("name")
                    .map(|n| self.text(n).to_ascii_lowercase()),
                _ => None,
            };
            if name.is_some_and(|f| sanitizers(self.kind).contains(&f.as_str()))
                && variables(c).into_iter().any(|v| self.same(v, d))
            {
                sanitized = true;
            }
        });
        if sanitized {
            self.validate(d);
        }
    }

    /// A call: the check it may be, and what it writes into its arguments.
    fn call(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        self.calls.push(n);
        let name = match self.target(n) {
            Some(Target::Function(f)) => f,
            Some(Target::Method(_, m)) | Some(Target::Static(_, m)) => m,
            _ => return,
        };
        if words.contains(&name.as_str()) || is_a_check_by_name(&name) {
            checks.push(n);
        }
        let args = arguments(n);
        match self.target(n) {
            Some(Target::Function(f)) => self.argument_writes(&f, &args),
            Some(Target::Method(receiver, m)) => self.method_writes(receiver, &m, &args),
            _ => {}
        }
    }

    /// `preg_match($p, $s, $m)`, `parse_str($s, $out)`, `array_push($a, $v)`:
    /// the variable gets the value.
    fn argument_writes(&mut self, name: &str, args: &[Node<'t>]) {
        let (from, to) = match name {
            "preg_match" | "preg_match_all" => (1, 2),
            "parse_str" => (0, 1),
            "array_push" | "array_unshift" => (1, 0),
            _ => return,
        };
        let Some((d, node)) = args.get(to).and_then(|a| self.base_of(*a)) else {
            return;
        };
        let sources: Vec<Node<'t>> = if name.starts_with("array_") {
            args.iter().skip(1).copied().collect()
        } else {
            args.get(from).copied().into_iter().collect()
        };
        for v in sources {
            self.write(d, node, v, How::Added);
        }
    }

    /// `$sb->append($v)`, `$q->set('k', $v)`: the object holds the value.
    fn method_writes(&mut self, receiver: Node<'t>, name: &str, args: &[Node<'t>]) {
        if !matches!(name, "append" | "add" | "set" | "put" | "push" | "write") {
            return;
        }
        if let (Some((d, node)), Some(v)) = (self.base_of(receiver), args.last()) {
            self.write(d, node, *v, How::Added);
        }
    }

    /// The variable an expression names, and the node that names it: through
    /// `$a[..]`, `$a->p` and `$a->m()`.
    fn base_of(&self, n: Node<'t>) -> Option<(DeclId, Node<'t>)> {
        let mut n = n;
        for _ in 0..16 {
            match n.kind() {
                "variable_name" => return Some((self.decl_of(n)?, n)),
                "parenthesized_expression" | "reference_assignment_expression" => {
                    n = n.named_child(0)?
                }
                "subscript_expression" => n = n.named_child(0)?,
                "member_access_expression" | "nullsafe_member_access_expression" => {
                    n = n.child_by_field_name("object")?
                }
                "member_call_expression" | "nullsafe_member_call_expression" => {
                    n = n.child_by_field_name("object")?
                }
                _ => return None,
            }
        }
        None
    }

    /// The declaration `n` names, as a declaration or as a reference.
    fn decl_of(&self, n: Node<'t>) -> Option<DeclId> {
        if n.kind() != "variable_name" {
            return None;
        }
        self.by_node
            .get(&n.id())
            .copied()
            .or_else(|| self.m.decl_id_of(n))
    }

    /// Whether `v` names the variable `d` is, in any of its versions.
    fn same(&self, v: Node<'t>, d: DeclId) -> bool {
        self.decl_of(v)
            .is_some_and(|e| self.origin(e) == self.origin(d))
    }

    /// A variable of a number's type, which can't hold what injects.
    fn is_inert(&self, d: DeclId) -> bool {
        // A property has no declaration to read a type from.
        self.origin(d) < self.m.decls.len()
            && self
                .decl(d)
                .ty
                .is_some_and(|t| NUMERIC_TYPES.contains(&self.text(t).trim_start_matches('?')))
    }

    // ------------------------------------------------------------ calls

    /// What a call calls.
    fn target(&self, call: Node<'t>) -> Option<Target<'t>> {
        match call.kind() {
            "function_call_expression" => Some(Target::Function(call_name(call, self.src)?)),
            "member_call_expression" | "nullsafe_member_call_expression" => {
                let name = call.child_by_field_name("name")?;
                (name.kind() == "name").then(|| {
                    Target::Method(
                        call.child_by_field_name("object").unwrap_or(call),
                        self.text(name).to_ascii_lowercase(),
                    )
                })
            }
            "scoped_call_expression" => {
                let name = call.child_by_field_name("name")?;
                let scope = call.child_by_field_name("scope")?;
                (name.kind() == "name").then(|| {
                    Target::Static(
                        self.text(scope).trim_start_matches('\\').to_string(),
                        self.text(name).to_ascii_lowercase(),
                    )
                })
            }
            "object_creation_expression" => {
                let mut c = call.walk();
                let class = call
                    .named_children(&mut c)
                    .find(|k| matches!(k.kind(), "name" | "qualified_name"))?;
                Some(Target::New(
                    self.text(class).trim_start_matches('\\').to_string(),
                ))
            }
            _ => None,
        }
    }

    /// The request object `n` is, or is a part of: a variable that holds
    /// one, or `$request->query` and the like.
    fn is_request(&self, n: Node<'t>) -> bool {
        let mut n = n;
        for _ in 0..8 {
            match n.kind() {
                "variable_name" => {
                    return self
                        .decl_of(n)
                        .is_some_and(|d| self.requests.contains(&self.origin(d)));
                }
                "parenthesized_expression" => match n.named_child(0) {
                    Some(inner) => n = inner,
                    None => return false,
                },
                "member_access_expression" | "nullsafe_member_access_expression" => {
                    if let Some(d) = self.property_id(n) {
                        return self.request_props.contains(&d);
                    }
                    let part = n
                        .child_by_field_name("name")
                        .map_or(String::new(), |p| self.text(p).to_ascii_lowercase());
                    if !REQUEST_PARTS.contains(&part.as_str()) {
                        return false;
                    }
                    match n.child_by_field_name("object") {
                        Some(o) => n = o,
                        None => return false,
                    }
                }
                _ => return false,
            }
        }
        false
    }

    // ------------------------------------------------------------ evaluation

    /// What `n`'s kind of expression holds, `next` levels down.
    fn expression(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        next: u32,
    ) -> Option<Path<'t>> {
        match n.kind() {
            "variable_name" => {
                let name = self.text(n);
                if REQUEST_ARRAYS.contains(&name) {
                    return Some(source_step(n, name));
                }
                held(self.decl_of(n), &self.checked, state)
            }
            "parenthesized_expression" | "reference_assignment_expression" => {
                self.taint(n.named_child(0)?, state, next)
            }
            "sequence_expression"
            | "encapsed_string"
            | "heredoc"
            | "heredoc_body"
            | "shell_command_expression"
            | "array_creation_expression"
            | "array_element_initializer"
            | "argument"
            | "arguments" => best(
                named_children(n)
                    .into_iter()
                    .map(|c| self.taint(c, state, next)),
            ),
            "subscript_expression" => self.subscript_taint(n, state, next),
            "member_access_expression" | "nullsafe_member_access_expression" => {
                self.property_taint(n, state, next)
            }
            "binary_expression" => {
                let op = n
                    .child_by_field_name("operator")
                    .map_or("", |o| self.text(o));
                match op {
                    "." => {
                        if self.starts_the_text() {
                            return self.address_taint(n, state, next);
                        }
                        best_of(n, &["left", "right"], |c| self.taint(c, state, next))
                    }
                    "??" => best_of(n, &["left", "right"], |c| self.taint(c, state, next)),
                    _ => None,
                }
            }
            "conditional_expression" => best_of(n, &["condition", "body", "alternative"], |c| {
                self.taint(c, state, next)
            }),
            "cast_expression" => {
                let numeric = n
                    .child_by_field_name("type")
                    .is_some_and(|t| NUMERIC_TYPES.contains(&self.text(t).trim()));
                if numeric {
                    return None;
                }
                self.taint(n.child_by_field_name("value")?, state, next)
            }
            "assignment_expression" => self.taint(n.child_by_field_name("right")?, state, next),
            "error_suppression_expression" => self.taint(n.named_child(0)?, state, next),
            "function_call_expression"
            | "member_call_expression"
            | "nullsafe_member_call_expression"
            | "scoped_call_expression" => self.call_taint(n, state, next),
            _ => None,
        }
    }

    /// `$_GET['id']`, `$_SERVER['HTTP_HOST']`, `$row['n']`.
    fn subscript_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let base = n.named_child(0)?;
        // `$_FILES['f']['tmp_name']` is where the server put the upload.
        let server_set = matches!(
            n.named_child(1)
                .map(|k| self.text(k).trim_matches(['\'', '"'])),
            Some("tmp_name" | "error" | "size")
        );
        if server_set
            && self
                .root_variable(base)
                .is_some_and(|r| self.text(r) == "$_FILES")
        {
            return None;
        }
        if base.kind() == "variable_name" && self.text(base) == "$_SERVER" {
            let key = n.named_child(1)?;
            let key = self.text(key).trim_matches(['\'', '"']);
            // The `Host` the client wrote is how a redirect to `https://` + host
            // moves to HTTPS, and a victim's browser can't be made to send
            // another.
            let host = matches!(key, "HTTP_HOST") && matches!(self.kind, SinkKind::Redirect);
            return (is_client_server_key(key) && !host).then(|| source_step(n, "$_SERVER"));
        }
        self.taint(base, state, depth)
    }

    /// The variable an element chain starts at: `$_FILES` for `$_FILES['f']['name']`.
    fn root_variable(&self, n: Node<'t>) -> Option<Node<'t>> {
        let mut n = n;
        for _ in 0..8 {
            match n.kind() {
                "variable_name" => return Some(n),
                "subscript_expression" => n = n.named_child(0)?,
                _ => return None,
            }
        }
        None
    }

    /// `$request->email` (Laravel reads an input as a property), or a
    /// property of a tainted value.
    fn property_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        if let Some(d) = self.property_id(n) {
            return held(Some(d), &self.checked, state);
        }
        let object = n.child_by_field_name("object")?;
        if self.is_request(object) {
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

    fn call_taint(
        &self,
        call: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let args = arguments(call);
        match self.target(call)? {
            Target::Function(name) => self.function_taint(call, &name, &args, state, depth),
            Target::Method(receiver, name) => {
                if self.is_request(receiver) && REQUEST_METHODS.contains(&name.as_str()) {
                    return Some(source_step(call, &name));
                }
                if self.local_callee(call).is_none()
                    && matches!(
                        name.as_str(),
                        "get"
                            | "first"
                            | "all"
                            | "value"
                            | "tostring"
                            | "__tostring"
                            | "getvalue"
                            | "toarray"
                    )
                    && let Some(path) = self.taint(receiver, state, depth)
                {
                    return Some(path);
                }
                self.through_function(call, &args, state, depth)
            }
            Target::Static(class, name) => {
                // Laravel's facade: `Request::input('q')`.
                if last_name(&class) == "Request" && REQUEST_METHODS.contains(&name.as_str()) {
                    return Some(source_step(call, &name));
                }
                self.through_function(call, &args, state, depth)
            }
            Target::New(_) => None,
        }
    }

    /// What `f(..)` returns: what a source gives, the text of an argument for
    /// the functions that change text, or what a function of the file returns.
    fn function_taint(
        &self,
        call: Node<'t>,
        name: &str,
        args: &[Node<'t>],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        match name {
            "getallheaders" | "apache_request_headers" => return Some(source_step(call, name)),
            "filter_input" | "filter_input_array" => {
                let kind = args.first().map_or("", |a| self.text(*a));
                if matches!(
                    kind,
                    "INPUT_GET" | "INPUT_POST" | "INPUT_COOKIE" | "INPUT_REQUEST"
                ) {
                    return Some(source_step(call, name));
                }
                return None;
            }
            "file_get_contents" | "stream_get_contents" | "fopen" | "readfile"
                if args
                    .first()
                    .is_some_and(|a| self.text(*a).contains("php://input")) =>
            {
                return Some(source_step(call, "php://input"));
            }
            _ => {}
        }
        if self.starts_the_text() && matches!(name, "sprintf") {
            return self.format_taint(args, state, depth);
        }
        if PROPAGATING_FUNCTIONS.contains(&name)
            && !(name == "strip_tags" && matches!(self.kind, SinkKind::Html))
            && self.local_callee(call).is_none()
        {
            return best(args.iter().map(|a| self.taint(*a, state, depth)));
        }
        self.through_function(call, args, state, depth)
    }

    /// `"/orders/" . $id`, `"https://" . $host . $path`: the operands of a
    /// concatenation, from the first (see `address_path`). A `header`'s name
    /// isn't part of the address: `'Location: ' . $base . $id` is `$base . $id`.
    fn address_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let mut operands = Vec::new();
        concatenation(n, self.src, &mut operands);
        let after_header = |s: &'a str| {
            s.get(..9)
                .filter(|h| h.eq_ignore_ascii_case("location:"))
                .map(|_| s[9..].trim_start())
        };
        let mut start = operands.first().and_then(|o| self.literal(*o));
        if let Some(rest) = start.and_then(after_header) {
            if rest.is_empty() && operands.len() > 1 {
                operands.remove(0);
                start = operands.first().and_then(|o| self.literal(*o));
            } else {
                start = Some(rest);
            }
        }
        address_path(&operands, start, |o| self.taint(o, state, depth))
    }

    /// The text of a string written out, without interpolation.
    fn literal(&self, n: Node<'t>) -> Option<&'a str> {
        let n = unwrap(n);
        (n.kind() == "string").then(|| self.text(n).trim_matches(['\'', '"']))
    }

    // ------------------------------------------------------------ sinks

    /// The sink a node is, for this kind, and the arguments that take the
    /// value.
    fn sink_call(&self, call: Node<'t>) -> Option<(String, Vec<Node<'t>>)> {
        match call.kind() {
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression" => (self.kind == SinkKind::Path)
                .then(|| (call.kind().to_string(), named_children(call))),
            "echo_statement" => (self.kind == SinkKind::Html).then(|| {
                let mut out = Vec::new();
                for c in named_children(call) {
                    if c.kind() == "sequence_expression" {
                        out.extend(named_children(c));
                    } else {
                        out.push(c);
                    }
                }
                ("echo".to_string(), out)
            }),
            "print_intrinsic" | "exit_statement" => (self.kind == SinkKind::Html).then(|| {
                (
                    call.kind()
                        .replace("_intrinsic", "")
                        .replace("_statement", ""),
                    named_children(call),
                )
            }),
            "expression_statement" => (self.kind == SinkKind::Html && self.is_short_echo(call))
                .then(|| ("<?=".to_string(), named_children(call))),
            "object_creation_expression" => {
                let Some(Target::New(class)) = self.target(call) else {
                    return None;
                };
                let args = arguments(call);
                let at = self.constructor_sink(&last_name(&class).to_ascii_lowercase())?;
                Some((
                    format!("new {class}"),
                    args.get(at).copied().into_iter().collect(),
                ))
            }
            _ => {
                let args = arguments(call);
                let (name, at) = match self.target(call)? {
                    Target::Function(f) => {
                        let at = self.function_sink(&f, &args)?;
                        (f, at)
                    }
                    Target::Method(receiver, m) => {
                        let at = self.method_sink(receiver, &m)?;
                        (m, at)
                    }
                    Target::Static(class, m) => {
                        let at = self.static_sink(&class, &m)?;
                        (format!("{class}::{m}"), at)
                    }
                    Target::New(_) => return None,
                };
                let taking = at
                    .into_iter()
                    .filter_map(|i| args.get(i).copied())
                    .collect();
                Some((name, taking))
            }
        }
    }

    /// The position of the argument of `new Class(..)` that takes the value.
    fn constructor_sink(&self, class: &str) -> Option<usize> {
        match (self.kind, class) {
            (SinkKind::Path, "splfileobject" | "directoryiterator" | "splfileinfo") => Some(0),
            (SinkKind::Redirect, "redirectresponse") => Some(0),
            (SinkKind::Ssrf, "soapclient") => Some(0),
            _ => None,
        }
    }

    /// The positions of the arguments of a function that take the value, if
    /// it's a sink of this kind.
    fn function_sink(&self, name: &str, args: &[Node<'t>]) -> Option<Vec<usize>> {
        match (self.kind, name) {
            (
                SinkKind::Sql,
                "mysql_query" | "mysql_unbuffered_query" | "sqlite_query" | "sqlite_exec",
            ) => Some(vec![0]),
            (
                SinkKind::Sql,
                "mysqli_query" | "mysqli_multi_query" | "mysqli_real_query" | "pg_send_query"
                | "odbc_exec" | "sqlsrv_query" | "mssql_query",
            ) => Some(vec![1]),
            (SinkKind::Sql, "pg_query") => Some(vec![args.len().saturating_sub(1).min(1)]),
            (
                SinkKind::Command,
                "system" | "exec" | "shell_exec" | "passthru" | "popen" | "proc_open"
                | "pcntl_exec" | "expect_popen",
            ) => Some(vec![0]),
            (
                SinkKind::Path,
                "fopen"
                | "file_get_contents"
                | "file"
                | "readfile"
                | "unlink"
                | "mkdir"
                | "rmdir"
                | "scandir"
                | "opendir"
                | "is_dir"
                | "highlight_file"
                | "show_source"
                | "parse_ini_file"
                | "simplexml_load_file"
                | "fpassthru"
                | "touch"
                | "chmod"
                | "file_put_contents"
                | "readlink"
                | "glob"
                | "dir"
                | "md5_file"
                | "sha1_file",
            ) => Some(vec![0]),
            (SinkKind::Path, "rename" | "copy" | "symlink" | "link") => Some(vec![0, 1]),
            (SinkKind::Path, "move_uploaded_file") => Some(vec![1]),
            (SinkKind::Redirect, "header") => {
                let literal = args.first().and_then(|a| self.header_location(*a));
                literal.map(|_| vec![0])
            }
            // `wp_safe_redirect` only goes to the hosts the site allows.
            (SinkKind::Redirect, "wp_redirect" | "redirect") => Some(vec![0]),
            (
                SinkKind::Ssrf,
                "curl_init"
                | "file_get_contents"
                | "fopen"
                | "get_headers"
                | "readfile"
                | "wp_remote_get"
                | "wp_remote_post"
                | "wp_remote_request"
                | "wp_safe_remote_get"
                | "simplexml_load_file",
            ) => Some(vec![0]),
            (SinkKind::Ssrf, "curl_setopt") => args
                .get(1)
                .is_some_and(|o| self.text(*o) == "CURLOPT_URL")
                .then(|| vec![2]),
            (SinkKind::Code, "eval" | "assert" | "create_function") => Some(vec![0]),
            (SinkKind::Code, "call_user_func" | "call_user_func_array") => Some(vec![0]),
            (SinkKind::Html, "printf" | "vprintf" | "die" | "exit") => Some(vec![0]),
            (SinkKind::Html, "print_r" | "var_export") => args
                .get(1)
                .is_none_or(|a| self.text(*a) != "true")
                .then(|| vec![0]),
            _ => None,
        }
    }

    /// The argument of a `header(..)` call, when it sets a `Location`.
    fn header_location(&self, arg: Node<'t>) -> Option<()> {
        let mut operands = Vec::new();
        concatenation(unwrap(arg), self.src, &mut operands);
        let first = operands.first()?;
        let text = match first.kind() {
            "string" => self.text(*first).trim_matches(['\'', '"']),
            "encapsed_string" => self.text(*first).trim_matches('"'),
            _ => return None,
        };
        text.to_ascii_lowercase()
            .starts_with("location:")
            .then_some(())
    }

    /// The positions of the arguments of a method that take the value, if
    /// it's a sink of this kind.
    fn method_sink(&self, receiver: Node<'t>, name: &str) -> Option<Vec<usize>> {
        match self.kind {
            SinkKind::Sql => {
                if self.is_statement(receiver) {
                    return None;
                }
                match name {
                    "query" | "exec" | "prepare" | "multi_query" | "real_query"
                    | "unbuffered_query" | "get_results" | "get_row" | "get_var" | "get_col"
                    | "whereraw" | "selectraw" | "orderbyraw" | "havingraw" | "fromraw"
                    | "joinraw" | "raw" | "statement" | "unprepared" => Some(vec![0]),
                    _ => None,
                }
            }
            SinkKind::Ssrf => (matches!(
                name,
                "get" | "post" | "put" | "delete" | "patch" | "head" | "request" | "send"
            ) && self.is_client(receiver))
            .then(|| if name == "request" { vec![1] } else { vec![0] }),
            SinkKind::Redirect => {
                matches!(name, "redirect" | "redirectto" | "away").then(|| vec![0])
            }
            SinkKind::Html => None,
            _ => None,
        }
    }

    /// The positions of the arguments of a static method that take the value.
    fn static_sink(&self, class: &str, name: &str) -> Option<Vec<usize>> {
        let class = last_name(class);
        match (self.kind, class, name) {
            (
                SinkKind::Sql,
                "DB",
                "select" | "statement" | "raw" | "unprepared" | "insert" | "update" | "delete",
            ) => Some(vec![0]),
            (SinkKind::Redirect, "Redirect", "to" | "away") => Some(vec![0]),
            _ => None,
        }
    }

    /// Whether a receiver is a prepared statement, whose `execute` takes
    /// values for its placeholders, not text.
    fn is_statement(&self, receiver: Node<'t>) -> bool {
        let Some(d) = self.decl_of(unwrap(receiver)) else {
            return false;
        };
        let name = self.decl(d).name.to_ascii_lowercase();
        name.contains("stmt") || name.contains("statement")
    }

    /// Whether a receiver reads as an HTTP client.
    fn is_client(&self, receiver: Node<'t>) -> bool {
        let named = self.text(receiver).to_ascii_lowercase();
        named.contains("client") || named.contains("guzzle") || named.contains("http")
    }

    // ------------------------------------------------------------ functions (T3)

    /// The function or method of this file a call calls, when it's
    /// unambiguous: the only one of that name that takes that many
    /// arguments, and for a method, of the class the call names.
    fn local_callee(&self, call: Node<'t>) -> Option<usize> {
        let arity = arguments(call).len();
        let (name, class) = match self.target(call)? {
            Target::Function(f) => (f, None),
            Target::Method(receiver, m) => (m, Some(self.class_of(receiver, call)?)),
            Target::Static(class, m) => (m, Some(self.named_class(&class, call)?)),
            Target::New(_) => return None,
        };
        // A method the class inherits is the nearest ancestor's.
        let class = match class {
            Some(c) => Some(self.defining_class(&c, &name)?),
            None => None,
        };
        let candidates: Vec<usize> = self
            .by_name
            .get(&name)?
            .iter()
            .copied()
            .filter(|&j| {
                let f = &self.m.functions[j];
                let variadic = f.node.child_by_field_name("parameters").is_some_and(|p| {
                    named_children(p)
                        .iter()
                        .any(|c| c.kind() == "variadic_parameter")
                });
                arity <= f.params.len()
                    && !variadic
                    && match &class {
                        None => f.node.kind() == "function_definition",
                        Some(c) => f.node.kind() == "method_declaration" && &self.classes[j] == c,
                    }
            })
            .collect();
        match candidates.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// The class of the file that defines method `name` for `class`: its own
    /// or the nearest ancestor's.
    fn defining_class(&self, class: &str, name: &str) -> Option<String> {
        let defines = |c: &str| {
            self.by_name
                .get(name)
                .is_some_and(|js| js.iter().any(|&j| self.classes[j] == c))
        };
        let mut lineage = vec![class.to_string()];
        let mut i = 0;
        while let Some(c) = lineage.get(i).cloned() {
            if defines(&c) {
                return Some(c);
            }
            for p in self.parents.get(&c).into_iter().flatten() {
                if !lineage.contains(p) && lineage.len() < 16 {
                    lineage.push(p.clone());
                }
            }
            i += 1;
        }
        None
    }

    /// The class a method is called on: `$this`'s, a variable declared with
    /// one, or made by `new`.
    fn class_of(&self, receiver: Node<'t>, call: Node<'t>) -> Option<String> {
        let receiver = unwrap(receiver);
        if receiver.kind() == "variable_name" && self.text(receiver) == "$this" {
            return Some(self.class_at(call).to_string()).filter(|c| !c.is_empty());
        }
        let d = self.decl_of(receiver)?;
        let written = match self.decl(d).ty {
            Some(t) => self.text(t).to_string(),
            None => self.inferred_class(d)?,
        };
        Some(last_name(written.trim_start_matches('?')).to_ascii_lowercase())
    }

    /// `self::`, `static::`, or a class's name.
    fn named_class(&self, class: &str, call: Node<'t>) -> Option<String> {
        match class {
            "self" | "static" => Some(self.class_at(call).to_string()).filter(|c| !c.is_empty()),
            "parent" => self.parents.get(self.class_at(call))?.first().cloned(),
            _ => Some(last_name(class).to_ascii_lowercase()),
        }
    }

    /// The class of a variable declared without one, from `$x = new Foo(..)`.
    fn inferred_class(&self, d: DeclId) -> Option<String> {
        let holder = self.decl(d).declarator?;
        let value = (holder.kind() == "assignment_expression")
            .then(|| holder.child_by_field_name("right"))
            .flatten()?;
        let Some(Target::New(class)) = self.target(unwrap(value)) else {
            return None;
        };
        Some(class)
    }
}

// ---------------------------------------------------------------- other files (T4)

impl<'a, 't> Cx<'a, 't> {
    /// The other file's function a call calls, as this file writes it: a
    /// function the language doesn't have and this file doesn't define, or a
    /// method of a class this file names.
    fn find_external_callee(&self, call: Node<'t>) -> Option<Callee> {
        if self.local_callee(call).is_some() {
            return None;
        }
        let php = |class: Option<String>, name: &str| Callee::Php {
            class,
            name: name.to_string(),
        };
        match self.target(call)? {
            Target::Function(name) => {
                let defined_here = self.by_name.contains_key(&name);
                (!defined_here && !is_builtin(&name)).then(|| php(None, &name))
            }
            Target::Method(receiver, name) => {
                if self.is_request(receiver) {
                    return None;
                }
                let class = self.class_of(receiver, call)?;
                let defined_here = self.defining_class(&class, &name).is_some();
                (!defined_here).then(|| php(Some(class), &name))
            }
            Target::Static(class, name) => {
                let class = self.named_class(&class, call)?;
                let defined_here = self.defining_class(&class, &name).is_some();
                (!defined_here).then(|| php(Some(class), &name))
            }
            Target::New(class) => Some(php(
                Some(last_name(&class).to_ascii_lowercase()),
                "__construct",
            )),
        }
    }

    fn raw_key(&self, j: usize) -> Option<Key> {
        let f = &self.m.functions[j];
        let name = &self.names[j];
        if name.is_empty() || self.is_variadic(f.node) {
            return None;
        }
        let export = match f.node.kind() {
            "function_definition" => name.clone(),
            "method_declaration" if !self.classes[j].is_empty() => {
                format!("{}::{name}", self.classes[j])
            }
            _ => return None,
        };
        Some(Key {
            export,
            member: None,
        })
    }

    fn is_variadic(&self, function: Node<'t>) -> bool {
        function.child_by_field_name("parameters").is_some_and(|p| {
            named_children(p)
                .iter()
                .any(|c| c.kind() == "variadic_parameter")
        })
    }
}

flow_for!(Cx, from_call);
externals_for!(Cx);
locals_for!(Cx);
evaluation_for!(Cx);
function_keys_for!(Cx);
summarize_for!(
    Cx,
    &[
        "function_definition",
        "method_declaration",
        "anonymous_function",
        "arrow_function",
    ],
    |cx: &Cx, d| cx.is_inert(d) || cx.requests.contains(&d)
);
exports_for!(Cx);

// ---------------------------------------------------------------- syntax

/// A step for a value a request's call returns, or a superglobal gives.
fn source_step<'t>(n: Node<'t>, name: &str) -> Path<'t> {
    vec![Step {
        node: n,
        message: format!("read from the request by `{name}`"),
    }]
}

/// The name a call calls, lowercased and without a leading namespace.
fn call_name(call: Node, src: &[u8]) -> Option<String> {
    let f = call.child_by_field_name("function")?;
    let name = match f.kind() {
        "name" => f,
        "qualified_name" => {
            let mut c = f.walk();
            f.named_children(&mut c)
                .filter(|n| n.kind() == "name")
                .last()?
        }
        _ => return None,
    };
    Some(
        std::str::from_utf8(&src[name.byte_range()])
            .unwrap_or_default()
            .to_ascii_lowercase(),
    )
}

/// The last name of a class or a type as written: `\App\Http\Request` is
/// `Request`.
fn last_name(ty: &str) -> &str {
    let ty = ty.trim().trim_start_matches('?');
    ty.rsplit(['\\', '|']).next().unwrap_or(ty).trim()
}

/// A call's arguments, each without its `name:` label.
fn arguments(call: Node) -> Vec<Node> {
    let list = call.child_by_field_name("arguments").or_else(|| {
        let mut c = call.walk();
        call.named_children(&mut c)
            .find(|k| k.kind() == "arguments")
    });
    let Some(list) = list else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|a| a.kind() == "argument")
        .filter_map(|a| a.named_child(u32::try_from(a.named_child_count().checked_sub(1)?).ok()?))
        .collect()
}

fn named_children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// Calls `f` for `n` and every node below it.
fn walk_nodes<'t>(n: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(n);
    let mut c = n.walk();
    for child in n.children(&mut c) {
        walk_nodes(child, f);
    }
}

/// The variables in a node, not looking into a function.
fn variables<'t>(n: Node<'t>) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![n];
    while let Some(x) = stack.pop() {
        if x.kind() == "variable_name" {
            out.push(x);
            continue;
        }
        let mut c = x.walk();
        let kids: Vec<Node<'t>> = x.named_children(&mut c).collect();
        stack.extend(kids.into_iter().rev());
    }
    out
}

/// The operands of a chain of `.`, left to right.
fn concatenation<'t>(n: Node<'t>, src: &[u8], out: &mut Vec<Node<'t>>) {
    let is_dot = n.kind() == "binary_expression"
        && n.child_by_field_name("operator")
            .is_some_and(|o| &src[o.byte_range()] == b".");
    match (
        is_dot,
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

/// An expression without the parentheses around it.
/// The lowercase name of the class (or trait, enum) around `n`.
fn enclosing_class(n: Node, src: &[u8]) -> Option<String> {
    let mut p = n.parent();
    while let Some(a) = p {
        if matches!(
            a.kind(),
            "class_declaration" | "trait_declaration" | "enum_declaration"
        ) {
            let name = a.child_by_field_name("name")?;
            return Some(name.utf8_text(src).ok()?.to_ascii_lowercase());
        }
        p = a.parent();
    }
    None
}

/// Calls `f` on every node under `root`, in source order, until it says to
/// stop: without a list of children per node, as `walk` makes.
fn each_node<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>) -> bool) {
    let mut cursor = root.walk();
    loop {
        if !f(cursor.node()) {
            return;
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() || cursor.node().id() == root.id() {
                return;
            }
        }
    }
}

/// Whether a loop is around `n`, inside its function.
fn in_loop(n: Node) -> bool {
    let mut p = n.parent();
    while let Some(a) = p {
        match a.kind() {
            "while_statement" | "do_statement" | "for_statement" | "foreach_statement" => {
                return true;
            }
            "function_definition"
            | "method_declaration"
            | "anonymous_function"
            | "arrow_function" => return false,
            _ => p = a.parent(),
        }
    }
    false
}

fn unwrap(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => return n,
        }
    }
    n
}

fn is_built(n: Node) -> bool {
    n.kind() == "binary_expression"
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::flagged_php as flagged;
    use crate::lang::Lang;

    #[test]
    fn a_superglobal_in_a_query_a_command_a_path_and_a_page() {
        let src = "function h($db) {\n    $id = $_GET['id'];\n    mysqli_query($db, \"SELECT * FROM t WHERE id = '$id'\");\n    shell_exec('ping ' . $id);\n    file_get_contents('/srv/' . $id);\n    echo 'Hello ' . $id;\n    print $id;\n    mysqli_query($db, 'SELECT 1');\n}\n";
        assert_eq!(flagged("php/sql-injection", src), [3]);
        assert_eq!(flagged("php/command-injection", src), [4]);
        assert_eq!(flagged("php/path-injection", src), [5]);
        assert_eq!(flagged("php/xss", src), [6, 7]);
    }

    #[test]
    fn short_echo_tags_and_what_a_server_variable_holds() {
        let src = "function h() {\n    $a = $_SERVER['HTTP_USER_AGENT'];\n    $b = $_SERVER['SERVER_NAME'];\n    $c = $_FILES['f']['name'];\n    $d = $_FILES['f']['tmp_name'];\n    echo $a;\n    echo $b;\n    echo $c;\n    echo $d;\n}\n";
        assert_eq!(flagged("php/xss", src), [6, 8]);
        let template =
            "?>\n<p><?= $_GET['name'] ?></p>\n<p><?= htmlspecialchars($_GET['name']) ?></p>\n";
        assert_eq!(flagged("php/xss", template), [2]);
    }

    #[test]
    fn escaping_checking_and_comparing_clear_the_value() {
        let src = "function h($db) {\n    $a = $_GET['a'];\n    echo htmlspecialchars($a);\n    $b = $_GET['b'];\n    $b = mysqli_real_escape_string($db, $b);\n    mysqli_query($db, \"SELECT * FROM t WHERE b = '$b'\");\n    $c = $_GET['c'];\n    if (is_numeric($c)) {\n        mysqli_query($db, \"SELECT * FROM t WHERE c = $c\");\n    }\n    $e = $_GET['e'];\n    if (strtolower($e) == 'jpg') {\n        file_get_contents('/srv/x.' . $e);\n    }\n    $f = explode('.', $_GET['f']);\n    if (is_numeric($f[0]) && is_numeric($f[1])) {\n        shell_exec('ping ' . $f[0] . '.' . $f[1]);\n    }\n    $g = (int) $_GET['g'];\n    mysqli_query($db, \"SELECT * FROM t WHERE g = $g\");\n}\n";
        assert!(flagged("php/sql-injection", src).is_empty());
        assert!(flagged("php/xss", src).is_empty());
        assert!(flagged("php/path-injection", src).is_empty());
        assert!(flagged("php/command-injection", src).is_empty());
    }

    #[test]
    fn request_objects_of_the_frameworks() {
        let laravel = "function a(Request $request) {\n    DB::select(\"SELECT * FROM t WHERE n = '\" . $request->input('n') . \"'\");\n    DB::select('SELECT * FROM t WHERE n = ?', [$request->input('n')]);\n    $name = $request->email;\n    echo $name;\n}\n";
        assert_eq!(flagged("php/sql-injection", laravel), [2]);
        assert_eq!(flagged("php/xss", laravel), [5]);
        let symfony = "function b(Request $request) {\n    $q = $request->query->get('q');\n    return new RedirectResponse($q);\n}\n";
        assert_eq!(flagged("php/open-redirect", symfony), [3]);
        let psr = "function c(ServerRequestInterface $request) {\n    $p = $request->getQueryParams();\n    echo $p['name'];\n}\n";
        assert_eq!(flagged("php/xss", psr), [3]);
        let other = "function d(Logger $request, $x) {\n    echo $request->input('n');\n}\n";
        assert!(flagged("php/xss", other).is_empty());
    }

    #[test]
    fn only_the_start_of_an_address_sets_where_it_goes() {
        let src = "function h($base) {\n    $u = $_GET['u'];\n    header('Location: ' . $u);\n    header('Location: /orders/' . $u);\n    header('Location: ' . $base . $u);\n    header('Location: https://' . $u);\n    header('X-Other: ' . $u);\n    wp_redirect($u);\n}\n";
        assert_eq!(flagged("php/open-redirect", src), [3, 6, 8]);
    }

    #[test]
    fn a_cast_back_into_the_same_variable_and_the_host_header() {
        let src = "function h($db) {\n    foreach ($_REQUEST['ids'] as $id) {\n        $id = (int) $id;\n        $ids[] = $id;\n    }\n    $list = implode(',', $ids);\n    $db->query(\"DELETE FROM t WHERE id IN ($list)\");\n    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);\n    header('Location: ' . $_SERVER['HTTP_REFERER']);\n    wp_safe_redirect($_GET['u']);\n}\n";
        assert!(flagged("php/sql-injection", src).is_empty());
        assert_eq!(flagged("php/open-redirect", src), [9]);
    }

    #[test]
    fn through_the_functions_and_methods_of_the_file() {
        let src = "function find($db, $id) {\n    return mysqli_query($db, \"SELECT * FROM t WHERE id = $id\");\n}\nfunction clean($x) {\n    return $x;\n}\nclass Repo {\n    private $db;\n    public function load($id) {\n        return $this->run($id);\n    }\n    private function run($sql) {\n        return mysqli_query($this->db, 'SELECT ' . $sql);\n    }\n    public static function make($v) {\n        return self::build($v);\n    }\n    private static function build($v) {\n        return shell_exec($v);\n    }\n}\nfunction h($db) {\n    find($db, clean($_GET['id']));\n    $r = new Repo();\n    $r->load($_POST['x']);\n    Repo::make($_POST['y']);\n}\n";
        assert_eq!(flagged("php/sql-injection", src), [2, 13]);
        assert_eq!(flagged("php/command-injection", src), [19]);
    }

    #[test]
    fn a_prepared_statement_binds_its_values() {
        let src = "function h($db) {\n    $id = $_GET['id'];\n    $stmt = $db->prepare('SELECT * FROM t WHERE id = ?');\n    $stmt->execute([$id]);\n    $db->query(\"SELECT * FROM t WHERE id = $id\");\n    $db->prepare(\"SELECT * FROM t WHERE id = $id\");\n}\n";
        assert_eq!(flagged("php/sql-injection", src), [5, 6]);
    }

    #[test]
    fn a_reassignment_that_always_runs_kills_what_the_variable_held() {
        // Past the `=`, `$t` is no request's value.
        let src = "function h() {\n    $t = $_GET['t'];\n    $t = 'ping';\n    system($t);\n}\n";
        assert!(flagged("php/command-injection", src).is_empty());
        // Before it, it still is.
        let src = "function h() {\n    $t = $_GET['t'];\n    system($t);\n    $t = 'ping';\n}\n";
        assert_eq!(flagged("php/command-injection", src), [3]);
        // The octets of the checked address, put back together (DVWA).
        let src = "function h() {\n    $t = $_GET['ip'];\n    $o = explode('.', $t);\n    if (is_numeric($o[0]) && is_numeric($o[1])) {\n        $t = $o[0] . '.' . $o[1];\n        shell_exec('ping ' . $t);\n    }\n}\n";
        assert!(flagged("php/command-injection", src).is_empty());
    }

    #[test]
    fn a_reassignment_that_may_not_run_or_run_again_keeps_the_value() {
        // In a branch: the read after it may see either.
        let src = "function h($c) {\n    $t = 'ls';\n    if ($c) {\n        $t = $_GET['t'];\n    }\n    system($t);\n}\n";
        assert_eq!(flagged("php/command-injection", src), [6]);
        // Two blocks deep, both writes reach the read after them.
        let src = "function h($c) {\n    $t = 'ls';\n    if ($c) {\n        $t = 'a';\n        if ($c) {\n            $t = $_GET['t'];\n        }\n    }\n    system($t);\n}\n";
        assert_eq!(flagged("php/command-injection", src), [9]);
        // In a loop nothing is killed: the read at its top sees the last
        // pass's write, and one after a reassignment is kept the same way.
        let src = "function h($xs) {\n    $t = 'ls';\n    foreach ($xs as $x) {\n        $t = 'a';\n        system($t);\n        $t = $_GET['t'];\n    }\n}\n";
        assert_eq!(flagged("php/command-injection", src), [5]);
        let src = "function h($xs) {\n    $t = 'ls';\n    foreach ($xs as $x) {\n        system($t);\n        $t = $_GET['t'];\n    }\n}\n";
        assert_eq!(flagged("php/command-injection", src), [4]);
    }

    #[test]
    fn a_sanitizing_reassignment_still_clears_the_variable_past_its_block() {
        let src = "function h($c) {\n    $n = 'x';\n    if ($c) {\n        $n = $_GET['n'];\n        $n = escapeshellarg($n);\n    }\n    system($n);\n}\n";
        assert!(flagged("php/command-injection", src).is_empty());
    }

    #[test]
    fn a_property_set_in_one_method_and_read_in_another() {
        let src = "class C {\n    private $q;\n    function __construct() { $this->q = $_GET['q']; }\n    function run($db) {\n        $db->query(\"SELECT * FROM t WHERE a = $this->q\");\n    }\n}\n";
        assert_eq!(flagged("php/sql-injection", src), [5]);
        // One class's property is not another's.
        let src = "class C {\n    function set() { $this->q = $_GET['q']; }\n}\nclass D {\n    function run($db) { $this->q = 'x'; system($this->q); }\n}\n";
        assert!(flagged("php/command-injection", src).is_empty());
        // Added to by an element, and read as one.
        let src = "class C {\n    function add() { $this->args[] = $_GET['a']; }\n    function run() { system(implode(' ', $this->args)); }\n}\n";
        assert_eq!(flagged("php/command-injection", src), [3]);
        // A check on the property clears it.
        let src = "class C {\n    function set() { $this->id = $_GET['id']; }\n    function run($db) {\n        if (!is_numeric($this->id)) { return; }\n        $db->query(\"SELECT * FROM t WHERE id = $this->id\");\n    }\n}\n";
        assert!(flagged("php/sql-injection", src).is_empty());
    }

    #[test]
    fn a_property_that_holds_the_request() {
        let src = "class C {\n    private Request $request;\n    function run($db) { $db->query('SELECT ' . $this->request->input('c')); }\n}\n";
        assert_eq!(flagged("php/sql-injection", src), [3]);
        let src = "class C {\n    function __construct(private Request $req) {}\n    function run() { system($this->req->get('c')); }\n}\n";
        assert_eq!(flagged("php/command-injection", src), [3]);
    }

    // ------------------------------------------------------------ across files (T4)

    /// The lines `rule` flags in a project of PHP files, as (path, line).
    fn project(rule: &str, files: &[(&str, &str)]) -> Vec<(String, usize)> {
        crate::analysis::tests::project_flagged(
            rule,
            Lang::Php,
            files,
            crate::analysis::taint_project_rules,
        )
    }

    #[test]
    fn a_function_defined_in_another_file() {
        let page = "<?php\nrequire 'db.php';\nfunction show() {\n    find_user($_GET['id']);\n}\n";
        let db = "<?php\nfunction find_user($id) {\n    return mysqli_query($GLOBALS['db'], \"SELECT * FROM u WHERE id = $id\");\n}\n";
        let found = project(
            "php/sql-injection",
            &[("page.php", page), ("lib/db.php", db)],
        );
        assert_eq!(found, [("lib/db.php".to_string(), 3)]);
        // No file defines it: nothing to follow.
        let found = project("php/sql-injection", &[("page.php", page)]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_helpers_result_into_a_sink_in_the_callers_file() {
        let page = "<?php\nfunction show() {\n    $path = data_path($_GET['n']);\n    echo file_get_contents($path);\n}\n";
        let keeps = "<?php\nfunction data_path($n) {\n    return '/data/' . $n;\n}\n";
        let found = project(
            "php/path-injection",
            &[("page.php", page), ("paths.php", keeps)],
        );
        assert_eq!(found, [("page.php".to_string(), 4)]);
        let fixed = "<?php\nfunction data_path($n) {\n    return '/data/fixed';\n}\n";
        let found = project(
            "php/path-injection",
            &[("page.php", page), ("paths.php", fixed)],
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_method_of_a_class_defined_in_another_file() {
        let page = "<?php\nfunction a() {\n    $s = new Store();\n    $s->find($_GET['id']);\n}\nfunction b(Store $s) {\n    $s->find($_POST['id']);\n}\nfunction c(Other $o) {\n    $o->find($_POST['id']);\n}\n";
        let store = "<?php\nclass Store {\n    public function find($id) {\n        return mysqli_query($this->db, \"SELECT * FROM t WHERE id = $id\");\n    }\n}\n";
        let found = project(
            "php/sql-injection",
            &[("page.php", page), ("Store.php", store)],
        );
        assert_eq!(found, [("Store.php".to_string(), 4)]);
    }

    #[test]
    fn a_method_a_class_inherits() {
        // From a parent class and a trait in the same file.
        let src = "class Base {\n    function find($db, $id) { $db->query(\"SELECT * FROM t WHERE id = $id\"); }\n}\ntrait T {\n    function drop($db, $id) { $db->query(\"DELETE FROM t WHERE id = $id\"); }\n}\nclass Repo extends Base {\n    use T;\n    function run($db) {\n        $this->find($db, $_GET['a']);\n        $this->drop($db, $_GET['b']);\n        parent::find($db, $_GET['c']);\n    }\n}\n";
        assert_eq!(flagged("php/sql-injection", src), [2, 5]);
    }

    #[test]
    fn an_override_is_the_method_called() {
        let src = "class Base {\n    function find($db, $id) { $db->query(\"SELECT * FROM t WHERE id = $id\"); }\n}\nclass Repo extends Base {\n    function find($db, $id) { $db->query('SELECT 1'); }\n    function run($db) { $this->find($db, $_GET['a']); }\n}\n";
        assert!(flagged("php/sql-injection", src).is_empty());
    }

    #[test]
    fn a_method_inherited_from_a_class_in_another_file() {
        let page = "<?php\nfunction a() {\n    $s = new Store();\n    $s->find($_GET['id']);\n}\n";
        let store = "<?php\nclass Store extends Base {\n}\n";
        let base = "<?php\nclass Base {\n    public function find($id) {\n        return mysqli_query($this->db, \"SELECT * FROM t WHERE id = $id\");\n    }\n}\n";
        let found = project(
            "php/sql-injection",
            &[("page.php", page), ("Store.php", store), ("Base.php", base)],
        );
        assert_eq!(found, [("Base.php".to_string(), 4)]);
        // A subclass's own method wins over the parent's.
        let store =
            "<?php\nclass Store extends Base {\n    public function find($id) { return 1; }\n}\n";
        let found = project(
            "php/sql-injection",
            &[("page.php", page), ("Store.php", store), ("Base.php", base)],
        );
        assert!(found.is_empty());
    }

    #[test]
    fn a_constructor_in_another_file() {
        let page = "<?php\nfunction a() {\n    return new Runner($_GET['cmd']);\n}\n";
        let runner = "<?php\nclass Runner {\n    public function __construct($cmd) {\n        shell_exec($cmd);\n    }\n}\n";
        let found = project(
            "php/command-injection",
            &[("page.php", page), ("Runner.php", runner)],
        );
        assert_eq!(found, [("Runner.php".to_string(), 4)]);
    }
}
