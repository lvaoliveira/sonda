//! Taint analysis for Java, phases T2 to T4 (ADR-0027): which values that came from
//! a request reach a sink, and by what path.
//!
//! Like JavaScript's and Python's, it's **flow-insensitive**, over the
//! scopes of Java's binder (S1): a variable that is ever assigned a request's
//! value holds it everywhere in its scope, and the whole file is one fixed
//! point over its writes.
//!
//! Precision before recall, as the ADR says:
//! - a call this module doesn't know returns an untainted value, so a
//!   program's own escaping helper sanitizes, and `Integer.parseInt(x)`,
//!   `x.length()` and the like are numbers, which can't inject;
//! - a value that's tested, in the file, by a call that reads as a check
//!   (`startsWith`, `matches`, `getCanonicalPath`, an allow-list's
//!   `contains`, ...) is taken as validated, for the sink kinds that check
//!   guards;
//! - the request object itself isn't tainted, only what it returns.
//!
//! Sources are a servlet request's values (`request.getParameter`,
//! `getHeader`, `getQueryString`, a cookie's value, ...) and the parameters a
//! framework fills from the request: Spring's (`@RequestParam`,
//! `@PathVariable`, `@RequestBody`, ...) and JAX-RS's (`@QueryParam`,
//! `@PathParam`, `@FormParam`, ...).
//!
//! A call to a method of the same file (T3) is followed through its summary,
//! per parameter: whether the parameter reaches the return value, and which
//! sinks it reaches inside the method or the methods it calls. A call is
//! resolved only when it's unambiguous: on `this` or nothing, on `new T(..)`
//! or on a variable declared as `T`, with one method of that name and arity
//! in the class.
//!
//! A call to a method of another file (T4) is a callee the project pass
//! resolves with the Java index: the declared type of what it's called on,
//! as written, the types the call is inside of, and the method's name and
//! arity. The file reports the request's values it passes to such a call,
//! a summary per method for the values other files pass to it, and the
//! results of other files' methods that reach a sink here (their paths start
//! at the call, and are a request's value only if the project pass finds
//! the method returns one). Overloads of one name and arity can't be told
//! apart, so none is followed.

use super::taint::{
    CallFact, Callee, Facts, Finding, Key, ReturnFact, SinkKind, Step, SummaryFact, TaintResult,
    cap,
};
use super::taint_core::{
    FROM_CALL, Flow, How, Path, Reaches, Summaries, Write, best, call_facts, decl_index, exported,
    finish, flow_for, from_call, inside, note_return, record_return, short, through_returns,
    through_sinks, tick,
};
use super::{DeclId, Model};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;

// ---------------------------------------------------------------- tables

/// Annotations that make a parameter a request's value.
const SOURCE_ANNOTATIONS: &[&str] = &[
    // Spring MVC
    "RequestParam",
    "PathVariable",
    "RequestHeader",
    "CookieValue",
    "RequestBody",
    "ModelAttribute",
    "MatrixVariable",
    "RequestPart",
    // JAX-RS
    "QueryParam",
    "PathParam",
    "FormParam",
    "HeaderParam",
    "CookieParam",
    "MatrixParam",
    "BeanParam",
    // Micronaut and Quarkus
    "QueryValue",
    "Header",
    "CookieValue",
    "Body",
    "PathVariable",
];

/// Types a request's values can't inject through: a number, a boolean, a
/// date, an id.
const INERT_TYPES: &[&str] = &[
    "int",
    "long",
    "short",
    "byte",
    "float",
    "double",
    "boolean",
    "char",
    "Integer",
    "Long",
    "Short",
    "Byte",
    "Float",
    "Double",
    "Boolean",
    "Character",
    "BigInteger",
    "BigDecimal",
    "UUID",
    "Date",
    "LocalDate",
    "LocalDateTime",
    "LocalTime",
    "Instant",
    "OffsetDateTime",
    "ZonedDateTime",
    "Duration",
    "Pageable",
    "Locale",
    "Principal",
    "Model",
    "BindingResult",
];

/// Types of an incoming request, and the methods that return a value from
/// it.
const REQUEST_TYPES: &[&str] = &[
    "HttpServletRequest",
    "ServletRequest",
    "HttpServletRequestWrapper",
    "WebRequest",
    "NativeWebRequest",
    "ContainerRequestContext",
    "ServerHttpRequest",
    "UriInfo",
    "HttpHeaders",
];

const REQUEST_METHODS: &[&str] = &[
    "getParameter",
    "getParameterValues",
    "getParameterMap",
    "getParameterNames",
    "getHeader",
    "getHeaders",
    "getHeaderNames",
    "getHeaderString",
    "getRequestHeader",
    "getRequestHeaders",
    "getQueryString",
    "getRequestURI",
    "getPathInfo",
    "getPathTranslated",
    "getCookies",
    "getInputStream",
    "getReader",
    "getPart",
    "getParts",
    "getQueryParameters",
    "getPathParameters",
    "getPath",
    "getRawPath",
    "getQuery",
    "getBody",
];

/// Methods that return their receiver's text, or part of it, changed: a
/// tainted receiver gives a tainted result.
const PROPAGATING_METHODS: &[&str] = &[
    "trim",
    "strip",
    "stripLeading",
    "stripTrailing",
    "toLowerCase",
    "toUpperCase",
    "substring",
    "replace",
    "replaceAll",
    "replaceFirst",
    "concat",
    "intern",
    "toString",
    "toCharArray",
    "getBytes",
    "split",
    "lines",
    "repeat",
    "formatted",
    "get",
    "getFirst",
    "getLast",
    "getOrDefault",
    "orElse",
    "orElseGet",
    "orElseThrow",
    "getValue",
    "getName",
    "readLine",
    "nextLine",
    "next",
    "nextElement",
    "nextToken",
    "elements",
    "values",
    "keySet",
    "entrySet",
    "iterator",
    "stream",
    "findFirst",
    "toList",
    "collect",
    "map",
    "filter",
    "decode",
    "valueOf",
    "toArray",
    "asList",
];

/// Methods that add their arguments to their receiver, and return it.
const BUILDER_METHODS: &[&str] = &[
    "append",
    "insert",
    "add",
    "addAll",
    "put",
    "putAll",
    "offer",
    "push",
    "addFirst",
    "addLast",
    "setLength",
];

/// Classes whose static methods return text built from their arguments.
const PROPAGATING_CLASSES: &[&str] = &[
    "String",
    "StringUtils",
    "Objects",
    "MessageFormat",
    "Optional",
    "Arrays",
    "List",
    "Set",
    "Map",
    "Stream",
    "Collections",
    "URLDecoder",
    "Paths",
    "Path",
    "Joiner",
    "URI",
];

/// Constructors whose object holds the text of their first argument.
const PROPAGATING_NEW: &[&str] = &[
    "StringBuilder",
    "StringBuffer",
    "String",
    "StringJoiner",
    "ArrayList",
    "LinkedList",
    "HashSet",
    "StringReader",
    "URI",
    "Scanner",
    "BufferedReader",
    "InputStreamReader",
    "ByteArrayInputStream",
];

/// Which of a sink's arguments takes the value.
#[derive(Clone, Copy)]
enum Args {
    First,
    /// The first two: an LDAP search's base and filter.
    FirstTwo,
    /// Every argument: a command's parts.
    All,
}

/// A sink: the types (or chained calls, or class names) its receiver can
/// be, the methods, and the arguments.
type Sink = (&'static [&'static str], &'static [&'static str], Args);

const SQL_SINKS: &[Sink] = &[
    (
        &[
            "Statement",
            "createStatement",
            "CallableStatement",
            "PreparedStatement",
        ],
        &[
            "execute",
            "executeQuery",
            "executeUpdate",
            "executeLargeUpdate",
            "addBatch",
        ],
        Args::First,
    ),
    (
        &["Connection", "getConnection"],
        &["prepareStatement", "prepareCall", "nativeSQL"],
        Args::First,
    ),
    (
        &[
            "JdbcTemplate",
            "NamedParameterJdbcTemplate",
            "JdbcOperations",
            "NamedParameterJdbcOperations",
            "SimpleJdbcTemplate",
            "getJdbcTemplate",
        ],
        &[
            "query",
            "queryForObject",
            "queryForList",
            "queryForMap",
            "queryForRowSet",
            "queryForStream",
            "queryForInt",
            "queryForLong",
            "update",
            "batchUpdate",
            "execute",
        ],
        Args::First,
    ),
    (
        &[
            "EntityManager",
            "getEntityManager",
            "Session",
            "currentSession",
            "getSession",
        ],
        &["createQuery", "createNativeQuery", "createSQLQuery"],
        Args::First,
    ),
    (&["JdbcClient"], &["sql"], Args::First),
];

const COMMAND_SINKS: &[Sink] = &[
    (&["Runtime", "getRuntime"], &["exec"], Args::All),
    (&["ProcessBuilder"], &["command"], Args::All),
    (&["CommandLine"], &["parse", "addArgument"], Args::First),
];

const COMMAND_NEW: &[&str] = &["ProcessBuilder", "CommandLine"];

const PATH_SINKS: &[Sink] = &[
    (&["Paths", "Path"], &["get", "of"], Args::All),
    (
        &["Files"],
        &[
            "readAllBytes",
            "readString",
            "readAllLines",
            "newInputStream",
            "newOutputStream",
            "newBufferedReader",
            "newBufferedWriter",
            "write",
            "writeString",
            "copy",
            "move",
            "delete",
            "deleteIfExists",
            "createFile",
            "createDirectory",
            "createDirectories",
            "lines",
            "list",
            "walk",
            "exists",
            "isDirectory",
        ],
        Args::First,
    ),
];

const PATH_NEW: &[&str] = &[
    "File",
    "FileInputStream",
    "FileOutputStream",
    "FileReader",
    "FileWriter",
    "RandomAccessFile",
    "PrintWriter",
    "ClassPathResource",
    "FileSystemResource",
    "FileSystemResourceLoader",
];

const REDIRECT_SINKS: &[Sink] = &[
    (
        &[
            "HttpServletResponse",
            "ServletResponse",
            "response",
            "resp",
            "res",
        ],
        &["sendRedirect"],
        Args::First,
    ),
    (
        &["ResponseEntity", "HeadersBuilder", "BodyBuilder"],
        &["location"],
        Args::First,
    ),
];

const REDIRECT_NEW: &[&str] = &["RedirectView"];

const SSRF_SINKS: &[Sink] = &[
    (
        &["HttpRequest", "Builder", "newBuilder"],
        &["newBuilder", "uri"],
        Args::First,
    ),
    (
        &["RestTemplate", "TestRestTemplate"],
        &[
            "getForObject",
            "getForEntity",
            "postForObject",
            "postForEntity",
            "postForLocation",
            "exchange",
            "execute",
            "put",
            "delete",
            "headForHeaders",
            "optionsForAllow",
            "patchForObject",
        ],
        Args::First,
    ),
    (&["Jsoup"], &["connect"], Args::First),
    (&["WebClient", "RestClient"], &["uri"], Args::First),
];

const SSRF_NEW: &[&str] = &[
    "URL",
    "HttpGet",
    "HttpPost",
    "HttpPut",
    "HttpDelete",
    "HttpPatch",
    "HttpHead",
    "HttpOptions",
];

const XPATH_SINKS: &[Sink] = &[
    (
        &["XPath", "newXPath"],
        &["evaluate", "compile", "evaluateExpression"],
        Args::First,
    ),
    (
        &["Document", "Node", "Element", "DocumentHelper"],
        &["selectNodes", "selectSingleNode"],
        Args::First,
    ),
];

const LDAP_SINKS: &[Sink] = &[(
    &[
        "DirContext",
        "InitialDirContext",
        "LdapContext",
        "InitialLdapContext",
        "LdapTemplate",
    ],
    &[
        "search",
        "find",
        "findOne",
        "authenticate",
        "searchForObject",
        "searchForContext",
    ],
    Args::FirstTwo,
)];

const CODE_SINKS: &[Sink] = &[
    (&["ScriptEngine", "getEngineByName"], &["eval"], Args::First),
    (&["GroovyShell"], &["evaluate", "parse"], Args::First),
    (
        &["ExpressionParser", "SpelExpressionParser"],
        &["parseExpression"],
        Args::First,
    ),
    (
        &["Ognl"],
        &["getValue", "parseExpression", "setValue"],
        Args::First,
    ),
    (&["MVEL"], &["eval", "compileExpression"], Args::First),
];

/// What the file must contain for the kind's sinks to be in it.
fn might_have_sinks(src: &[u8], kind: SinkKind) -> bool {
    // Names are case-insensitive here: a field called `jdbcTemplate`, a
    // variable called `xpath`.
    let lower = src.to_ascii_lowercase();
    let has = |n: &[u8]| {
        let n = n.to_ascii_lowercase();
        lower.windows(n.len()).any(|w| w == n.as_slice())
    };
    let words: &[&[u8]] = match kind {
        SinkKind::Sql => &[
            b"Statement",
            b"prepareStatement",
            b"prepareCall",
            b"JdbcTemplate",
            b"JdbcOperations",
            b"JdbcClient",
            b"createQuery",
            b"createNativeQuery",
            b"createSQLQuery",
            b"nativeSQL",
            b"executeQuery",
            b"executeUpdate",
            b"addBatch",
            b"queryFor",
            b"batchUpdate",
            b".execute(",
        ],
        SinkKind::Command => &[b"exec(", b"ProcessBuilder", b"CommandLine"],
        SinkKind::Path => &[
            b"File",
            b"Paths",
            b"Path.of",
            b"Files.",
            b"Resource",
            b"RandomAccessFile",
            b"PrintWriter",
        ],
        SinkKind::Redirect => &[b"sendRedirect", b"RedirectView", b"redirect:", b"location("],
        SinkKind::Ssrf => &[
            b"URL(",
            b"URI",
            b"newBuilder",
            b"RestTemplate",
            b"HttpGet",
            b"HttpPost",
            b"HttpPut",
            b"HttpDelete",
            b"Jsoup",
            b"WebClient",
            b"RestClient",
        ],
        SinkKind::XPath => &[b"XPath", b"selectNodes", b"selectSingleNode"],
        SinkKind::Ldap => &[b"DirContext", b"LdapTemplate", b"LdapContext"],
        SinkKind::Format => &[],
        SinkKind::Code => &[
            b"ScriptEngine",
            b"GroovyShell",
            b"parseExpression",
            b"Ognl",
            b"MVEL",
        ],
    };
    words.iter().any(|w| has(w))
}

/// Whether the file can read a request or define a method other files
/// call: it has a class with a method.
fn might_pass_values(src: &[u8]) -> bool {
    let has = |n: &[u8]| src.windows(n.len()).any(|w| w == n);
    has(b"class ") || has(b"interface ") || has(b"record ") || has(b"enum ")
}

/// Calls that, with a value as argument or receiver, read as checking it
/// for this kind of sink: the value is taken as validated.
fn check_words(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Path => &[
            "startsWith",
            "getCanonicalPath",
            "getCanonicalFile",
            "toRealPath",
            "normalize",
            "matches",
            "isAlphanumeric",
            "contains",
            "equals",
        ],
        SinkKind::Redirect | SinkKind::Ssrf => &[
            "startsWith",
            "matches",
            "contains",
            "equals",
            "isValid",
            "validate",
            "endsWith",
        ],
        SinkKind::Sql
        | SinkKind::Command
        | SinkKind::XPath
        | SinkKind::Ldap
        | SinkKind::Code
        | SinkKind::Format => &[
            "matches",
            "isNumeric",
            "isAlphanumeric",
            "isAlpha",
            "isDigits",
            "contains",
            "equals",
            "validate",
        ],
    }
}

// ---------------------------------------------------------------- entry

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    // A file with neither a sink nor a request can still define a method
    // that other files' values reach, or pass one on, which only the
    // project pass can follow; those are the files with methods.
    if !might_have_sinks(src, kind) && !might_pass_values(src) {
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

struct Cx<'a, 't> {
    m: &'a Model<'t>,
    src: &'a [u8],
    kind: SinkKind,
    by_node: HashMap<usize, DeclId>,
    /// Variables that hold a request.
    requests: HashSet<DeclId>,
    /// Parameters a framework fills from the request, with the path that
    /// starts at them.
    initial: HashMap<DeclId, Path<'t>>,
    /// Variables a check reads as validating, for this kind of sink.
    checked: HashSet<DeclId>,
    writes: Vec<Write<'t>>,
    calls: Vec<Node<'t>>,
    returns: Vec<Node<'t>>,
    evaluations: Cell<u64>,
    /// The methods of this file by name, for a call to one of them (T3).
    methods: HashMap<String, Vec<usize>>,
    /// The file's package, for the names other files call its types by.
    package: String,
    /// Whether other files' methods' results count, as paths that start at\n    /// the call: for the file's own run, not a summary's.
    from_calls: Cell<bool>,
    /// Other files' methods' results that reach a sink here.
    return_facts: RefCell<Vec<ReturnFact<'t>>>,
    summaries: Summaries<SummaryKey, Summary<'t>>,
}

/// A method of the file, and the parameter a summary follows (none: the
/// value the method reads itself).
impl<'t> Reaches<'t> for Summary<'t> {
    fn sinks(&self) -> &[(Path<'t>, Node<'t>)] {
        &self.sinks
    }

    fn calls(&self) -> &[(Path<'t>, Callee, usize)] {
        &self.calls
    }
}

type SummaryKey = (usize, Option<usize>);

/// What a request's value does inside a method of the file, for one of
/// its parameters (or none, for a value the method reads itself).
#[derive(Default)]
struct Summary<'t> {
    /// A request's value the method returns, with the path from the
    /// parameter.
    returns: Option<Path<'t>>,
    /// The sinks the value reaches inside the method, or in methods it
    /// calls, each with the path from the parameter and the sink.
    sinks: Vec<(Path<'t>, Node<'t>)>,
    /// The other files' methods the value is passed on to: the path to the
    /// call, the callee, and its argument.
    calls: Vec<(Path<'t>, Callee, usize)>,
}

/// Summaries per file, at most: past it, calls to other methods give
/// nothing.
const MAX_SUMMARIES: usize = 256;

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
            writes: Vec::new(),
            calls: Vec::new(),
            returns: Vec::new(),
            evaluations: Cell::new(0),
            methods: HashMap::new(),
            package: package_of(root, src),
            from_calls: Cell::new(false),
            return_facts: RefCell::default(),
            summaries: Summaries::new(MAX_SUMMARIES),
        };
        for (i, d) in m.decls.iter().enumerate() {
            if d.ty
                .is_some_and(|t| REQUEST_TYPES.contains(&type_name(t, src).as_str()))
            {
                cx.requests.insert(i);
            }
        }
        cx.collect(root)?;
        cx.annotated_parameters();
        cx.index_methods();
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// Walks the file once, in source order, for its writes, calls and
    /// checks. None past a limit.
    fn collect(&mut self, root: Node<'t>) -> Option<()> {
        let mut stack = vec![root];
        let mut checks: Vec<Node<'t>> = Vec::new();
        while let Some(n) = stack.pop() {
            self.visit(n, &mut checks);
            if self.writes.len() > MAX_WRITES {
                return None;
            }
            let mut c = n.walk();
            let children: Vec<Node<'t>> = n.named_children(&mut c).collect();
            stack.extend(children.into_iter().rev());
        }
        // A variable named as a check's receiver or argument is validated.
        for call in checks {
            let mut named: Vec<Node<'t>> = arguments(call);
            named.extend(call.child_by_field_name("object"));
            for n in named {
                if let Some(d) = self.decl_of(unwrap(n)) {
                    self.checked.insert(d);
                }
            }
        }
        Some(())
    }

    /// Records what one node writes, calls or checks.
    fn visit(&mut self, n: Node<'t>, checks: &mut Vec<Node<'t>>) {
        let field = |name: &str| n.child_by_field_name(name);
        match n.kind() {
            "variable_declarator" => {
                if let (Some(name), Some(value)) = (field("name"), field("value"))
                    && value.kind() != "array_initializer"
                {
                    self.write(name, value, How::Assigned);
                }
            }
            "resource" => {
                if let (Some(name), Some(value)) = (field("name"), field("value")) {
                    self.write(name, value, How::Assigned);
                }
            }
            "assignment_expression" => self.assignment(n),
            "enhanced_for_statement" => {
                if let (Some(name), Some(value)) = (field("name"), field("value")) {
                    self.write(name, value, How::Read);
                }
            }
            "instanceof_expression" => {
                if let (Some(name), Some(left)) = (field("name"), field("left")) {
                    self.write(name, left, How::Assigned);
                }
            }
            "method_invocation" => self.invocation(n, checks),
            "object_creation_expression" => self.calls.push(n),
            "return_statement" => self.returns.push(n),
            _ => {}
        }
    }

    /// `x = v`, `x += v`, `this.x = v`.
    fn assignment(&mut self, n: Node<'t>) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        let how = match n.child_by_field_name("operator").map(|o| self.text(o)) {
            Some("=") | None => How::Assigned,
            _ => How::Added,
        };
        let target = if left.kind() == "field_access" {
            left.child_by_field_name("field")
        } else {
            Some(left)
        };
        if let Some(target) = target {
            self.write(target, right, how);
        }
    }

    /// A call: a possible sink, a builder that takes its arguments in, a
    /// check.
    fn invocation(&mut self, n: Node<'t>, checks: &mut Vec<Node<'t>>) {
        self.calls.push(n);
        let name = n.child_by_field_name("name").map_or("", |x| self.text(x));
        if let Some(object) = n.child_by_field_name("object")
            && BUILDER_METHODS.contains(&name)
            && object.kind() == "identifier"
        {
            for arg in arguments(n) {
                self.write(object, arg, How::Added);
            }
        }
        if check_words(self.kind).contains(&name) {
            checks.push(n);
        }
    }

    /// Records `name = value`, when `name` is a variable of this file.
    fn write(&mut self, name: Node<'t>, value: Node<'t>, how: How) {
        if let Some(target) = self.decl_of(name) {
            self.writes.push(Write {
                target,
                target_node: name,
                value,
                how,
            });
        }
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

    /// Parameters a framework fills from the request: tainted from the
    /// start, unless their type is a number, a date or another value
    /// that can't inject.
    fn annotated_parameters(&mut self) {
        let mut found: Vec<(DeclId, Path<'t>)> = Vec::new();
        for f in &self.m.functions {
            let Some(list) = f.node.child_by_field_name("parameters") else {
                continue;
            };
            if list.kind() != "formal_parameters" {
                continue;
            }
            let mut c = list.walk();
            found.extend(
                list.named_children(&mut c)
                    .filter_map(|p| self.parameter_source(p)),
            );
        }
        self.initial.extend(found);
    }

    /// A parameter a framework fills from the request, and the path that
    /// starts at it.
    fn parameter_source(&self, p: Node<'t>) -> Option<(DeclId, Path<'t>)> {
        let annotation = self.source_annotation(p)?;
        let name = match p.kind() {
            "formal_parameter" => p.child_by_field_name("name")?,
            "spread_parameter" => {
                let mut k = p.walk();
                p.named_children(&mut k)
                    .find(|x| x.kind() == "variable_declarator")?
                    .child_by_field_name("name")?
            }
            _ => return None,
        };
        let &decl = self.by_node.get(&name.id())?;
        if let Some(ty) = self.m.decls[decl].ty
            && INERT_TYPES.contains(&type_name(ty, self.src).as_str())
        {
            return None;
        }
        let step = Step {
            node: name,
            message: format!("request parameter `{}` (`@{annotation}`)", self.text(name)),
        };
        Some((decl, vec![step]))
    }

    /// The source annotation on a parameter, by its name.
    fn source_annotation(&self, p: Node<'t>) -> Option<&'a str> {
        let mut c = p.walk();
        let modifiers = p.named_children(&mut c).find(|x| x.kind() == "modifiers")?;
        let mut k = modifiers.walk();
        for a in modifiers.named_children(&mut k) {
            if !matches!(a.kind(), "annotation" | "marker_annotation") {
                continue;
            }
            let name = a.child_by_field_name("name")?;
            let last = self.text(name).rsplit('.').next().unwrap_or("");
            if SOURCE_ANNOTATIONS.contains(&last) {
                return Some(last);
            }
        }
        None
    }

    // ------------------------------------------------------------ the fixed point

    /// The variables that hold a request's value, each with its path, or
    /// None if the file is past a limit.
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
            "identifier" => {
                let d = self.decl_of(n)?;
                if self.checked.contains(&d) {
                    return None;
                }
                state.get(&d).cloned()
            }
            "parenthesized_expression" => self.taint(n.named_child(0)?, state, next),
            "cast_expression" => {
                let ty = n.child_by_field_name("type")?;
                if INERT_TYPES.contains(&last_name(self.text(ty))) {
                    return None;
                }
                self.taint(n.child_by_field_name("value")?, state, next)
            }
            "ternary_expression" => self.either(n, &["consequence", "alternative"], state, next),
            "binary_expression" => {
                if self.text(n.child_by_field_name("operator")?) != "+" {
                    return None;
                }
                self.either(n, &["left", "right"], state, next)
            }
            "assignment_expression" => self.taint(n.child_by_field_name("right")?, state, next),
            "array_access" => self.taint(n.child_by_field_name("array")?, state, next),
            "array_creation_expression" => self.taint(n.child_by_field_name("value")?, state, next),
            "array_initializer" => {
                let mut c = n.walk();
                let elements: Vec<Node<'t>> = n.named_children(&mut c).collect();
                best(elements.into_iter().map(|e| self.taint(e, state, next)))
            }
            "field_access" => self.field_taint(n, state, next),
            "method_invocation" => self.call_taint(n, state, next),
            "object_creation_expression" => self.new_taint(n, state, next),
            _ => None,
        }
    }

    /// `this.x` is the field's, any other `o.x` is `o`'s.
    fn field_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let object = n.child_by_field_name("object")?;
        if object.kind() != "this" {
            return self.taint(object, state, depth);
        }
        let d = self.decl_of(n.child_by_field_name("field")?)?;
        if self.checked.contains(&d) {
            return None;
        }
        state.get(&d).cloned()
    }

    /// `new StringBuilder(x)`: an object that holds its argument's text.
    fn new_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let ty = n.child_by_field_name("type")?;
        if !PROPAGATING_NEW.contains(&last_name(self.text(ty))) {
            return None;
        }
        best(
            arguments(n)
                .into_iter()
                .map(|a| self.taint(a, state, depth)),
        )
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

    /// What a call returns: a request's value for a request's accessor, and
    /// the text of a tainted receiver or argument for the methods that
    /// change text; nothing for a call this module doesn't know.
    fn call_taint(
        &self,
        call: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let name = self.text(call.child_by_field_name("name")?);
        let object = call.child_by_field_name("object");
        if let Some(o) = object
            && let Some(path) = self.request_value(call, o, name)
        {
            return Some(path);
        }
        let args = arguments(call);
        if let Some(path) = self.through_method(call, &args, state, depth) {
            return Some(path);
        }
        let object = object?;
        if BUILDER_METHODS.contains(&name) {
            return best(
                std::iter::once(self.taint(object, state, depth))
                    .chain(args.into_iter().map(|a| self.taint(a, state, depth))),
            );
        }
        // `String.format(..)`, or written out: `java.net.URLDecoder.decode(..)`.
        let class = match object.kind() {
            "identifier" if self.decl_of(object).is_none() => Some(self.text(object)),
            "field_access" => Some(last_name(self.text(object))),
            _ => None,
        };
        if class.is_some_and(|c| PROPAGATING_CLASSES.contains(&c)) {
            return best(args.into_iter().map(|a| self.taint(a, state, depth)));
        }
        let Some(receiver) = self.taint(object, state, depth) else {
            // Another file's method: what it returns is for the project
            // pass to say.
            return (self.from_calls.get() && self.external_callee(call).is_some()).then(|| {
                vec![Step {
                    node: call,
                    message: FROM_CALL.to_string(),
                }]
            });
        };
        let getter = name.starts_with("get") && name != "getClass";
        (PROPAGATING_METHODS.contains(&name) || getter).then_some(receiver)
    }

    // ------------------------------------------------------------ methods of the file (T3)

    /// Indexes the methods of the file by name.
    fn index_methods(&mut self) {
        for (j, f) in self.m.functions.iter().enumerate() {
            if f.node.kind() != "method_declaration" {
                continue;
            }
            if let Some(name) = f.node.child_by_field_name("name") {
                self.methods
                    .entry(self.text(name).to_string())
                    .or_default()
                    .push(j);
            }
        }
    }

    /// The method of this file a call calls, when it's unambiguous: a call
    /// on `this` or on nothing, on `new T(..)`, or on a variable declared
    /// as `T`, with `T` a class of the file.
    fn local_callee(&self, call: Node<'t>) -> Option<usize> {
        let name = self.text(call.child_by_field_name("name")?);
        let arity = arguments(call).len();
        let named: Vec<usize> = self
            .methods
            .get(name)?
            .iter()
            .copied()
            .filter(|&j| self.accepts(j, arity))
            .collect();
        let owner = match call.child_by_field_name("object").map(unwrap) {
            None => None,
            Some(o) if o.kind() == "this" => None,
            Some(o) if o.kind() == "object_creation_expression" => {
                Some(last_name(self.text(o.child_by_field_name("type")?)).to_string())
            }
            Some(o) if o.kind() == "identifier" => {
                let d = self.decl_of(o)?;
                Some(type_name(self.m.decls[d].ty?, self.src))
            }
            Some(_) => return None,
        };
        let candidates: Vec<usize> = match &owner {
            Some(t) => named
                .into_iter()
                .filter(|&j| self.class_of(j).as_deref() == Some(t.as_str()))
                .collect(),
            // Among the classes the call is inside of.
            None => named
                .into_iter()
                .filter(|&j| {
                    self.class_of(j)
                        .is_some_and(|c| self.encloses_class(call, &c))
                })
                .collect(),
        };
        match candidates.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// Whether method `j` takes `arity` arguments.
    fn accepts(&self, j: usize, arity: usize) -> bool {
        let params = &self.m.functions[j].params;
        let variadic = self.m.functions[j]
            .node
            .child_by_field_name("parameters")
            .is_some_and(|l| {
                let mut c = l.walk();
                l.named_children(&mut c)
                    .any(|p| p.kind() == "spread_parameter")
            });
        params.len() == arity || (variadic && arity + 1 >= params.len())
    }

    /// The name of the class method `j` is declared in.
    fn class_of(&self, j: usize) -> Option<String> {
        let mut n = self.m.functions[j].node.parent();
        while let Some(p) = n {
            if matches!(
                p.kind(),
                "class_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "record_declaration"
            ) {
                return Some(self.text(p.child_by_field_name("name")?).to_string());
            }
            if p.kind() == "object_creation_expression" {
                return None;
            }
            n = p.parent();
        }
        None
    }

    /// Whether `node` is inside the class called `class`.
    fn encloses_class(&self, node: Node<'t>, class: &str) -> bool {
        let mut n = node.parent();
        while let Some(p) = n {
            if p.child_by_field_name("name")
                .is_some_and(|c| self.text(c) == class)
                && matches!(
                    p.kind(),
                    "class_declaration" | "enum_declaration" | "record_declaration"
                )
            {
                return true;
            }
            n = p.parent();
        }
        false
    }

    /// What a call to a method of the file returns: a request's value the
    /// method reads itself, or the one of a tainted argument that reaches
    /// its return value.
    fn through_method(
        &self,
        call: Node<'t>,
        args: &[Node<'t>],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let j = self.local_callee(call)?;
        let name = self.text(call.child_by_field_name("name")?);
        through_returns(
            call,
            name,
            self.summary(j, None).returns.clone(),
            args,
            |a| self.taint(a, state, depth),
            |i| self.summary(j, Some(i)).returns.clone(),
        )
    }

    /// The sinks a request's value reaches inside the methods of the file
    /// that the calls with a tainted argument call.
    fn reached_through_methods(&self, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let mut out = Vec::new();
        for &call in &self.calls {
            if call.kind() != "method_invocation" {
                continue;
            }
            out.extend(self.sinks_through(call, state));
        }
        out
    }

    /// The findings at the sinks inside the method `call` calls, for its
    /// tainted arguments.
    fn sinks_through(&self, call: Node<'t>, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let Some(j) = self.local_callee(call) else {
            return Vec::new();
        };
        let name = self.text(call.child_by_field_name("name").unwrap_or(call));
        through_sinks(
            call,
            name,
            arguments(call),
            |a| self.taint(a, state, 0).filter(|p| !from_call(p)),
            |i| self.summary(j, Some(i)).sinks.clone(),
        )
    }

    /// What a request's value does in method `j`, for its parameter `p`
    /// (or for nothing but what the method reads itself).
    fn summary(&self, j: usize, p: Option<usize>) -> Rc<Summary<'t>> {
        self.summaries.get((j, p), || self.summarize(j, p))
    }

    fn summarize(&self, j: usize, p: Option<usize>) -> Option<Summary<'t>> {
        // A summary is what the method does with its parameter, whatever
        // other files' methods return.
        let before = self.from_calls.replace(false);
        let summary = self.summarize_method(j, p);
        self.from_calls.set(before);
        summary
    }

    fn summarize_method(&self, j: usize, p: Option<usize>) -> Option<Summary<'t>> {
        let f = &self.m.functions[j];
        let mut state: HashMap<DeclId, Path<'t>> = HashMap::new();
        if let Some(p) = p {
            for &d in f.params.get(p)? {
                let decl = &self.m.decls[d];
                if decl
                    .ty
                    .is_some_and(|t| INERT_TYPES.contains(&type_name(t, self.src).as_str()))
                {
                    return Some(Summary::default());
                }
                state.insert(
                    d,
                    vec![Step {
                        node: decl.node,
                        message: format!(
                            "`{}`'s parameter `{}`",
                            self.method_name(f.node),
                            decl.name
                        ),
                    }],
                );
            }
        }
        self.propagate(Some(f.node), &mut state)?;
        let mut summary = Summary::default();
        for &r in &self.returns {
            if !inside(r, f.node) {
                continue;
            }
            if let Some(path) = r.named_child(0).and_then(|v| self.taint(v, &state, 0)) {
                summary.returns = Some(path);
                break;
            }
        }
        if p.is_some() {
            self.summary_sinks(f.node, &state, &mut summary);
        }
        Some(summary)
    }

    /// The sinks inside `method` that `state`'s values reach, directly or
    /// through the methods it calls.
    fn summary_sinks(
        &self,
        method: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        summary: &mut Summary<'t>,
    ) {
        for &call in &self.calls {
            if !inside(call, method) {
                continue;
            }
            if let Some((name, args)) = self.sink_call(call)
                && let Some(mut path) = args.into_iter().find_map(|a| self.taint(a, state, 0))
            {
                path.push(Step {
                    node: call,
                    message: format!("passed to `{name}`"),
                });
                summary.sinks.push((path, call));
            }
            if call.kind() == "method_invocation" {
                let nested = self.sinks_through(call, state);
                summary
                    .sinks
                    .extend(nested.into_iter().map(|f| (f.steps, f.sink)));
                for (mut path, callee, arg) in self.passed_on(call, state) {
                    path.push(Step {
                        node: call,
                        message: format!("passed to `{}`", callee.display()),
                    });
                    summary.calls.push((path, callee, arg));
                }
            }
        }
    }

    // ------------------------------------------------------------ other files (T4)

    /// The other file's method a call calls, as this file writes it: the
    /// type of what it's called on, as declared, or the class named
    /// directly. The project pass resolves it, and finds nothing for a
    /// library's.
    fn external_callee(&self, call: Node<'t>) -> Option<Callee> {
        if call.kind() != "method_invocation" || self.local_callee(call).is_some() {
            return None;
        }
        let method = self.text(call.child_by_field_name("name")?);
        let object = unwrap(call.child_by_field_name("object")?);
        let written = match object.kind() {
            "identifier" => match self.decl_of(object) {
                Some(d) => self.text(self.m.decls[d].ty?),
                None => {
                    let t = self.text(object);
                    if !t.starts_with(char::is_uppercase) {
                        return None;
                    }
                    t
                }
            },
            "field_access" if object.child_by_field_name("object")?.kind() == "this" => {
                let d = self.decl_of(object.child_by_field_name("field")?)?;
                self.text(self.m.decls[d].ty?)
            }
            "object_creation_expression" => self.text(object.child_by_field_name("type")?),
            _ => return None,
        };
        let (qualifier, name) = split_type(written);
        if name.is_empty() || LIBRARY_TYPES.contains(&name.as_str()) {
            return None;
        }
        Some(Callee::Java {
            qualifier,
            name,
            within: self.enclosing_types(call),
            method: method.to_string(),
            arity: arguments(call).len(),
        })
    }

    /// The names of the types `node` is inside of, outermost first.
    fn enclosing_types(&self, node: Node<'t>) -> Vec<String> {
        let mut out = Vec::new();
        let mut n = node.parent();
        while let Some(p) = n {
            if matches!(
                p.kind(),
                "class_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "record_declaration"
            ) && let Some(name) = p.child_by_field_name("name")
            {
                out.push(self.text(name).to_string());
            }
            n = p.parent();
        }
        out.reverse();
        out
    }

    /// The request's values this file passes to other files' methods.
    fn passed_to_other_files(&self, state: &HashMap<DeclId, Path<'t>>) -> Vec<CallFact<'t>> {
        call_facts(&self.calls, |call| self.passed_on(call, state))
    }

    /// What the methods of the file do with a value passed to them, for
    /// other files: which parameters reach a sink, or another file's
    /// method.
    fn exported_summaries(&self) -> Vec<SummaryFact<'t>> {
        exported(
            self.m.functions.len(),
            |j| self.method_key(j),
            |j| self.m.functions[j].params.len(),
            |j, p| self.summary(j, Some(p)),
            |j, p, fact| note_return(fact, p, self.summary(j, p).returns.clone()),
        )
    }

    /// Another file's method's result reaching the sink `sink`: the call,
    /// the request's values in its arguments, and the path after it.
    fn record_return(&self, sink: Node<'t>, path: Path<'t>, state: &HashMap<DeclId, Path<'t>>) {
        let call = path[0].node;
        let Some(callee) = self.external_callee(call) else {
            return;
        };
        record_return(
            &self.return_facts,
            call,
            callee,
            arguments(call),
            |a| self.taint(a, state, 0).filter(|p| !from_call(p)),
            path[1..].to_vec(),
            sink,
        );
    }

    /// What other files call method `j` by: its type's full name, and its
    /// name and arity. None for a method of an anonymous class.
    fn method_key(&self, j: usize) -> Option<Key> {
        let f = &self.m.functions[j];
        if f.node.kind() != "method_declaration" || self.class_of(j).is_none() {
            return None;
        }
        let name = self.text(f.node.child_by_field_name("name")?);
        // Overloads of one arity can't be told apart by a call's name and
        // arity: none of them is followed.
        let class = self.class_of(j);
        let same = self.methods.get(name)?.iter().filter(|&&k| {
            self.m.functions[k].params.len() == f.params.len() && self.class_of(k) == class
        });
        if same.count() > 1 {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        if !self.package.is_empty() {
            parts.push(self.package.clone());
        }
        parts.extend(self.enclosing_types(f.node));
        Some(Key {
            export: parts.join("."),
            member: Some(format!("{name}/{}", f.params.len())),
        })
    }

    fn method_name(&self, method: Node<'t>) -> &'a str {
        method
            .child_by_field_name("name")
            .map_or("method", |n| self.text(n))
    }

    /// A request's accessor: `request.getParameter("id")`. Its path starts
    /// here.
    fn request_value(&self, call: Node<'t>, object: Node<'t>, name: &str) -> Option<Path<'t>> {
        if !REQUEST_METHODS.contains(&name) {
            return None;
        }
        let object = unwrap(object);
        let is_request = match object.kind() {
            "identifier" => match self.decl_of(object) {
                Some(d) => self.requests.contains(&d),
                // Declared in a base class or another file.
                None => matches!(self.text(object), "request" | "req"),
            },
            // `((HttpServletRequest) r).getParameter(..)`.
            "cast_expression" => object
                .child_by_field_name("type")
                .is_some_and(|t| REQUEST_TYPES.contains(&last_name(self.text(t)))),
            _ => false,
        };
        is_request.then(|| {
            vec![Step {
                node: call,
                message: format!("request value `{}`", short(self.text(call))),
            }]
        })
    }

    // ------------------------------------------------------------ sinks

    /// Every sink a tainted value reaches, with its path.
    fn reached(&self, state: &HashMap<DeclId, Path<'t>>) -> Vec<Finding<'t>> {
        let mut out = Vec::new();
        for &call in &self.calls {
            let Some((name, args)) = self.sink_call(call) else {
                continue;
            };
            if let Some(mut path) = best(args.into_iter().map(|a| self.taint(a, state, 0))) {
                path.push(Step {
                    node: call,
                    message: format!("passed to `{name}`"),
                });
                if from_call(&path) {
                    self.record_return(call, path, state);
                } else {
                    out.push(Finding {
                        sink: call,
                        steps: cap(path),
                    });
                }
            }
        }
        out.extend(self.reached_through_methods(state));
        if self.kind == SinkKind::Redirect {
            for &r in &self.returns {
                let Some(value) = r.named_child(0) else {
                    continue;
                };
                if self.redirect_prefix(value)
                    && let Some(mut path) = self.taint(value, state, 0).filter(|p| !from_call(p))
                {
                    path.push(Step {
                        node: value,
                        message: "returned as a `redirect:` view".to_string(),
                    });
                    out.push(Finding {
                        sink: value,
                        steps: cap(path),
                    });
                }
            }
        }
        out
    }

    /// A Spring view name that starts `redirect:`.
    fn redirect_prefix(&self, value: Node<'t>) -> bool {
        let mut n = unwrap(value);
        while n.kind() == "binary_expression" {
            let Some(left) = n.child_by_field_name("left") else {
                return false;
            };
            n = unwrap(left);
        }
        n.kind() == "string_literal" && self.text(n).starts_with("\"redirect:")
    }

    /// The sink a call is, for this kind, and the arguments that take the
    /// value.
    fn sink_call(&self, call: Node<'t>) -> Option<(String, Vec<Node<'t>>)> {
        let args = arguments(call);
        if call.kind() == "object_creation_expression" {
            let ty = last_name(self.text(call.child_by_field_name("type")?));
            let news: &[&str] = match self.kind {
                SinkKind::Command => COMMAND_NEW,
                SinkKind::Path => PATH_NEW,
                SinkKind::Redirect => REDIRECT_NEW,
                SinkKind::Ssrf => SSRF_NEW,
                _ => &[],
            };
            if !news.contains(&ty) {
                return None;
            }
            // `new File(parent, child)` and `new ProcessBuilder(a, b)`
            // take their parts alike; a `PrintWriter` over a stream isn't
            // a path.
            return Some((format!("new {ty}"), args));
        }
        let name = self.text(call.child_by_field_name("name")?);
        let table: &[Sink] = match self.kind {
            SinkKind::Sql => SQL_SINKS,
            SinkKind::Command => COMMAND_SINKS,
            SinkKind::Path => PATH_SINKS,
            SinkKind::Redirect => REDIRECT_SINKS,
            SinkKind::Ssrf => SSRF_SINKS,
            SinkKind::XPath => XPATH_SINKS,
            SinkKind::Ldap => LDAP_SINKS,
            SinkKind::Code => CODE_SINKS,
            SinkKind::Format => return None,
        };
        if self.kind == SinkKind::Redirect
            && matches!(name, "setHeader" | "addHeader" | "header")
            && args
                .first()
                .is_some_and(|a| self.text(*a).eq_ignore_ascii_case("\"location\""))
        {
            return Some((name.to_string(), args.into_iter().skip(1).collect()));
        }
        let receiver = self.receiver_key(call.child_by_field_name("object"));
        for (receivers, methods, which) in table {
            if !methods.contains(&name) {
                continue;
            }
            if !receiver
                .as_ref()
                .is_some_and(|r| receivers.contains(&r.as_str()))
            {
                continue;
            }
            let taken = match which {
                Args::First => args.into_iter().take(1).collect(),
                Args::FirstTwo => args.into_iter().take(2).collect(),
                Args::All => args,
            };
            return Some((name.to_string(), taken));
        }
        None
    }

    /// What a call's receiver is, for the sink tables: a class name
    /// (`Files`), the declared type of a variable (`Statement`), or the
    /// method that returned it (`createStatement`).
    fn receiver_key(&self, object: Option<Node<'t>>) -> Option<String> {
        let object = unwrap(object?);
        match object.kind() {
            "identifier" => match self.decl_of(object) {
                Some(d) => {
                    let ty = self.m.decls[d].ty?;
                    Some(type_name(ty, self.src))
                }
                None => Some(self.unresolved_receiver(self.text(object))),
            },
            "method_invocation" => Some(self.text(object.child_by_field_name("name")?).to_string()),
            "field_access" => {
                let field = object.child_by_field_name("field")?;
                match self.decl_of(field) {
                    Some(d) => Some(type_name(self.m.decls[d].ty?, self.src)),
                    None => Some(self.unresolved_receiver(self.text(field))),
                }
            }
            "cast_expression" => {
                Some(last_name(self.text(object.child_by_field_name("type")?)).to_string())
            }
            _ => None,
        }
    }

    /// A name declared somewhere else (a base class, another file): a class
    /// name as written, or a variable named for its type.
    fn unresolved_receiver(&self, name: &str) -> String {
        let lower = name.to_ascii_lowercase();
        let guess = if lower.contains("jdbc") {
            "JdbcTemplate"
        } else if lower.contains("stmt") || lower.contains("statement") {
            "Statement"
        } else if lower.contains("xpath") {
            "XPath"
        } else if lower.contains("entitymanager") || lower == "em" {
            "EntityManager"
        } else if matches!(lower.as_str(), "response" | "resp" | "res") {
            "response"
        } else {
            return name.to_string();
        };
        guess.to_string()
    }
}

flow_for!(Cx, from_call);

// ---------------------------------------------------------------- syntax

/// Types of the JDK and common libraries: a call on one is no call to
/// another file of the project.
const LIBRARY_TYPES: &[&str] = &[
    "String",
    "StringBuilder",
    "StringBuffer",
    "Object",
    "Integer",
    "Long",
    "Double",
    "Boolean",
    "Math",
    "System",
    "Objects",
    "Optional",
    "List",
    "ArrayList",
    "Map",
    "HashMap",
    "Set",
    "HashSet",
    "Collection",
    "Collections",
    "Arrays",
    "Stream",
    "Collectors",
    "Files",
    "Paths",
    "Path",
    "File",
    "URI",
    "URL",
    "UUID",
    "LocalDate",
    "LocalDateTime",
    "Instant",
    "Duration",
    "Logger",
    "LoggerFactory",
    "Thread",
    "Class",
    "Enumeration",
    "Iterator",
    "Matcher",
    "Pattern",
    "HttpServletRequest",
    "HttpServletResponse",
    "ResponseEntity",
    "Model",
    "Cookie",
];

/// The file's package, `com.shop.orders`; empty without one.
fn package_of(root: Node, src: &[u8]) -> String {
    let mut c = root.walk();
    let Some(p) = root
        .named_children(&mut c)
        .find(|n| n.kind() == "package_declaration")
    else {
        return String::new();
    };
    let text = p.utf8_text(src).unwrap_or_default();
    text.trim_start_matches("package")
        .trim()
        .trim_end_matches(';')
        .trim()
        .to_string()
}

/// A type as written, as its qualifier and its name: `java.util.List<T>`
/// is (`java.util`, `List`).
fn split_type(t: &str) -> (String, String) {
    let t = t.split('<').next().unwrap_or(t);
    let t = t.trim_end_matches("[]").trim_end_matches("...").trim();
    match t.rsplit_once('.') {
        Some((q, n)) => (q.to_string(), n.to_string()),
        None => (String::new(), t.to_string()),
    }
}

/// The arguments of a call or a `new`.
fn arguments(call: Node) -> Vec<Node> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|a| !matches!(a.kind(), "line_comment" | "block_comment"))
        .collect()
}

/// An expression without the parentheses around it.
fn unwrap(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => return n,
        }
    }
    n
}

/// A type as written, without its package or its type arguments:
/// `java.util.List<String>` is `List`.
fn type_name(ty: Node, src: &[u8]) -> String {
    last_name(ty.utf8_text(src).unwrap_or_default()).to_string()
}

fn last_name(t: &str) -> &str {
    let t = t.split('<').next().unwrap_or(t);
    let t = t.trim_end_matches("[]").trim_end_matches("...");
    t.rsplit('.').next().unwrap_or(t).trim()
}

/// Text built by concatenation, which the path says: `"a" + b`.
fn is_built(n: Node) -> bool {
    matches!(n.kind(), "binary_expression")
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
        let file = analyze("T.java", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    fn servlet(body: &str) -> String {
        format!(
            "class S extends HttpServlet {{\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {{\n{body}\n  }}\n}}"
        )
    }

    #[test]
    fn a_requests_value_in_a_query_through_variables() {
        let src = servlet(
            "    String id = request.getParameter(\"id\");\n    String q = \"SELECT * FROM t WHERE id = '\" + id + \"'\";\n    stmt.executeQuery(q);",
        );
        assert_eq!(flagged("java/sql-injection", &src), [5]);
    }

    #[test]
    fn a_parameter_a_framework_fills_is_a_source() {
        let src = "@RestController class C {\n  @GetMapping(\"/o\")\n  Object o(@RequestParam String id, @RequestParam int n) {\n    return jdbcTemplate.queryForList(\"SELECT * FROM o WHERE id = \" + id);\n  }\n  @GetMapping(\"/p\")\n  Object p(@RequestParam int n) {\n    return jdbcTemplate.queryForList(\"SELECT * FROM o WHERE id = \" + n);\n  }\n}";
        assert_eq!(flagged("java/sql-injection", src), [4]);
    }

    #[test]
    fn parameters_and_constants_are_no_sink_findings() {
        let src = servlet(
            "    String id = request.getParameter(\"id\");\n    PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM t WHERE id = ?\");\n    ps.setString(1, id);\n    stmt.executeQuery(\"SELECT 1\");\n    int n = Integer.parseInt(id);\n    stmt.executeQuery(\"SELECT * FROM t LIMIT \" + n);",
        );
        assert_eq!(flagged("java/sql-injection", &src), Vec::<usize>::new());
    }

    #[test]
    fn builders_and_string_methods_carry_the_value() {
        let src = servlet(
            "    StringBuilder sb = new StringBuilder(\"SELECT * FROM t WHERE a = \");\n    sb.append(request.getParameter(\"a\").trim());\n    stmt.execute(sb.toString());",
        );
        assert_eq!(flagged("java/sql-injection", &src), [5]);
    }

    #[test]
    fn a_checked_value_is_validated() {
        let src = servlet(
            "    String f = request.getParameter(\"f\");\n    if (!f.matches(\"[a-z]+\")) { return; }\n    new FileInputStream(f);",
        );
        assert_eq!(flagged("java/path-injection", &src), Vec::<usize>::new());
        let unchecked =
            servlet("    String f = request.getParameter(\"f\");\n    new FileInputStream(f);");
        assert_eq!(flagged("java/path-injection", &unchecked), [4]);
    }

    #[test]
    fn each_kind_of_sink() {
        let cases = [
            (
                "java/command-injection",
                "Runtime.getRuntime().exec(\"ping \" + request.getParameter(\"h\"));",
            ),
            (
                "java/open-redirect",
                "response.sendRedirect(request.getParameter(\"u\"));",
            ),
            (
                "java/ssrf",
                "new URL(request.getParameter(\"u\")).openStream();",
            ),
            (
                "java/xpath-injection",
                "xpath.evaluate(\"//u[@n='\" + request.getParameter(\"n\") + \"']\", doc);",
            ),
            (
                "java/ldap-injection",
                "DirContext ctx = null; ctx.search(\"ou=u\", \"(uid=\" + request.getParameter(\"u\") + \")\", null);",
            ),
            (
                "java/code-injection",
                "ScriptEngine e = null; e.eval(request.getParameter(\"c\"));",
            ),
        ];
        for (rule, body) in cases {
            assert_eq!(
                flagged(rule, &servlet(&format!("    {body}"))),
                [3],
                "{rule}"
            );
        }
    }

    #[test]
    fn a_redirect_view_name_built_from_a_value() {
        let src = "@Controller class C {\n  @GetMapping(\"/go\")\n  String go(@RequestParam String to) {\n    return \"redirect:\" + to;\n  }\n}";
        assert_eq!(flagged("java/open-redirect", src), [4]);
    }

    #[test]
    fn a_value_through_a_helper_that_returns_it() {
        let src = "class S extends HttpServlet {\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String p = request.getParameter(\"p\");\n    String bar = new Helper().clean(request, p);\n    stmt.executeQuery(\"SELECT \" + bar);\n  }\n  private static class Helper {\n    String clean(HttpServletRequest request, String param) {\n      String x = param.trim();\n      return x;\n    }\n  }\n}";
        assert_eq!(flagged("java/sql-injection", src), [5]);
    }

    #[test]
    fn a_helper_that_returns_a_constant_clears_the_value() {
        let src = "class S extends HttpServlet {\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String p = request.getParameter(\"p\");\n    String bar = clean(p);\n    stmt.executeQuery(\"SELECT \" + bar);\n  }\n  private String clean(String param) {\n    return \"safe\";\n  }\n}";
        assert_eq!(flagged("java/sql-injection", src), Vec::<usize>::new());
    }

    #[test]
    fn a_sink_inside_a_helper() {
        let src = "class S extends HttpServlet {\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    find(request.getParameter(\"id\"));\n  }\n  private void find(String id) throws Exception {\n    stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id);\n  }\n  private void safe(String id) throws Exception {\n    stmt.executeQuery(\"SELECT 1\");\n  }\n}";
        assert_eq!(flagged("java/sql-injection", src), [6]);
    }

    #[test]
    fn a_sink_two_helpers_down_and_a_helper_that_reads_the_request() {
        let src = "class S extends HttpServlet {\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    outer(request.getParameter(\"id\"));\n    String own = fromRequest(request);\n    runIt(own);\n  }\n  private void outer(String a) throws Exception { inner(a); }\n  private void inner(String b) throws Exception {\n    stmt.executeQuery(\"SELECT \" + b);\n  }\n  private String fromRequest(HttpServletRequest r) { return r.getParameter(\"q\"); }\n  private void runIt(String q) throws Exception {\n    stmt.executeUpdate(\"DELETE \" + q);\n  }\n}";
        assert_eq!(flagged("java/sql-injection", src), [9, 13]);
    }

    #[test]
    fn recursive_helpers_end_and_overloads_of_one_arity_are_skipped() {
        // `other` resolves to the class's own, not the nested class's.
        let src = "class S extends HttpServlet {\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String p = request.getParameter(\"p\");\n    String a = twice(p);\n    String b = other(p);\n    stmt.executeQuery(\"SELECT \" + b);\n  }\n  String twice(String s) { return twice(s); }\n  String other(String s) { return s; }\n  static class A { String other(String s) { return s; } }\n}";
        assert_eq!(flagged("java/sql-injection", src), [6]);
        // Two methods of one name and arity: which one is called isn't known.
        let ambiguous = "class S extends HttpServlet {\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String c = pick(request.getParameter(\"p\"));\n    stmt.executeQuery(\"SELECT \" + c);\n  }\n  String pick(String s) { return s; }\n  String pick(Integer n) { return \"1\"; }\n}";
        assert_eq!(
            flagged("java/sql-injection", ambiguous),
            Vec::<usize>::new()
        );
    }

    // ------------------------------------------------------------ across files (T4)

    /// The taint issues of a project of Java files, `(path, source)`.
    fn project(files: &[(&str, &str)]) -> Vec<crate::model::Issue> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<_> = files
            .iter()
            .map(|(path, src)| {
                analyze(path, Lang::Java, src, &rules, &cfg, far_deadline()).unwrap()
            })
            .collect();
        crate::analysis::taint_project_rules(&mut analyzed, &rules);
        analyzed
            .into_iter()
            .flat_map(|f| f.issues)
            .filter(|i| i.rule.starts_with("java/") && !i.flow.is_empty())
            .collect()
    }

    const CONTROLLER: &str = "package com.shop.web;\nimport com.shop.orders.OrderService;\n@RestController class OrderController {\n  @Autowired private OrderService orders;\n  @GetMapping(\"/o\")\n  Object find(@RequestParam String id) {\n    return orders.find(id);\n  }\n}\n";

    #[test]
    fn a_request_value_into_another_files_method_that_queries() {
        let service = "package com.shop.orders;\n@Service class OrderService {\n  Object find(String id) {\n    return jdbc.queryForList(\"SELECT * FROM o WHERE id = \" + id);\n  }\n}\n";
        let found = project(&[
            ("web/OrderController.java", CONTROLLER),
            ("orders/OrderService.java", service),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule, "java/sql-injection");
        assert_eq!(found[0].path, "orders/OrderService.java");
        let flow: Vec<&str> = found[0].flow.iter().map(|s| s.message.as_str()).collect();
        assert_eq!(
            flow.first().copied(),
            Some("request parameter `id` (`@RequestParam`)")
        );
        assert!(flow.contains(&"passed to `find`"), "{flow:?}");
        assert_eq!(flow.last().copied(), Some("passed to `queryForList`"));
    }

    #[test]
    fn through_an_interface_to_its_implementation_and_on_to_a_third_file() {
        let iface =
            "package com.shop.orders;\ninterface OrderService { Object find(String id); }\n";
        let service = "package com.shop.orders;\nimport com.shop.data.OrderDao;\n@Service class OrderServiceImpl implements OrderService {\n  private OrderDao dao;\n  public Object find(String id) { return dao.byId(id); }\n}\n";
        let dao = "package com.shop.data;\n@Repository class OrderDao {\n  Object byId(String id) {\n    return stmt.executeQuery(\"SELECT * FROM o WHERE id = \" + id);\n  }\n}\n";
        let found = project(&[
            ("web/OrderController.java", CONTROLLER),
            ("orders/OrderService.java", iface),
            ("orders/OrderServiceImpl.java", service),
            ("data/OrderDao.java", dao),
        ]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "data/OrderDao.java");
        let files: Vec<Option<&str>> = found[0].flow.iter().map(|s| s.path.as_deref()).collect();
        assert!(
            files.contains(&Some("orders/OrderServiceImpl.java")),
            "{files:?}"
        );
    }

    #[test]
    fn a_method_that_doesnt_reach_a_sink_or_isnt_the_one_called_gives_nothing() {
        let service = "package com.shop.orders;\n@Service class OrderService {\n  Object find(String id) { return null; }\n  Object find(String id, String other) {\n    return jdbc.queryForList(\"SELECT \" + id);\n  }\n}\n";
        let found = project(&[
            ("web/OrderController.java", CONTROLLER),
            ("orders/OrderService.java", service),
        ]);
        assert!(found.is_empty(), "{found:?}");
        // Overloads of one arity can't be told apart by a call.
        let overloaded = "package com.shop.orders;\n@Service class OrderService {\n  Object find(String id) {\n    return jdbc.queryForList(\"SELECT \" + id);\n  }\n  Object find(Long id) { return null; }\n}\n";
        assert!(
            project(&[
                ("web/OrderController.java", CONTROLLER),
                ("orders/OrderService.java", overloaded),
            ])
            .is_empty()
        );
        // A type the project doesn't declare is a library's.
        let lib = "package com.shop.web;\nimport org.lib.Mailer;\n@RestController class C {\n  private Mailer mailer;\n  void f(@RequestParam String id) { mailer.send(id); }\n}\n";
        assert!(project(&[("web/C.java", lib)]).is_empty());
    }

    #[test]
    fn another_files_method_returning_the_value_to_a_sink_here() {
        let controller = "package com.shop.web;\nimport com.shop.sql.Where;\n@RestController class C {\n  @GetMapping(\"/o\")\n  Object find(@RequestParam String name) throws Exception {\n    String q = Where.eq(name);\n    return stmt.executeQuery(q);\n  }\n}\n";
        let helper = "package com.shop.sql;\nclass Where {\n  static String eq(String n) { return \"SELECT * FROM o WHERE n = '\" + n + \"'\"; }\n}\n";
        let found = project(&[("web/C.java", controller), ("sql/Where.java", helper)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "web/C.java");
        let flow: Vec<&str> = found[0].flow.iter().map(|s| s.message.as_str()).collect();
        assert!(flow.contains(&"returned by `eq`"), "{flow:?}");
        assert_eq!(flow.last().copied(), Some("passed to `executeQuery`"));
        // A method that returns a constant gives nothing.
        let constant = "package com.shop.sql;\nclass Where {\n  static String eq(String n) { return \"SELECT 1\"; }\n}\n";
        assert!(project(&[("web/C.java", controller), ("sql/Where.java", constant)]).is_empty());
    }

    #[test]
    fn another_files_method_that_reads_the_request_itself() {
        let controller = "package com.shop.web;\nimport com.shop.web.Params;\n@RestController class C {\n  Object find(HttpServletRequest request) throws Exception {\n    String id = Params.id(request);\n    return stmt.executeQuery(\"SELECT * FROM o WHERE id = \" + id);\n  }\n}\n";
        let params = "package com.shop.web;\nclass Params {\n  static String id(HttpServletRequest r) { return r.getParameter(\"id\"); }\n}\n";
        let found = project(&[("web/C.java", controller), ("web/Params.java", params)]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "web/C.java");
    }

    #[test]
    fn a_value_that_may_come_from_another_file_doesnt_hide_one_that_does() {
        // The ternary's first branch is another class's method, which might
        // return a request's value; the second surely is one.
        let src = "class S extends HttpServlet {\n  void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String id = request.getParameter(\"id\");\n    String pick = (id == null ? Random.next() : id) + \".jpg\";\n    new File(\"/pics\", pick);\n    String again = Util.read();\n    again = request.getParameter(\"a\");\n    new FileInputStream(again);\n  }\n}";
        assert_eq!(flagged("java/path-injection", src), [5, 8]);
    }
}
