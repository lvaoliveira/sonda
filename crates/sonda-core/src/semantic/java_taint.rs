//! Taint analysis for Java, phases T2 and T3 (ADR-0027): which values that came from
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
//! in the class. Not yet: other files' methods (T4).

use super::taint::{Finding, SinkKind, Step, TaintResult, cap};
use super::{DeclId, Model};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

type Path<'t> = Vec<Step<'t>>;

/// Rounds of the fixed point; past it, the file reports nothing.
const MAX_ROUNDS: usize = 64;
/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;
/// How deep an expression is followed for its taint.
const MAX_DEPTH: u32 = 64;
/// Expressions followed for their taint in one file, at most: past it,
/// what's left is untainted, so a pathological file costs a bounded time.
const MAX_EVALUATIONS: u64 = 5_000_000;

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
        SinkKind::Sql | SinkKind::Command | SinkKind::XPath | SinkKind::Ldap | SinkKind::Code => &[
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
    if !might_have_sinks(src, kind) {
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
    let mut findings = cx.reached(&tainted);
    findings.sort_by_key(|f| (f.sink.start_byte(), f.steps.len()));
    findings.dedup_by_key(|f| f.sink.id());
    TaintResult {
        findings,
        ..TaintResult::default()
    }
}

// ---------------------------------------------------------------- the file

/// A write of a value into a variable.
struct Write<'t> {
    target: DeclId,
    target_node: Node<'t>,
    value: Node<'t>,
    how: How,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum How {
    Assigned,
    /// `q += x`, `sb.append(x)`: the target keeps what it had.
    Added,
    /// `for (String s : xs)`.
    Read,
}

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
    summaries: RefCell<HashMap<SummaryKey, Rc<Summary<'t>>>>,
    /// The summaries being computed: a method that calls itself, or two
    /// that call each other, has nothing more to learn.
    busy: RefCell<HashSet<SummaryKey>>,
}

/// A method of the file, and the parameter a summary follows (none: the
/// value the method reads itself).
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
            by_node: m
                .decls
                .iter()
                .enumerate()
                .map(|(i, d)| (d.node.id(), i))
                .collect(),
            requests: HashSet::new(),
            initial: HashMap::new(),
            checked: HashSet::new(),
            writes: Vec::new(),
            calls: Vec::new(),
            returns: Vec::new(),
            evaluations: Cell::new(0),
            methods: HashMap::new(),
            summaries: RefCell::default(),
            busy: RefCell::default(),
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
        self.propagate(None, &mut tainted)?;
        Some(tainted)
    }

    /// The fixed point over the writes, all of the file's or those inside
    /// `within`; None past a limit.
    fn propagate(
        &self,
        within: Option<Node<'t>>,
        tainted: &mut HashMap<DeclId, Path<'t>>,
    ) -> Option<()> {
        for _ in 0..MAX_ROUNDS {
            let mut changed = false;
            for w in &self.writes {
                if tainted.contains_key(&w.target)
                    || self.checked.contains(&w.target)
                    || within.is_some_and(|f| !inside(w.target_node, f))
                {
                    continue;
                }
                let Some(mut path) = self.taint(w.value, tainted, 0) else {
                    continue;
                };
                let name = self.text(w.target_node);
                path.push(Step {
                    node: w.target_node,
                    message: match w.how {
                        How::Read => format!("read into `{name}`"),
                        How::Added => format!("added to `{name}`"),
                        How::Assigned if is_built(w.value) => {
                            format!("concatenated into `{name}`")
                        }
                        How::Assigned => format!("assigned to `{name}`"),
                    },
                });
                tainted.insert(w.target, path);
                changed = true;
            }
            if self.evaluations.get() > MAX_EVALUATIONS {
                return None;
            }
            if !changed {
                return Some(());
            }
        }
        None
    }

    // ------------------------------------------------------------ expressions

    /// The path a request's value takes to `n`, if `n` holds one.
    fn taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let evaluated = self.evaluations.get() + 1;
        self.evaluations.set(evaluated);
        if depth > MAX_DEPTH || evaluated > MAX_EVALUATIONS {
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
                elements
                    .into_iter()
                    .find_map(|e| self.taint(e, state, next))
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
        arguments(n)
            .into_iter()
            .find_map(|a| self.taint(a, state, depth))
    }

    /// The path of the first of `n`'s `fields` that holds a request's value.
    fn either(
        &self,
        n: Node<'t>,
        fields: &[&str],
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        fields
            .iter()
            .filter_map(|f| n.child_by_field_name(f))
            .find_map(|o| self.taint(o, state, depth))
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
            return self
                .taint(object, state, depth)
                .or_else(|| args.into_iter().find_map(|a| self.taint(a, state, depth)));
        }
        // `String.format(..)`, or written out: `java.net.URLDecoder.decode(..)`.
        let class = match object.kind() {
            "identifier" if self.decl_of(object).is_none() => Some(self.text(object)),
            "field_access" => Some(last_name(self.text(object))),
            _ => None,
        };
        if class.is_some_and(|c| PROPAGATING_CLASSES.contains(&c)) {
            return args.into_iter().find_map(|a| self.taint(a, state, depth));
        }
        let receiver = self.taint(object, state, depth)?;
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
        if let Some(mut path) = self.summary(j, None).returns.clone() {
            path.push(Step {
                node: call,
                message: format!("returned by `{name}`"),
            });
            return Some(path);
        }
        for (i, a) in args.iter().enumerate() {
            let Some(mut path) = self.taint(*a, state, depth) else {
                continue;
            };
            let Some(returned) = self.summary(j, Some(i)).returns.clone() else {
                continue;
            };
            path.push(Step {
                node: call,
                message: format!("passed to `{name}`"),
            });
            path.extend(returned);
            path.push(Step {
                node: call,
                message: format!("returned by `{name}`"),
            });
            return Some(path);
        }
        None
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
        let mut out = Vec::new();
        for (i, a) in arguments(call).into_iter().enumerate() {
            let Some(path) = self.taint(a, state, 0) else {
                continue;
            };
            for (inside, sink) in &self.summary(j, Some(i)).sinks {
                let mut steps = path.clone();
                steps.push(Step {
                    node: call,
                    message: format!("passed to `{name}`"),
                });
                steps.extend(inside.iter().cloned());
                out.push(Finding {
                    sink: *sink,
                    steps: cap(steps),
                });
            }
        }
        out
    }

    /// What a request's value does in method `j`, for its parameter `p`
    /// (or for nothing but what the method reads itself).
    fn summary(&self, j: usize, p: Option<usize>) -> Rc<Summary<'t>> {
        if let Some(s) = self.summaries.borrow().get(&(j, p)) {
            return s.clone();
        }
        if self.summaries.borrow().len() >= MAX_SUMMARIES || !self.busy.borrow_mut().insert((j, p))
        {
            return Rc::default();
        }
        let summary = Rc::new(self.summarize(j, p).unwrap_or_default());
        self.busy.borrow_mut().remove(&(j, p));
        self.summaries.borrow_mut().insert((j, p), summary.clone());
        summary
    }

    fn summarize(&self, j: usize, p: Option<usize>) -> Option<Summary<'t>> {
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
            }
        }
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
            for a in args {
                if let Some(mut path) = self.taint(a, state, 0) {
                    path.push(Step {
                        node: call,
                        message: format!("passed to `{name}`"),
                    });
                    out.push(Finding {
                        sink: call,
                        steps: cap(path),
                    });
                    break;
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
                    && let Some(mut path) = self.taint(value, state, 0)
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

// ---------------------------------------------------------------- syntax

/// Whether `n` is inside `outer`.
fn inside(n: Node, outer: Node) -> bool {
    outer.start_byte() <= n.start_byte() && n.end_byte() <= outer.end_byte()
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

/// A call's text, short enough for a step's message.
fn short(t: &str) -> String {
    let one_line: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= 60 {
        one_line
    } else {
        let cut: String = one_line.chars().take(57).collect();
        format!("{cut}...")
    }
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
}
