//! Taint analysis for C#, phase T1 (ADR-0027): within one function, which
//! values that came from a request reach a sink, and by what path.
//!
//! A forward may-analysis over `cs_cfg`'s graph. Each block maps the
//! variables that may hold a request's value to the path that value took
//! (its source, then each assignment). Writes follow the block's events in
//! evaluation order: a write of an untainted value clears the variable, one
//! that may not happen keeps what it had. Joins are unions, so the result
//! is every path some execution may take.
//!
//! Precision before recall, as the ADR says:
//! - a call the tables below don't know returns an untainted value: flows
//!   through the program's own helpers wait for T3;
//! - a value-typed expression (a number, a `Guid`, an enum) is never
//!   tainted, so `int.Parse(id)` sanitizes by its type;
//! - fields and properties of `this` aren't tracked: only locals and
//!   parameters, and members of a tainted object, as a whole.
//!
//! Bounded like liveness: past a cap on rounds or tracked variables, the
//! function reports nothing.

use super::cs_cfg::{self, Access, Cfg, ENTRY};
use super::cs_infer::{Found, Infer, Ty};
use super::taint::{Finding, SinkKind, Step, cap};
use super::{DeclId, DeclKind, Model};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

/// The most variables tracked in one function, and rounds of the fixed
/// point; past either, the function reports nothing.
const MAX_TRACKED: usize = 512;
const MAX_ROUNDS: usize = 512;
/// How deep an expression is followed for its taint.
const MAX_EXPR_NODES: usize = 4096;

type Path<'t> = Vec<Step<'t>>;
type State<'t> = BTreeMap<DeclId, Path<'t>>;

// ---------------------------------------------------------------- tables

const HTTP_REQUEST: &str = "Microsoft.AspNetCore.Http.HttpRequest";
/// What a request carries from its sender.
const REQUEST_MEMBERS: &[&str] = &[
    "Query",
    "QueryString",
    "Form",
    "Headers",
    "Cookies",
    "Path",
    "PathBase",
    "RouteValues",
];
const CONTROLLER_BASE: &str = "Microsoft.AspNetCore.Mvc.ControllerBase";
const ENDPOINT_ROUTE_BUILDER: &str = "Microsoft.AspNetCore.Routing.IEndpointRouteBuilder";
const MAP_METHODS: &[&str] = &[
    "Map",
    "MapGet",
    "MapPost",
    "MapPut",
    "MapDelete",
    "MapPatch",
    "MapMethods",
    "MapFallback",
];
/// Parameter attributes that bind a value from the request.
const FROM_REQUEST: &[&str] = &[
    "FromQuery",
    "FromRoute",
    "FromBody",
    "FromForm",
    "FromHeader",
];

/// ADO.NET commands whose constructor's first argument is the command's
/// text: (namespace, type). The providers ship as packages, not with the
/// platform, so they're matched by name with their namespace imported.
const SQL_COMMANDS: &[(&str, &str)] = &[
    ("Microsoft.Data.SqlClient", "SqlCommand"),
    ("Microsoft.Data.SqlClient", "SqlDataAdapter"),
    ("System.Data.SqlClient", "SqlCommand"),
    ("System.Data.SqlClient", "SqlDataAdapter"),
    ("Microsoft.Data.Sqlite", "SqliteCommand"),
    ("System.Data.SQLite", "SQLiteCommand"),
    ("System.Data.SQLite", "SQLiteDataAdapter"),
    ("Npgsql", "NpgsqlCommand"),
    ("Npgsql", "NpgsqlDataAdapter"),
    ("MySql.Data.MySqlClient", "MySqlCommand"),
    ("MySql.Data.MySqlClient", "MySqlDataAdapter"),
    ("MySqlConnector", "MySqlCommand"),
    ("MySqlConnector", "MySqlDataAdapter"),
    ("Oracle.ManagedDataAccess.Client", "OracleCommand"),
    ("Oracle.ManagedDataAccess.Client", "OracleDataAdapter"),
    ("System.Data.Odbc", "OdbcCommand"),
    ("System.Data.Odbc", "OdbcDataAdapter"),
    ("System.Data.OleDb", "OleDbCommand"),
    ("System.Data.OleDb", "OleDbDataAdapter"),
];
/// The platform's command types, whose `CommandText` is the query.
const DB_COMMANDS: &[&str] = &["System.Data.IDbCommand", "System.Data.Common.DbCommand"];
/// Entity Framework Core's raw-SQL methods: the query is the first
/// argument after the receiver.
const EF_RAW: &[&str] = &[
    "ExecuteSqlRaw",
    "ExecuteSqlRawAsync",
    "FromSqlRaw",
    "SqlQueryRaw",
    "ExecuteSqlCommand",
    "ExecuteSqlCommandAsync",
];
/// Dapper's extension methods on a connection: the query is the first
/// argument.
const DAPPER: &[&str] = &[
    "Query",
    "QueryAsync",
    "QueryFirst",
    "QueryFirstAsync",
    "QueryFirstOrDefault",
    "QueryFirstOrDefaultAsync",
    "QuerySingle",
    "QuerySingleAsync",
    "QuerySingleOrDefault",
    "QuerySingleOrDefaultAsync",
    "QueryMultiple",
    "QueryMultipleAsync",
    "Execute",
    "ExecuteAsync",
    "ExecuteScalar",
    "ExecuteScalarAsync",
    "ExecuteReader",
    "ExecuteReaderAsync",
];

/// A platform method whose arguments at `args` (as written, not counting
/// an extension method's receiver) mustn't hold a request's value.
struct MethodSink {
    kind: SinkKind,
    declaring: &'static str,
    methods: &'static [&'static str],
    args: &'static [usize],
}

/// A constructor of a platform type, by its arguments.
struct CtorSink {
    kind: SinkKind,
    ty: &'static str,
    args: &'static [usize],
}

/// A property of a platform type, set from a request's value.
struct PropertySink {
    kind: SinkKind,
    declaring: &'static str,
    property: &'static str,
}

const FILE: &str = "System.IO.File";
const DIRECTORY: &str = "System.IO.Directory";
const CONTROLLER_REDIRECTS: &[&str] = &[
    "Redirect",
    "RedirectPermanent",
    "RedirectPreserveMethod",
    "RedirectPermanentPreserveMethod",
];

const METHOD_SINKS: &[MethodSink] = &[
    MethodSink {
        kind: SinkKind::Command,
        declaring: "System.Diagnostics.Process",
        methods: &["Start"],
        args: &[0, 1],
    },
    MethodSink {
        kind: SinkKind::Path,
        declaring: FILE,
        methods: &[
            "ReadAllText",
            "ReadAllTextAsync",
            "ReadAllBytes",
            "ReadAllBytesAsync",
            "ReadAllLines",
            "ReadAllLinesAsync",
            "ReadLines",
            "WriteAllText",
            "WriteAllTextAsync",
            "WriteAllBytes",
            "WriteAllBytesAsync",
            "WriteAllLines",
            "WriteAllLinesAsync",
            "AppendAllText",
            "AppendAllTextAsync",
            "AppendAllLines",
            "Open",
            "OpenRead",
            "OpenWrite",
            "OpenText",
            "Create",
            "CreateText",
            "AppendText",
            "Delete",
        ],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Path,
        declaring: FILE,
        methods: &["Copy", "Move", "Replace"],
        args: &[0, 1],
    },
    MethodSink {
        kind: SinkKind::Path,
        declaring: DIRECTORY,
        methods: &[
            "Delete",
            "CreateDirectory",
            "GetFiles",
            "GetDirectories",
            "EnumerateFiles",
            "EnumerateDirectories",
            "EnumerateFileSystemEntries",
        ],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Path,
        declaring: DIRECTORY,
        methods: &["Move"],
        args: &[0, 1],
    },
    MethodSink {
        kind: SinkKind::Path,
        declaring: CONTROLLER_BASE,
        methods: &["PhysicalFile"],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Redirect,
        declaring: CONTROLLER_BASE,
        methods: CONTROLLER_REDIRECTS,
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Redirect,
        declaring: "Microsoft.AspNetCore.Http.HttpResponse",
        methods: &["Redirect"],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Redirect,
        declaring: "Microsoft.AspNetCore.Http.Results",
        methods: &["Redirect"],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Redirect,
        declaring: "Microsoft.AspNetCore.Http.TypedResults",
        methods: &["Redirect"],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Ssrf,
        declaring: "System.Net.Http.HttpClient",
        methods: &[
            "GetAsync",
            "GetStringAsync",
            "GetByteArrayAsync",
            "GetStreamAsync",
            "PostAsync",
            "PutAsync",
            "PatchAsync",
            "DeleteAsync",
        ],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Ssrf,
        declaring: "System.Net.Http.Json.HttpClientJsonExtensions",
        methods: &[
            "GetFromJsonAsync",
            "PostAsJsonAsync",
            "PutAsJsonAsync",
            "PatchAsJsonAsync",
            "DeleteFromJsonAsync",
        ],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::Ssrf,
        declaring: "System.Net.WebRequest",
        methods: &["Create", "CreateHttp"],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::XPath,
        declaring: "System.Xml.XmlNode",
        methods: &["SelectNodes", "SelectSingleNode"],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::XPath,
        declaring: "System.Xml.XPath.XPathNavigator",
        methods: &[
            "Select",
            "SelectSingleNode",
            "Evaluate",
            "Compile",
            "Matches",
        ],
        args: &[0],
    },
    MethodSink {
        kind: SinkKind::XPath,
        declaring: "System.Xml.XPath.XPathExpression",
        methods: &["Compile"],
        args: &[0],
    },
];

const CTOR_SINKS: &[CtorSink] = &[
    CtorSink {
        kind: SinkKind::Command,
        ty: "System.Diagnostics.ProcessStartInfo",
        args: &[0, 1],
    },
    CtorSink {
        kind: SinkKind::Path,
        ty: "System.IO.FileStream",
        args: &[0],
    },
    CtorSink {
        kind: SinkKind::Path,
        ty: "System.IO.StreamReader",
        args: &[0],
    },
    CtorSink {
        kind: SinkKind::Path,
        ty: "System.IO.StreamWriter",
        args: &[0],
    },
    CtorSink {
        kind: SinkKind::Path,
        ty: "System.IO.FileInfo",
        args: &[0],
    },
    CtorSink {
        kind: SinkKind::Path,
        ty: "System.IO.DirectoryInfo",
        args: &[0],
    },
    CtorSink {
        kind: SinkKind::Redirect,
        ty: "Microsoft.AspNetCore.Mvc.RedirectResult",
        args: &[0],
    },
    CtorSink {
        kind: SinkKind::Ssrf,
        ty: "System.Net.Http.HttpRequestMessage",
        args: &[1],
    },
];

const PROPERTY_SINKS: &[PropertySink] = &[
    PropertySink {
        kind: SinkKind::Command,
        declaring: "System.Diagnostics.ProcessStartInfo",
        property: "FileName",
    },
    PropertySink {
        kind: SinkKind::Command,
        declaring: "System.Diagnostics.ProcessStartInfo",
        property: "Arguments",
    },
    PropertySink {
        kind: SinkKind::Ssrf,
        declaring: "System.Net.Http.HttpRequestMessage",
        property: "RequestUri",
    },
    PropertySink {
        kind: SinkKind::Ssrf,
        declaring: "System.Net.Http.HttpClient",
        property: "BaseAddress",
    },
];

/// LDAP's searcher is a Windows package, outside the platform's
/// declarations: matched by name with its namespace imported, as the SQL
/// providers are.
const LDAP_NAMESPACE: &str = "System.DirectoryServices";
const LDAP_SEARCHER: &str = "DirectorySearcher";

const STRING: &str = "System.String";
const STRING_BUILDER: &str = "System.Text.StringBuilder";
/// Types whose methods return what their receiver and arguments hold.
const PROPAGATING_TYPES: &[&str] = &[
    STRING,
    STRING_BUILDER,
    "System.IO.Path",
    "System.Uri",
    "Microsoft.Extensions.Primitives.StringValues",
    "System.Convert",
];
/// Methods that hand back what a collection holds, on any type.
const PROPAGATING_METHODS: &[&str] = &[
    "ToString",
    "First",
    "FirstOrDefault",
    "Last",
    "LastOrDefault",
    "Single",
    "SingleOrDefault",
    "ElementAt",
    "ElementAtOrDefault",
    "ToArray",
    "ToList",
    "GetValueOrDefault",
];
/// Methods that put their argument into their receiver.
const INTO_RECEIVER: &[&str] = &[
    "Append",
    "AppendLine",
    "AppendFormat",
    "AppendJoin",
    "Insert",
    "Add",
    "AddRange",
    "Push",
    "Enqueue",
];

// ---------------------------------------------------------------- analysis

/// Every function's findings for `kind`, in source order.
pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> Vec<Finding<'t>> {
    // Every source is a controller's (by name, attribute or base class), a
    // `Request`'s member, or a `Map…` handler's parameter: a file that
    // mentions none of them has no request's value to follow. Most don't.
    if !might_have_sources(src) {
        return Vec::new();
    }
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let by_node = cs_cfg::decls_by_node(m);
    let file = FileCx {
        m,
        infer: &infer,
        src,
        by_node: &by_node,
        functions: m.functions.iter().map(|f| f.node).collect(),
        kind,
        cfgs: RefCell::new(HashMap::new()),
        summaries: RefCell::new(HashMap::new()),
        busy: RefCell::new(HashSet::new()),
        callees: RefCell::new(HashMap::new()),
        sinks: RefCell::new(HashMap::new()),
        reaches: RefCell::new(HashMap::new()),
        checks: RefCell::new(HashMap::new()),
    };
    let mut found = Vec::new();
    for i in 0..m.functions.len() {
        if !file.analyzable(i) {
            continue;
        }
        let sinks = file.sinks(i);
        let calls = file.calls_with_sinks(i);
        if sinks.is_empty() && calls.is_empty() {
            continue;
        }
        let Some(cfg) = file.cfg(i) else {
            continue;
        };
        let a = file.analysis(i);
        let sources = source_params(m, &infer, i, src);
        if let Some(inn) = a.run(&cfg, sources) {
            found.extend(a.findings(&cfg, &inn, &sinks, &calls));
        }
    }
    // A sink a helper has, reached from several callers: its shortest path.
    found.sort_by_key(|f| (f.sink.start_byte(), f.steps.len()));
    found.dedup_by_key(|f| f.sink.id());
    found
}

/// One file's functions, as T3 sees them (ADR-0027): each function's graph
/// and summary, computed once, for every call to it.
struct FileCx<'a, 't> {
    m: &'a Model<'t>,
    infer: &'a Infer<'a, 't>,
    src: &'a [u8],
    by_node: &'a HashMap<usize, DeclId>,
    functions: Vec<Node<'t>>,
    kind: SinkKind,
    cfgs: RefCell<HashMap<usize, Option<Rc<Cfg<'t>>>>>,
    summaries: RefCell<HashMap<usize, Rc<Summary<'t>>>>,
    /// Functions whose summary is being computed: a call back to one of
    /// them, through recursion, counts as one without a summary.
    busy: RefCell<HashSet<usize>>,
    /// Each call's function in this file, by the call's node id.
    callees: RefCell<HashMap<usize, Option<usize>>>,
    /// Each function's own sinks.
    sinks: RefCell<HashMap<usize, Rc<Vec<Sink<'t>>>>>,
    /// Whether a function has a sink, itself or through its calls: only those
    /// get a summary of their sinks.
    reaches: RefCell<HashMap<usize, bool>>,
    /// The parameters each function checks (`checked_values`), by position:
    /// a call to it checks the matching arguments.
    checks: RefCell<HashMap<usize, Option<Rc<Vec<usize>>>>>,
}

/// What a function does with its parameters, for its callers (T3).
#[derive(Default)]
struct Summary<'t> {
    /// Parameters (by position) whose value reaches the return value, with
    /// the path from the parameter.
    returns: Vec<(usize, Path<'t>)>,
    /// A request's value the function itself reads and returns, such as
    /// `string Id() => Request.Query["id"]`.
    returns_source: Option<Path<'t>>,
    /// Parameters that reach a sink inside it: (position, the sink, the path
    /// from the parameter to the sink).
    sinks: Vec<(usize, Node<'t>, Path<'t>)>,
}

/// A call to a function of the same file, and that function.
#[derive(Clone, Copy)]
struct LocalCall<'t> {
    call: Node<'t>,
    callee: usize,
}

impl<'a, 't> FileCx<'a, 't> {
    /// A function with a body, parsed cleanly, without preprocessor branches.
    fn analyzable(&self, i: usize) -> bool {
        let node = self.functions[i];
        if node.child_by_field_name("body").is_none() || node.has_error() {
            return false;
        }
        let text = node.utf8_text(self.src).unwrap_or_default();
        !["#if", "#else", "#elif", "#endif"]
            .iter()
            .any(|d| text.contains(d))
    }

    fn cfg(&self, i: usize) -> Option<Rc<Cfg<'t>>> {
        self.cfgs
            .borrow_mut()
            .entry(i)
            .or_insert_with(|| {
                cs_cfg::build(self.m, self.functions[i], self.src, self.by_node).map(Rc::new)
            })
            .clone()
    }

    fn analysis(&'a self, i: usize) -> Analysis<'a, 't> {
        let node = self.functions[i];
        let mut a = Analysis {
            m: self.m,
            infer: self.infer,
            src: self.src,
            by_node: self.by_node,
            kind: self.kind,
            checked: HashSet::new(),
            controller: ancestor(node, "class_declaration")
                .is_some_and(|c| is_controller(self.infer, c, self.src)),
            file: self,
        };
        a.checked = a.checked_values(node, &self.functions);
        a
    }

    /// The function of this file a call resolves to, once per call.
    fn callee(&self, call: Node<'t>) -> Option<usize> {
        if let Some(j) = self.callees.borrow().get(&call.id()) {
            return *j;
        }
        let j = self.resolve_callee(call);
        self.callees.borrow_mut().insert(call.id(), j);
        j
    }

    fn sinks(&self, i: usize) -> Rc<Vec<Sink<'t>>> {
        if let Some(s) = self.sinks.borrow().get(&i) {
            return s.clone();
        }
        let s = Rc::new(sinks_in(
            self.m,
            self.infer,
            self.functions[i],
            &self.functions,
            self.kind,
            self.src,
        ));
        self.sinks.borrow_mut().insert(i, s.clone());
        s
    }

    /// The calls in function `i`'s own body to functions of this file.
    fn local_calls(&self, i: usize) -> Vec<LocalCall<'t>> {
        let function = self.functions[i];
        let mut out = Vec::new();
        let mut stack: Vec<Node<'t>> = function.child_by_field_name("body").into_iter().collect();
        while let Some(n) = stack.pop() {
            if n.id() != function.id() && self.functions.iter().any(|f| f.id() == n.id()) {
                continue;
            }
            if n.kind() == "invocation_expression"
                && let Some(j) = self.callee(n)
                && j != i
            {
                out.push(LocalCall { call: n, callee: j });
            }
            stack.extend(children(n));
        }
        out
    }

    /// Whether function `j` has a sink, itself or through the functions of
    /// this file it calls. Cheap, unlike a summary: no analysis runs.
    fn reaches_sink(&self, j: usize) -> bool {
        if let Some(r) = self.reaches.borrow().get(&j) {
            return *r;
        }
        // Assumed false while it's computed, which ends recursion.
        self.reaches.borrow_mut().insert(j, false);
        let r = !self.sinks(j).is_empty()
            || self
                .local_calls(j)
                .iter()
                .any(|c| self.reaches_sink(c.callee));
        self.reaches.borrow_mut().insert(j, r);
        r
    }

    /// The parameters function `j` checks before using them, by position.
    fn checks(&'a self, j: usize) -> Rc<Vec<usize>> {
        if let Some(c) = self.checks.borrow().get(&j) {
            return c.clone().unwrap_or_default();
        }
        self.checks.borrow_mut().insert(j, None);
        let checked = self.analysis(j).checked;
        let c: Vec<usize> = self.m.functions[j]
            .params
            .iter()
            .enumerate()
            .filter(|(_, decls)| {
                decls
                    .iter()
                    .any(|d| checked.contains(&self.m.decls[*d].name))
            })
            .map(|(p, _)| p)
            .collect();
        let c = Rc::new(c);
        self.checks.borrow_mut().insert(j, Some(c.clone()));
        c
    }

    /// The function of this file a call resolves to: a method or a local
    /// function, by type inference, else by a name only one function has.
    fn resolve_callee(&self, call: Node<'t>) -> Option<usize> {
        let owner_of = |decl_node: Node| {
            let owner = decl_node.parent()?;
            self.functions.iter().position(|f| f.id() == owner.id())
        };
        if let Some(c) = self.infer.call(call) {
            let local: Vec<usize> = c
                .methods
                .iter()
                .filter_map(|m| match m {
                    Found::Local(d) => owner_of(d.node),
                    _ => None,
                })
                .collect();
            if let [only] = local.as_slice() {
                return Some(*only);
            }
            if !c.methods.is_empty() {
                return None;
            }
        }
        let function = call.child_by_field_name("function")?;
        // Another object's method may share the name: only `X(...)`,
        // `this.X(...)`, or `Class.X(...)` with the class that declares X.
        let (name_node, through) = match function.kind() {
            "member_access_expression" => {
                let receiver = function.child_by_field_name("expression")?;
                let through = match receiver.kind() {
                    "this_expression" => None,
                    "identifier" => Some(self.text(receiver)),
                    _ => return None,
                };
                (function.child_by_field_name("name")?, through)
            }
            _ => (function, None),
        };
        let name = self.text(bare_name(name_node));
        let arity = arguments(call).len();
        let class_name = |f: &Node<'t>| {
            ancestor(*f, "class_declaration")
                .and_then(|c| c.child_by_field_name("name"))
                .map(|n| self.text(n))
        };
        let mut named = self.functions.iter().enumerate().filter(|(_, f)| {
            matches!(f.kind(), "method_declaration" | "local_function_statement")
                && f.child_by_field_name("name")
                    .is_some_and(|n| self.text(n) == name)
                && f.child_by_field_name("parameters").map_or(0, |p| {
                    children(p)
                        .into_iter()
                        .filter(|c| c.kind() == "parameter")
                        .count()
                }) == arity
                && through.is_none_or(|t| class_name(f) == Some(t))
        });
        let (j, _) = named.next()?;
        named.next().is_none().then_some(j)
    }

    fn text(&self, n: Node) -> &'a str {
        self.infer.text_of(n)
    }

    /// The calls in function `i`'s own body to functions of this file whose
    /// parameters reach a sink.
    fn calls_with_sinks(&self, i: usize) -> Vec<LocalCall<'t>> {
        self.local_calls(i)
            .into_iter()
            .filter(|c| self.reaches_sink(c.callee) && !self.summary(c.callee).sinks.is_empty())
            .collect()
    }

    /// Function `j`'s summary, computed once.
    fn summary(&self, j: usize) -> Rc<Summary<'t>> {
        if let Some(s) = self.summaries.borrow().get(&j) {
            return s.clone();
        }
        if !self.busy.borrow_mut().insert(j) {
            return Rc::new(Summary::default());
        }
        let s = Rc::new(self.compute_summary(j));
        self.busy.borrow_mut().remove(&j);
        self.summaries.borrow_mut().insert(j, s.clone());
        s
    }

    fn compute_summary(&self, j: usize) -> Summary<'t> {
        let mut summary = Summary::default();
        if !self.analyzable(j) {
            return summary;
        }
        let Some(cfg) = self.cfg(j) else {
            return summary;
        };
        let function = self.functions[j];
        let name = function
            .child_by_field_name("name")
            .map_or("the function", |n| self.text(n));
        let a = self.analysis(j);
        let sinks = self.sinks(j);
        let calls: Vec<LocalCall<'t>> = self
            .calls_with_sinks(j)
            .into_iter()
            .filter(|c| c.callee != j)
            .collect();
        let returns = return_values(function, &self.functions);
        // What the function returns of a request's value it reads itself.
        if let Some(inn) = a.run(&cfg, source_params(self.m, self.infer, j, self.src)) {
            summary.returns_source = returns.iter().find_map(|r| {
                let st = a.state_at(&cfg, &inn, *r);
                a.taint(*r, &st)
            });
        }
        // Each parameter, tainted alone: what reaches the return, and sinks.
        for (p, decls) in self.m.functions[j].params.iter().enumerate() {
            for d in decls {
                let decl = &self.m.decls[*d];
                if decl
                    .ty
                    .and_then(|t| self.infer.written(t))
                    .is_some_and(|t| is_safe_type(self.infer, &t))
                {
                    continue;
                }
                let marker = Step {
                    node: decl.node,
                    message: format!("`{name}`'s parameter `{}`", decl.name),
                };
                let mut entry = State::new();
                entry.insert(*d, vec![marker]);
                let Some(inn) = a.run(&cfg, entry) else {
                    continue;
                };
                let from_param =
                    |path: &Path<'t>| path.first().is_some_and(|s| s.node.id() == decl.node.id());
                for r in &returns {
                    let st = a.state_at(&cfg, &inn, *r);
                    if let Some(path) = a.taint(*r, &st).filter(from_param) {
                        summary.returns.push((p, cap(path)));
                        break;
                    }
                }
                for f in a.findings(&cfg, &inn, sinks.as_slice(), &calls) {
                    if from_param(&f.steps) {
                        summary.sinks.push((p, f.sink, f.steps));
                    }
                }
            }
        }
        summary
    }
}

/// The values a function returns: `return x;` in its own body, or its
/// expression body.
fn return_values<'t>(function: Node<'t>, functions: &[Node<'t>]) -> Vec<Node<'t>> {
    let Some(body) = function.child_by_field_name("body") else {
        return Vec::new();
    };
    match body.kind() {
        "block" => {}
        "arrow_expression_clause" => return body.named_child(0).into_iter().collect(),
        _ => return vec![body],
    }
    let mut out = Vec::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if n.id() != function.id() && functions.iter().any(|f| f.id() == n.id()) {
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

/// The argument a call passes to its callee's parameter `p`: by name, or by
/// position; an extension method's receiver is its first.
fn argument_for<'t>(
    file: &FileCx<'_, 't>,
    call: Node<'t>,
    callee: usize,
    p: usize,
) -> Option<Node<'t>> {
    let params: Vec<Node> = file.functions[callee]
        .child_by_field_name("parameters")
        .map(children)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.kind() == "parameter")
        .collect();
    let param = params.get(p)?;
    let name = param.child_by_field_name("name").map(|n| file.text(n));
    let extension = params
        .first()
        .is_some_and(|first| file.text(*first).starts_with("this "));
    let receiver = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")
        .and_then(|f| f.child_by_field_name("expression"));
    if extension && p == 0 {
        return receiver;
    }
    let list: Vec<Node> = call
        .child_by_field_name("arguments")
        .map(children)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.kind() == "argument")
        .collect();
    let value = |a: Node<'t>| a.named_child(a.named_child_count().saturating_sub(1) as u32);
    if let Some(name) = name
        && let Some(a) = list.iter().find(|a| {
            a.child_by_field_name("name")
                .is_some_and(|n| file.text(n) == name)
        })
    {
        return value(*a);
    }
    let position = if extension { p - 1 } else { p };
    list.get(position)
        .filter(|a| a.child_by_field_name("name").is_none())
        .and_then(|a| value(*a))
}

/// Whether a file can have a source at all: a controller (by name,
/// attribute or base class), a request (`HttpRequest`, `HttpContext`, a
/// controller's `Request.Query`), or a `Map…` handler. Checked on the bytes
/// first, since most files have none: a DTO named `…Request` doesn't count.
fn might_have_sources(src: &[u8]) -> bool {
    const NEEDLES: &[&[u8]] = &[b"Controller", b"HttpRequest", b"HttpContext", b".Map"];
    let has = |needle: &[u8]| src.windows(needle.len()).any(|w| w == needle);
    NEEDLES.iter().any(|n| has(n))
        || REQUEST_MEMBERS
            .iter()
            .any(|m| has(format!("Request.{m}").as_bytes()))
}

/// The parameters of a function that a request fills: a controller
/// action's, or a minimal API handler's.
fn source_params<'t>(m: &Model<'t>, infer: &Infer<'_, 't>, i: usize, src: &[u8]) -> State<'t> {
    let function = &m.functions[i];
    let node = function.node;
    let action = node.kind() == "method_declaration" && is_action(infer, node, src);
    let handler = node.kind() == "lambda_expression" && is_handler(infer, node);
    let mut state = State::new();
    if !action && !handler {
        return state;
    }
    for d in function.params.iter().flatten() {
        let decl = &m.decls[*d];
        if decl.kind != DeclKind::Param {
            continue;
        }
        let Some(param) = decl.node.parent().filter(|p| p.kind() == "parameter") else {
            continue;
        };
        let attributes = attribute_names(param, src);
        if attributes.iter().any(|a| a == "FromServices") {
            continue;
        }
        let declared = decl.ty.and_then(|t| infer.written(t));
        let bound = attributes
            .iter()
            .any(|a| FROM_REQUEST.contains(&a.as_str()));
        let fills = if action {
            // Model binding fills any parameter of an action but services;
            // a number can't carry an injection.
            !declared.as_ref().is_some_and(|t| is_safe_type(infer, t))
        } else {
            // A handler's other parameters are mostly services: only
            // strings, or what an attribute binds from the request.
            bound || declared.as_ref().is_some_and(is_stringish)
        };
        if fills {
            state.insert(
                *d,
                vec![Step {
                    node: decl.node,
                    message: format!("request parameter `{}`", decl.name),
                }],
            );
        }
    }
    state
}

/// A public instance method of a controller, not marked `[NonAction]`.
fn is_action(infer: &Infer, method: Node, src: &[u8]) -> bool {
    let modifiers: Vec<&str> = children(method)
        .into_iter()
        .filter(|c| c.kind() == "modifier")
        .filter_map(|c| c.utf8_text(src).ok())
        .collect();
    if !modifiers.contains(&"public") || modifiers.contains(&"static") {
        return false;
    }
    if attribute_names(method, src)
        .iter()
        .any(|a| a == "NonAction")
    {
        return false;
    }
    let Some(class) = ancestor(method, "class_declaration") else {
        return false;
    };
    is_controller(infer, class, src)
}

/// A controller as ASP.NET Core finds one: a public class named
/// `…Controller`, or marked `[Controller]` or `[ApiController]`, or deriving
/// from `ControllerBase`, and not marked `[NonController]`. The name matters
/// because projects derive their controllers from a base of their own, in
/// another file, which this one can't see.
fn is_controller(infer: &Infer, class: Node, src: &[u8]) -> bool {
    let public = children(class)
        .into_iter()
        .any(|c| c.kind() == "modifier" && c.utf8_text(src) == Ok("public"));
    let attributes = attribute_names(class, src);
    if !public || attributes.iter().any(|a| a == "NonController") {
        return false;
    }
    let named = class
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(src).ok())
        .is_some_and(|n| n.ends_with("Controller"));
    named
        || attributes
            .iter()
            .any(|a| a == "Controller" || a == "ApiController")
        || infer
            .enclosing_type(class.child_by_field_name("body").unwrap_or(class))
            .is_some_and(|t| infer.supertypes(&t).iter().any(|s| s.is(CONTROLLER_BASE)))
}

/// A lambda passed to `app.MapGet(...)` and the like on a route builder.
fn is_handler(infer: &Infer, lambda: Node) -> bool {
    let Some(invocation) = lambda
        .parent()
        .filter(|p| p.kind() == "argument")
        .and_then(|a| a.parent())
        .filter(|l| l.kind() == "argument_list")
        .and_then(|l| l.parent())
        .filter(|i| i.kind() == "invocation_expression")
    else {
        return false;
    };
    let Some(function) = invocation
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")
    else {
        return false;
    };
    let named = function
        .child_by_field_name("name")
        .is_some_and(|n| MAP_METHODS.contains(&infer.text_of(bare_name(n))));
    named
        && function
            .child_by_field_name("expression")
            .and_then(|r| infer.type_of(r))
            .is_some_and(|t| {
                t.is(ENDPOINT_ROUTE_BUILDER)
                    || infer
                        .supertypes(&t)
                        .iter()
                        .any(|s| s.is(ENDPOINT_ROUTE_BUILDER))
            })
}

fn is_stringish(t: &Ty) -> bool {
    t.is(STRING)
        || t.is("Microsoft.Extensions.Primitives.StringValues")
        || matches!(t, Ty::Array(e) if e.is(STRING))
}

/// Types no injection can travel in: numbers, `bool`, `Guid`, dates and
/// times, enums, and nullable ones. Not `char`, which can be a quote, nor
/// other value types, such as `StringValues`, which hold strings.
const SAFE_TYPES: &[&str] = &[
    "System.Boolean",
    "System.Byte",
    "System.SByte",
    "System.Int16",
    "System.UInt16",
    "System.Int32",
    "System.UInt32",
    "System.Int64",
    "System.UInt64",
    "System.Int128",
    "System.UInt128",
    "System.IntPtr",
    "System.UIntPtr",
    "System.Single",
    "System.Double",
    "System.Decimal",
    "System.Half",
    "System.Guid",
    "System.DateTime",
    "System.DateTimeOffset",
    "System.DateOnly",
    "System.TimeOnly",
    "System.TimeSpan",
    "System.Threading.CancellationToken",
];

fn is_safe_type(infer: &Infer, t: &Ty) -> bool {
    if t.is("System.Nullable`1") {
        return t.args().first().is_some_and(|a| is_safe_type(infer, a));
    }
    SAFE_TYPES.iter().any(|k| t.is(k)) || infer.kind(t) == Some("enum")
}

/// The simple names of a declaration's attributes, without `Attribute`.
fn attribute_names(node: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for list in children(node)
        .into_iter()
        .filter(|c| c.kind() == "attribute_list")
    {
        for attribute in children(list)
            .into_iter()
            .filter(|c| c.kind() == "attribute")
        {
            if let Some(name) = attribute.child_by_field_name("name") {
                let text = name.utf8_text(src).unwrap_or_default();
                let simple = text.rsplit('.').next().unwrap_or(text);
                out.push(simple.trim_end_matches("Attribute").to_string());
            }
        }
    }
    out
}

/// `Request` or `Response` as a controller's own property, which type
/// inference doesn't resolve through the platform base class: unqualified,
/// or as `HttpContext.Request`, and not a local or parameter of that name.
fn controller_property(
    m: &Model,
    infer: &Infer,
    receiver: Node,
    name: &str,
    controller: bool,
) -> bool {
    if !controller {
        return false;
    }
    match receiver.kind() {
        "identifier" => infer.text_of(receiver) == name && m.decl_of(receiver).is_none(),
        "member_access_expression" => {
            receiver
                .child_by_field_name("name")
                .is_some_and(|n| infer.text_of(n) == name)
                && receiver
                    .child_by_field_name("expression")
                    .is_some_and(|e| e.kind() == "identifier" && infer.text_of(e) == "HttpContext")
        }
        _ => false,
    }
}

/// A member's name without type arguments: `Query` in `c.Query<int>`.
fn bare_name(n: Node) -> Node {
    if n.kind() == "generic_name" {
        n.named_child(0).unwrap_or(n)
    } else {
        n
    }
}

fn children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// A sink, and the expression whose value it takes.
#[derive(Clone)]
struct Sink<'t> {
    node: Node<'t>,
    /// The values it takes from the code: the first tainted one is reported.
    values: Vec<Node<'t>>,
    /// "passed to `SqlCommand`".
    what: &'static str,
    name: String,
}

/// The sinks of `kind` in a function's own body, not in nested functions.
fn sinks_in<'t>(
    m: &Model<'t>,
    infer: &Infer<'_, 't>,
    function: Node<'t>,
    functions: &[Node<'t>],
    kind: SinkKind,
    src: &[u8],
) -> Vec<Sink<'t>> {
    // A controller's own `Redirect(url)`, when its base, in another file,
    // keeps the call from resolving.
    let controller =
        ancestor(function, "class_declaration").is_some_and(|c| is_controller(infer, c, src));
    let mut out = Vec::new();
    let mut stack: Vec<Node<'t>> = function.child_by_field_name("body").into_iter().collect();
    while let Some(n) = stack.pop() {
        if functions.iter().any(|f| f.id() == n.id()) && n.id() != function.id() {
            continue;
        }
        let sink = match kind {
            SinkKind::Sql => sql_sink(m, infer, n),
            SinkKind::Ldap => ldap_sink(m, infer, n),
            _ => table_sink(m, infer, n, kind, controller),
        };
        out.extend(sink);
        stack.extend(children(n).into_iter().rev());
    }
    out
}

/// A sink from the platform tables: a method, a constructor or a property.
fn table_sink<'t>(
    m: &Model<'t>,
    infer: &Infer<'_, 't>,
    n: Node<'t>,
    kind: SinkKind,
    controller: bool,
) -> Option<Sink<'t>> {
    let pick = |args: &[usize], all: &[Node<'t>]| -> Vec<Node<'t>> {
        args.iter().filter_map(|i| all.get(*i).copied()).collect()
    };
    match n.kind() {
        "invocation_expression" => {
            let function = n.child_by_field_name("function")?;
            let name_node = match function.kind() {
                "member_access_expression" => function.child_by_field_name("name")?,
                _ => function,
            };
            let name = infer.text_of(bare_name(name_node));
            let all = arguments(n);
            let resolved = infer.call(n).and_then(|call| {
                METHOD_SINKS.iter().find(|s| {
                    s.kind == kind
                        && s.methods.contains(&name)
                        && call.methods.iter().any(|m| {
                            matches!(m, Found::Platform { declaring, .. } if declaring.name == s.declaring)
                        })
                })
            });
            // `Response.Redirect(url)` on a controller's own response.
            let response = || {
                (name == "Redirect"
                    && function.kind() == "member_access_expression"
                    && function
                        .child_by_field_name("expression")
                        .is_some_and(|r| controller_property(m, infer, r, "Response", controller)))
                .then(|| {
                    METHOD_SINKS.iter().find(|s| {
                        s.kind == kind && s.declaring == "Microsoft.AspNetCore.Http.HttpResponse"
                    })
                })
                .flatten()
            };
            // `Redirect(url)` in a controller whose base doesn't resolve.
            let inherited = || {
                (controller && matches!(function.kind(), "identifier" | "generic_name"))
                    .then(|| {
                        METHOD_SINKS.iter().find(|s| {
                            s.kind == kind
                                && s.declaring == CONTROLLER_BASE
                                && s.methods.contains(&name)
                        })
                    })
                    .flatten()
            };
            let spec = resolved.or_else(response).or_else(inherited)?;
            let values = pick(spec.args, &all);
            (!values.is_empty()).then(|| Sink {
                node: n,
                values,
                what: "passed to",
                name: name.to_string(),
            })
        }
        "object_creation_expression" => {
            let ty = infer.written(n.child_by_field_name("type")?)?;
            let spec = CTOR_SINKS.iter().find(|s| s.kind == kind && ty.is(s.ty))?;
            let values = pick(spec.args, &arguments(n));
            let name = spec.ty.rsplit('.').next().unwrap_or(spec.ty);
            (!values.is_empty()).then(|| Sink {
                node: n,
                values,
                what: "passed to",
                name: name.to_string(),
            })
        }
        "assignment_expression" => {
            let left = n
                .child_by_field_name("left")
                .filter(|l| l.kind() == "member_access_expression")?;
            (infer.text_of(n.child_by_field_name("operator")?) == "=").then_some(())?;
            let property = infer.text_of(left.child_by_field_name("name")?);
            let receiver = infer.type_of(left.child_by_field_name("expression")?)?;
            let spec = PROPERTY_SINKS.iter().find(|s| {
                s.kind == kind
                    && s.property == property
                    && (receiver.is(s.declaring)
                        || infer
                            .supertypes(&receiver)
                            .iter()
                            .any(|t| t.is(s.declaring)))
            })?;
            Some(Sink {
                node: n,
                values: vec![n.child_by_field_name("right")?],
                what: "assigned to",
                name: spec.property.to_string(),
            })
        }
        _ => None,
    }
}

/// `new DirectorySearcher(filter)` and `searcher.Filter = filter`.
fn ldap_sink<'t>(m: &Model<'t>, infer: &Infer<'_, 't>, n: Node<'t>) -> Option<Sink<'t>> {
    let imported = |at: usize| infer.in_scope(LDAP_NAMESPACE, at) && !infer.declares(LDAP_SEARCHER);
    let names_searcher = |t: Node| {
        let text = infer.text_of(t);
        text == format!("{LDAP_NAMESPACE}.{LDAP_SEARCHER}")
            || (text == LDAP_SEARCHER && imported(n.start_byte()))
    };
    match n.kind() {
        "object_creation_expression" => {
            names_searcher(n.child_by_field_name("type")?).then_some(())?;
            Some(Sink {
                node: n,
                values: vec![first_argument(n)?],
                what: "passed to",
                name: LDAP_SEARCHER.to_string(),
            })
        }
        "assignment_expression" => {
            let left = n
                .child_by_field_name("left")
                .filter(|l| l.kind() == "member_access_expression")?;
            (infer.text_of(left.child_by_field_name("name")?) == "Filter").then_some(())?;
            let receiver = left.child_by_field_name("expression")?;
            let decl = (receiver.kind() == "identifier")
                .then(|| m.decl_of(receiver))
                .flatten()?;
            let declared = decl.ty.is_some_and(names_searcher);
            let created = decl
                .declarator
                .and_then(|d| d.named_child(d.named_child_count().saturating_sub(1) as u32))
                .filter(|v| v.kind() == "object_creation_expression")
                .and_then(|v| v.child_by_field_name("type"))
                .is_some_and(names_searcher);
            (declared || created).then_some(())?;
            Some(Sink {
                node: n,
                values: vec![n.child_by_field_name("right")?],
                what: "assigned to",
                name: "Filter".to_string(),
            })
        }
        _ => None,
    }
}

fn sql_sink<'t>(m: &Model<'t>, infer: &Infer<'_, 't>, n: Node<'t>) -> Option<Sink<'t>> {
    let text = |x: Node<'t>| infer.text_of(x);
    match n.kind() {
        "object_creation_expression" => {
            let ty = n.child_by_field_name("type")?;
            let name = text(ty).rsplit('.').next().unwrap_or_default();
            let named = |ns: &str| {
                let full = text(ty);
                full == format!("{ns}.{name}")
                    || (full == name && infer.in_scope(ns, n.start_byte()) && !infer.declares(name))
            };
            SQL_COMMANDS
                .iter()
                .any(|(ns, t)| *t == name && named(ns))
                .then_some(())?;
            Some(Sink {
                node: n,
                values: vec![first_argument(n)?],
                what: "passed to",
                name: name.to_string(),
            })
        }
        "invocation_expression" => {
            let function = n
                .child_by_field_name("function")
                .filter(|f| f.kind() == "member_access_expression")?;
            let name = text(bare_name(function.child_by_field_name("name")?));
            let byte = n.start_byte();
            let raw =
                EF_RAW.contains(&name) && infer.in_scope("Microsoft.EntityFrameworkCore", byte);
            let dapper = DAPPER.contains(&name) && infer.in_scope("Dapper", byte);
            (raw || dapper).then_some(())?;
            Some(Sink {
                node: n,
                values: vec![first_argument(n)?],
                what: "passed to",
                name: name.to_string(),
            })
        }
        "assignment_expression" => {
            let left = n.child_by_field_name("left")?;
            (left.kind() == "member_access_expression").then_some(())?;
            (text(left.child_by_field_name("name")?) == "CommandText").then_some(())?;
            (text(n.child_by_field_name("operator")?) == "=").then_some(())?;
            let receiver = left.child_by_field_name("expression")?;
            is_command(m, infer, receiver).then_some(())?;
            Some(Sink {
                node: n,
                values: vec![n.child_by_field_name("right")?],
                what: "assigned to",
                name: "CommandText".to_string(),
            })
        }
        _ => None,
    }
}

/// Whether an expression is a database command: a platform command type,
/// or a variable declared as, or set to a new, provider command.
fn is_command(m: &Model, infer: &Infer, receiver: Node) -> bool {
    if let Some(t) = infer.type_of(receiver)
        && (DB_COMMANDS.iter().any(|k| t.is(k))
            || infer
                .supertypes(&t)
                .iter()
                .any(|s| DB_COMMANDS.iter().any(|k| s.is(k))))
    {
        return true;
    }
    let provider = |name: &str, at: usize| {
        SQL_COMMANDS
            .iter()
            .any(|(ns, t)| *t == name && infer.in_scope(ns, at) && !infer.declares(name))
    };
    let Some(decl) = (receiver.kind() == "identifier")
        .then(|| m.decl_of(receiver))
        .flatten()
    else {
        return false;
    };
    let written = decl
        .ty
        .is_some_and(|t| provider(infer.text_of(t), receiver.start_byte()));
    let initializer = decl
        .declarator
        .and_then(|d| d.named_child(d.named_child_count().saturating_sub(1) as u32));
    let created = initializer
        .filter(|v| v.kind() == "object_creation_expression")
        .and_then(|v| v.child_by_field_name("type"))
        .is_some_and(|t| provider(infer.text_of(t), receiver.start_byte()));
    // `connection.CreateCommand()`, ADO.NET's factory, on a connection whose
    // type the platform doesn't declare (EF Core's `GetDbConnection()`).
    let factory = initializer
        .filter(|v| v.kind() == "invocation_expression")
        .and_then(|v| v.child_by_field_name("function"))
        .filter(|f| f.kind() == "member_access_expression")
        .and_then(|f| f.child_by_field_name("name"))
        .is_some_and(|n| infer.text_of(n) == "CreateCommand");
    written || created || factory
}

fn first_argument(call: Node) -> Option<Node> {
    let list = call.child_by_field_name("arguments")?;
    let arg = children(list)
        .into_iter()
        .find(|a| a.kind() == "argument")?;
    // `name: value`, `out x`: the value is the last named child.
    arg.named_child(arg.named_child_count().saturating_sub(1) as u32)
}

struct Analysis<'a, 't> {
    m: &'a Model<'t>,
    infer: &'a Infer<'a, 't>,
    src: &'a [u8],
    by_node: &'a HashMap<usize, DeclId>,
    kind: SinkKind,
    /// What the function checks before using it (`checked_values`).
    checked: HashSet<String>,
    /// The function is a controller's: its `Request` is the request.
    controller: bool,
    file: &'a FileCx<'a, 't>,
}

impl<'t> Analysis<'_, 't> {
    fn text(&self, n: Node) -> &str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// The state at each block's entry, from the state at the function's
    /// entry; None past the bounds.
    fn run(&self, cfg: &Cfg<'t>, entry: State<'t>) -> Option<Vec<State<'t>>> {
        let n = cfg.blocks.len();
        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, b) in cfg.blocks.iter().enumerate() {
            for s in &b.succ {
                preds[*s].push(i);
            }
        }
        let mut inn: Vec<State<'t>> = vec![State::new(); n];
        let mut out: Vec<State<'t>> = vec![State::new(); n];
        inn[ENTRY] = entry;
        for _ in 0..(n + 2).min(MAX_ROUNDS) {
            let mut changed = false;
            for i in 0..n {
                let mut state = if i == ENTRY {
                    inn[ENTRY].clone()
                } else {
                    let mut s = State::new();
                    for p in &preds[i] {
                        for (d, path) in &out[*p] {
                            s.entry(*d).or_insert_with(|| path.clone());
                        }
                    }
                    s
                };
                inn[i] = state.clone();
                self.transfer(cfg, i, &mut state, None);
                if state.len() > MAX_TRACKED {
                    return None;
                }
                if !same_keys(&state, &out[i]) {
                    changed = true;
                }
                out[i] = state;
            }
            if !changed {
                return Some(inn);
            }
        }
        None
    }

    /// The state just before `node`.
    fn state_at(&self, cfg: &Cfg<'t>, inn: &[State<'t>], node: Node<'t>) -> State<'t> {
        let Some(block) = innermost_block(cfg, node) else {
            return State::new();
        };
        let mut state = inn[block].clone();
        self.transfer(cfg, block, &mut state, Some(node.start_byte()));
        state
    }

    /// What reaches the function's sinks, and its calls' (T3).
    fn findings(
        &self,
        cfg: &Cfg<'t>,
        inn: &[State<'t>],
        sinks: &[Sink<'t>],
        calls: &[LocalCall<'t>],
    ) -> Vec<Finding<'t>> {
        let mut found = Vec::new();
        for sink in sinks {
            let state = self.state_at(cfg, inn, sink.node);
            if let Some(mut steps) = sink.values.iter().find_map(|v| self.taint(*v, &state)) {
                steps.push(Step {
                    node: sink.node,
                    message: format!("{} `{}`", sink.what, sink.name),
                });
                found.push(Finding {
                    sink: sink.node,
                    steps: cap(steps),
                });
            }
        }
        for c in calls {
            let summary = self.file.summary(c.callee);
            let state = self.state_at(cfg, inn, c.call);
            let name = self.file.functions[c.callee]
                .child_by_field_name("name")
                .map_or("", |n| self.text(n));
            for (p, sink, path) in &summary.sinks {
                let Some(arg) = argument_for(self.file, c.call, c.callee, *p) else {
                    continue;
                };
                if let Some(mut steps) = self.taint(arg, &state) {
                    steps.push(Step {
                        node: c.call,
                        message: format!("passed to `{name}`"),
                    });
                    steps.extend(path.iter().cloned());
                    found.push(Finding {
                        sink: *sink,
                        steps: cap(steps),
                    });
                }
            }
        }
        found
    }

    /// Applies block `i`'s writes, in order, up to byte `until` when given.
    fn transfer(&self, cfg: &Cfg<'t>, i: usize, state: &mut State<'t>, until: Option<usize>) {
        let block = &cfg.blocks[i];
        for e in &block.events {
            if until.is_some_and(|u| e.node.end_byte() > u) {
                break;
            }
            if e.access == Access::Read {
                continue;
            }
            let value = self.written_value(e.node, e.decl, state);
            match (e.access, value) {
                (_, Some(path)) => {
                    state.insert(e.decl, path);
                }
                (Access::Write, None) => {
                    state.remove(&e.decl);
                }
                _ => {}
            }
        }
        // `sb.Append(id)`, `list.Add(id)`: the receiver holds the value now.
        if let Some(syntax) = block.syntax {
            for call in self.calls_into_receiver(syntax) {
                if until.is_some_and(|u| call.end_byte() > u) {
                    continue;
                }
                let Some((decl, receiver)) = self.receiver_decl(call) else {
                    continue;
                };
                if state.contains_key(&decl) {
                    continue;
                }
                let tainted = call
                    .child_by_field_name("arguments")
                    .map(children)
                    .into_iter()
                    .flatten()
                    .filter(|a| a.kind() == "argument")
                    .find_map(|a| self.taint(a, state));
                if let Some(mut path) = tainted {
                    path.push(Step {
                        node: call,
                        message: format!("added to `{}`", self.text(receiver)),
                    });
                    state.insert(decl, path);
                }
            }
        }
    }

    /// The path of the value a write event stores, if it's tainted.
    fn written_value(&self, node: Node<'t>, decl: DeclId, state: &State<'t>) -> Option<Path<'t>> {
        let name = &self.m.decls[decl].name;
        let (value, old) = match node.kind() {
            "assignment_expression" => {
                let op = node
                    .child_by_field_name("operator")
                    .map_or("=", |o| self.text(o));
                (node.child_by_field_name("right"), op != "=")
            }
            "variable_declarator" => (
                (node.named_child_count() > 1)
                    .then(|| node.named_child(node.named_child_count() as u32 - 1))
                    .flatten(),
                false,
            ),
            // `out var v` / `out v` of a call whose receiver is tainted:
            // `Request.Query.TryGetValue("id", out var v)`.
            "argument" | "declaration_expression" => {
                let call = ancestor(node, "invocation_expression")?;
                let receiver = call
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "member_access_expression")
                    .and_then(|f| f.child_by_field_name("expression"))?;
                let mut path = self.taint(receiver, state)?;
                path.push(Step {
                    node,
                    message: format!("read into `{name}`"),
                });
                return Some(path);
            }
            // The loop variable of `foreach (var x in xs)`.
            "identifier" => match node.parent() {
                Some(p) if p.kind() == "foreach_statement" => {
                    (p.child_by_field_name("right"), false)
                }
                _ => (None, false),
            },
            _ => (None, false),
        };
        let carried = value.and_then(|v| self.taint(v, state));
        let kept = if old { state.get(&decl).cloned() } else { None };
        let mut path = carried.or(kept)?;
        let concatenated = value.is_some_and(|v| {
            matches!(
                v.kind(),
                "binary_expression" | "interpolated_string_expression"
            ) || (v.kind() == "invocation_expression" && self.text(v).contains("Format"))
        });
        path.push(Step {
            node,
            message: format!(
                "{} `{name}`",
                if concatenated || old {
                    "concatenated into"
                } else {
                    "assigned to"
                }
            ),
        });
        Some(path)
    }

    /// The path of the first tainted value an expression carries, in
    /// source order, or None.
    fn taint(&self, expr: Node<'t>, state: &State<'t>) -> Option<Path<'t>> {
        let mut stack = vec![expr];
        let mut visited = 0;
        while let Some(n) = stack.pop() {
            visited += 1;
            if visited > MAX_EXPR_NODES {
                return None;
            }
            if self.untainted_by_type(n) {
                continue;
            }
            match n.kind() {
                "identifier" | "member_access_expression"
                    if self.checked.contains(self.text(n)) => {}
                "identifier" => {
                    if let Some(path) = self.decl(n).and_then(|d| state.get(&d)) {
                        return Some(path.clone());
                    }
                }
                "member_access_expression" => {
                    if let Some(path) = self.request_member(n) {
                        return Some(path);
                    }
                    stack.extend(n.child_by_field_name("expression"));
                }
                "element_access_expression" | "conditional_access_expression" => {
                    stack.extend(
                        n.child_by_field_name("expression")
                            .or_else(|| n.named_child(0)),
                    );
                }
                "invocation_expression" => {
                    if let Some(j) = self.file.callee(n) {
                        // A function of this file: what its summary says.
                        if let Some(path) = self.through_local_call(n, j, state) {
                            return Some(path);
                        }
                    } else if !self.sanitizes(n) {
                        stack.extend(self.propagated(n).into_iter().rev());
                    }
                }
                "object_creation_expression" => {
                    let ty = n.child_by_field_name("type").map(|t| self.text(t));
                    if matches!(
                        ty,
                        Some(
                            "StringBuilder"
                                | "System.Text.StringBuilder"
                                | "string"
                                | "Uri"
                                | "System.Uri"
                        )
                    ) {
                        stack.extend(arguments(n).into_iter().rev());
                    }
                }
                "binary_expression" | "interpolated_string_expression" if self.fixes_origin(n) => {}
                "binary_expression" => {
                    let op = n.child_by_field_name("operator").map(|o| self.text(o));
                    if matches!(op, Some("+" | "??")) {
                        stack.extend(n.child_by_field_name("right"));
                        stack.extend(n.child_by_field_name("left"));
                    }
                }
                "conditional_expression" => {
                    stack.extend(n.child_by_field_name("alternative"));
                    stack.extend(n.child_by_field_name("consequence"));
                }
                "assignment_expression" => stack.extend(n.child_by_field_name("right")),
                "interpolated_string_expression" => {
                    for part in children(n).into_iter().rev() {
                        if part.kind() == "interpolation" {
                            // `{`, the value, `,alignment`, `:format`, `}`.
                            stack.extend(children(part).into_iter().find(|c| {
                                !matches!(
                                    c.kind(),
                                    "interpolation_brace"
                                        | "interpolation_alignment_clause"
                                        | "interpolation_format_clause"
                                )
                            }));
                        }
                    }
                }
                "parenthesized_expression"
                | "cast_expression"
                | "postfix_unary_expression"
                | "await_expression"
                | "checked_expression"
                | "argument" => {
                    if let Some(v) = n
                        .child_by_field_name("value")
                        .or_else(|| n.named_child(n.named_child_count().saturating_sub(1) as u32))
                    {
                        stack.push(v);
                    }
                }
                "as_expression" => stack.extend(n.child_by_field_name("left")),
                _ => {}
            }
        }
        None
    }

    /// For a request (SSRF) or a redirect: a URL built after text that
    /// already fixes where it goes, `"https://api.example.com/" + x`, or a
    /// path on this site, `"/orders/" + id`, which a client resolves against
    /// its base address. What follows can't change the host. The leftmost
    /// part may be a variable or constant set to such text.
    fn fixes_origin(&self, n: Node) -> bool {
        matches!(self.kind, SinkKind::Ssrf | SinkKind::Redirect) && self.fixed_prefix(n, 4)
    }

    fn fixed_prefix(&self, n: Node, depth: u8) -> bool {
        // The leftmost part of a concatenation or interpolation.
        let mut first = n;
        loop {
            match first.kind() {
                "binary_expression" => match first.child_by_field_name("left") {
                    Some(l) => first = l,
                    None => return false,
                },
                "parenthesized_expression" => match first.named_child(0) {
                    Some(inner) => first = inner,
                    None => return false,
                },
                _ => break,
            }
        }
        let prefix: String = match first.kind() {
            "string_literal" | "verbatim_string_literal" => {
                let t = self.text(first);
                t.trim_start_matches('@').trim_matches('"').to_string()
            }
            "interpolated_string_expression" => children(first)
                .into_iter()
                .take_while(|c| c.kind() != "interpolation")
                .filter(|c| c.kind() == "string_content")
                .map(|c| self.text(c))
                .collect(),
            // `KoboImageHost + suffix`, `newPath + query`: what the name
            // was set to where it's declared.
            "identifier" if depth > 0 => {
                return self
                    .m
                    .decl_of(first)
                    .and_then(|d| d.declarator)
                    .filter(|d| d.named_child_count() > 1)
                    .and_then(|d| d.named_child(d.named_child_count() as u32 - 1))
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
        absolute || local
    }

    /// A call that makes its argument safe for this analysis's sink:
    /// `Path.GetFileName` keeps a file name, without directories.
    fn sanitizes(&self, call: Node) -> bool {
        self.kind == SinkKind::Path
            && self.infer.call(call).is_some_and(|c| {
                c.methods.iter().any(|m| {
                    matches!(m, Found::Platform { declaring, member, .. }
                        if declaring.name == "System.IO.Path" && member.name == "GetFileName")
                })
            })
    }

    /// What a function checks before using it for this analysis's sink,
    /// by its text (`returnUrl`, `model.ReturnUrl`): what the check is for.
    /// - redirects: `Url.IsLocalUrl(x)`, and IdentityServer's
    ///   `IsValidReturnUrl(x)` and `GetAuthorizationContextAsync(x)`, which
    ///   is null for a URL no client registered;
    /// - paths: `x.StartsWith(root)`, and a helper named like a path check,
    ///   `IsPathWithinDirectory(dir, x)`.
    ///
    /// A check anywhere in the function counts, not only one guarding the
    /// sink: precision before recall.
    fn checked_values(&self, function: Node<'t>, functions: &[Node<'t>]) -> HashSet<String> {
        let mut out = HashSet::new();
        let mut stack: Vec<Node<'t>> = vec![function];
        while let Some(n) = stack.pop() {
            if n.id() != function.id() && functions.iter().any(|f| f.id() == n.id()) {
                continue;
            }
            if n.kind() == "invocation_expression"
                && let Some(f) = n.child_by_field_name("function")
            {
                let name = self.text(bare_name(f.child_by_field_name("name").unwrap_or(f)));
                let validates = match self.kind {
                    SinkKind::Redirect => matches!(
                        name,
                        "IsLocalUrl" | "IsValidReturnUrl" | "GetAuthorizationContextAsync"
                    ),
                    SinkKind::Path => {
                        name.starts_with("Is")
                            && ["Path", "Within", "Inside", "Safe"]
                                .iter()
                                .any(|w| name.contains(w))
                    }
                    _ => false,
                };
                if validates {
                    out.extend(arguments(n).into_iter().map(|a| self.text(a).to_string()));
                }
                if self.kind == SinkKind::Path && name == "StartsWith" {
                    out.extend(
                        f.child_by_field_name("expression")
                            .map(|r| self.text(r).to_string()),
                    );
                }
                // A function of this file that checks what it's given, such
                // as a validation helper that calls `IsPathWithinDirectory`.
                if let Some(j) = self.file.callee(n)
                    && self.file.functions[j].id() != function.id()
                {
                    for p in self.file.checks(j).iter() {
                        out.extend(
                            argument_for(self.file, n, j, *p).map(|a| self.text(a).to_string()),
                        );
                    }
                }
            }
            stack.extend(children(n));
        }
        out
    }

    /// The value a call to function `j` of this file returns, when its
    /// summary says a tainted argument, or a request it reads, reaches it.
    fn through_local_call(&self, call: Node<'t>, j: usize, state: &State<'t>) -> Option<Path<'t>> {
        let summary = self.file.summary(j);
        let name = self.file.functions[j]
            .child_by_field_name("name")
            .map_or("", |n| self.text(n));
        let returned = |mut path: Path<'t>| {
            path.push(Step {
                node: call,
                message: format!("returned by `{name}`"),
            });
            cap(path)
        };
        for (p, inside) in &summary.returns {
            let Some(arg) = argument_for(self.file, call, j, *p) else {
                continue;
            };
            if let Some(mut path) = self.taint(arg, state) {
                path.extend(inside.iter().cloned());
                return Some(returned(path));
            }
        }
        summary.returns_source.clone().map(returned)
    }

    /// A number, a `Guid`, an enum: nothing a request can inject through.
    fn untainted_by_type(&self, n: Node) -> bool {
        matches!(
            n.kind(),
            "invocation_expression"
                | "member_access_expression"
                | "element_access_expression"
                | "identifier"
        ) && self
            .infer
            .type_of(n)
            .is_some_and(|t| is_safe_type(self.infer, &t))
    }

    /// `Request.Query`, `HttpContext.Request.Form`: a source.
    fn request_member(&self, n: Node<'t>) -> Option<Path<'t>> {
        let name = self.text(n.child_by_field_name("name")?);
        if !REQUEST_MEMBERS.contains(&name) {
            return None;
        }
        let receiver = n.child_by_field_name("expression")?;
        let request = self
            .infer
            .type_of(receiver)
            .is_some_and(|t| t.is(HTTP_REQUEST))
            || controller_property(self.m, self.infer, receiver, "Request", self.controller);
        request.then(|| {
            vec![Step {
                node: n,
                message: format!("the request's `{name}`"),
            }]
        })
    }

    /// What a call's result carries: its receiver and arguments, for the
    /// propagators in the tables; nothing for any other call.
    fn propagated(&self, call: Node<'t>) -> Vec<Node<'t>> {
        let function = call.child_by_field_name("function");
        let name = function
            .and_then(|f| f.child_by_field_name("name"))
            .map(|n| self.text(bare_name(n)))
            .unwrap_or_default();
        let receiver = function
            .filter(|f| f.kind() == "member_access_expression")
            .and_then(|f| f.child_by_field_name("expression"));
        let args = arguments(call);
        let resolved = self.infer.call(call);
        let on_type = |key: &str| {
            resolved.as_ref().is_some_and(|c| {
                c.methods.iter().any(
                    |m| matches!(m, Found::Platform { declaring, .. } if declaring.name == key),
                )
            })
        };
        let mut from = Vec::new();
        if PROPAGATING_TYPES.iter().any(|k| on_type(k)) {
            from.extend(receiver);
            from.extend(args);
        } else if PROPAGATING_METHODS.contains(&name) {
            // On a collection or any object: what it holds. An extension
            // method's receiver is the call's receiver too.
            from.extend(receiver);
        }
        from
    }

    /// Calls in a statement that put an argument into their receiver.
    fn calls_into_receiver(&self, syntax: Node<'t>) -> Vec<Node<'t>> {
        let mut out = Vec::new();
        let mut stack = vec![syntax];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "lambda_expression"
                | "anonymous_method_expression"
                | "local_function_statement" => continue,
                // A nested statement is a block of its own.
                k if k.ends_with("_statement") && n.id() != syntax.id() => continue,
                "block" if n.id() != syntax.id() => continue,
                "invocation_expression" => {
                    let name = n
                        .child_by_field_name("function")
                        .filter(|f| f.kind() == "member_access_expression")
                        .and_then(|f| f.child_by_field_name("name"))
                        .map(|x| self.text(bare_name(x)));
                    if name.is_some_and(|x| INTO_RECEIVER.contains(&x)) {
                        out.push(n);
                    }
                }
                _ => {}
            }
            stack.extend(children(n).into_iter().rev());
        }
        out
    }

    /// The local a call's receiver names: `sb` in `sb.Append(x)`.
    fn receiver_decl(&self, call: Node<'t>) -> Option<(DeclId, Node<'t>)> {
        let receiver = call
            .child_by_field_name("function")?
            .child_by_field_name("expression")?;
        (receiver.kind() == "identifier").then_some(())?;
        Some((self.decl(receiver)?, receiver))
    }

    /// The local or parameter an identifier refers to.
    fn decl(&self, n: Node) -> Option<DeclId> {
        let d = self.m.decl_of(n)?;
        let id = *self.by_node.get(&d.node.id())?;
        matches!(
            d.kind,
            DeclKind::Let | DeclKind::Param | DeclKind::CatchParam
        )
        .then_some(id)
    }
}

/// A call's argument values, in order.
fn arguments(call: Node) -> Vec<Node> {
    call.child_by_field_name("arguments")
        .map(children)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| a.kind() == "argument")
        .filter_map(|a| a.named_child(a.named_child_count().saturating_sub(1) as u32))
        .collect()
}

fn ancestor<'t>(n: Node<'t>, kind: &str) -> Option<Node<'t>> {
    let mut cur = n.parent();
    while let Some(p) = cur {
        if p.kind() == kind {
            return Some(p);
        }
        cur = p.parent();
    }
    None
}

/// The block whose syntax most closely contains `node`.
fn innermost_block(cfg: &Cfg, node: Node) -> Option<usize> {
    cfg.blocks
        .iter()
        .enumerate()
        .filter_map(|(i, b)| b.syntax.map(|s| (i, s)))
        .filter(|(_, s)| s.start_byte() <= node.start_byte() && node.end_byte() <= s.end_byte())
        .min_by_key(|(_, s)| s.end_byte() - s.start_byte())
        .map(|(i, _)| i)
}

fn same_keys(a: &State, b: &State) -> bool {
    a.len() == b.len() && a.keys().eq(b.keys())
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::model::Issue;
    use crate::rules::RuleSet;

    const RULE: &str = "cs/sql-injection";
    const USINGS: &str = "using Microsoft.AspNetCore.Mvc;\nusing Microsoft.AspNetCore.Http;\n\
                          using Microsoft.Data.SqlClient;\nusing System.Data.Common;\nusing System.Text;\n";

    fn issues(src: &str) -> Vec<Issue> {
        issues_of(RULE, src)
    }

    fn issues_of(rule: &str, src: &str) -> Vec<Issue> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t.cs", Lang::CSharp, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues.into_iter().filter(|i| i.rule == rule).collect()
    }

    /// Lines the rule flags in a controller action taking `string v`.
    fn flagged_in(rule: &str, usings: &str, body: &str) -> bool {
        let src = format!(
            "{USINGS}{usings}\npublic class C : Controller {{\npublic object Get(string v, int n) {{\n{body}\nreturn null;\n}}\n}}\n"
        );
        !issues_of(rule, &src).is_empty()
    }

    /// A controller action with `params` and `body`.
    fn action(params: &str, body: &str) -> String {
        format!(
            "{USINGS}public class Orders : ControllerBase {{\npublic void Get({params}) {{\n{body}\n}}\n}}\n"
        )
    }

    fn flow(i: &Issue) -> Vec<&str> {
        i.flow.iter().map(|s| s.message.as_str()).collect()
    }

    fn flags(src: &str) -> bool {
        !issues(src).is_empty()
    }

    #[test]
    fn a_parameter_concatenated_into_a_query_is_reported_with_its_path() {
        let src = action(
            "string id, SqlConnection c",
            "var q = \"SELECT * FROM o WHERE id = '\" + id + \"'\";\nvar cmd = new SqlCommand(q, c);",
        );
        let found = issues(&src);
        assert_eq!(found.len(), 1);
        let i = &found[0];
        assert_eq!(i.line, 9, "the sink");
        assert_eq!(
            flow(i),
            [
                "request parameter `id`",
                "concatenated into `q`",
                "passed to `SqlCommand`"
            ]
        );
        assert_eq!(i.flow.iter().map(|s| s.line).collect::<Vec<_>>(), [7, 8, 9]);
    }

    #[test]
    fn direct_interpolated_and_formatted_queries() {
        for body in [
            "new SqlCommand(\"SELECT * FROM o WHERE id = \" + id, c);",
            "new SqlCommand($\"SELECT * FROM o WHERE id = {id}\", c);",
            "var q = string.Format(\"SELECT * FROM o WHERE id = {0}\", id); new SqlCommand(q, c);",
            "var q = \"SELECT * FROM o WHERE id = \"; q += id; new SqlCommand(q, c);",
            "var q = id.Trim().ToUpper(); new SqlCommand(\"SELECT \" + q, c);",
        ] {
            assert!(flags(&action("string id, SqlConnection c", body)), "{body}");
        }
    }

    #[test]
    fn constant_and_parameterized_queries_are_not() {
        for body in [
            "new SqlCommand(\"SELECT * FROM o WHERE id = @id\", c).Parameters.AddWithValue(\"@id\", id);",
            "var q = \"SELECT \" + \"1\"; new SqlCommand(q, c);",
            "var table = \"orders\"; new SqlCommand(\"SELECT * FROM \" + table, c);",
            // A number can't inject: parsing sanitizes by its type.
            "var n = int.Parse(id); new SqlCommand(\"SELECT * FROM o WHERE id = \" + n, c);",
            "new SqlCommand(\"SELECT * FROM o WHERE id = \" + id.Length, c);",
            // Overwritten before use.
            "var q = \"SELECT \" + id; q = \"SELECT 1\"; new SqlCommand(q, c);",
            // An unknown helper's result is untainted until T3.
            "var q = Build(id); new SqlCommand(q, c);",
        ] {
            assert!(
                !flags(&action("string id, SqlConnection c", body)),
                "{body}"
            );
        }
    }

    #[test]
    fn value_typed_and_service_parameters_are_not_sources() {
        let body = "new SqlCommand(\"SELECT * FROM o WHERE id = \" + id, c);";
        assert!(!flags(&action("int id, SqlConnection c", body)));
        assert!(!flags(&action("System.Guid id, SqlConnection c", body)));
        assert!(!flags(&action(
            "[FromServices] string id, SqlConnection c",
            body
        )));
        assert!(flags(&action(
            "[FromQuery] string id, SqlConnection c",
            body
        )));
    }

    #[test]
    fn only_a_controllers_public_instance_methods_take_requests() {
        let body = "new SqlCommand(\"SELECT * FROM o WHERE id = \" + id, c);";
        let class = |head: &str, method: &str| {
            format!("{USINGS}{head} {{\n{method}(string id, SqlConnection c) {{\n{body}\n}}\n}}\n")
        };
        assert!(flags(&class(
            "public class Orders : ControllerBase",
            "public void Get"
        )));
        assert!(flags(&class(
            "public class Orders : Controller",
            "public void Get"
        )));
        assert!(!flags(&class(
            "public class Orders : ControllerBase",
            "private void Get"
        )));
        assert!(!flags(&class(
            "public class Orders : ControllerBase",
            "public static void Get"
        )));
        assert!(!flags(&class(
            "public class Orders : ControllerBase",
            "[NonAction] public void Get"
        )));
        // A library method's parameter isn't a request's value, as far as
        // one function can tell.
        assert!(!flags(&class("class Repository", "public void Get")));
        // As ASP.NET Core finds controllers: by name, whatever the base
        // (often a project's own, in another file), or by attribute.
        assert!(flags(&class(
            "public class OrdersController : BaseApiController",
            "public void Get"
        )));
        assert!(flags(&class(
            "[ApiController] public class Orders",
            "public void Get"
        )));
        assert!(!flags(&class("class OrdersController", "public void Get")));
        assert!(!flags(&class(
            "[NonController] public class OrdersController",
            "public void Get"
        )));
        // Actions a controller inherits from an abstract one are its own.
        assert!(flags(&class(
            "public abstract class BaseController : ControllerBase",
            "public void Get"
        )));
    }

    #[test]
    fn branches_and_loops_join_their_paths() {
        let branch = action(
            "string id, bool all, SqlConnection c",
            "var q = \"SELECT * FROM o\";\nif (!all) { q = q + \" WHERE id = \" + id; }\nnew SqlCommand(q, c);",
        );
        assert!(flags(&branch));
        let looped = action(
            "string[] ids, SqlConnection c",
            "var sb = new StringBuilder(\"SELECT * FROM o WHERE id IN (\");\n\
             foreach (var id in ids) { sb.Append(id).Append(','); }\n\
             new SqlCommand(sb.ToString(), c);",
        );
        let found = issues(&looped);
        assert_eq!(found.len(), 1);
        assert_eq!(flow(&found[0]).first(), Some(&"request parameter `ids`"));
    }

    #[test]
    fn the_requests_own_collections_are_sources() {
        let src = format!(
            "{USINGS}class Handler {{\nvoid Run(HttpRequest r, SqlConnection c) {{\n\
             var id = r.Query[\"id\"].ToString();\nnew SqlCommand(\"SELECT * FROM o WHERE id = \" + id, c);\n\
             r.Query.TryGetValue(\"name\", out var name);\nnew SqlCommand(\"SELECT * FROM o WHERE n = \" + name, c);\n}}\n}}\n"
        );
        let found = issues(&src);
        assert_eq!(found.len(), 2, "{found:#?}");
        assert_eq!(flow(&found[0])[0], "the request's `Query`");
        assert_eq!(flow(&found[1])[1], "read into `name`");
    }

    #[test]
    fn command_text_entity_framework_and_dapper() {
        for (extra, body) in [
            (
                "",
                "var cmd = new SqlCommand();\ncmd.CommandText = \"SELECT \" + id;",
            ),
            (
                "",
                "DbCommand cmd = c.CreateCommand();\ncmd.CommandText = \"SELECT \" + id;",
            ),
            (
                "",
                "var cmd = db.GetConnection().CreateCommand();\ncmd.CommandText = \"SELECT \" + id;",
            ),
            (
                "using Microsoft.EntityFrameworkCore;\n",
                "db.Database.ExecuteSqlRaw(\"DELETE FROM o WHERE id = \" + id);",
            ),
            (
                "using Dapper;\n",
                "c.Query<int>(\"SELECT 1 FROM o WHERE id = \" + id);",
            ),
        ] {
            let src = format!(
                "{extra}{}",
                action("string id, SqlConnection c, Db db", body)
            );
            assert!(flags(&src), "{body}");
        }
        // Without Dapper imported, `Query` is someone else's method.
        assert!(!flags(&action(
            "string id, Repo c",
            "c.Query<int>(\"SELECT 1 WHERE id = \" + id);"
        )));
        // EF Core's interpolated variant parameterizes: not a sink.
        assert!(!flags(&format!(
            "using Microsoft.EntityFrameworkCore;\n{}",
            action(
                "string id, Db db",
                "db.Database.ExecuteSqlInterpolated($\"DELETE FROM o WHERE id = {id}\");"
            )
        )));
    }

    #[test]
    fn a_type_of_the_files_own_named_like_a_command_is_not_a_sink() {
        let src = format!(
            "{}class SqlCommand {{ public SqlCommand(string s, object c) {{ }} }}\n",
            action(
                "string id, object c",
                "new SqlCommand(\"SELECT \" + id, c);"
            )
        );
        assert!(!flags(&src));
    }

    #[test]
    fn minimal_api_handlers_take_string_parameters_from_the_request() {
        let src = format!(
            "{USINGS}using Microsoft.AspNetCore.Builder;\nclass P {{\nstatic void Main(string[] args) {{\n\
             var app = WebApplication.CreateBuilder(args).Build();\n\
             app.MapGet(\"/o/{{id}}\", (string id, SqlConnection c) => {{\n\
             var cmd = new SqlCommand(\"SELECT * FROM o WHERE id = \" + id, c);\n}});\n}}\n}}\n"
        );
        assert!(flags(&src));
    }

    #[test]
    fn a_long_path_keeps_its_first_and_last_steps() {
        let hops: String = (1..=20)
            .map(|i| format!("var v{i} = v{} + \"x\";\n", i - 1))
            .collect();
        let src = action(
            "string v0, SqlConnection c",
            &format!("{hops}new SqlCommand(v20, c);"),
        );
        let found = issues(&src);
        assert_eq!(found.len(), 1);
        let steps = flow(&found[0]);
        assert_eq!(steps.len(), crate::semantic::taint::MAX_STEPS);
        assert_eq!(steps[0], "request parameter `v0`");
        assert_eq!(
            steps[crate::semantic::taint::MAX_STEPS - 1],
            "passed to `SqlCommand`"
        );
    }

    #[test]
    fn os_commands() {
        let rule = "cs/command-injection";
        let u = "using System.Diagnostics;";
        for body in [
            "Process.Start(\"sh\", \"-c 'ping \" + v + \"'\");",
            "Process.Start(v);",
            "var p = new ProcessStartInfo(\"git\", \"log \" + v); Process.Start(p);",
            "var p = new ProcessStartInfo(\"git\"); p.Arguments = \"log \" + v;",
        ] {
            assert!(flagged_in(rule, u, body), "{body}");
        }
        for body in [
            "Process.Start(\"git\", \"log -n \" + n);",
            // One argument each, never parsed by a shell: not a sink.
            "var p = new ProcessStartInfo(\"git\"); p.ArgumentList.Add(v);",
        ] {
            assert!(!flagged_in(rule, u, body), "{body}");
        }
    }

    #[test]
    fn file_paths() {
        let rule = "cs/path-injection";
        let u = "using System.IO;";
        for body in [
            "File.ReadAllText(\"/data/\" + v);",
            "File.Copy(\"/data/a\", Path.Combine(\"/data\", v));",
            "new FileStream(v, FileMode.Open);",
            "Directory.Delete(\"/tmp/\" + v, true);",
            "PhysicalFile(Path.GetFullPath(v), \"text/plain\");",
        ] {
            assert!(flagged_in(rule, u, body), "{body}");
        }
        for body in [
            // A file name only, whatever the request sent.
            "File.ReadAllText(Path.Combine(\"/data\", Path.GetFileName(v)));",
            "File.ReadAllText(\"/data/\" + n + \".json\");",
            "File.ReadAllText(\"/data/fixed.json\");",
        ] {
            assert!(!flagged_in(rule, u, body), "{body}");
        }
    }

    #[test]
    fn open_redirects() {
        let rule = "cs/open-redirect";
        for body in [
            "return Redirect(v);",
            "return RedirectPermanent($\"{v}/done\");",
            "Response.Redirect(v);",
            "return new RedirectResult(v);",
        ] {
            assert!(flagged_in(rule, "", body), "{body}");
        }
        for body in [
            "return LocalRedirect(v);",
            "if (Url.IsLocalUrl(v)) { return Redirect(v); }",
            "if (!Url.IsLocalUrl(v)) { return BadRequest(); } return Redirect(v);",
            "return Redirect(\"/orders/\" + v);",
            "return Redirect(\"https://shop.example.com/orders/\" + v);",
        ] {
            assert!(!flagged_in(rule, "", body), "{body}");
        }
        // A path starting with `//` is another host's: not fixed.
        assert!(flagged_in(rule, "", "return Redirect(\"//\" + v);"));
        // A controller whose base is in another file still redirects.
        let src = format!(
            "{USINGS}public class AccountController : AppController {{\npublic object Done(string v) {{\nreturn Redirect(v);\n}}\n}}\n"
        );
        assert_eq!(issues_of(rule, &src).len(), 1);
    }

    #[test]
    fn server_side_requests() {
        let rule = "cs/ssrf";
        let u = "using System.Net.Http; using System.Net.Http.Json;";
        let client = "var http = new HttpClient();";
        for body in [
            "http.GetStringAsync(v);",
            "http.GetAsync(new System.Uri(v));",
            "http.GetFromJsonAsync<int>($\"{v}/api\");",
            "var m = new HttpRequestMessage(HttpMethod.Get, v); http.SendAsync(m);",
            "http.BaseAddress = new System.Uri(v);",
        ] {
            assert!(flagged_in(rule, u, &format!("{client} {body}")), "{body}");
        }
        for body in [
            "http.GetStringAsync(\"https://api.example.com/rates?c=\" + v);",
            "http.GetStringAsync($\"https://api.example.com/users/{v}\");",
            "http.GetStringAsync(\"https://api.example.com/\");",
        ] {
            assert!(!flagged_in(rule, u, &format!("{client} {body}")), "{body}");
        }
        // The host itself from the request: not fixed.
        assert!(flagged_in(
            rule,
            u,
            &format!("{client} http.GetStringAsync(\"https://\" + v + \"/x\");")
        ));
    }

    #[test]
    fn xpath_and_ldap() {
        let u = "using System.Xml; using System.Xml.XPath;";
        let doc = "var doc = new XmlDocument();";
        assert!(flagged_in(
            "cs/xpath-injection",
            u,
            &format!("{doc} doc.SelectNodes(\"//u[name='\" + v + \"']\");")
        ));
        assert!(flagged_in(
            "cs/xpath-injection",
            u,
            &format!(
                "{doc} var nav = doc.CreateNavigator(); nav.Evaluate(\"count(//u[@id='\" + v + \"'])\");"
            )
        ));
        assert!(!flagged_in(
            "cs/xpath-injection",
            u,
            &format!("{doc} doc.SelectNodes(\"//u\");")
        ));
        let ldap = "using System.DirectoryServices;";
        assert!(flagged_in(
            "cs/ldap-injection",
            ldap,
            "new DirectorySearcher(\"(uid=\" + v + \")\");"
        ));
        assert!(flagged_in(
            "cs/ldap-injection",
            ldap,
            "var s = new DirectorySearcher(); s.Filter = $\"(mail={v})\";"
        ));
        assert!(!flagged_in(
            "cs/ldap-injection",
            ldap,
            "new DirectorySearcher(\"(objectClass=person)\");"
        ));
        // Without the namespace imported, someone else's DirectorySearcher.
        assert!(!flagged_in(
            "cs/ldap-injection",
            "",
            "new DirectorySearcher(\"(uid=\" + v + \")\");"
        ));
    }

    #[test]
    fn each_sink_reports_once_under_its_own_rule() {
        let src = format!(
            "{USINGS}using System.IO;\npublic class C : Controller {{\npublic object Get(string v, SqlConnection c) {{\n\
             File.ReadAllText(v);\nnew SqlCommand(\"SELECT \" + v, c);\nreturn Redirect(v);\n}}\n}}\n"
        );
        for (rule, line) in [
            ("cs/path-injection", 9),
            ("cs/sql-injection", 10),
            ("cs/open-redirect", 11),
        ] {
            let found = issues_of(rule, &src);
            assert_eq!(
                found.iter().map(|i| i.line).collect::<Vec<_>>(),
                [line],
                "{rule}"
            );
        }
    }

    #[test]
    fn a_controllers_own_request_is_a_source() {
        for body in [
            "var id = Request.Query[\"id\"].ToString(); new SqlCommand(\"SELECT \" + id, c);",
            "var n = HttpContext.Request.Form[\"n\"]; new SqlCommand($\"SELECT {n}\", c);",
        ] {
            let src = format!(
                "{USINGS}public class C : Controller {{\npublic void Get(SqlConnection c) {{\n{body}\n}}\n}}\n"
            );
            assert_eq!(issues(&src).len(), 1, "{body}");
            assert!(flow(&issues(&src)[0])[0].starts_with("the request's"));
        }
        // Outside a controller, or shadowed by a local, `Request` is something else.
        let other = format!(
            "{USINGS}public class Job {{\npublic void Run(SqlConnection c) {{\nvar id = Request.Query[\"id\"]; new SqlCommand(\"SELECT \" + id, c);\n}}\n}}\n"
        );
        assert!(issues(&other).is_empty());
        let shadowed = format!(
            "{USINGS}public class C : Controller {{\npublic void Get(SqlConnection c, Lookup Request) {{\nvar id = Request.Query[\"id\"]; new SqlCommand(\"SELECT \" + id, c);\n}}\n}}\n"
        );
        // A parameter named Request is an action parameter: a source anyway,
        // but as itself, not as the request's Query.
        assert!(
            issues(&shadowed)
                .iter()
                .all(|i| flow(i)[0] == "request parameter `Request`")
        );
    }

    /// False positives found on real applications (BTCPay Server, eShop,
    /// Kavita, Bitwarden), reduced to their pattern.
    #[test]
    fn checks_and_fixed_hosts_from_real_code() {
        // A local path in a variable, the query string appended (BTCPay).
        assert!(!flagged_in(
            "cs/open-redirect",
            "",
            "var p = \"/server/translations\" + (n > 0 ? \"\" : $\"/{v}\"); return RedirectPermanent(p + Request.QueryString);"
        ));
        // A constant host (Kavita).
        let constant = format!(
            "{USINGS}public class K : Controller {{\nprivate const string Host = \"https://cdn.example.com/img/\";\n\
             public object Get(string v) {{ return Redirect(Host + v); }}\n}}\n"
        );
        assert!(issues_of("cs/open-redirect", &constant).is_empty());
        // A model's URL checked with IsLocalUrl, or by IdentityServer (eShop).
        assert!(!flagged_in(
            "cs/open-redirect",
            "",
            "var m = new Model(); if (Url.IsLocalUrl(m.ReturnUrl)) { return Redirect(m.ReturnUrl); }"
        ));
        assert!(!flagged_in(
            "cs/open-redirect",
            "",
            "var ctx = interaction.GetAuthorizationContextAsync(v); if (ctx != null) { return Redirect(v); }"
        ));
        // A path relative to the client's base address (Bitwarden).
        assert!(!flagged_in(
            "cs/ssrf",
            "using System.Net.Http;",
            "var http = new HttpClient(); var p = $\"/Account/PreValidate?hint={v}\"; http.GetAsync(p);"
        ));
        // A file name checked against its directory (Kavita), or by prefix.
        assert!(!flagged_in(
            "cs/path-injection",
            "using System.IO;",
            "if (!IsPathWithinDirectory(\"/tmp\", v)) { return null; } return PhysicalFile(Path.Join(\"/tmp\", v));"
        ));
        assert!(!flagged_in(
            "cs/path-injection",
            "using System.IO;",
            "var full = Path.GetFullPath(Path.Combine(\"/data\", v)); if (!full.StartsWith(\"/data/\")) { return null; } File.Delete(full);"
        ));
        // Unchecked, the same code is reported.
        assert!(flagged_in(
            "cs/path-injection",
            "using System.IO;",
            "return PhysicalFile(Path.Join(\"/tmp\", v));"
        ));
    }

    /// A controller with `action` and other members `rest`, for T3.
    fn controller(action: &str, rest: &str) -> String {
        format!("{USINGS}public class C : Controller {{\n{action}\n{rest}\n}}\n")
    }

    #[test]
    fn through_a_helper_with_the_sink() {
        let src = controller(
            "public void Get(string id, SqlConnection c) { Find(id, c); }",
            "void Find(string key, SqlConnection c) {\nvar q = \"SELECT * FROM o WHERE id = \" + key;\nnew SqlCommand(q, c);\n}",
        );
        let found = issues(&src);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 10, "the sink, in the helper");
        assert_eq!(
            flow(&found[0]),
            [
                "request parameter `id`",
                "passed to `Find`",
                "`Find`'s parameter `key`",
                "concatenated into `q`",
                "passed to `SqlCommand`"
            ]
        );
    }

    #[test]
    fn through_a_helper_that_returns_the_query() {
        let src = controller(
            "public void Get(string id, SqlConnection c) { var q = Build(id); new SqlCommand(q, c); }",
            "string Build(string key) => \"SELECT * FROM o WHERE id = \" + key;",
        );
        let found = issues(&src);
        assert_eq!(found.len(), 1);
        let steps = flow(&found[0]);
        assert!(steps.contains(&"returned by `Build`"), "{steps:?}");
        assert_eq!(steps.first(), Some(&"request parameter `id`"));
        // A block body with `return`, and a static helper called by its class.
        let block = controller(
            "public void Get(string id, SqlConnection c) { new SqlCommand(C.Build(id), c); }",
            "static string Build(string key) { var s = \"SELECT \" + key; return s; }",
        );
        assert_eq!(issues(&block).len(), 1);
    }

    #[test]
    fn a_helper_that_reads_the_request_itself() {
        let src = controller(
            "public void Get(SqlConnection c) { new SqlCommand(\"SELECT \" + Id(), c); }",
            "string Id() => Request.Query[\"id\"].ToString();",
        );
        let found = issues(&src);
        assert_eq!(found.len(), 1);
        assert_eq!(flow(&found[0])[0], "the request's `Query`");
    }

    #[test]
    fn chains_and_named_arguments() {
        let chain = controller(
            "public void Get(string id, SqlConnection c) { Outer(id, c); }",
            "void Outer(string a, SqlConnection c) { Inner(c: c, key: a.Trim()); }\n\
             void Inner(SqlConnection c, string key) { new SqlCommand(\"SELECT \" + key, c); }",
        );
        let found = issues(&chain);
        assert_eq!(found.len(), 1);
        let steps = flow(&found[0]);
        assert!(
            steps.contains(&"passed to `Outer`") && steps.contains(&"passed to `Inner`"),
            "{steps:?}"
        );
        // The connection isn't the query: only the right argument counts.
        let wrong = controller(
            "public void Get(string id, SqlConnection c) { Inner(c, \"1\"); }",
            "void Inner(SqlConnection c, string key) { new SqlCommand(\"SELECT \" + key, c); }",
        );
        assert!(issues(&wrong).is_empty());
    }

    #[test]
    fn safe_values_and_helpers_are_not_reported() {
        for (action, rest) in [
            // A constant passed in.
            (
                "public void Get(string id, SqlConnection c) { Find(\"1\", c); }",
                "void Find(string key, SqlConnection c) { new SqlCommand(\"SELECT \" + key, c); }",
            ),
            // A helper that parses: a number comes back.
            (
                "public void Get(string id, SqlConnection c) { new SqlCommand(\"SELECT \" + Parse(id), c); }",
                "int Parse(string s) => int.Parse(s);",
            ),
            // A helper that ignores its parameter.
            (
                "public void Get(string id, SqlConnection c) { new SqlCommand(Fixed(id), c); }",
                "string Fixed(string s) => \"SELECT 1\";",
            ),
            // A helper nobody calls with a request's value.
            (
                "public void Get(int id) { }",
                "void Find(string key, SqlConnection c) { new SqlCommand(\"SELECT \" + key, c); }",
            ),
        ] {
            assert!(issues(&controller(action, rest)).is_empty(), "{rest}");
        }
    }

    #[test]
    fn a_helper_called_twice_is_reported_once() {
        let src = controller(
            "public void Get(string id, SqlConnection c) { Find(id, c); }\n\
             public void Post(string name, SqlConnection c) { Find(\"x\" + name, c); }",
            "void Find(string key, SqlConnection c) { new SqlCommand(\"SELECT \" + key, c); }",
        );
        let found = issues(&src);
        assert_eq!(found.len(), 1);
        assert_eq!(
            flow(&found[0])[0],
            "request parameter `id`",
            "the shortest path"
        );
    }

    #[test]
    fn recursion_and_ambiguous_overloads_end() {
        let recursive = controller(
            "public void Get(string id, SqlConnection c) { Walk(id, c, 3); }",
            "void Walk(string key, SqlConnection c, int n) { if (n > 0) { Walk(key + \"x\", c, n - 1); } else { new SqlCommand(\"SELECT \" + key, c); } }",
        );
        assert_eq!(issues(&recursive).len(), 1, "the base case's sink");
        let mutual = controller(
            "public void Get(string id) { A(id); }",
            "string A(string s) => B(s);\nstring B(string s) => A(s);",
        );
        assert!(issues(&mutual).is_empty());
        // Two helpers named alike that inference can't tell apart: neither.
        let overloads = controller(
            "public void Get(string id, SqlConnection c) { Find(id, c); }",
            "void Find(string key, SqlConnection c) { new SqlCommand(\"SELECT \" + key, c); }\n\
             void Find(object key, SqlConnection c) { }",
        );
        assert!(issues(&overloads).len() <= 1);
    }

    /// A helper checks its parameter, and the action
    /// returns when the check fails. What it checks is safe in the caller;
    /// what it doesn't check isn't.
    #[test]
    fn a_check_inside_a_helper_counts_for_its_caller() {
        let checked = controller(
            "public object Save(string name) {\nif (Invalid(name)) return null;\nSave2(name);\nreturn null;\n}",
            "bool Invalid(string file) => !IsPathWithinDirectory(\"/data\", file);\n\
             void Save2(string file) { System.IO.File.Create(System.IO.Path.Join(\"/data\", file)); }",
        );
        assert!(issues_of("cs/path-injection", &checked).is_empty());
        // A parameter the helper doesn't check is still reported.
        let unchecked = controller(
            "public object Save(string name, string path) {\nif (Invalid(name, path)) return null;\nreturn null;\n}",
            "bool Invalid(string file, string full) {\nif (!IsPathWithinDirectory(\"/data\", file)) return true;\n\
             System.IO.File.Delete(full);\nreturn false;\n}",
        );
        let found = issues_of("cs/path-injection", &unchecked);
        assert_eq!(found.len(), 1);
        assert_eq!(flow(&found[0])[0], "request parameter `path`");
    }
}
