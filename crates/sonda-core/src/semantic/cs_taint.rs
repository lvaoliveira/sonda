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
use super::{DeclId, DeclKind, Model};
use std::collections::{BTreeMap, HashMap};
use tree_sitter::Node;

/// The most variables tracked in one function, and rounds of the fixed
/// point; past either, the function reports nothing.
const MAX_TRACKED: usize = 512;
const MAX_ROUNDS: usize = 512;
/// The most steps a path keeps: its first and its last half.
pub(crate) const MAX_STEPS: usize = 10;
/// How deep an expression is followed for its taint.
const MAX_EXPR_NODES: usize = 4096;

/// One step of a path: where, and what happened to the value there.
#[derive(Clone, Debug)]
pub(crate) struct Step<'t> {
    pub(crate) node: Node<'t>,
    pub(crate) message: String,
}

/// A source reaching a sink: the sink's expression, and the path, which
/// ends at the sink.
#[derive(Debug)]
pub(crate) struct Finding<'t> {
    pub(crate) sink: Node<'t>,
    pub(crate) steps: Vec<Step<'t>>,
}

type Path<'t> = Vec<Step<'t>>;
type State<'t> = BTreeMap<DeclId, Path<'t>>;

/// What a sink is for; a sanitizer clears taint for its own kind only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SinkKind {
    Sql,
}

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

const STRING: &str = "System.String";
const STRING_BUILDER: &str = "System.Text.StringBuilder";
/// Types whose methods return what their receiver and arguments hold.
const PROPAGATING_TYPES: &[&str] = &[
    STRING,
    STRING_BUILDER,
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
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let by_node = cs_cfg::decls_by_node(m);
    let functions: Vec<Node<'t>> = m.functions.iter().map(|f| f.node).collect();
    let mut found = Vec::new();
    for (i, function) in m.functions.iter().enumerate() {
        let node = function.node;
        if node.child_by_field_name("body").is_none() || node.has_error() {
            continue;
        }
        let text = node.utf8_text(src).unwrap_or_default();
        if ["#if", "#else", "#elif", "#endif"]
            .iter()
            .any(|d| text.contains(d))
        {
            continue;
        }
        let sources = source_params(m, &infer, i, src);
        let sinks = sinks_in(m, &infer, node, &functions, kind);
        if sinks.is_empty() {
            continue;
        }
        let Some(cfg) = cs_cfg::build(m, node, src, &by_node) else {
            continue;
        };
        let a = Analysis {
            m,
            infer: &infer,
            src,
            by_node: &by_node,
        };
        found.extend(a.function(&cfg, sources, &sinks));
    }
    found.sort_by_key(|f| f.sink.start_byte());
    found
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
    value: Node<'t>,
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
) -> Vec<Sink<'t>> {
    let SinkKind::Sql = kind;
    let mut out = Vec::new();
    let mut stack: Vec<Node<'t>> = function.child_by_field_name("body").into_iter().collect();
    while let Some(n) = stack.pop() {
        if functions.iter().any(|f| f.id() == n.id()) && n.id() != function.id() {
            continue;
        }
        if let Some(sink) = sql_sink(m, infer, n) {
            out.push(sink);
        }
        stack.extend(children(n).into_iter().rev());
    }
    out
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
                value: first_argument(n)?,
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
                value: first_argument(n)?,
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
                value: n.child_by_field_name("right")?,
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
}

impl<'t> Analysis<'_, 't> {
    fn text(&self, n: Node) -> &str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// The findings of one function, from the state at its entry.
    fn function(&self, cfg: &Cfg<'t>, entry: State<'t>, sinks: &[Sink<'t>]) -> Vec<Finding<'t>> {
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
        let mut converged = false;
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
                    return Vec::new();
                }
                if !same_keys(&state, &out[i]) {
                    changed = true;
                }
                out[i] = state;
            }
            if !changed {
                converged = true;
                break;
            }
        }
        if !converged {
            return Vec::new();
        }
        let mut found = Vec::new();
        for sink in sinks {
            let Some(block) = innermost_block(cfg, sink.node) else {
                continue;
            };
            let mut state = inn[block].clone();
            self.transfer(cfg, block, &mut state, Some(sink.node.start_byte()));
            if let Some(mut steps) = self.taint(sink.value, &state) {
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
                "invocation_expression" => stack.extend(self.propagated(n).into_iter().rev()),
                "object_creation_expression" => {
                    let ty = n.child_by_field_name("type").map(|t| self.text(t));
                    if matches!(
                        ty,
                        Some("StringBuilder" | "System.Text.StringBuilder" | "string")
                    ) {
                        stack.extend(arguments(n).into_iter().rev());
                    }
                }
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
        self.infer
            .type_of(receiver)
            .is_some_and(|t| t.is(HTTP_REQUEST))
            .then(|| {
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

/// A long path keeps its first and last steps.
fn cap(steps: Vec<Step>) -> Vec<Step> {
    if steps.len() <= MAX_STEPS {
        return steps;
    }
    let half = MAX_STEPS / 2;
    let mut kept: Vec<Step> = steps[..half].to_vec();
    kept.extend_from_slice(&steps[steps.len() - half..]);
    kept
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
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t.cs", Lang::CSharp, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues.into_iter().filter(|i| i.rule == RULE).collect()
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
        assert_eq!(steps.len(), super::MAX_STEPS);
        assert_eq!(steps[0], "request parameter `v0`");
        assert_eq!(steps[super::MAX_STEPS - 1], "passed to `SqlCommand`");
    }
}
