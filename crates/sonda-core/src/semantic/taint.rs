//! What taint analysis reports, whatever the language (ADR-0027): a sink a
//! request's value reaches, and the path it took. Each language's engine
//! (`cs_taint`, `js_taint`) produces these; the rules and the report only
//! see this module.

use tree_sitter::Node;

/// The most steps a path keeps: its first and its last half.
pub(crate) const MAX_STEPS: usize = 10;

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

/// What a sink is for; a sanitizer clears taint for its own kind only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SinkKind {
    Sql,
    Command,
    Path,
    Redirect,
    Ssrf,
    XPath,
    Ldap,
    /// Code the program runs: `eval`, `new Function`, `vm.runInContext`.
    Code,
    /// The format of a `printf`: a value there reads or writes memory.
    Format,
    /// Text a page prints: a value there runs as script in the reader's
    /// browser unless it was escaped for HTML.
    Html,
}

/// A long path keeps its first and last steps.
pub(crate) fn cap(steps: Vec<Step>) -> Vec<Step> {
    if steps.len() <= MAX_STEPS {
        return steps;
    }
    let half = MAX_STEPS / 2;
    let mut kept: Vec<Step> = steps[..half].to_vec();
    kept.extend_from_slice(&steps[steps.len() - half..]);
    kept
}

/// What a taint rule finds in one file: its issues, and what the project
/// pass needs to follow values into and out of other files (ADR-0027, T4).
#[derive(Default)]
pub(crate) struct TaintResult<'t> {
    pub(crate) findings: Vec<Finding<'t>>,
    pub(crate) facts: Facts<'t>,
}

/// A file's part of a path that crosses files: its functions' summaries,
/// the request's values it passes to other files' functions, and the
/// results of other files' functions it passes to a sink.
#[derive(Default)]
pub(crate) struct Facts<'t> {
    pub(crate) summaries: Vec<SummaryFact<'t>>,
    pub(crate) calls: Vec<CallFact<'t>>,
    pub(crate) returns: Vec<ReturnFact<'t>>,
}

impl Facts<'_> {
    pub(crate) fn is_empty(&self) -> bool {
        self.summaries.is_empty() && self.calls.is_empty() && self.returns.is_empty()
    }
}

/// A function other files can call, and what its parameters reach.
pub(crate) struct SummaryFact<'t> {
    pub(crate) key: Key,
    /// Its return value reads as SQL, for a query method whose caller's
    /// text doesn't show any.
    pub(crate) returns_sql: bool,
    /// Each parameter that reaches a sink: the path from the parameter,
    /// ending at the sink, and the sink.
    pub(crate) to_sink: Vec<(usize, Vec<Step<'t>>, Node<'t>)>,
    /// Each parameter that reaches the return value, and its path.
    pub(crate) to_return: Vec<(usize, Vec<Step<'t>>)>,
    /// A request's value the function reads and returns itself.
    pub(crate) returns_source: Option<Vec<Step<'t>>>,
    /// Each parameter passed on to another file's function: its path, ending
    /// at the call, and the callee's argument it becomes.
    pub(crate) to_call: Vec<(usize, Vec<Step<'t>>, Callee, usize)>,
}

/// What a function is called from other files. JavaScript: the name it's
/// exported as (`default` for a default export), and for a class's method
/// or a default-exported object's, the member.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub(crate) struct Key {
    pub(crate) export: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) member: Option<String>,
}

/// A call to a function of another file, as the calling file sees it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "lang", rename_all = "lowercase")]
pub(crate) enum Callee {
    /// `import { find } from './users'; find(x)` is `./users`'s `find`;
    /// `users.find(x)` with `users` a namespace or a `require` has no name
    /// and `find` as its member; `new UserService().find(x)` names
    /// `UserService` and its member `find`.
    Js {
        spec: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        member: Option<String>,
    },
    /// `from app.db import query; query(x)` is `app.db`'s `query`;
    /// `db.query(x)` with `db` a module is the module's `query`;
    /// `UserService().find(x)` names `UserService` and its member `find`.
    /// Relative modules keep their dots (`.db`); the project pass resolves
    /// them from the calling file.
    Py {
        module: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        member: Option<String>,
    },
    /// `orders.Find(id)` with `orders` declared as `IOrderService`: the
    /// type as written, where it's written (the namespace, and the type the
    /// call is in, for nested types), and the method's name and arity. The
    /// project pass resolves the type with ADR-0020's index, and an
    /// interface or a base class to its implementations too.
    Cs {
        #[serde(rename = "type")]
        ty: super::cs_index::TypeRef,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        namespace: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        owner: String,
        method: String,
        arity: usize,
    },
    /// `orders.find(id)` with `orders` declared as `OrderService`: the type
    /// as written (its qualifier and name), the types the call is inside of
    /// (outermost first), and the method's name and arity. The project pass
    /// resolves the type as Java does, with the java-index fact, and an
    /// interface or a base class to its implementations too.
    Java {
        #[serde(default, skip_serializing_if = "String::is_empty")]
        qualifier: String,
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        within: Vec<String>,
        method: String,
        arity: usize,
    },
    /// `db::find(x)`, `User::find(x)` or `repo.find(x)`: the path as written,
    /// with its first name taken through the file's `use`s, and for a method
    /// call on a typed receiver, the receiver's type path and the method. The
    /// project pass reads the path as Rust's modules do, from the calling
    /// file's own module (`crate::`, `self::`, `super::`, a child module).
    Rs {
        path: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<String>,
    },
    /// `find(x)`, `db::find(x)` or `repo.find(x)`: the names as written (for
    /// a method call, its receiver's declared type and the method), the
    /// number of arguments, the scopes the name may be in (the namespaces and
    /// classes the call is inside of, and the file's `using namespace`s, each
    /// as `a::b`), and the file's quoted `#include`s. The project pass finds
    /// the one definition whose file a header named there belongs to.
    Cpp {
        path: Vec<String>,
        arity: usize,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scopes: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        includes: Vec<String>,
    },
    /// `helper(x)`, `store.Find(x)` or `util.Run(x)`: the function's name and
    /// number of arguments; for a method, its receiver's type; and the
    /// import path of the package it's in, none for the calling file's own
    /// (a package is a directory, so its other files). The project pass finds
    /// the directory, and the one function of that name in it.
    Go {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        package: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receiver: Option<String>,
        name: String,
        arity: usize,
    },
    /// `helper($x)`, `$store->find($x)`, `Store::find($x)` or `new Store($x)`:
    /// the function's name, lowercase (PHP reads names without regard to case),
    /// and for a method its class's, as written without a namespace. The
    /// project pass looks for the one function of that name in the project's
    /// other PHP files.
    Php {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        class: Option<String>,
        name: String,
    },
    /// `Users.find(x)`, `find(x)` in a class, `Users.new(x)` (its
    /// `initialize`): a method by its class, as written without its modules,
    /// and whether it's one of the class itself (`def self.find`). The project
    /// pass looks for it in the class and what the class extends and includes.
    Ruby {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        class: Option<String>,
        name: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        singleton: bool,
    },
}

impl Callee {
    /// The name the path shows: `find`, `UserService.find`.
    pub(crate) fn display(&self) -> String {
        match self {
            Callee::Cs { method, .. } | Callee::Java { method, .. } => method.clone(),
            Callee::Cpp { path, .. } => path.join("::"),
            Callee::Go {
                receiver: Some(r),
                name,
                ..
            } => format!("{r}.{name}"),
            Callee::Go { name, .. } => name.clone(),
            Callee::Php {
                class: Some(c),
                name,
            } => format!("{c}::{name}"),
            Callee::Php { name, .. } => name.clone(),
            Callee::Ruby {
                class: Some(c),
                name,
                singleton,
            } => format!("{c}{}{name}", if *singleton { "." } else { "#" }),
            Callee::Ruby { name, .. } => name.clone(),
            Callee::Rs { path, method } => method
                .clone()
                .or_else(|| path.last().cloned())
                .unwrap_or_default(),
            Callee::Py { name, member, .. } => match (name.as_deref(), member.as_deref()) {
                (Some(n), Some(m)) => format!("{n}.{m}"),
                (_, Some(m)) => m.to_string(),
                (Some(n), None) => n.to_string(),
                (None, None) => String::new(),
            },
            Callee::Js { name, member, .. } => match (name.as_deref(), member.as_deref()) {
                (Some(n), Some(m)) if n != "default" => format!("{n}.{m}"),
                (_, Some(m)) => m.to_string(),
                (Some(n), None) => n.to_string(),
                (None, None) => "default".to_string(),
            },
        }
    }
}

/// A request's value passed to another file's function: its path up to
/// the call, the call, and the argument.
pub(crate) struct CallFact<'t> {
    pub(crate) steps: Vec<Step<'t>>,
    pub(crate) call: Node<'t>,
    pub(crate) callee: Callee,
    pub(crate) arg: usize,
}

/// Another file's function's result passed to a sink here: the call, the
/// request's values in its arguments, the path after it, ending at the
/// sink, and the sink.
pub(crate) struct ReturnFact<'t> {
    pub(crate) call: Node<'t>,
    pub(crate) callee: Callee,
    pub(crate) args: Vec<(usize, Vec<Step<'t>>)>,
    pub(crate) after: Vec<Step<'t>>,
    pub(crate) sink: Node<'t>,
    /// The sink is a query method whose text the caller doesn't show as
    /// SQL: the callee's result has to read as SQL.
    pub(crate) needs_sql: bool,
}
