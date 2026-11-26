//! Taint analysis for Ruby (ADR-0027, ADR-0033; tree-sitter-ruby): a value
//! from a request reaching a query, a command, a path, a redirect, an
//! outgoing request, code or a page, within a file.
//!
//! What is a request's value, and what isn't:
//! - `params` and `cookies`, whatever is read from them, and `request`'s
//!   `params`, `body`, `url`, `headers`, `env` and the like (Rails and
//!   Sinatra); what a method returns when it's called on one;
//! - a number (`to_i`, `Integer(..)`), a boolean (`include?`, `blank?`) or a
//!   size isn't, nor is what a sanitizer for the sink makes (`Shellwords`,
//!   `File.basename`, `h`, `sanitize_sql`);
//! - a value tested (`ALLOWED.include?(x)`, `x =~ /\A\d+\z/`, a `case` with
//!   literals, a method called `valid_..`/`allowed?`) is taken as validated;
//! - `@name` is a variable of its class, so a value one method sets
//!   (`before_action`) reaches the reads of it in the others.
//!
//! A method's last expression is what it returns, as `return` does.

use super::taint::{Callee, Key, ReturnFact, SinkKind, Step, TaintResult};
use super::taint_core::{
    Exports, Flow, How, Path, Summaries, Summary, SummaryKey, Write, address_path, best, best_of,
    contains_any, decl_index, evaluation_for, exports_for, externals_for, flow_for, from_call,
    function_keys_for, held, locals_for, names_a_check, summarize_for, walk,
};
use super::{DeclId, Model};
use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Writes in one file; past it, the file reports nothing.
const MAX_WRITES: usize = 50_000;
/// Summaries per file, at most: past it, calls to other functions give nothing.
const MAX_SUMMARIES: usize = 256;

// ---------------------------------------------------------------- entry

pub(crate) fn find<'t>(m: &Model<'t>, src: &[u8], kind: SinkKind) -> TaintResult<'t> {
    if !(might_have_sources(src) || contains_any(src, &[b"def "])) {
        return TaintResult::default();
    }
    Cx::file_result(m, src, kind).unwrap_or_default()
}

/// The fact a Ruby file's classes are in, for the project pass.
pub(crate) const FACT: &str = "ruby-classes";

/// A class or module a file declares: what it extends and includes, and the
/// methods it defines, instance and its own (`def self.m`, `class << self`):
/// where a call to a method it inherits goes.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct ClassFact {
    pub(crate) name: String,
    /// The superclass and the modules `include`d or `prepend`ed.
    #[serde(default)]
    pub(crate) parents: Vec<String>,
    /// The modules `extend`ed: their methods are the class's own.
    #[serde(default)]
    pub(crate) extends: Vec<String>,
    #[serde(default)]
    pub(crate) methods: Vec<String>,
    #[serde(default)]
    pub(crate) singletons: Vec<String>,
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

/// What a class or a module extends, includes and defines.
fn class_fact(n: Node, src: &[u8]) -> Option<ClassFact> {
    if !matches!(n.kind(), "class" | "module") {
        return None;
    }
    let text = |n: Node| n.utf8_text(src).unwrap_or_default();
    let mut fact = ClassFact {
        name: last_name(text(n.child_by_field_name("name")?)).to_string(),
        ..ClassFact::default()
    };
    if let Some(sup) = named_children(n)
        .into_iter()
        .find(|c| c.kind() == "superclass")
        .and_then(|c| c.named_child(0))
    {
        fact.parents.push(last_name(text(sup)).to_string());
    }
    let body = n.child_by_field_name("body");
    for member in body.map(named_children).unwrap_or_default() {
        class_member(member, src, &mut fact, false);
    }
    Some(fact)
}

/// One statement of a class's body: a method, a method of the class itself,
/// an `include`.
fn class_member(member: Node, src: &[u8], fact: &mut ClassFact, own: bool) {
    let text = |n: Node| n.utf8_text(src).unwrap_or_default();
    let name = |n: Node| n.child_by_field_name("name").map(|c| text(c).to_string());
    match member.kind() {
        "method" => {
            let list = if own {
                &mut fact.singletons
            } else {
                &mut fact.methods
            };
            list.extend(name(member));
        }
        "singleton_method" => fact.singletons.extend(name(member)),
        "singleton_class" => {
            let body = member.child_by_field_name("body");
            for m in body.map(named_children).unwrap_or_default() {
                class_member(m, src, fact, true);
            }
        }
        // `include A, B`, `private def m`.
        "call" if member.child_by_field_name("receiver").is_none() => {
            let verb = call_name(member, src).unwrap_or_default();
            for a in arguments(member) {
                match (verb, a.kind()) {
                    ("include" | "prepend", "constant" | "scope_resolution") => {
                        fact.parents.push(last_name(text(a)).to_string());
                    }
                    ("extend", "constant" | "scope_resolution") => {
                        fact.extends.push(last_name(text(a)).to_string());
                    }
                    (_, "method" | "singleton_method") => class_member(a, src, fact, own),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Every class of the project, or of a file, by name: which one defines a
/// method a class has.
#[derive(Default)]
pub(crate) struct ClassIndex {
    classes: HashMap<String, ClassFact>,
}

impl ClassIndex {
    pub(crate) fn new(facts: impl IntoIterator<Item = ClassFact>) -> Self {
        let mut classes: HashMap<String, ClassFact> = HashMap::new();
        for f in facts {
            let c = classes.entry(f.name.clone()).or_insert_with(|| ClassFact {
                name: f.name.clone(),
                ..ClassFact::default()
            });
            c.parents.extend(f.parents);
            c.extends.extend(f.extends);
            c.methods.extend(f.methods);
            c.singletons.extend(f.singletons);
        }
        ClassIndex { classes }
    }

    /// Whether a class extends or includes anything.
    pub(crate) fn inherits(&self, class: &str) -> bool {
        self.classes
            .get(class)
            .is_some_and(|f| !f.parents.is_empty() || !f.extends.is_empty())
    }

    /// The class that defines method `name` for `class`, and whether it's
    /// one of that class's own: the class's, or the nearest ancestor's or
    /// module's.
    pub(crate) fn defining(
        &self,
        class: &str,
        name: &str,
        singleton: bool,
    ) -> Option<(String, bool)> {
        let mut queue = vec![(class.to_string(), singleton)];
        let mut i = 0;
        while let Some((c, own)) = queue.get(i).cloned() {
            i += 1;
            let Some(f) = self.classes.get(&c) else {
                continue;
            };
            let defined = if own { &f.singletons } else { &f.methods };
            if defined.iter().any(|m| m == name) {
                return Some((c, own));
            }
            for p in &f.parents {
                if queue.len() < 32 && !queue.contains(&(p.clone(), own)) {
                    queue.push((p.clone(), own));
                }
            }
            // A module a class extends gives it its methods as its own.
            if own {
                queue.extend(f.extends.iter().map(|e| (e.clone(), false)).take(8));
            }
        }
        None
    }
}

fn might_have_sources(src: &[u8]) -> bool {
    contains_any(src, &[b"params", b"cookies", b"request"])
}

// ---------------------------------------------------------------- tables

/// What `request.` reads from the client.
const REQUEST_METHODS: &[&str] = &[
    "params",
    "parameters",
    "query_parameters",
    "request_parameters",
    "path_parameters",
    "GET",
    "POST",
    "query_string",
    "raw_post",
    "body",
    "url",
    "fullpath",
    "original_url",
    "original_fullpath",
    "path",
    "path_info",
    "referer",
    "referrer",
    "user_agent",
    "host",
    "headers",
    "env",
    "cookies",
    "cgi",
];

/// Calls whose result is a number, a boolean or a size: it can't carry what
/// injects.
const SAFE_METHODS: &[&str] = &[
    "to_i",
    "to_int",
    "to_f",
    "to_r",
    "to_c",
    "Integer",
    "Float",
    "Rational",
    "size",
    "length",
    "count",
    "empty?",
    "blank?",
    "present?",
    "nil?",
    "include?",
    "member?",
    "key?",
    "has_key?",
    "is_a?",
    "kind_of?",
    "instance_of?",
    "respond_to?",
    "start_with?",
    "end_with?",
    "match?",
    "eql?",
    "equal?",
    "zero?",
    "positive?",
    "negative?",
    "any?",
    "all?",
    "none?",
    "between?",
    "integer?",
    "hash",
    "object_id",
    "class",
    "nonzero?",
    "to_json",
];

/// Calls that put their arguments in their result: a path joined, a string
/// formatted, a URL parsed.
const ARGUMENT_METHODS: &[&str] = &[
    "join",
    "format",
    "sprintf",
    "+",
    "concat",
    "prepend",
    "insert",
    "new",
    "URI",
    "parse",
    "escape",
    "unescape",
    "decode",
    "encode",
    "to_s",
    "String",
    "Array",
    "dup",
    "clone",
    "freeze",
    "merge",
    "expand_path",
    "absolute_path",
    "realpath",
    "dirname",
    "relative_path_from",
    "cleanpath",
    "squish",
    "titleize",
    "humanize",
    "underscore",
    "camelize",
    "classify",
    "tableize",
    "pluralize",
    "singularize",
    "dasherize",
    "parameterize",
];

/// Methods that run their block once for each element.
const ITERATORS: &[&str] = &[
    "each",
    "each_with_index",
    "each_pair",
    "each_value",
    "each_key",
    "each_line",
    "each_char",
    "map",
    "collect",
    "flat_map",
    "select",
    "filter",
    "reject",
    "find",
    "detect",
    "find_all",
    "tap",
    "then",
    "sort_by",
    "group_by",
    "partition",
    "min_by",
    "max_by",
    "sum",
    "times",
    "filter_map",
    "each_slice",
    "each_cons",
];

/// Calls that add their last argument to what they're called on.
const ADDERS: &[&str] = &[
    "push", "append", "concat", "prepend", "insert", "unshift", "add", "store", "update", "merge!",
    "replace", "<<", "write",
];

/// Calls that test a value, by kind: what they say about it makes it
/// validated.
fn check_names(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Path | SinkKind::Redirect | SinkKind::Ssrf => &[
            "include?",
            "member?",
            "in?",
            "start_with?",
            "end_with?",
            "match?",
            "key?",
            "has_key?",
            "valid?",
        ],
        _ => &[
            "include?", "member?", "in?", "match?", "key?", "has_key?", "valid?",
        ],
    }
}

/// A method whose name says it checks its argument.
fn is_a_check_by_name(name: &str) -> bool {
    // It marks text safe; it doesn't test it.
    name != "html_safe"
        && names_a_check(
            name,
            &[
                "valid",
                "safe",
                "allowed",
                "sanitized",
                "verified",
                "permitted",
            ],
            &["sanitiz", "allowlist", "whitelist"],
        )
}

/// The methods that make a value safe for where it goes, by kind (those that
/// make a number are in `SAFE_METHODS`).
fn sanitizers(kind: SinkKind) -> &'static [&'static str] {
    match kind {
        SinkKind::Sql => &[
            "quote",
            "quote_string",
            "quote_column_name",
            "quote_table_name",
            "sanitize_sql",
            "sanitize_sql_array",
            "sanitize_sql_for_conditions",
            "sanitize_sql_for_assignment",
            "sanitize_sql_like",
            "escape_string",
        ],
        SinkKind::Command => &["shellescape", "shelljoin"],
        SinkKind::Path => &["basename", "sanitize_filename"],
        SinkKind::Html => &[
            "h",
            "j",
            "html_escape",
            "html_escape_once",
            "escapeHTML",
            "escape_html",
            "sanitize",
            "strip_tags",
            "escape_javascript",
            "simple_format",
            "sanitize_html",
        ],
        _ => &[],
    }
}

/// `Shellwords.escape(x)`: a method that is a sanitizer only on its own
/// class.
fn is_a_class_sanitizer(kind: SinkKind, receiver: &str, name: &str) -> bool {
    match kind {
        SinkKind::Command => receiver.ends_with("Shellwords") && matches!(name, "escape" | "join"),
        SinkKind::Html => {
            receiver.ends_with("CGI") && name == "escapeHTML"
                || receiver.ends_with("Util") && matches!(name, "h" | "html_escape")
                || receiver.ends_with("Utils") && name == "escape_html"
        }
        SinkKind::Sql => name == "escape" && !receiver.is_empty(),
        _ => false,
    }
}

// ---------------------------------------------------------------- context

struct Cx<'a, 't> {
    m: &'a Model<'t>,
    src: &'a [u8],
    kind: SinkKind,
    by_node: HashMap<usize, DeclId>,
    /// Each class's `@name`, as a variable of its own.
    props: HashMap<(String, String), DeclId>,
    property_nodes: HashMap<usize, DeclId>,
    /// The classes of the file: what a call to a method it inherits calls.
    index: ClassIndex,
    /// Variables a check reads as validating, for this kind of sink.
    checked: HashSet<DeclId>,
    /// Expressions a check tested that no variable holds: `params[:t]` in
    /// `ALLOWED.include?(params[:t])`, read the same way after it.
    checked_exprs: HashSet<String>,
    writes: Vec<Write<'t>>,
    calls: Vec<Node<'t>>,
    /// Each method's name and its class's, by its index in the model's
    /// functions, and the methods by name.
    names: Vec<String>,
    classes: Vec<String>,
    by_name: HashMap<String, Vec<usize>>,
    evaluations: Cell<u64>,
    summaries: Summaries<SummaryKey, Summary<'t>>,
    from_calls: Cell<bool>,
    return_facts: RefCell<Vec<ReturnFact<'t>>>,
    keys: OnceCell<Vec<Option<Key>>>,
    callees: RefCell<HashMap<usize, Option<Callee>>>,
    /// The method of the file each call calls, worked out once per call.
    locals: RefCell<HashMap<usize, Option<usize>>>,
}

impl<'a, 't> Cx<'a, 't> {
    fn new(m: &'a Model<'t>, src: &'a [u8], kind: SinkKind, root: Node<'t>) -> Option<Self> {
        let mut cx = Cx {
            m,
            src,
            kind,
            by_node: decl_index(m),
            props: HashMap::new(),
            property_nodes: HashMap::new(),
            index: ClassIndex::default(),
            checked: HashSet::new(),
            checked_exprs: HashSet::new(),
            writes: Vec::new(),
            calls: Vec::new(),
            names: Vec::new(),
            classes: Vec::new(),
            by_name: HashMap::new(),
            evaluations: Cell::new(0),
            summaries: Summaries::new(MAX_SUMMARIES),
            from_calls: Cell::new(false),
            return_facts: RefCell::new(Vec::new()),
            keys: OnceCell::new(),
            callees: RefCell::new(HashMap::new()),
            locals: RefCell::new(HashMap::new()),
        };
        cx.properties(root);
        cx.collect(root)?;
        cx.index();
        Some(cx)
    }

    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// The methods of the file by name and class.
    fn index(&mut self) {
        for f in &self.m.functions {
            let name = f
                .node
                .child_by_field_name("name")
                .map_or(String::new(), |n| self.text(n).to_string());
            self.classes
                .push(enclosing_class(f.node, self.src).unwrap_or_default());
            self.names.push(name);
        }
        for (j, name) in self.names.iter().enumerate() {
            if !name.is_empty() {
                self.by_name.entry(name.clone()).or_default().push(j);
            }
        }
    }

    // -------------------------------------------------------- variables

    /// The variable `@name` is, for each class that names it.
    fn properties(&mut self, root: Node<'t>) {
        let mut found: Vec<Node<'t>> = Vec::new();
        let mut classes: Vec<ClassFact> = Vec::new();
        let _ = walk(root, |n| {
            if n.kind() == "instance_variable" {
                found.push(n);
            }
            classes.extend(class_fact(n, self.src));
            found.len() <= MAX_WRITES
        });
        self.index = ClassIndex::new(classes);
        for n in found {
            let key = (
                enclosing_class(n, self.src).unwrap_or_default(),
                self.text(n).to_string(),
            );
            let next = self.m.decls.len() + self.props.len();
            let id = *self.props.entry(key).or_insert(next);
            self.property_nodes.insert(n.id(), id);
        }
    }

    /// The declaration `n` names, as a declaration or as a reference; the
    /// variable `@name` is.
    fn decl_of(&self, n: Node<'t>) -> Option<DeclId> {
        match n.kind() {
            "identifier" => self
                .by_node
                .get(&n.id())
                .copied()
                .or_else(|| self.m.decl_id_of(n)),
            "instance_variable" => self.property_nodes.get(&n.id()).copied(),
            _ => None,
        }
    }

    /// The variable an expression names, and the node that names it: through
    /// `a[..]`, `a.b` and `a.m(..)`.
    fn base_of(&self, n: Node<'t>) -> Option<(DeclId, Node<'t>)> {
        let mut n = n;
        for _ in 0..16 {
            match n.kind() {
                "identifier" | "instance_variable" => return Some((self.decl_of(n)?, n)),
                "parenthesized_statements" => n = n.named_child(0)?,
                "element_reference" => n = n.child_by_field_name("object")?,
                "call" => n = n.child_by_field_name("receiver")?,
                _ => return None,
            }
        }
        None
    }

    // -------------------------------------------------------- writes

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
        for call in checks {
            let mut named = arguments(call);
            named.extend(call.child_by_field_name("receiver"));
            for v in named {
                match self.checked_variable(v) {
                    Some(d) => {
                        self.checked.insert(d);
                    }
                    None if matches!(v.kind(), "element_reference" | "call") => {
                        self.checked_exprs.insert(squeezed(self.text(v)));
                    }
                    None => {}
                }
            }
        }
        Some(())
    }

    /// Records what one node writes, calls or checks.
    fn visit(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        match n.kind() {
            "assignment" => self.assignment(n, How::Assigned),
            "operator_assignment" => {
                let how = match n
                    .child_by_field_name("operator")
                    .map_or("", |o| self.text(o))
                {
                    "||=" | "&&=" => How::Assigned,
                    "+=" | "<<=" if self.appends() => How::Added,
                    _ => return,
                };
                self.assignment(n, how);
            }
            "binary" => self.binary(n),
            "for" => {
                if let (Some(p), Some(v)) = (
                    n.child_by_field_name("pattern"),
                    n.child_by_field_name("value"),
                ) {
                    for t in targets(p) {
                        self.write_to(t, v, How::Read);
                    }
                }
            }
            "case" => self.case(n),
            "call" => self.call(n, words, checks),
            "subshell" => self.calls.push(n),
            _ => {}
        }
    }

    /// Whether adding to a string can change what it means: not for an
    /// address, whose start is what decides where it goes.
    fn appends(&self) -> bool {
        !matches!(self.kind, SinkKind::Redirect | SinkKind::Ssrf)
    }

    fn write(&mut self, target: DeclId, target_node: Node<'t>, value: Node<'t>, how: How) {
        self.writes.push(Write {
            target,
            target_node,
            value,
            how,
        });
    }

    /// `a = v`, `a[i] = v`, `a, b = v`: each variable gets the value.
    fn assignment(&mut self, n: Node<'t>, how: How) {
        let (Some(left), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
        ) else {
            return;
        };
        self.sanitizes_itself(left, right);
        let how = match left.kind() {
            "element_reference" => How::Added,
            "left_assignment_list" | "destructured_left_assignment" => How::Read,
            _ => how,
        };
        for t in targets(left) {
            self.write_to(t, right, how);
        }
    }

    fn write_to(&mut self, target: Node<'t>, value: Node<'t>, how: How) {
        if let Some((d, node)) = self.base_of(target) {
            self.write(d, node, value, how);
        }
    }

    /// `s << v`: the string or array holds the value.
    fn binary(&mut self, n: Node<'t>) {
        let (Some(l), Some(r), Some(op)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("right"),
            n.child_by_field_name("operator"),
        ) else {
            return;
        };
        match self.text(op) {
            "<<" if self.appends() => self.write_to(l, r, How::Added),
            "==" | "===" | "!=" if !matches!(self.kind, SinkKind::Sql) => {
                for side in [l, r] {
                    if let Some(d) = self.checked_variable(side) {
                        self.checked.insert(d);
                    }
                }
            }
            "=~" | "!~" => {
                for side in [l, r] {
                    if let Some(d) = self.checked_variable(side) {
                        self.checked.insert(d);
                    }
                }
            }
            _ => {}
        }
    }

    /// `case x when 'a', 'b'`: `x` is one of the values written out.
    fn case(&mut self, n: Node<'t>) {
        if let Some(d) = n
            .child_by_field_name("value")
            .and_then(|v| self.checked_variable(v))
        {
            self.checked.insert(d);
        }
    }

    /// The variable a test is about: `x` in `x.include?`, `x[0]`,
    /// `x.strip`, `x.to_s`.
    fn checked_variable(&self, n: Node<'t>) -> Option<DeclId> {
        let mut n = n;
        for _ in 0..8 {
            match n.kind() {
                "identifier" | "instance_variable" => return self.decl_of(n),
                "parenthesized_statements" => n = n.named_child(0)?,
                "element_reference" => n = n.child_by_field_name("object")?,
                "call" => n = n.child_by_field_name("receiver")?,
                _ => return None,
            }
        }
        None
    }

    /// `v = v.to_i`, `v = Shellwords.escape(v)`: a variable the program
    /// passes through what makes it safe for where it goes is taken as
    /// validated, wherever it's read: the flow-insensitive model can't tell
    /// the line before from the line after.
    fn sanitizes_itself(&mut self, left: Node<'t>, right: Node<'t>) {
        let Some(d) = self.decl_of(left) else {
            return;
        };
        let mut sanitized = false;
        walk_nodes(right, &mut |c| {
            if c.kind() != "call" {
                return;
            }
            let (name, receiver) = (call_name(c, self.src), receiver_text(c, self.src));
            let makes_safe = name.is_some_and(|f| {
                SAFE_METHODS.contains(&f)
                    || sanitizers(self.kind).contains(&f)
                    || is_a_class_sanitizer(self.kind, receiver.unwrap_or(""), f)
            });
            let mentions = c
                .child_by_field_name("receiver")
                .into_iter()
                .chain(arguments(c))
                .any(|a| self.checked_variable(a) == Some(d));
            sanitized |= makes_safe && mentions;
        });
        if sanitized {
            self.checked.insert(d);
        }
    }

    /// A call: the check it may be, what it writes into its receiver, and
    /// what its block's parameters hold.
    fn call(&mut self, n: Node<'t>, words: &[&str], checks: &mut Vec<Node<'t>>) {
        self.calls.push(n);
        let Some(name) = call_name(n, self.src) else {
            return;
        };
        if words.contains(&name) || is_a_check_by_name(name) {
            checks.push(n);
        }
        let receiver = n.child_by_field_name("receiver");
        if ADDERS.contains(&name)
            && self.appends()
            && let (Some(r), Some(v)) = (receiver, arguments(n).last().copied())
        {
            self.write_to(r, v, How::Added);
        }
        if ITERATORS.contains(&name)
            && let (Some(r), Some(block)) = (receiver, n.child_by_field_name("block"))
            && let Some(list) = block.child_by_field_name("parameters")
        {
            let mut c = list.walk();
            let params: Vec<Node<'t>> = list.named_children(&mut c).collect();
            for p in params {
                let name = if p.kind() == "identifier" {
                    Some(p)
                } else {
                    p.child_by_field_name("name")
                };
                if let Some((d, node)) = name.and_then(|p| Some((self.decl_of(p)?, p))) {
                    self.write(d, node, r, How::Read);
                }
            }
        }
    }

    // -------------------------------------------------------- reading

    fn expression(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        next: u32,
    ) -> Option<Path<'t>> {
        if matches!(n.kind(), "element_reference" | "call")
            && !self.checked_exprs.is_empty()
            && self.checked_exprs.contains(&squeezed(self.text(n)))
        {
            return None;
        }
        match n.kind() {
            "identifier" => self.identifier_taint(n, state, next),
            "instance_variable" => held(self.decl_of(n), &self.checked, state),
            "string" | "subshell" => self.string_taint(n, state, next),
            "interpolation"
            | "array"
            | "hash"
            | "argument_list"
            | "splat_argument"
            | "hash_splat_argument"
            | "right_assignment_list"
            | "chained_string" => best(
                named_children(n)
                    .into_iter()
                    .map(|c| self.taint(c, state, next)),
            ),
            "pair" => self.taint(n.child_by_field_name("value")?, state, next),
            "element_reference" => self.taint(n.child_by_field_name("object")?, state, next),
            "binary" => self.binary_taint(n, state, next),
            "conditional" | "if" | "unless" | "elsif" => {
                best_of(n, &["consequence", "alternative"], |c| {
                    self.taint(c, state, next)
                })
            }
            "if_modifier" | "unless_modifier" => {
                self.taint(n.child_by_field_name("body")?, state, next)
            }
            "case" => best(
                named_children(n)
                    .into_iter()
                    .filter_map(|c| match c.kind() {
                        "when" => c.child_by_field_name("body"),
                        "else" => Some(c),
                        _ => None,
                    })
                    .map(|c| self.taint(c, state, next)),
            ),
            "then" | "else" | "body_statement" | "begin" | "parenthesized_statements" => {
                self.taint(last_statement(n)?, state, next)
            }
            "assignment" | "operator_assignment" => {
                self.taint(n.child_by_field_name("right")?, state, next)
            }
            "rescue_modifier" => best(
                named_children(n)
                    .into_iter()
                    .map(|c| self.taint(c, state, next)),
            ),
            "call" => self.call_taint(n, state, next),
            _ => None,
        }
    }

    /// A name: a variable's value, `params` or `cookies`, or a method of the
    /// file called with no arguments.
    fn identifier_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        if let Some(d) = self.decl_of(n) {
            return held(Some(d), &self.checked, state);
        }
        let name = self.text(n);
        if matches!(name, "params" | "cookies") {
            return Some(source_step(n, name));
        }
        self.through_function(n, &[], state, depth)
    }

    fn string_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let parts = named_children(n);
        if self.starts_the_text() {
            let start = parts
                .first()
                .filter(|p| p.kind() == "string_content")
                .map(|p| self.text(*p));
            // A string that starts with a value: that value decides.
            return address_path(&parts, start, |o| self.taint(o, state, depth));
        }
        best(parts.into_iter().map(|c| self.taint(c, state, depth)))
    }

    fn binary_taint(
        &self,
        n: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let op = n
            .child_by_field_name("operator")
            .map_or("", |o| self.text(o));
        match op {
            "+" if self.starts_the_text() => {
                let mut operands = Vec::new();
                concatenation(n, self.src, &mut operands);
                let start = operands.first().and_then(|o| self.literal(*o));
                address_path(&operands, start, |o| self.taint(o, state, depth))
            }
            "+" | "<<" | "%" | "||" | "or" => {
                best_of(n, &["left", "right"], |c| self.taint(c, state, depth))
            }
            "&&" | "and" => self.taint(n.child_by_field_name("right")?, state, depth),
            _ => None,
        }
    }

    /// The text of a string written out, without interpolation.
    fn literal(&self, n: Node<'t>) -> Option<&'a str> {
        let mut c = n.walk();
        (n.kind() == "string"
            && n.named_children(&mut c)
                .all(|k| k.kind() != "interpolation"))
        .then(|| self.text(n).trim_matches(['\'', '"']))
    }

    /// What `a.m(..)` and `m(..)` return: what a source gives, the value of
    /// what it's called on, the text of an argument for the methods that
    /// join them, or what a method of the file returns.
    fn call_taint(
        &self,
        call: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
        depth: u32,
    ) -> Option<Path<'t>> {
        let name = call_name(call, self.src)?;
        let receiver = call.child_by_field_name("receiver");
        let args = arguments(call);
        let receiver_name = receiver_text(call, self.src).unwrap_or("");
        if let Some(r) = receiver
            && self.is_request(r)
            && REQUEST_METHODS.contains(&name)
        {
            // The app's own path can't change where a redirect goes.
            let own = matches!(
                name,
                "path" | "fullpath" | "path_info" | "original_fullpath" | "host"
            );
            return (!(own && matches!(self.kind, SinkKind::Redirect)))
                .then(|| source_step(call, name));
        }
        // An upload's `path` is the server's own file.
        let upload = name == "tempfile" || (name == "path" && receiver_name.starts_with("params["));
        if upload
            || SAFE_METHODS.contains(&name)
            || sanitizers(self.kind).contains(&name)
            || is_a_class_sanitizer(self.kind, receiver_name, name)
        {
            return None;
        }
        if self.local_callee(call).is_some() {
            return self.through_function(call, &args, state, depth);
        }
        if let Some(r) = receiver
            && let Some(path) = self.taint(r, state, depth)
        {
            return Some(path);
        }
        if matches!(name, "format" | "sprintf") && self.starts_the_text() {
            return self.format_taint(&args, state, depth);
        }
        if ARGUMENT_METHODS.contains(&name) {
            return best(args.iter().map(|a| self.taint(*a, state, depth)));
        }
        self.through_function(call, &args, state, depth)
    }

    /// Whether `n` is the request, or part of it: `request`, `request.env`.
    fn is_request(&self, n: Node<'t>) -> bool {
        n.kind() == "identifier" && self.text(n) == "request" && self.decl_of(n).is_none()
    }

    // -------------------------------------------------------- sinks

    /// The call that is a sink for this kind, and the arguments whose value
    /// it takes as what injects.
    fn sink_call(&self, n: Node<'t>) -> Option<(String, Vec<Node<'t>>)> {
        if n.kind() == "subshell" {
            return matches!(self.kind, SinkKind::Command).then(|| ("`...`".to_string(), vec![n]));
        }
        let name = call_name(n, self.src)?;
        let receiver = receiver_text(n, self.src);
        let args = arguments(n);
        let positional: Vec<Node<'t>> = args
            .iter()
            .copied()
            .filter(|a| !matches!(a.kind(), "pair" | "block_argument" | "hash_splat_argument"))
            .collect();
        let taken = match self.kind {
            SinkKind::Sql => self.sql_args(name, receiver, &args, &positional),
            SinkKind::Command => command_args(name, receiver, &positional),
            SinkKind::Path => self.path_args(n, name, receiver, &positional),
            SinkKind::Redirect => self.redirect_args(n, name, receiver, &args),
            SinkKind::Ssrf => self.ssrf_args(name, receiver, &args, &positional),
            SinkKind::Code => self.code_args(n, name, receiver, &args, &positional),
            SinkKind::Html => self.html_args(n, name, receiver, &positional),
            _ => Vec::new(),
        };
        (!taken.is_empty()).then(|| (name.to_string(), taken))
    }

    fn sql_args(
        &self,
        name: &str,
        receiver: Option<&str>,
        args: &[Node<'t>],
        positional: &[Node<'t>],
    ) -> Vec<Node<'t>> {
        // What an Active Record model or relation is called with.
        let relation = matches!(
            name,
            "where"
                | "find_by_sql"
                | "order"
                | "reorder"
                | "group"
                | "having"
                | "joins"
                | "pluck"
                | "from"
                | "delete_all"
                | "update_all"
                | "count_by_sql"
                | "find_by"
        );
        // What a connection is called with: `Search.execute` isn't one.
        let connection = matches!(
            name,
            "execute"
                | "exec_query"
                | "select_all"
                | "select_one"
                | "select_value"
                | "select_rows"
                | "query"
                | "exec_params"
                | "exec"
        ) && receiver.is_none_or(|r| {
            let lower = r.to_ascii_lowercase();
            ["conn", "db", "client", "sql", "pg", "adapter"]
                .iter()
                .any(|w| lower.contains(w))
        });
        // `where(name: x)` and `where(attributes)` bind their values.
        match (relation || connection, args.first(), positional.first()) {
            (true, Some(first), Some(p)) if first.id() == p.id() && !self.is_collection(*p) => {
                vec![*p]
            }
            _ => Vec::new(),
        }
    }

    /// Whether a variable holds a hash or an array: handed whole to a query,
    /// its values are bound.
    fn is_collection(&self, n: Node<'t>) -> bool {
        let hash_call = |v: Node<'t>| {
            matches!(v.kind(), "hash" | "array" | "pair")
                || call_name(v, self.src).is_some_and(|c| {
                    matches!(
                        c,
                        "permit"
                            | "slice"
                            | "except"
                            | "to_h"
                            | "to_unsafe_h"
                            | "merge"
                            | "require"
                    )
                })
        };
        if hash_call(n) {
            return true;
        }
        let Some(d) = self.decl_of(n) else {
            return false;
        };
        self.writes
            .iter()
            .any(|w| w.target == d && w.how == How::Assigned && hash_call(w.value))
    }

    fn path_args(
        &self,
        call: Node<'t>,
        name: &str,
        receiver: Option<&str>,
        positional: &[Node<'t>],
    ) -> Vec<Node<'t>> {
        let first = positional.first().copied();
        match receiver {
            Some("File" | "IO" | "FileUtils" | "Pathname" | "Dir") => match name {
                "read" | "readlines" | "binread" | "write" | "binwrite" | "open" | "new"
                | "delete" | "unlink" | "rm" | "rm_f" | "rm_r" | "rm_rf" | "foreach"
                | "entries" | "glob" | "chmod" | "mkdir" | "mkdir_p" | "touch" | "readlink"
                | "stat" | "size" | "exist?" | "file?" | "directory?" | "children" => {
                    first.into_iter().collect()
                }
                "cp" | "cp_r" | "mv" | "copy_file" | "rename" | "symlink" | "ln_s" | "link" => {
                    positional.iter().take(2).copied().collect()
                }
                _ => Vec::new(),
            },
            None => match name {
                "send_file" | "open" | "require" | "load" => first.into_iter().collect(),
                "render" => pair_value(call, self.src, &["file", "template"]),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        }
    }

    fn redirect_args(
        &self,
        call: Node<'t>,
        name: &str,
        receiver: Option<&str>,
        args: &[Node<'t>],
    ) -> Vec<Node<'t>> {
        let text = self.text(call);
        if receiver.is_some()
            || !matches!(name, "redirect_to" | "redirect")
            || text.contains("only_path")
            // The option says the program decided.
            || text.contains("allow_other_host")
        {
            return Vec::new();
        }
        args.first()
            .filter(|a| !matches!(a.kind(), "pair" | "hash"))
            .copied()
            .into_iter()
            .collect()
    }

    fn ssrf_args(
        &self,
        name: &str,
        receiver: Option<&str>,
        args: &[Node<'t>],
        positional: &[Node<'t>],
    ) -> Vec<Node<'t>> {
        let Some(receiver) = receiver else {
            return Vec::new();
        };
        let client = matches!(
            receiver,
            "HTTParty" | "RestClient" | "Faraday" | "Typhoeus" | "Excon" | "HTTP" | "Curl"
        ) && matches!(
            name,
            "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "request" | "new"
        );
        let net = receiver == "Net::HTTP"
            && matches!(
                name,
                "get" | "get_response" | "post" | "post_form" | "start" | "new" | "get_print"
            );
        let open = receiver == "URI" && matches!(name, "open" | "read");
        if !(client || net || open) {
            return Vec::new();
        }
        let mut taken: Vec<Node<'t>> = positional.iter().take(1).copied().collect();
        taken.extend(
            args.iter()
                .filter(|a| a.kind() == "pair")
                .filter(|a| {
                    a.child_by_field_name("key")
                        .is_some_and(|k| matches!(self.text(k).trim_matches(':'), "url" | "uri"))
                })
                .filter_map(|a| a.child_by_field_name("value")),
        );
        taken
    }

    fn code_args(
        &self,
        call: Node<'t>,
        name: &str,
        receiver: Option<&str>,
        args: &[Node<'t>],
        positional: &[Node<'t>],
    ) -> Vec<Node<'t>> {
        let first = positional.first().copied();
        let none = Vec::new;
        match name {
            "eval" if receiver.is_none() || receiver == Some("Kernel") => {
                first.into_iter().collect()
            }
            "instance_eval" | "class_eval" | "module_eval"
                if call.child_by_field_name("block").is_none() =>
            {
                first.into_iter().collect()
            }
            "send"
            | "public_send"
            | "__send__"
            | "const_get"
            | "instance_variable_get"
            | "instance_variable_set" => first.into_iter().collect(),
            "constantize" | "safe_constantize" => {
                call.child_by_field_name("receiver").into_iter().collect()
            }
            "new" if receiver == Some("ERB") => first.into_iter().collect(),
            "load" | "unsafe_load" | "restore"
                if matches!(receiver, Some("YAML" | "Psych" | "Marshal")) =>
            {
                first.into_iter().collect()
            }
            "render" if receiver.is_none() => pair_value(call, self.src, &["inline"]),
            _ => {
                let _ = args;
                none()
            }
        }
    }

    fn html_args(
        &self,
        call: Node<'t>,
        name: &str,
        receiver: Option<&str>,
        positional: &[Node<'t>],
    ) -> Vec<Node<'t>> {
        match name {
            "raw" if receiver.is_none() => positional.first().copied().into_iter().collect(),
            "html_safe" => call.child_by_field_name("receiver").into_iter().collect(),
            _ => Vec::new(),
        }
    }

    // -------------------------------------------------------- methods

    /// What a call calls: the method's name, its class, and whether it's the
    /// class's own. On nothing or `self` it's a method of the class the call
    /// is in; on a class (`Users.find`, `Users.new`) one of that class; on a
    /// variable made by `Users.new`, an instance method of it.
    fn call_target(&self, call: Node<'t>) -> Option<(String, String, bool)> {
        let here = || Some((enclosing_class(call, self.src)?, singleton_context(call)));
        if call.kind() == "identifier" {
            let (class, own) = here()?;
            return Some((self.text(call).to_string(), class, own));
        }
        let name = call_name(call, self.src)?;
        let receiver = call.child_by_field_name("receiver");
        let Some(r) = receiver.filter(|r| r.kind() != "self") else {
            let (class, own) = here()?;
            return Some((name.to_string(), class, own));
        };
        let written = self.text(r);
        if r.kind() == "identifier" {
            return Some((name.to_string(), self.inferred_class(r)?, false));
        }
        if !matches!(r.kind(), "constant" | "scope_resolution") {
            return None;
        }
        let class = last_name(written).to_string();
        // `Users.new(x)` runs `initialize`.
        Some(if name == "new" {
            ("initialize".to_string(), class, false)
        } else {
            (name.to_string(), class, true)
        })
    }

    /// The class of a variable made by `x = Users.new(..)`.
    fn inferred_class(&self, v: Node<'t>) -> Option<String> {
        let d = self.decl_of(v)?;
        let value = self
            .m
            .decls
            .get(d)?
            .declarator
            .filter(|a| a.kind() == "assignment")?
            .child_by_field_name("right")?;
        let made = call_name(value, self.src) == Some("new");
        let class = value.child_by_field_name("receiver")?;
        (made && matches!(class.kind(), "constant" | "scope_resolution"))
            .then(|| last_name(self.text(class)).to_string())
    }

    /// The method of the file a call calls, if there is exactly one: in the
    /// class, or the nearest class or module of the file it inherits it from.
    fn local_callee(&self, call: Node<'t>) -> Option<usize> {
        if let Some(known) = self.locals.borrow().get(&call.id()) {
            return *known;
        }
        let found = self.find_local_callee(call);
        self.locals.borrow_mut().insert(call.id(), found);
        found
    }

    fn find_local_callee(&self, call: Node<'t>) -> Option<usize> {
        let (name, class, own) = self.call_target(call)?;
        // Outside every class, a method is the file's own.
        let (class, own) = if class.is_empty() {
            (class, own)
        } else {
            self.index.defining(&class, &name, own)?
        };
        let arity = arguments(call).len();
        let candidates: Vec<usize> = self
            .by_name
            .get(&name)?
            .iter()
            .copied()
            .filter(|&j| {
                let f = &self.m.functions[j];
                self.classes[j] == class
                    && singleton_context(f.node) == own
                    && arity <= f.params.len()
            })
            .collect();
        match candidates.as_slice() {
            [only] => Some(*only),
            _ => None,
        }
    }

    /// The method of another file a call calls: by its class, and the
    /// project pass finds where the class or what it inherits defines it.
    fn find_external_callee(&self, call: Node<'t>) -> Option<Callee> {
        if self.local_callee(call).is_some() {
            return None;
        }
        let (name, class, singleton) = self.call_target(call)?;
        // On nothing, a method of another file is one the class inherits.
        let on_nothing = call.kind() == "identifier"
            || call
                .child_by_field_name("receiver")
                .is_none_or(|r| r.kind() == "self");
        if class.is_empty()
            || (on_nothing && !self.index.inherits(&class))
            || (!on_nothing && is_library(self.text(call.child_by_field_name("receiver")?)))
        {
            return None;
        }
        Some(Callee::Ruby {
            class: Some(class),
            name,
            singleton,
        })
    }

    /// Whether another file gains from what a method does with its parameter
    /// `p`: not when its name is written once, where it's declared.
    fn exports_a_param(&self, j: usize, p: usize) -> bool {
        let f = &self.m.functions[j];
        let text = self.text(f.node);
        f.params.get(p).is_none_or(|ds| {
            ds.iter().any(|&d| {
                let name = &self.m.decls[d].name;
                text.matches(name.as_str()).count() > 1
            })
        })
    }

    fn exports_a_return(&self, _j: usize) -> bool {
        true
    }

    /// What other files call a method by: `Users#find`, `Users.find`.
    fn raw_key(&self, j: usize) -> Option<Key> {
        let f = &self.m.functions[j];
        let name = &self.names[j];
        let splat = f.node.child_by_field_name("parameters").is_some_and(|p| {
            named_children(p)
                .iter()
                .any(|c| matches!(c.kind(), "splat_parameter" | "hash_splat_parameter"))
        });
        if name.is_empty() || splat {
            return None;
        }
        let class = &self.classes[j];
        let export = if class.is_empty() {
            name.clone()
        } else {
            let sep = if singleton_context(f.node) { '.' } else { '#' };
            format!("{class}{sep}{name}")
        };
        Some(Key {
            export,
            member: None,
        })
    }
}

flow_for!(Cx, from_call);
locals_for!(Cx);
evaluation_for!(Cx);
function_keys_for!(Cx);
externals_for!(Cx);
exports_for!(Cx, exports_a_param, exports_a_return);

fn never<'a, 't>(_: &Cx<'a, 't>, _: DeclId) -> bool {
    false
}

summarize_for!(
    Cx,
    &["method", "singleton_method", "class", "module"],
    never,
    "return",
    Some(implicit_return)
);

// ---------------------------------------------------------------- syntax

/// The value a method returns when it says no `return` for it: its last
/// statement.
fn implicit_return<'t>(function: Node<'t>) -> Option<Node<'t>> {
    let body = function.child_by_field_name("body")?;
    if body.kind() == "body_statement" {
        last_statement(body)
    } else {
        Some(body)
    }
}

/// The last statement of a block, not a comment or a clause.
fn last_statement<'t>(n: Node<'t>) -> Option<Node<'t>> {
    named_children(n)
        .into_iter()
        .rev()
        .find(|c| {
            !matches!(
                c.kind(),
                "comment" | "rescue" | "ensure" | "else" | "empty_statement"
            )
        })
        .or_else(|| (n.kind() == "else").then_some(n))
}

fn source_step<'t>(n: Node<'t>, name: &str) -> Path<'t> {
    vec![Step {
        node: n,
        message: format!("read from the request: `{name}`"),
    }]
}

/// The variables an assignment's left side writes (see the binder).
fn targets<'t>(left: Node<'t>) -> Vec<Node<'t>> {
    match left.kind() {
        // `obj.attr = v` sets an attribute: the object isn't text.
        "identifier" | "instance_variable" | "element_reference" => vec![left],
        "left_assignment_list" | "destructured_left_assignment" | "rest_assignment" => {
            named_children(left).into_iter().flat_map(targets).collect()
        }
        _ => Vec::new(),
    }
}

/// The name a call calls.
fn call_name<'a>(call: Node, src: &'a [u8]) -> Option<&'a str> {
    if call.kind() != "call" {
        return None;
    }
    call.child_by_field_name("method")?.utf8_text(src).ok()
}

/// The text of what a call is made on.
fn receiver_text<'a>(call: Node, src: &'a [u8]) -> Option<&'a str> {
    call.child_by_field_name("receiver")?.utf8_text(src).ok()
}

/// A call's arguments: its keyword arguments are `pair`s.
fn arguments(call: Node) -> Vec<Node> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    named_children(list)
        .into_iter()
        .filter(|a| a.kind() != "comment")
        .collect()
}

/// The values of a call's keyword arguments named `keys`: `file: x`.
fn pair_value<'t>(call: Node<'t>, src: &[u8], keys: &[&str]) -> Vec<Node<'t>> {
    arguments(call)
        .into_iter()
        .filter(|a| a.kind() == "pair")
        .filter(|a| {
            a.child_by_field_name("key").is_some_and(|k| {
                let t = std::str::from_utf8(&src[k.byte_range()]).unwrap_or_default();
                keys.contains(&t.trim_matches(':'))
            })
        })
        .filter_map(|a| a.child_by_field_name("value"))
        .collect()
}

/// A command run by a call that goes through a shell: `system("ls #{d}")`,
/// not `system("ls", d)`.
fn command_args<'t>(name: &str, receiver: Option<&str>, positional: &[Node<'t>]) -> Vec<Node<'t>> {
    let shell = match receiver {
        None | Some("Kernel") => matches!(name, "system" | "exec" | "spawn"),
        Some("IO") => name == "popen",
        Some("Open3") => {
            name.starts_with("capture") || name.starts_with("popen") || name.starts_with("pipeline")
        }
        Some("PTY") => name == "spawn",
        _ => false,
    };
    let commands: Vec<Node<'t>> = positional
        .iter()
        .copied()
        .filter(|a| a.kind() != "hash")
        .collect();
    match commands.as_slice() {
        [only] if shell && only.kind() != "array" => vec![*only],
        _ => Vec::new(),
    }
}

/// Text without whitespace, to tell two spellings of one expression.
fn squeezed(t: &str) -> String {
    t.chars().filter(|c| !c.is_whitespace()).collect()
}

fn named_children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// The operands of a chain of `+`, left to right.
fn concatenation<'t>(n: Node<'t>, src: &[u8], out: &mut Vec<Node<'t>>) {
    let is_plus = |x: Node| {
        x.kind() == "binary"
            && x.child_by_field_name("operator")
                .is_some_and(|o| src.get(o.byte_range()) == Some(b"+".as_slice()))
    };
    if is_plus(n) {
        for side in ["left", "right"] {
            if let Some(c) = n.child_by_field_name(side) {
                concatenation(c, src, out);
            }
        }
    } else {
        out.push(n);
    }
}

fn walk_nodes<'t>(n: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(n);
    let mut c = n.walk();
    for child in n.children(&mut c) {
        walk_nodes(child, f);
    }
}

/// The lowercase-insensitive last part of a class's name: `Admin::Users`.
fn last_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

/// Whether a class is Ruby's or a framework's own, which no file of the
/// project defines a method of.
fn is_library(class: &str) -> bool {
    let first = class
        .trim_start_matches("::")
        .split("::")
        .next()
        .unwrap_or("");
    matches!(
        first,
        "Rails"
            | "File"
            | "FileUtils"
            | "IO"
            | "Dir"
            | "Time"
            | "Date"
            | "DateTime"
            | "JSON"
            | "YAML"
            | "Psych"
            | "Marshal"
            | "Hash"
            | "Array"
            | "String"
            | "Integer"
            | "Float"
            | "Kernel"
            | "Process"
            | "ENV"
            | "Set"
            | "Regexp"
            | "Math"
            | "Logger"
            | "I18n"
            | "ActiveSupport"
            | "ActiveRecord"
            | "ActionController"
            | "ActionView"
            | "ActionMailer"
            | "ActiveModel"
            | "ActiveJob"
            | "Rack"
            | "Net"
            | "URI"
            | "CGI"
            | "ERB"
            | "Base64"
            | "Digest"
            | "OpenSSL"
            | "SecureRandom"
            | "Open3"
            | "Shellwords"
            | "Pathname"
            | "Thread"
            | "Mutex"
            | "Object"
            | "Class"
            | "Module"
            | "Struct"
            | "Gem"
    )
}

/// Whether `n` is in the class itself, not in its instances: in a `def
/// self.m`, or in `class << self`.
pub(crate) fn singleton_context(n: Node) -> bool {
    let mut p = Some(n);
    while let Some(a) = p {
        match a.kind() {
            "singleton_method" | "singleton_class" => return true,
            "class" | "module" => return false,
            _ => p = a.parent(),
        }
    }
    false
}

/// The name of the class or module around `n`, or `Some("")` outside any.
fn enclosing_class(n: Node, src: &[u8]) -> Option<String> {
    let mut p = n.parent();
    while let Some(a) = p {
        if matches!(a.kind(), "class" | "module") {
            let name = a.child_by_field_name("name")?;
            return Some(last_name(name.utf8_text(src).ok()?).to_string());
        }
        p = a.parent();
    }
    Some(String::new())
}

/// Whether a node builds text by joining: `is_built` for the labels of a
/// path.
fn is_built(n: Node) -> bool {
    matches!(n.kind(), "binary" | "string")
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::flagged_ruby as flagged;

    #[test]
    fn a_params_value_reaches_a_query_through_a_variable() {
        let src = "def show\n  id = params[:id]\n  User.where(\"id = #{id}\")\nend\n";
        assert_eq!(flagged("ruby/sql-injection", src), [3]);
        // Bound as a value, or turned into a number: safe.
        let src = "def show\n  User.where('id = ?', params[:id])\n  User.where(id: params[:id])\n  User.where(\"id = #{params[:id].to_i}\")\nend\n";
        assert!(flagged("ruby/sql-injection", src).is_empty());
    }

    #[test]
    fn the_request_object_and_the_cookies_are_sources() {
        let src = "def a\n  User.find_by_sql(\"x #{request.query_string}\")\n  User.order(cookies[:sort])\n  User.group(request.headers['X'])\nend\n";
        assert_eq!(flagged("ruby/sql-injection", src), [2, 3, 4]);
        // A method that isn't one of the request's reads isn't a source.
        let src = "def a\n  User.order(request.format)\nend\n";
        assert!(flagged("ruby/sql-injection", src).is_empty());
    }

    #[test]
    fn a_value_reaches_a_command_only_through_the_shell() {
        let src = "def a\n  host = params[:host]\n  system(\"ping #{host}\")\n  system('ping', host)\n  `ping #{host}`\n  system(\"ping #{Shellwords.escape(host)}\")\n  system(\"ping #{host.shellescape}\")\nend\n";
        assert_eq!(flagged("ruby/command-injection", src), [3, 5]);
    }

    #[test]
    fn a_path_from_params_unless_it_is_a_basename() {
        let src = "def a\n  f = params[:f]\n  File.read(File.join(DIR, f))\n  send_file f\n  File.read(File.join(DIR, File.basename(f)))\n  render file: f\nend\n";
        assert_eq!(flagged("ruby/path-injection", src), [3, 4, 6]);
    }

    #[test]
    fn only_the_start_of_an_address_sets_where_it_goes() {
        let src = "def a\n  redirect_to params[:u]\n  redirect_to \"/orders/#{params[:id]}\"\n  redirect_to \"https://#{params[:h]}/x\"\n  redirect_to params[:u], only_path: true\n  redirect_to root_url(params)\n  redirect_to request.referer\n  redirect_to request.path\n  redirect_to params[:u], allow_other_host: false\nend\n";
        assert_eq!(flagged("ruby/open-redirect", src), [2, 4, 7]);
        let src = "def a\n  Net::HTTP.get(URI(params[:u]))\n  Net::HTTP.get(URI(\"https://api/#{params[:q]}\"))\n  HTTParty.get(params[:u])\n  RestClient.get(\"/x\", params: params)\nend\n";
        assert_eq!(flagged("ruby/ssrf", src), [2, 4]);
    }

    #[test]
    fn code_and_pages() {
        let src = "def a\n  eval(params[:c])\n  params[:m].constantize\n  send(params[:m])\n  send(:run, params[:a])\n  obj.instance_eval(params[:c])\n  obj.instance_eval { params }\nend\n";
        assert_eq!(flagged("ruby/code-injection", src), [2, 3, 4, 6]);
        let src = "def a\n  raw(params[:h])\n  params[:h].html_safe\n  \"<b>#{params[:n]}</b>\".html_safe\n  raw(h(params[:h]))\n  raw(\"<b>\")\nend\n";
        assert_eq!(flagged("ruby/xss", src), [2, 3, 4]);
    }

    #[test]
    fn a_method_of_the_file_passes_the_value_on_and_returns_it() {
        let src = "class C\n  def a\n    run(params[:q])\n  end\n  def run(q)\n    system(\"x #{q}\")\n  end\nend\n";
        assert_eq!(flagged("ruby/command-injection", src), [6]);
        // The last expression is what a method returns.
        let src = "class C\n  def a\n    system(\"x #{q}\")\n  end\n  def q\n    params[:q]\n  end\nend\n";
        assert_eq!(flagged("ruby/command-injection", src), [3]);
        let src = "class C\n  def a\n    system(\"x #{q}\")\n  end\n  def q\n    params[:q].to_i\n  end\nend\n";
        assert!(flagged("ruby/command-injection", src).is_empty());
    }

    #[test]
    fn an_instance_variable_is_the_classs_from_one_method_to_another() {
        let src = "class C\n  def before\n    @q = params[:q]\n  end\n  def show\n    User.where(\"n = #{@q}\")\n  end\nend\nclass D\n  def show\n    User.where(\"n = #{@q}\")\n  end\nend\n";
        assert_eq!(flagged("ruby/sql-injection", src), [6]);
    }

    #[test]
    fn a_checked_value_is_validated() {
        let src = "def a\n  id = params[:id]\n  return unless ALLOWED.include?(id)\n  system(\"x #{id}\")\nend\ndef b\n  id = params[:id]\n  return unless id =~ /\\A\\d+\\z/\n  system(\"x #{id}\")\nend\ndef c\n  id = params[:id]\n  id = id.to_i\n  system(\"x #{id}\")\nend\ndef d\n  t = params[:t]\n  case t\n  when 'a', 'b' then system(\"x #{t}\")\n  end\nend\n";
        assert!(flagged("ruby/command-injection", src).is_empty());
    }

    #[test]
    fn what_an_expression_was_tested_as_is_validated_where_it_is_read_again() {
        let src = "def a\n  raise 'x' unless %w[a b].include?(params[:t])\n  send(\"#{params[:t]}_run\")\n  send(params[:u])\nend\n";
        assert_eq!(flagged("ruby/code-injection", src), [4]);
    }

    #[test]
    fn a_hash_handed_whole_to_a_query_binds_its_values_and_only_a_connection_executes() {
        let src = "def a(rel)
  attrs = {}
  attrs[:n] = params[:n]
  rel.where(attrs)
  rel.find_by(params.permit(:n))
  q = params[:q]
  rel.where(q)
  Search.execute(params[:t])
  conn.execute(params[:t])
  I18n.exists?(params[:id])
end
";
        assert_eq!(flagged("ruby/sql-injection", src), [7, 9]);
    }

    #[test]
    fn an_upload_has_a_path_of_its_own_and_an_address_has_a_start() {
        let src = "def a
  File.read(params[:file].path)
  File.read(params[:file].original_filename)
end
";
        assert_eq!(flagged("ruby/path-injection", src), [3]);
        // Adding to an address can't change where it goes; its start can.
        let src = "def a
  url = '/x'
  url += \"?#{request.query_string}\"\n  redirect_to url\n  u = params[:u]\n  u += '/more'\n  redirect_to u\nend\n";
        assert_eq!(flagged("ruby/open-redirect", src), [7]);
    }

    #[test]
    fn a_string_that_starts_with_a_value_is_decided_by_that_value() {
        let src = "def a\n  redirect_to \"#{base}/x/#{params[:t]}\"\n  redirect_to \"#{params[:t]}/x\"\n  redirect_to \"/x/#{params[:t]}\"\nend\n";
        assert_eq!(flagged("ruby/open-redirect", src), [3]);
    }

    // ---------------------------------------------------- inheritance

    #[test]
    fn a_method_a_class_inherits_or_includes_in_the_file() {
        let src = "module Runs\n  def run(c)\n    system(\"x #{c}\")\n  end\nend\nclass Base\n  def log(m)\n    system(\"echo #{m}\")\n  end\nend\nclass C < Base\n  include Runs\n  def a\n    log(params[:m])\n    run(params[:c])\n    self.class.zz(params[:z])\n  end\nend\n";
        assert_eq!(flagged("ruby/command-injection", src), [3, 8]);
    }

    #[test]
    fn an_override_is_the_method_called_and_new_runs_initialize() {
        let src = "class Base\n  def log(m)\n    system(\"echo #{m}\")\n  end\nend\nclass C < Base\n  def log(m)\n    nil\n  end\n  def a\n    log(params[:m])\n  end\nend\n";
        assert!(flagged("ruby/command-injection", src).is_empty());
        let src = "class Job\n  def initialize(cmd)\n    system(\"x #{cmd}\")\n  end\nend\ndef a\n  Job.new(params[:c])\nend\n";
        assert_eq!(flagged("ruby/command-injection", src), [3]);
    }

    #[test]
    fn a_method_of_the_class_itself_and_one_in_class_self() {
        let src = "class Shell\n  def self.run(c)\n    system(\"x #{c}\")\n  end\n  class << self\n    def go(c)\n      system(\"y #{c}\")\n    end\n  end\nend\ndef a\n  Shell.run(params[:c])\n  Shell.go(params[:c])\n  Shell.nope(params[:c])\nend\n";
        assert_eq!(flagged("ruby/command-injection", src), [3, 7]);
    }

    // ---------------------------------------------------- across files (T4)

    /// The lines `rule` flags in a project of Ruby files, as (path, line).
    fn project(rule: &str, files: &[(&str, &str)]) -> Vec<(String, usize)> {
        crate::analysis::tests::project_flagged(
            rule,
            crate::lang::Lang::Ruby,
            files,
            crate::analysis::taint_project_rules,
        )
    }

    #[test]
    fn a_class_method_defined_in_another_file() {
        let page = "class PingController\n  def show\n    Pinger.run(params[:host])\n    Pinger.argv(params[:host])\n  end\nend\n";
        let pinger = "class Pinger\n  def self.run(host)\n    system(\"ping #{host}\")\n  end\n  def self.argv(host)\n    system('ping', host)\n  end\nend\n";
        let found = project(
            "ruby/command-injection",
            &[("ping_controller.rb", page), ("pinger.rb", pinger)],
        );
        assert_eq!(found, [("pinger.rb".to_string(), 3)]);
    }

    #[test]
    fn a_constructor_and_an_instance_method_in_another_file() {
        let page = "class C\n  def a\n    s = Searcher.new(params[:q])\n    s.run(params[:t])\n  end\nend\n";
        let searcher = "class Searcher\n  def initialize(q)\n    User.where(\"n = #{q}\")\n  end\n  def run(t)\n    User.order(t)\n  end\nend\n";
        let found = project(
            "ruby/sql-injection",
            &[("c.rb", page), ("searcher.rb", searcher)],
        );
        assert_eq!(
            found,
            [
                ("searcher.rb".to_string(), 3),
                ("searcher.rb".to_string(), 6)
            ]
        );
    }

    #[test]
    fn a_method_inherited_from_a_class_or_a_concern_in_another_file() {
        let app = "class ApplicationController\n  def filter\n    params[:f]\n  end\nend\n";
        let concern = "module Exports\n  def export(path)\n    File.read(path)\n  end\nend\n";
        let users = "class UsersController < ApplicationController\n  include Exports\n  def index\n    User.where(\"a = #{filter}\")\n    export(params[:p])\n  end\nend\n";
        let found = project(
            "ruby/sql-injection",
            &[
                ("users.rb", users),
                ("app.rb", app),
                ("concern.rb", concern),
            ],
        );
        assert_eq!(found, [("users.rb".to_string(), 4)]);
        let found = project(
            "ruby/path-injection",
            &[
                ("users.rb", users),
                ("app.rb", app),
                ("concern.rb", concern),
            ],
        );
        assert_eq!(found, [("concern.rb".to_string(), 3)]);
    }

    #[test]
    fn values_move_through_blocks_collections_and_appends() {
        let src = "def a\n  params[:ids].each do |id|\n    system(\"x #{id}\")\n  end\n  cmd = +'ls '\n  cmd << params[:d]\n  system(cmd)\n  parts = []\n  parts << params[:p]\n  system(parts.join(' '))\n  x, y = params[:x], 1\n  system(\"x #{x}\")\nend\n";
        assert_eq!(flagged("ruby/command-injection", src), [3, 7, 10, 12]);
    }
}
