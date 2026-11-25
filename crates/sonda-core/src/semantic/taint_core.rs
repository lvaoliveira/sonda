//! What the taint engines of Java and Rust share (ADR-0027): a path as a list
//! of steps, a write of a value into a variable, the fixed point over a
//! file's writes, a function's summaries and two helpers over syntax nodes.
//! Each engine says what a value is (its `taint`), what its names are called,
//! and how a call is read; the loop that carries a request's value from one
//! variable to the next is the same.

use super::taint::{CallFact, Callee, Finding, Key, ReturnFact, Step, SummaryFact, cap};
use super::{DeclId, Model};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::rc::Rc;
use tree_sitter::Node;

pub(super) type Path<'t> = Vec<Step<'t>>;

/// Rounds of the fixed point; past it, the file reports nothing.
const MAX_ROUNDS: usize = 64;
/// Expressions followed for their taint in one file, at most: past it, what's
/// left is untainted, so a pathological file costs a bounded time.
const MAX_EVALUATIONS: u64 = 5_000_000;

/// How a variable gets its value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum How {
    Assigned,
    /// `q += x`, `sb.append(x)`: the target keeps what it had.
    Added,
    /// `for (String s : xs)`, `if let Some(x) = v`: a part of the value.
    Read,
}

/// A write of a value into a variable.
pub(super) struct Write<'t> {
    pub(super) target: DeclId,
    pub(super) target_node: Node<'t>,
    pub(super) value: Node<'t>,
    pub(super) how: How,
}

/// The fixed point over a file's writes: a variable that is ever written a
/// request's value holds it.
pub(super) trait Flow<'t> {
    fn writes(&self) -> &[Write<'t>];
    /// Variables a check reads as validating, which hold nothing.
    fn checked(&self) -> &HashSet<DeclId>;
    fn evaluations(&self) -> &Cell<u64>;
    /// The path a request's value takes to `value`, given what the variables
    /// hold.
    fn eval(&self, value: Node<'t>, state: &HashMap<DeclId, Path<'t>>) -> Option<Path<'t>>;
    /// What the path says of a write: "assigned to `q`".
    fn label(&self, w: &Write<'t>) -> String;
    /// Whether a path only may hold a request's value (it starts at another
    /// file's method's result), so a sure one replaces it.
    fn is_maybe(&self, _path: &Path<'t>) -> bool {
        false
    }
    /// The other file's function a call calls, if it is one.
    fn external(&self, call: Node<'t>) -> Option<Callee>;
    /// A call's arguments.
    fn call_arguments(&self, call: Node<'t>) -> Vec<Node<'t>>;

    /// The tainted arguments of a call to another file's function: the path
    /// to the call, the callee and the argument.
    fn passed_on(
        &self,
        call: Node<'t>,
        state: &HashMap<DeclId, Path<'t>>,
    ) -> Vec<(Path<'t>, Callee, usize)> {
        tainted_arguments(self.external(call), self.call_arguments(call), |a| {
            self.eval(a, state)
        })
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
            for w in self.writes() {
                if within.is_none_or(|f| inside(w.target_node, f)) {
                    changed |= self.apply(w, tainted);
                }
            }
            if self.evaluations().get() > MAX_EVALUATIONS {
                return None;
            }
            if !changed {
                return Some(());
            }
        }
        None
    }

    /// One write: the target holds its value's path, unless it's validated or
    /// already holds one that surely comes from a request. Whether the target
    /// changed.
    fn apply(&self, w: &Write<'t>, tainted: &mut HashMap<DeclId, Path<'t>>) -> bool {
        if tainted.get(&w.target).is_some_and(|p| !self.is_maybe(p))
            || self.checked().contains(&w.target)
        {
            return false;
        }
        let Some(mut path) = self.eval(w.value, tainted) else {
            return false;
        };
        if tainted.contains_key(&w.target) && self.is_maybe(&path) {
            return false;
        }
        path.push(Step {
            node: w.target_node,
            message: self.label(w),
        });
        tainted.insert(w.target, path);
        true
    }
}

/// What the functions of a file do with a value, computed once each. A
/// function that calls itself, or two that call each other, have nothing more
/// to learn the second time.
pub(super) struct Summaries<K, S> {
    done: RefCell<HashMap<K, Rc<S>>>,
    busy: RefCell<HashSet<K>>,
    most: usize,
}

impl<K: Hash + Eq + Copy, S: Default> Summaries<K, S> {
    pub(super) fn new(most: usize) -> Self {
        Summaries {
            done: RefCell::default(),
            busy: RefCell::default(),
            most,
        }
    }

    /// The summary under `key`, computed by `compute` the first time; the
    /// default one past the limit or while it's being computed.
    pub(super) fn get(&self, key: K, compute: impl FnOnce() -> Option<S>) -> Rc<S> {
        if let Some(s) = self.done.borrow().get(&key) {
            return s.clone();
        }
        if self.done.borrow().len() >= self.most || !self.busy.borrow_mut().insert(key) {
            return Rc::default();
        }
        let summary = Rc::new(compute().unwrap_or_default());
        self.busy.borrow_mut().remove(&key);
        self.done.borrow_mut().insert(key, summary.clone());
        summary
    }
}

/// How deep an expression is followed for its taint.
const MAX_DEPTH: u32 = 64;

/// Counts one expression followed; false past a limit, where what's left is
/// untainted.
pub(super) fn tick(evaluations: &Cell<u64>, depth: u32) -> bool {
    let n = evaluations.get() + 1;
    evaluations.set(n);
    depth <= MAX_DEPTH && n <= MAX_EVALUATIONS
}

/// Each declaration by the id of the node that names it.
pub(super) fn decl_index(m: &Model) -> HashMap<usize, DeclId> {
    m.decls
        .iter()
        .enumerate()
        .map(|(i, d)| (d.node.id(), i))
        .collect()
}

/// The findings in source order, each sink once, by its shortest path.
pub(super) fn finish(mut findings: Vec<Finding<'_>>) -> Vec<Finding<'_>> {
    findings.sort_by_key(|f| (f.sink.start_byte(), f.steps.len()));
    findings.dedup_by_key(|f| f.sink.id());
    findings
}

fn step<'t>(node: Node<'t>, message: String) -> Step<'t> {
    Step { node, message }
}

/// What a call to a function of the file returns: what the function reads
/// itself (`own`), or the path of a tainted argument that reaches its result
/// (`returned`, by the argument's position).
pub(super) fn through_returns<'t>(
    call: Node<'t>,
    name: &str,
    own: Option<Path<'t>>,
    args: &[Node<'t>],
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
    returned: impl Fn(usize) -> Option<Path<'t>>,
) -> Option<Path<'t>> {
    if let Some(mut path) = own {
        path.push(step(call, format!("returned by `{name}`")));
        return Some(path);
    }
    for (i, a) in args.iter().enumerate() {
        let Some(mut path) = taint(*a) else {
            continue;
        };
        let Some(inside) = returned(i) else {
            continue;
        };
        path.push(step(call, format!("passed to `{name}`")));
        path.extend(inside);
        path.push(step(call, format!("returned by `{name}`")));
        return Some(path);
    }
    None
}

/// The sinks a call's tainted arguments reach inside the function it calls
/// (`sinks`, by the argument's position), each a finding with the path that
/// goes through the call.
pub(super) fn through_sinks<'t>(
    call: Node<'t>,
    name: &str,
    args: Vec<Node<'t>>,
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
    sinks: impl Fn(usize) -> Vec<(Path<'t>, Node<'t>)>,
) -> Vec<Finding<'t>> {
    let mut out = Vec::new();
    for (i, a) in args.into_iter().enumerate() {
        let Some(path) = taint(a) else {
            continue;
        };
        for (inside, sink) in sinks(i) {
            let mut steps = path.clone();
            steps.push(step(call, format!("passed to `{name}`")));
            steps.extend(inside);
            out.push(Finding {
                sink,
                steps: cap(steps),
            });
        }
    }
    out
}

/// `Flow` for an engine whose context is `$cx`, with `writes`, `checked` and
/// `evaluations` fields and a `taint` and a `text` method, and an `is_built`
/// function in scope that tells a concatenation from a plain assignment.
macro_rules! flow_for {
    ($cx:ident $(, $maybe:path)?) => {
        impl<'a, 't> $crate::semantic::taint_core::Flow<'t> for $cx<'a, 't> {
            fn writes(&self) -> &[$crate::semantic::taint_core::Write<'t>] {
                &self.writes
            }

            fn checked(&self) -> &::std::collections::HashSet<$crate::semantic::DeclId> {
                &self.checked
            }

            fn evaluations(&self) -> &::std::cell::Cell<u64> {
                &self.evaluations
            }

            fn eval(
                &self,
                value: ::tree_sitter::Node<'t>,
                state: &::std::collections::HashMap<
                    $crate::semantic::DeclId,
                    $crate::semantic::taint_core::Path<'t>,
                >,
            ) -> Option<$crate::semantic::taint_core::Path<'t>> {
                self.taint(value, state, 0)
            }

            fn external(
                &self,
                call: ::tree_sitter::Node<'t>,
            ) -> Option<$crate::semantic::taint::Callee> {
                self.external_callee(call)
            }

            fn call_arguments(&self, call: ::tree_sitter::Node<'t>) -> Vec<::tree_sitter::Node<'t>> {
                arguments(call)
            }

            fn label(&self, w: &$crate::semantic::taint_core::Write<'t>) -> String {
                use $crate::semantic::taint_core::How;
                let name = self.text(w.target_node);
                match w.how {
                    How::Read => format!("read into `{name}`"),
                    How::Added => format!("added to `{name}`"),
                    How::Assigned if is_built(w.value) => format!("concatenated into `{name}`"),
                    How::Assigned => format!("assigned to `{name}`"),
                }
            }

            $(
                fn is_maybe(&self, path: &$crate::semantic::taint_core::Path<'t>) -> bool {
                    $maybe(path)
                }
            )?
        }
    };
}
pub(super) use flow_for;

/// What a function's summary holds that other files need: the sinks and the
/// other files' functions a parameter's value reaches inside it.
pub(super) trait Reaches<'t> {
    fn sinks(&self) -> &[(Path<'t>, Node<'t>)];
    fn calls(&self) -> &[(Path<'t>, Callee, usize)];
}

/// Parameters followed per function for other files, at most.
const MAX_PARAMS: usize = 12;

/// The summaries of a file's functions that other files need: for each
/// function (`key` names it, none for one they can't call), what each of its
/// parameters (`params` of them) reaches, and what `refine` adds (a parameter's
/// result, or what the function reads itself, for `None`).
pub(super) fn exported<'t, S: Reaches<'t>>(
    functions: usize,
    key: impl Fn(usize) -> Option<Key>,
    params: impl Fn(usize) -> usize,
    summary: impl Fn(usize, usize) -> Rc<S>,
    refine: impl Fn(usize, Option<usize>, &mut SummaryFact<'t>),
) -> Vec<SummaryFact<'t>> {
    let mut out = Vec::new();
    for j in 0..functions {
        let Some(key) = key(j) else {
            continue;
        };
        let mut fact = SummaryFact {
            key,
            returns_sql: false,
            to_sink: Vec::new(),
            to_return: Vec::new(),
            returns_source: None,
            to_call: Vec::new(),
        };
        for p in 0..params(j).min(MAX_PARAMS) {
            let s = summary(j, p);
            fact.to_sink.extend(
                s.sinks()
                    .iter()
                    .map(|(steps, sink)| (p, cap(steps.clone()), *sink)),
            );
            fact.to_call.extend(
                s.calls()
                    .iter()
                    .map(|(steps, callee, arg)| (p, cap(steps.clone()), callee.clone(), *arg)),
            );
            refine(j, Some(p), &mut fact);
        }
        refine(j, None, &mut fact);
        if !fact.to_sink.is_empty()
            || !fact.to_call.is_empty()
            || !fact.to_return.is_empty()
            || fact.returns_source.is_some()
        {
            out.push(fact);
        }
    }
    out
}

/// The request's values a file passes to other files' functions: for each
/// call (`passed_on` says its tainted arguments), a fact.
pub(super) fn call_facts<'t>(
    calls: &[Node<'t>],
    passed_on: impl Fn(Node<'t>) -> Vec<(Path<'t>, Callee, usize)>,
) -> Vec<CallFact<'t>> {
    calls
        .iter()
        .flat_map(|&call| {
            passed_on(call)
                .into_iter()
                .map(move |(steps, callee, arg)| CallFact {
                    steps: cap(steps),
                    call,
                    callee,
                    arg,
                })
        })
        .collect()
}

/// What an engine says of its file's functions, for the project pass: the
/// summaries other files need, and the calls into other files.
pub(super) trait Exports<'t>: Flow<'t> {
    type Sum: Reaches<'t> + Default;
    fn call_nodes(&self) -> &[Node<'t>];
    fn function_count(&self) -> usize;
    fn param_count(&self, j: usize) -> usize;
    fn key_of(&self, j: usize) -> Option<Key>;
    fn summary_of(&self, j: usize, p: Option<usize>) -> Rc<Self::Sum>;
    fn returned_by(summary: &Self::Sum) -> Option<Path<'t>>;

    /// Whether parameter `p` of function `j` is worth a summary for other
    /// files: not one that can't hold what injects.
    fn exports_param(&self, _j: usize, _p: usize) -> bool {
        true
    }

    /// Whether function `j` can return what injects: not one whose result
    /// is a number, a struct or nothing.
    fn exports_return(&self, _j: usize) -> bool {
        true
    }

    /// The request's values this file passes to other files' functions.
    fn passed_to_other_files(&self, state: &HashMap<DeclId, Path<'t>>) -> Vec<CallFact<'t>> {
        call_facts(self.call_nodes(), |call| self.passed_on(call, state))
    }

    /// What the functions of the file do with a value passed to them.
    fn exported_summaries(&self) -> Vec<SummaryFact<'t>> {
        let summary = |j: usize, p: Option<usize>| match p {
            Some(p) if !self.exports_param(j, p) => Rc::new(Self::Sum::default()),
            _ => self.summary_of(j, p),
        };
        exported(
            self.function_count(),
            |j| self.key_of(j),
            |j| self.param_count(j),
            |j, p| summary(j, Some(p)),
            |j, p, fact| {
                let returns = Self::returned_by(&summary(j, p));
                let returns = returns.filter(|r| !from_call(r) && self.exports_return(j));
                note_return(fact, p, returns);
            },
        )
    }
}

/// `Exports` for an engine whose context is `$cx`, with `m`, `calls`,
/// `function_key` and `summary` (whose `returns` is what a function returns).
macro_rules! exports_for {
    ($cx:ident $(, $worth:ident, $returns:ident)?) => {
        impl<'a, 't> $crate::semantic::taint_core::Exports<'t> for $cx<'a, 't> {
            type Sum = Summary<'t>;

            fn call_nodes(&self) -> &[::tree_sitter::Node<'t>] {
                &self.calls
            }

            fn function_count(&self) -> usize {
                self.m.functions.len()
            }

            fn param_count(&self, j: usize) -> usize {
                self.m.functions[j].params.len()
            }

            fn key_of(&self, j: usize) -> Option<$crate::semantic::taint::Key> {
                self.function_key(j)
            }

            fn summary_of(&self, j: usize, p: Option<usize>) -> ::std::rc::Rc<Summary<'t>> {
                self.summary(j, p)
            }

            fn returned_by(
                summary: &Summary<'t>,
            ) -> Option<$crate::semantic::taint_core::Path<'t>> {
                summary.returns.clone()
            }

            $(
                fn exports_param(&self, j: usize, p: usize) -> bool {
                    self.$worth(j, p)
                }

                fn exports_return(&self, j: usize) -> bool {
                    self.$returns(j)
                }
            )?
        }
    };
}
pub(super) use exports_for;

/// What a variable holds, unless a check validated it.
pub(super) fn held<'t>(
    decl: Option<DeclId>,
    checked: &HashSet<DeclId>,
    state: &HashMap<DeclId, Path<'t>>,
) -> Option<Path<'t>> {
    let d = decl?;
    if checked.contains(&d) {
        return None;
    }
    state.get(&d).cloned()
}

/// Each call that is a sink, with the arguments that take its value, as a
/// finding when one of them holds a request's value (`taint`).
pub(super) fn at_sinks<'t>(
    calls: &[Node<'t>],
    sink_of: impl Fn(Node<'t>) -> Option<(String, Vec<Node<'t>>)>,
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
) -> Vec<Finding<'t>> {
    let mut out = Vec::new();
    for &call in calls {
        let Some((name, args)) = sink_of(call) else {
            continue;
        };
        if let Some(mut path) = args.into_iter().find_map(&taint) {
            path.push(step(call, format!("passed to `{name}`")));
            out.push(Finding {
                sink: call,
                steps: cap(path),
            });
        }
    }
    out
}

/// Whether `n` is inside `outer`.
pub(super) fn inside(n: Node, outer: Node) -> bool {
    outer.start_byte() <= n.start_byte() && n.end_byte() <= outer.end_byte()
}

/// A call's text, short enough for a step's message.
pub(super) fn short(t: &str) -> String {
    let one_line: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.chars().count() <= 60 {
        one_line
    } else {
        let cut: String = one_line.chars().take(57).collect();
        format!("{cut}...")
    }
}

/// Another file's function's result reaching `sink` through `call`: noted once
/// per sink and call. `args` are the call's arguments (`taint` says which hold
/// a request's value), `after` the path from the result to the sink.
pub(super) fn record_return<'t>(
    returns: &RefCell<Vec<ReturnFact<'t>>>,
    call: Node<'t>,
    callee: Callee,
    args: Vec<Node<'t>>,
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
    after: Path<'t>,
    sink: Node<'t>,
) {
    let mut returns = returns.borrow_mut();
    if returns
        .iter()
        .any(|r| r.sink.id() == sink.id() && r.call.id() == call.id())
    {
        return;
    }
    let args = args
        .into_iter()
        .enumerate()
        .filter_map(|(i, a)| Some((i, cap(taint(a)?))))
        .collect();
    returns.push(ReturnFact {
        call,
        callee,
        args,
        after: cap(after),
        sink,
        needs_sql: false,
    });
}

/// The other files' functions a tainted value in `function` is passed on to:
/// for each, the path to the call (ending at it), the callee and its argument.
pub(super) fn calls_in<'t, F: Flow<'t>>(
    flow: &F,
    calls: &[Node<'t>],
    function: Node<'t>,
    state: &HashMap<DeclId, Path<'t>>,
) -> Vec<(Path<'t>, Callee, usize)> {
    let mut out = Vec::new();
    for &call in calls.iter().filter(|c| inside(**c, function)) {
        for (mut path, callee, arg) in flow.passed_on(call, state) {
            path.push(step(call, format!("passed to `{}`", callee.display())));
            out.push((path, callee, arg));
        }
    }
    out
}

/// Another file's function's result reaching the sink call that `sink_arg` is
/// an argument of, by `path` (which starts at the call to that function):
/// noted for the project pass. `external` says the callee of a call and its
/// arguments, `taint` which of them hold a request's value.
pub(super) fn record_return_at_sink<'t>(
    returns: &RefCell<Vec<ReturnFact<'t>>>,
    calls: &[Node<'t>],
    sink_call: impl Fn(Node<'t>) -> Option<(String, Vec<Node<'t>>)>,
    external: impl Fn(Node<'t>) -> Option<(Callee, Vec<Node<'t>>)>,
    sink_arg: Node<'t>,
    path: &Path<'t>,
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
) {
    let call = path[0].node;
    let Some((callee, args)) = external(call) else {
        return;
    };
    let is_sink = |c: &Node<'t>| {
        inside(sink_arg, *c)
            && sink_call(*c).is_some_and(|(_, a)| a.iter().any(|a| a.id() == sink_arg.id()))
    };
    let Some(sink) = calls.iter().copied().find(is_sink) else {
        return;
    };
    let name = sink_call(sink).map(|(n, _)| n).unwrap_or_default();
    let mut after = path[1..].to_vec();
    after.push(step(sink, format!("passed to `{name}`")));
    let sure = |a| taint(a).filter(|p| !from_call(p));
    record_return(returns, call, callee, args, sure, after, sink);
}

/// What a sink's argument holds: its path if surely a request's value; for
/// one that starts at another file's function's result, `record` notes it
/// for the project pass and it's no finding here.
pub(super) fn sure_path<'t>(
    path: Option<Path<'t>>,
    record: impl FnOnce(&Path<'t>),
) -> Option<Path<'t>> {
    let path = path?;
    if from_call(&path) {
        record(&path);
        return None;
    }
    Some(path)
}

/// The path of another file's function's result, which may hold a request's
/// value (the project pass decides): only once the fixed point is running
/// (`enabled`) and for a call that is such a function (`external`).
pub(super) fn maybe_path<'t>(
    enabled: bool,
    call: Node<'t>,
    external: impl FnOnce() -> bool,
) -> Option<Path<'t>> {
    (enabled && external()).then(|| vec![step(call, FROM_CALL.to_string())])
}

/// A path that starts at another file's function's result: a request's value
/// only if that function returns one, which the project pass decides (T4).
/// Its first step is the call, with this message.
pub(super) const FROM_CALL: &str = "\u{1}";

pub(super) fn from_call(path: &Path) -> bool {
    path.first().is_some_and(|s| s.message == FROM_CALL)
}

/// The first of `paths` that holds a request's value; failing that, the
/// first that may, if another file's function returns one.
pub(super) fn best<'t>(paths: impl Iterator<Item = Option<Path<'t>>>) -> Option<Path<'t>> {
    let mut maybe = None;
    for path in paths.flatten() {
        if !from_call(&path) {
            return Some(path);
        }
        maybe.get_or_insert(path);
    }
    maybe
}

/// The best path of an expression's children named by `fields`.
pub(super) fn best_of<'t>(
    n: Node<'t>,
    fields: &[&str],
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
) -> Option<Path<'t>> {
    best(
        fields
            .iter()
            .filter_map(|f| n.child_by_field_name(f))
            .map(taint),
    )
}

/// What a function returns, for other files: a request's value it reads
/// itself (`p` is None) or its parameter `p`'s.
pub(super) fn note_return<'t>(
    fact: &mut SummaryFact<'t>,
    p: Option<usize>,
    returns: Option<Path<'t>>,
) {
    match p {
        Some(p) => fact.to_return.extend(returns.map(|r| (p, cap(r)))),
        None => fact.returns_source = returns.map(cap),
    }
}

/// The arguments of a call to another file's function (`callee`) that hold a
/// request's value for sure: the path to the call, the callee and the
/// argument's position.
pub(super) fn tainted_arguments<'t>(
    callee: Option<Callee>,
    args: Vec<Node<'t>>,
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
) -> Vec<(Path<'t>, Callee, usize)> {
    let Some(callee) = callee else {
        return Vec::new();
    };
    args.into_iter()
        .enumerate()
        .filter_map(|(i, a)| {
            let path = taint(a).filter(|p| !from_call(p))?;
            Some((path, callee.clone(), i))
        })
        .collect()
}

/// Walks the syntax tree once, in source order; `visit` says whether to go
/// on. None when it stopped the walk.
pub(super) fn walk<'t>(root: Node<'t>, mut visit: impl FnMut(Node<'t>) -> bool) -> Option<()> {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if !visit(n) {
            return None;
        }
        let mut c = n.walk();
        let children: Vec<Node<'t>> = n.named_children(&mut c).collect();
        stack.extend(children.into_iter().rev());
    }
    Some(())
}

/// The values a function returns (`returns` is the kind of a return
/// statement), not those of the functions inside it (`nested` are their kinds).
pub(super) fn return_values<'t>(
    function: Node<'t>,
    nested: &[&str],
    returns: &str,
) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![function];
    while let Some(n) = stack.pop() {
        if n.id() != function.id() && nested.contains(&n.kind()) {
            continue;
        }
        if n.kind() == returns
            && let Some(v) = n.named_child(0)
        {
            out.push(v);
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    out
}

/// The sinks inside `function` that its tainted values reach, each with the
/// path to it: the calls that are sinks (`sink_of`), and what the calls into
/// other functions of the file reach (`through`).
pub(super) fn sinks_in<'t>(
    calls: &[Node<'t>],
    function: Node<'t>,
    sink_of: impl Fn(Node<'t>) -> Option<(String, Vec<Node<'t>>)>,
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
    through: impl Fn(Node<'t>) -> Vec<Finding<'t>>,
) -> Vec<(Path<'t>, Node<'t>)> {
    let mut out = Vec::new();
    for &call in calls.iter().filter(|c| inside(**c, function)) {
        if let Some((name, args)) = sink_of(call)
            && let Some(mut path) = best(args.into_iter().map(&taint))
        {
            path.push(step(call, format!("passed to `{name}`")));
            out.push((path, call));
        }
        out.extend(through(call).into_iter().map(|f| (f.steps, f.sink)));
    }
    out
}

/// What a function does with the values it holds: the path of what it
/// returns (`values` are the expressions it returns), and, for a function
/// whose parameter holds one, the sinks that reach (`sinks_in`).
pub(super) fn outcome<'t>(
    values: Vec<Node<'t>>,
    taint: impl Fn(Node<'t>) -> Option<Path<'t>>,
    sinks: Option<Vec<(Path<'t>, Node<'t>)>>,
) -> (Option<Path<'t>>, Vec<(Path<'t>, Node<'t>)>) {
    (
        best(values.into_iter().map(taint)),
        sinks.unwrap_or_default(),
    )
}

/// The variables named as the receiver or an argument of a check: those the
/// check validates. `arguments` are a call's, `receiver` is the field of a
/// method call's function that names the object, `resolve` the variable an
/// expression is.
pub(super) fn checked_names<'t>(
    checks: Vec<Node<'t>>,
    arguments: impl Fn(Node<'t>) -> Vec<Node<'t>>,
    receiver: (&str, &str),
    resolve: impl Fn(Node<'t>) -> Option<DeclId>,
) -> HashSet<DeclId> {
    let mut out = HashSet::new();
    for call in checks {
        let mut named = arguments(call);
        if let Some(f) = call.child_by_field_name("function")
            && f.kind() == receiver.0
        {
            named.extend(f.child_by_field_name(receiver.1));
        }
        out.extend(named.into_iter().filter_map(&resolve));
    }
    out
}
