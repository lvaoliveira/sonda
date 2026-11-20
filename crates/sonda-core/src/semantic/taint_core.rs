//! What the taint engines of Java and Rust share (ADR-0027): a path as a list
//! of steps, a write of a value into a variable, the fixed point over a
//! file's writes, a function's summaries and two helpers over syntax nodes.
//! Each engine says what a value is (its `taint`), what its names are called,
//! and how a call is read; the loop that carries a request's value from one
//! variable to the next is the same.

use super::taint::{Finding, Step, cap};
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
