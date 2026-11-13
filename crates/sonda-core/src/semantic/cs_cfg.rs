//! Control flow and liveness for C# (ADR-0008's phases S2 and S3).
//!
//! A control-flow graph per function: one block per statement, condition or
//! loop header, with edges for branches, loops, `switch`, `break`,
//! `continue`, `return`, `throw`, `goto` and `try`/`catch`/`finally`. Every
//! block inside a `try` also has an edge to its handlers and `finally`, since
//! an exception can leave it anywhere. Each block records the variables it
//! reads and writes, in evaluation order: `x = x + 1` reads x, then writes it.
//!
//! Liveness is a backward fixed point over the graph: a variable is live
//! after a block if some path from there reads it before writing it.
//!
//! Bounded like the rest of the layer: expressions are walked iteratively;
//! statements nest at most `MAX_DEPTH` deep and a graph holds at most
//! `MAX_BLOCKS` blocks, past which the function gets no graph; and the fixed
//! point stops after a bounded number of rounds.

use super::{DeclId, Model};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

const MAX_DEPTH: usize = 128;
const MAX_BLOCKS: usize = 20_000;

/// One read or write of a variable.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Access {
    Read,
    Write,
    /// A write that may not happen: in a branch of `?:`, the right side of
    /// `&&`, `||` or `??`, after `?.`, in a switch expression arm, or `??=`.
    /// It doesn't end an earlier value's life.
    MaybeWrite,
}

/// `events`' work: a node to visit, and whether it may not be evaluated,
/// or an event to emit.
enum EventTask<'t> {
    Visit(Node<'t>, bool),
    Emit(DeclId, Access, Node<'t>),
}

#[derive(Clone, Debug)]
pub(crate) struct Event<'t> {
    pub(crate) decl: DeclId,
    pub(crate) access: Access,
    /// The syntax that writes: the assignment, the declarator, the `++`.
    pub(crate) node: Node<'t>,
}

pub(crate) struct Block<'t> {
    /// The statement or condition the block stands for.
    pub(crate) syntax: Option<Node<'t>>,
    pub(crate) succ: Vec<usize>,
    pub(crate) events: Vec<Event<'t>>,
    /// The block calls the function itself on every evaluation (not in a
    /// branch of `?:`, `&&`, `||`, `??` or `?.`).
    pub(crate) recurses: bool,
    /// The loop or labeled statement whose cycle starts here.
    pub(crate) loop_statement: Option<Node<'t>>,
}

pub(crate) struct Cfg<'t> {
    pub(crate) blocks: Vec<Block<'t>>,
    /// Variables captured by a lambda or local function, whose reads the
    /// graph can't place.
    pub(crate) escaped: HashSet<DeclId>,
    pub(crate) has_try: bool,
}

pub(crate) const ENTRY: usize = 0;
pub(crate) const EXIT: usize = 1;

struct Builder<'m, 't, 's> {
    m: &'m Model<'t>,
    src: &'s [u8],
    decl_by_node: &'m HashMap<usize, DeclId>,
    blocks: Vec<Block<'t>>,
    labels: HashMap<String, usize>,
    gotos: Vec<(usize, String)>,
    escaped: HashSet<DeclId>,
    has_try: bool,
    failed: bool,
    depth: usize,
    /// The function's own name and parameter count, for recursion.
    own: Option<(String, usize)>,
}

#[derive(Clone, Copy)]
struct Targets {
    brk: Option<usize>,
    cont: Option<usize>,
}

fn named_children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c)
        .filter(|x| x.kind() != "comment")
        .collect()
}

fn unparenthesized(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}

/// Each declaration's id, by the id of the node that names it.
pub(crate) fn decls_by_node(m: &Model) -> HashMap<usize, DeclId> {
    m.decls
        .iter()
        .enumerate()
        .map(|(i, d)| (d.node.id(), i))
        .collect()
}

/// The graph of a function (method, constructor, accessor, local function
/// or lambda), or None past the bounds.
pub(crate) fn build<'t>(
    m: &Model<'t>,
    function: Node<'t>,
    src: &[u8],
    decl_by_node: &HashMap<usize, DeclId>,
) -> Option<Cfg<'t>> {
    let body = function.child_by_field_name("body")?;
    let own = function
        .child_by_field_name("name")
        .filter(|_| function.kind() == "method_declaration")
        .map(|n| {
            let params = function.child_by_field_name("parameters").map_or(0, |p| {
                let mut c = p.walk();
                p.named_children(&mut c)
                    .filter(|x| x.kind() == "parameter")
                    .count()
                    + usize::from(p.child_by_field_name("name").is_some())
            });
            (n.utf8_text(src).unwrap_or_default().to_string(), params)
        });
    let mut b = Builder {
        m,
        src,
        decl_by_node,
        blocks: Vec::new(),
        labels: HashMap::new(),
        gotos: Vec::new(),
        escaped: HashSet::new(),
        has_try: false,
        failed: false,
        depth: 0,
        own,
    };
    b.block(None, Vec::new()); // ENTRY
    b.block(None, Vec::new()); // EXIT
    let first = if body.kind() == "block" {
        b.statement(
            body,
            EXIT,
            Targets {
                brk: None,
                cont: None,
            },
        )
    } else {
        // `=> expression`
        let events = b.events(body);
        let recurses = b.recurses(body);
        let i = b.block(Some(body), vec![EXIT]);
        b.blocks[i].events = events;
        b.blocks[i].recurses = recurses;
        i
    };
    b.blocks[ENTRY].succ = vec![first];
    for (from, label) in std::mem::take(&mut b.gotos) {
        match b.labels.get(&label) {
            Some(to) => b.blocks[from].succ = vec![*to],
            None => b.failed = true,
        }
    }
    (!b.failed && b.blocks.len() <= MAX_BLOCKS).then_some(Cfg {
        blocks: b.blocks,
        escaped: b.escaped,
        has_try: b.has_try,
    })
}

impl<'t> Builder<'_, 't, '_> {
    fn text(&self, n: Node) -> &str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    fn block(&mut self, syntax: Option<Node<'t>>, succ: Vec<usize>) -> usize {
        self.blocks.push(Block {
            syntax,
            succ,
            events: Vec::new(),
            recurses: false,
            loop_statement: None,
        });
        self.blocks.len() - 1
    }

    /// A block for a statement or expression that runs straight through.
    fn simple(&mut self, syntax: Node<'t>, next: usize) -> usize {
        let events = self.events(syntax);
        let recurses = self.recurses(syntax);
        let i = self.block(Some(syntax), vec![next]);
        self.blocks[i].events = events;
        self.blocks[i].recurses = recurses;
        i
    }

    /// The entry block of `s`, which continues to `next`.
    fn statement(&mut self, s: Node<'t>, next: usize, t: Targets) -> usize {
        if self.failed || self.blocks.len() > MAX_BLOCKS {
            self.failed = true;
            return next;
        }
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            self.failed = true;
            self.depth -= 1;
            return next;
        }
        let entry = self.statement_inner(s, next, t);
        self.depth -= 1;
        entry
    }

    fn statement_inner(&mut self, s: Node<'t>, next: usize, t: Targets) -> usize {
        match s.kind() {
            "block" => {
                let mut entry = next;
                for child in named_children(s).into_iter().rev() {
                    entry = self.statement(child, entry, t);
                }
                entry
            }
            "return_statement" | "throw_statement" => self.simple(s, EXIT),
            "yield_statement" if self.text(s).starts_with("yield break") => {
                self.block(Some(s), vec![EXIT])
            }
            "break_statement" => self.block(Some(s), vec![t.brk.unwrap_or(next)]),
            "continue_statement" => self.block(Some(s), vec![t.cont.unwrap_or(next)]),
            "goto_statement" => self.goto(s, next),
            "labeled_statement" => self.labeled(s, next, t),
            "if_statement" => self.if_statement(s, next, t),
            "while_statement" => self.while_loop(s, next),
            "do_statement" => self.do_loop(s, next),
            "for_statement" => self.for_loop(s, next),
            "foreach_statement" => self.foreach_loop(s, next),
            "switch_statement" => self.switch(s, next, t),
            "try_statement" => self.try_statement(s, next, t),
            "using_statement" | "lock_statement" | "fixed_statement" | "checked_statement"
            | "unsafe_statement" => self.scoped_statement(s, next, t),
            "local_function_statement" => self.local_function(s, next),
            _ => self.simple(s, next),
        }
    }

    fn goto(&mut self, s: Node<'t>, next: usize) -> usize {
        let label = named_children(s).first().map(|l| self.text(*l).to_string());
        match label.filter(|_| {
            !self.text(s).starts_with("goto case") && !self.text(s).starts_with("goto default")
        }) {
            Some(label) => {
                let i = self.block(Some(s), Vec::new());
                self.gotos.push((i, label));
                i
            }
            None => {
                self.failed = true;
                next
            }
        }
    }

    fn labeled(&mut self, s: Node<'t>, next: usize, t: Targets) -> usize {
        let children = named_children(s);
        let (Some(label), Some(inner)) = (children.first(), children.get(1)) else {
            return next;
        };
        let label = self.text(*label).to_string();
        let i = self.block(Some(s), Vec::new());
        self.blocks[i].loop_statement = Some(s);
        self.labels.insert(label, i);
        let inner_entry = self.statement(*inner, next, t);
        self.blocks[i].succ = vec![inner_entry];
        i
    }

    fn if_statement(&mut self, s: Node<'t>, next: usize, t: Targets) -> usize {
        let Some(condition) = s.child_by_field_name("condition") else {
            return next;
        };
        let yes = s
            .child_by_field_name("consequence")
            .map_or(next, |c| self.statement(c, next, t));
        let no = s
            .child_by_field_name("alternative")
            .map_or(next, |a| self.statement(a, next, t));
        let i = self.simple(condition, next);
        self.blocks[i].succ = vec![yes, no];
        i
    }

    fn while_loop(&mut self, s: Node<'t>, next: usize) -> usize {
        let condition = s.child_by_field_name("condition");
        let head = self.block(condition, Vec::new());
        self.blocks[head].loop_statement = Some(s);
        let body = s.child_by_field_name("body").map_or(head, |b| {
            self.statement(
                b,
                head,
                Targets {
                    brk: Some(next),
                    cont: Some(head),
                },
            )
        });
        if let Some(c) = condition {
            self.blocks[head].events = self.events(c);
            self.blocks[head].recurses = self.recurses(c);
        }
        self.blocks[head].succ = if condition.is_some_and(|c| self.always_true(c)) {
            vec![body]
        } else {
            vec![body, next]
        };
        head
    }

    fn do_loop(&mut self, s: Node<'t>, next: usize) -> usize {
        let condition = s.child_by_field_name("condition");
        let check = self.block(condition, Vec::new());
        let body = s.child_by_field_name("body").map_or(check, |b| {
            self.statement(
                b,
                check,
                Targets {
                    brk: Some(next),
                    cont: Some(check),
                },
            )
        });
        self.blocks[check].loop_statement = Some(s);
        if let Some(c) = condition {
            self.blocks[check].events = self.events(c);
        }
        self.blocks[check].succ = if condition.is_some_and(|c| self.always_true(c)) {
            vec![body]
        } else {
            vec![body, next]
        };
        body
    }

    fn for_loop(&mut self, s: Node<'t>, next: usize) -> usize {
        let condition = s.child_by_field_name("condition");
        let head = self.block(condition, Vec::new());
        self.blocks[head].loop_statement = Some(s);
        // The updates, in order, after each pass of the body.
        let mut update_entry = head;
        let mut cursor = s.walk();
        let updates: Vec<Node<'t>> = s.children_by_field_name("update", &mut cursor).collect();
        for u in updates.into_iter().rev() {
            update_entry = self.simple(u, update_entry);
        }
        let body = s.child_by_field_name("body").map_or(update_entry, |b| {
            self.statement(
                b,
                update_entry,
                Targets {
                    brk: Some(next),
                    cont: Some(update_entry),
                },
            )
        });
        if let Some(c) = condition {
            self.blocks[head].events = self.events(c);
        }
        let forever = condition.is_none_or(|c| self.always_true(c));
        self.blocks[head].succ = if forever {
            vec![body]
        } else {
            vec![body, next]
        };
        let mut cursor = s.walk();
        let initializers: Vec<Node<'t>> = s
            .children_by_field_name("initializer", &mut cursor)
            .collect();
        let mut entry = head;
        for init in initializers.into_iter().rev() {
            entry = self.simple(init, entry);
        }
        entry
    }

    fn foreach_loop(&mut self, s: Node<'t>, next: usize) -> usize {
        // The collection is evaluated once; each pass writes the
        // loop variable, then runs the body.
        let head = self.block(Some(s), Vec::new());
        self.blocks[head].loop_statement = Some(s);
        let body = s.child_by_field_name("body").map_or(head, |b| {
            self.statement(
                b,
                head,
                Targets {
                    brk: Some(next),
                    cont: Some(head),
                },
            )
        });
        self.blocks[head].succ = vec![body, next];
        if let Some(left) = s.child_by_field_name("left") {
            self.blocks[head].events = self.definitions(left);
        }
        match s.child_by_field_name("right") {
            Some(collection) => self.simple(collection, head),
            None => head,
        }
    }

    fn switch(&mut self, s: Node<'t>, next: usize, t: Targets) -> usize {
        let value = s.child_by_field_name("value");
        let dispatch = self.block(value, Vec::new());
        if let Some(v) = value {
            self.blocks[dispatch].events = self.events(v);
        }
        let sections = s
            .child_by_field_name("body")
            .map(named_children)
            .unwrap_or_default();
        let mut entries = Vec::new();
        let mut has_default = false;
        for section in sections
            .into_iter()
            .filter(|x| x.kind() == "switch_section")
        {
            let mut c = section.walk();
            has_default |= section.children(&mut c).any(|x| x.kind() == "default");
            let parts = named_children(section);
            let (labels, statements): (Vec<Node<'t>>, Vec<Node<'t>>) = parts
                .into_iter()
                .partition(|p| p.kind().ends_with("pattern") || p.kind() == "when_clause");
            let mut entry = next;
            for st in statements.into_iter().rev() {
                entry = self.statement(
                    st,
                    entry,
                    Targets {
                        brk: Some(next),
                        cont: t.cont,
                    },
                );
            }
            // Patterns may declare variables: `case Foo f:`.
            let label_block = self.block(Some(section), vec![entry]);
            for l in labels {
                let events = self.events(l);
                self.blocks[label_block].events.extend(events);
            }
            entries.push(label_block);
        }
        if !has_default {
            entries.push(next);
        }
        self.blocks[dispatch].succ = entries;
        dispatch
    }

    fn try_statement(&mut self, s: Node<'t>, next: usize, t: Targets) -> usize {
        self.has_try = true;
        let children = named_children(s);
        let finally = children
            .iter()
            .find(|c| c.kind() == "finally_clause")
            .and_then(|f| named_children(*f).into_iter().next());
        let finally_entry = finally.map(|f| self.statement(f, next, t));
        let after = finally_entry.unwrap_or(next);
        let mut handlers = Vec::new();
        let catch_start = self.blocks.len();
        for clause in children.iter().filter(|c| c.kind() == "catch_clause") {
            let body = clause
                .child_by_field_name("body")
                .map_or(after, |b| self.statement(b, after, t));
            let head = self.block(Some(*clause), vec![body]);
            let mut events = Vec::new();
            for part in named_children(*clause) {
                match part.kind() {
                    "catch_declaration" => {
                        if let Some(name) = part.child_by_field_name("name") {
                            events.extend(self.definitions(name));
                        }
                    }
                    "catch_filter_clause" => events.extend(self.events(part)),
                    _ => {}
                }
            }
            self.blocks[head].events = events;
            handlers.push(head);
        }
        let catch_end = self.blocks.len();
        let try_start = self.blocks.len();
        let body = s
            .child_by_field_name("body")
            .map_or(after, |b| self.statement(b, after, t));
        let try_end = self.blocks.len();
        // An exception can leave any block of the try for a handler or
        // the finally, and any block of a handler for the finally.
        for block in &mut self.blocks[try_start..try_end] {
            block.succ.extend(handlers.iter().copied());
            block.succ.extend(finally_entry);
        }
        if let Some(f) = finally_entry {
            for block in &mut self.blocks[catch_start..catch_end] {
                block.succ.push(f);
            }
        }
        body
    }

    fn scoped_statement(&mut self, s: Node<'t>, next: usize, t: Targets) -> usize {
        let children = named_children(s);
        let body = s
            .child_by_field_name("body")
            .or_else(|| children.iter().rev().find(|c| c.kind() == "block").copied());
        let inner = body.map_or(next, |b| self.statement(b, next, t));
        let head = self.block(Some(s), vec![inner]);
        let mut events = Vec::new();
        for c in children.into_iter().filter(|c| Some(*c) != body) {
            events.extend(self.events(c));
        }
        self.blocks[head].events = events;
        head
    }

    /// A local function runs when called; its captures are handled
    /// where they're read.
    fn local_function(&mut self, s: Node<'t>, next: usize) -> usize {
        let events = self.events(s);
        let i = self.block(Some(s), vec![next]);
        self.blocks[i].events = events;
        i
    }

    fn always_true(&self, condition: Node) -> bool {
        let c = unparenthesized(condition);
        c.kind() == "boolean_literal" && self.text(c) == "true"
    }

    /// The declaration a name or declaring node refers to.
    fn decl(&self, n: Node) -> Option<DeclId> {
        let n = if n.kind() == "member_access_expression" && self.text(n).starts_with("this.") {
            n.child_by_field_name("name")?
        } else {
            n
        };
        self.decl_by_node.get(&n.id()).copied().or_else(|| {
            let d = self.m.decl_of(n)?;
            self.decl_by_node.get(&d.node.id()).copied()
        })
    }

    /// Writes of the names a declaration introduces: `x`, `(a, b)`.
    fn definitions(&self, n: Node<'t>) -> Vec<Event<'t>> {
        let mut out = Vec::new();
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            if x.kind() == "identifier" {
                if let Some(d) = self.decl(x) {
                    out.push(Event {
                        decl: d,
                        access: Access::Write,
                        node: x,
                    });
                }
                continue;
            }
            stack.extend(named_children(x).into_iter().rev());
        }
        out
    }

    /// Whether `n` calls the function itself on every evaluation.
    fn recurses(&self, n: Node) -> bool {
        let Some((name, arity)) = &self.own else {
            return false;
        };
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            match x.kind() {
                "lambda_expression"
                | "anonymous_method_expression"
                | "local_function_statement"
                | "conditional_access_expression" => continue,
                // Only the governing value of a switch expression always runs.
                "switch_expression" => {
                    stack.extend(x.named_child(0));
                    continue;
                }
                // Only the condition of `?:` always runs.
                "conditional_expression" => {
                    stack.extend(x.child_by_field_name("condition"));
                    continue;
                }
                "binary_expression"
                    if matches!(
                        x.child_by_field_name("operator").map(|o| self.text(o)),
                        Some("&&" | "||" | "??")
                    ) =>
                {
                    stack.extend(x.child_by_field_name("left"));
                    continue;
                }
                "invocation_expression" => {
                    let callee = x.child_by_field_name("function").map(|f| match f.kind() {
                        "member_access_expression" if self.text(f).starts_with("this.") => {
                            f.child_by_field_name("name").map(|n| self.text(n))
                        }
                        "identifier" => Some(self.text(f)),
                        _ => None,
                    });
                    let args = x
                        .child_by_field_name("arguments")
                        .map_or(0, |a| named_children(a).len());
                    if callee.flatten() == Some(name.as_str()) && args == *arity {
                        return true;
                    }
                }
                _ => {}
            }
            stack.extend(named_children(x));
        }
        false
    }

    /// The reads and writes in `n`, in evaluation order. Walked with an
    /// explicit stack: expressions can nest thousands deep.
    fn events(&mut self, n: Node<'t>) -> Vec<Event<'t>> {
        let mut out = Vec::new();
        let mut stack = vec![EventTask::Visit(n, false)];
        while let Some(task) = stack.pop() {
            match task {
                EventTask::Emit(decl, access, node) => out.push(Event { decl, access, node }),
                EventTask::Visit(x, maybe) => self.event_step(x, maybe, &mut stack, &mut out),
            }
        }
        out
    }

    /// The events of `x`, which may not be evaluated when `maybe`: pushed
    /// to `stack` for later, or to `out` when they're due now.
    fn event_step(
        &mut self,
        x: Node<'t>,
        maybe: bool,
        stack: &mut Vec<EventTask<'t>>,
        out: &mut Vec<Event<'t>>,
    ) {
        let write = if maybe {
            Access::MaybeWrite
        } else {
            Access::Write
        };
        match x.kind() {
            // Captured variables: read whenever the closure runs.
            "lambda_expression" | "anonymous_method_expression" | "local_function_statement" => {
                self.captured_reads(x, out);
            }
            "assignment_expression" => self.assignment_events(x, maybe, write, stack),
            // Parts that may not run.
            "binary_expression"
                if matches!(
                    x.child_by_field_name("operator").map(|o| self.text(o)),
                    Some("&&" | "||" | "??")
                ) =>
            {
                stack.extend(
                    x.child_by_field_name("right")
                        .map(|r| EventTask::Visit(r, true)),
                );
                stack.extend(
                    x.child_by_field_name("left")
                        .map(|l| EventTask::Visit(l, maybe)),
                );
            }
            "conditional_expression" | "switch_expression" | "conditional_access_expression" => {
                let first = x
                    .child_by_field_name("condition")
                    .or_else(|| x.named_child(0));
                for child in named_children(x).into_iter().rev() {
                    stack.push(EventTask::Visit(child, maybe || Some(child) != first));
                }
            }
            "prefix_unary_expression" | "postfix_unary_expression"
                if self.text(x).contains("++") || self.text(x).contains("--") =>
            {
                self.increment_events(x, maybe, write, stack);
            }
            "argument" => self.argument_events(x, maybe, write, stack),
            "declaration_expression" | "declaration_pattern" => {
                if let Some(name) = x.child_by_field_name("name") {
                    for e in self.definitions(name).into_iter().rev() {
                        stack.push(EventTask::Emit(e.decl, write, x));
                    }
                }
            }
            "variable_declarator" => self.declarator_events(x, maybe, write, stack),
            "identifier" => self.read_event(x, out),
            "member_access_expression" if self.text(x).starts_with("this.") => {
                self.read_event(x, out);
            }
            _ => {
                for child in named_children(x).into_iter().rev() {
                    stack.push(EventTask::Visit(child, maybe));
                }
            }
        }
    }

    /// A read of the variable `x` names, if it names one.
    fn read_event(&self, x: Node<'t>, out: &mut Vec<Event<'t>>) {
        if let Some(d) = self.decl(x) {
            out.push(Event {
                decl: d,
                access: Access::Read,
                node: x,
            });
        }
    }

    /// Every variable a closure mentions: read, and escaped, whenever it runs.
    fn captured_reads(&mut self, x: Node<'t>, out: &mut Vec<Event<'t>>) {
        let mut inner = vec![x];
        while let Some(y) = inner.pop() {
            if y.kind() == "identifier"
                && let Some(d) = self.decl(y)
            {
                self.escaped.insert(d);
                out.push(Event {
                    decl: d,
                    access: Access::Read,
                    node: y,
                });
            }
            inner.extend(named_children(y));
        }
    }

    /// The right side, then the write (and, for `+=` and the like, the read
    /// before it). `x ??= y` writes only when x is null.
    fn assignment_events(
        &self,
        x: Node<'t>,
        maybe: bool,
        write: Access,
        stack: &mut Vec<EventTask<'t>>,
    ) {
        let left = x.child_by_field_name("left");
        let right = x.child_by_field_name("right");
        let op = x
            .child_by_field_name("operator")
            .map(|o| self.text(o))
            .unwrap_or("=");
        let compound = op != "=";
        let access = if op == "??=" {
            Access::MaybeWrite
        } else {
            write
        };
        match left.and_then(|l| self.decl(unparenthesized(l))) {
            Some(d) => {
                stack.push(EventTask::Emit(d, access, x));
                if compound {
                    stack.push(EventTask::Emit(d, Access::Read, x));
                }
            }
            None => stack.extend(left.map(|l| EventTask::Visit(l, maybe))),
        }
        stack.extend(right.map(|r| EventTask::Visit(r, maybe || op == "??=")));
    }

    /// `x++`, `--x`: a read, then a write.
    fn increment_events(
        &self,
        x: Node<'t>,
        maybe: bool,
        write: Access,
        stack: &mut Vec<EventTask<'t>>,
    ) {
        match x.named_child(0).and_then(|o| self.decl(unparenthesized(o))) {
            Some(d) => {
                stack.push(EventTask::Emit(d, write, x));
                stack.push(EventTask::Emit(d, Access::Read, x));
            }
            None => stack.extend(x.named_child(0).map(|o| EventTask::Visit(o, maybe))),
        }
    }

    /// `out x` writes x; `ref x` reads it, then writes it.
    fn argument_events(
        &self,
        x: Node<'t>,
        maybe: bool,
        write: Access,
        stack: &mut Vec<EventTask<'t>>,
    ) {
        let t = self.text(x);
        let value = x.named_child(x.named_child_count().saturating_sub(1) as u32);
        let target = value.and_then(|v| self.decl(unparenthesized(v)));
        match (t.starts_with("out "), t.starts_with("ref "), target) {
            (true, _, Some(d)) => stack.push(EventTask::Emit(d, write, x)),
            (_, true, Some(d)) => {
                stack.push(EventTask::Emit(d, write, x));
                stack.push(EventTask::Emit(d, Access::Read, x));
            }
            _ => stack.extend(value.map(|v| EventTask::Visit(v, maybe))),
        }
    }

    /// The initializer runs, then the variable is written.
    fn declarator_events(
        &self,
        x: Node<'t>,
        maybe: bool,
        write: Access,
        stack: &mut Vec<EventTask<'t>>,
    ) {
        if x.named_child_count() <= 1 {
            return;
        }
        if let Some(name) = x.child_by_field_name("name")
            && let Some(d) = self.decl(name)
        {
            stack.push(EventTask::Emit(d, write, x));
        }
        stack.extend(
            x.named_child(x.named_child_count() as u32 - 1)
                .map(|v| EventTask::Visit(v, maybe)),
        );
    }
}

/// Which variables of `tracked` are live right after each block: read on
/// some path from there before any write.
pub(crate) fn live_after(cfg: &Cfg, tracked: &HashSet<DeclId>) -> Vec<HashSet<DeclId>> {
    let n = cfg.blocks.len();
    // Per block: reads before any write in it, and writes.
    let mut gen_sets: Vec<HashSet<DeclId>> = vec![HashSet::new(); n];
    let mut kill: Vec<HashSet<DeclId>> = vec![HashSet::new(); n];
    for (i, b) in cfg.blocks.iter().enumerate() {
        for e in b.events.iter().filter(|e| tracked.contains(&e.decl)) {
            match e.access {
                Access::Read if !kill[i].contains(&e.decl) => {
                    gen_sets[i].insert(e.decl);
                }
                Access::Write => {
                    kill[i].insert(e.decl);
                }
                _ => {}
            }
        }
    }
    let mut live_in: Vec<HashSet<DeclId>> = vec![HashSet::new(); n];
    let mut live_out: Vec<HashSet<DeclId>> = vec![HashSet::new(); n];
    // Each round only grows the sets, so this converges; the bound keeps a
    // pathological graph from taking long.
    for _ in 0..(n + 2).min(512) {
        let mut changed = false;
        for i in (0..n).rev() {
            let out: HashSet<DeclId> = cfg.blocks[i]
                .succ
                .iter()
                .flat_map(|s| live_in[*s].iter().copied())
                .collect();
            let mut inn: HashSet<DeclId> = out
                .iter()
                .copied()
                .filter(|d| !kill[i].contains(d))
                .collect();
            inn.extend(gen_sets[i].iter().copied());
            if inn != live_in[i] || out != live_out[i] {
                changed = true;
                live_in[i] = inn;
                live_out[i] = out;
            }
        }
        if !changed {
            return live_out;
        }
    }
    // Not converged: everything counts as live, so nothing is reported.
    vec![tracked.clone(); n]
}

/// The blocks reachable from `from`, not entering blocks `blocked` refuses.
pub(crate) fn reachable(cfg: &Cfg, from: usize, blocked: impl Fn(usize) -> bool) -> Vec<bool> {
    let mut seen = vec![false; cfg.blocks.len()];
    let mut stack = vec![from];
    while let Some(i) = stack.pop() {
        if seen[i] || (i != from && blocked(i)) {
            continue;
        }
        seen[i] = true;
        stack.extend(cfg.blocks[i].succ.iter().copied());
    }
    seen
}
