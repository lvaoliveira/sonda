//! Scopes and symbols for Ruby (ADR-0008, S1; tree-sitter-ruby), the model
//! the taint engine of ADR-0027 reads.
//!
//! A local variable in Ruby is whatever name was assigned before it, in the
//! source order: `x` is a method call until `x = ..` has been seen, and the
//! grammar has one node (`identifier`) for both. So the first assignment of
//! a name declares it, and an identifier is a use of a variable only if a
//! declaration is visible from where it is:
//! - a method (`def`, `def self.m`) sees nothing outside it, not the file's
//!   locals and not the class's: its scope has no parent to climb to;
//! - a class or module body is a scope of its own that sees nothing outside;
//! - a block, a `do` block and a lambda see the locals around them and take
//!   their own parameters, which hide the ones they share a name with.
//!
//! What binds: the targets of an assignment (`a = ..`, `a[i] = ..`,
//! `a.b = ..`, `a, b = ..`, `a ||= ..`), a `for`'s variable, a `rescue`'s
//! variable, and parameters. An identifier that is the name of a called
//! method (`puts x`, `a.size`) is never a use.
//!
//! Iterative and bounded by the file's deadline, like the other binders.

use super::walk::{Binder, Opened};
use super::{DeclKind, Model, ScopeId, ScopeKind};
use std::time::Instant;
use tree_sitter::Node;

struct Ruby<'t, 's> {
    b: Binder<'t, 's>,
    /// The parent of a method's scope: one that declares nothing, so a
    /// lookup from a method finds only the method's own variables.
    isolated: ScopeId,
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut b = Binder::new(src);
    let isolated = b.m.push_scope(0, ScopeKind::Block);
    // Nothing above it: a lookup that reaches it is over.
    b.m.scopes[isolated].parent = None;
    let mut ruby = Ruby { b, isolated };
    let done = super::walk::run(root, deadline, |node, ancestors, _, scope, _| {
        ruby.visit(node, ancestors, scope)
    });
    if !done {
        return None;
    }
    ruby.b.m.root = Some(root);
    ruby.b.m.resolve();
    Some(ruby.b.m)
}

impl<'t> Ruby<'t, '_> {
    fn visit(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) -> Opened {
        match node.kind() {
            "method" | "singleton_method" => Some((self.method(node), false)),
            "class" | "module" | "singleton_class" => {
                Some((self.b.m.push_scope(self.isolated, ScopeKind::Block), false))
            }
            "block" | "do_block" | "lambda" => Some((self.closure(node, scope), false)),
            "assignment" | "operator_assignment" => {
                self.assignment(node, scope);
                None
            }
            "for" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    for v in targets(pattern) {
                        self.bind(v, scope);
                    }
                }
                None
            }
            "exception_variable" => {
                for v in targets(node) {
                    self.bind(v, scope);
                }
                None
            }
            "identifier" => {
                self.reference(node, ancestors, scope);
                None
            }
            _ => None,
        }
    }

    /// What an assignment binds, each variable declared by it: the one it
    /// assigns.
    fn assignment(&mut self, node: Node<'t>, scope: ScopeId) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        let first = self.b.m.decls.len();
        for v in targets(left) {
            self.bind(v, scope);
        }
        for d in &mut self.b.m.decls[first..] {
            d.declarator = Some(node);
        }
    }

    /// A method's scope, holding its parameters.
    fn method(&mut self, node: Node<'t>) -> ScopeId {
        let list = node
            .child_by_field_name("parameters")
            .map(parameters)
            .unwrap_or_default();
        self.b.function(node, self.isolated, list)
    }

    /// A block's or a lambda's scope: its parameters, in a scope that sees
    /// the one around it. It's no function of the model: its body belongs to
    /// the method it's in.
    fn closure(&mut self, node: Node<'t>, parent: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(parent, ScopeKind::Function);
        if let Some(list) = node.child_by_field_name("parameters") {
            for (name, _, declarator) in parameters(list) {
                self.b.declare(inner, name, DeclKind::Param, None, false);
                if let Some(d) = self.b.m.decls.last_mut() {
                    d.declarator = Some(declarator);
                }
            }
        }
        inner
    }

    /// A variable written: declared if no declaration is visible, else a
    /// write of the one that is.
    fn bind(&mut self, v: Node<'t>, scope: ScopeId) {
        let text = self.b.text(v);
        if self.b.m.lookup(scope, &text).is_some() {
            return;
        }
        self.b.declare(scope, v, DeclKind::Var, None, false);
        if let Some(d) = self.b.m.decls.last_mut() {
            d.writes += 1;
        }
    }

    fn reference(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) {
        if self.b.not_refs.contains(&node.id()) || is_a_name(node, ancestors) {
            return;
        }
        let text = self.b.text(node);
        // Before an assignment, an identifier is a call.
        if self.b.m.lookup(scope, &text).is_none() {
            return;
        }
        let (read, write) = access(node, ancestors);
        self.b.add_ref(node, scope, read, write);
    }
}

/// The parameters of a method, a block or a lambda: each one's name, no
/// type, and the node that declares it.
fn parameters<'t>(list: Node<'t>) -> Vec<super::walk::Param<'t>> {
    let mut out = Vec::new();
    let mut c = list.walk();
    for p in list.named_children(&mut c) {
        let name = match p.kind() {
            "identifier" => Some(p),
            "optional_parameter"
            | "keyword_parameter"
            | "splat_parameter"
            | "hash_splat_parameter"
            | "block_parameter" => p
                .child_by_field_name("name")
                .or_else(|| first_identifier(p)),
            _ => None,
        };
        if let Some(name) = name {
            out.push((name, None, p));
        }
    }
    out
}

fn first_identifier(n: Node) -> Option<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).find(|k| k.kind() == "identifier")
}

/// The variables an assignment's left side writes: the name itself, the
/// variable an element or an attribute is set on (`a[i] = ..`, `a.b = ..`),
/// or every name of a destructuring.
fn targets<'t>(left: Node<'t>) -> Vec<Node<'t>> {
    match left.kind() {
        "identifier" => vec![left],
        "element_reference" => left
            .child_by_field_name("object")
            .map(targets)
            .unwrap_or_default(),
        "call" => left
            .child_by_field_name("receiver")
            .map(targets)
            .unwrap_or_default(),
        "left_assignment_list"
        | "destructured_left_assignment"
        | "rest_assignment"
        | "exception_variable" => {
            let mut c = left.walk();
            left.named_children(&mut c).flat_map(targets).collect()
        }
        _ => Vec::new(),
    }
}

/// Whether an identifier names a method, not a variable: the one a call
/// calls, or the one a `def` defines.
fn is_a_name(node: Node, ancestors: &[Node]) -> bool {
    let Some(&parent) = ancestors.last() else {
        return false;
    };
    let field = |n: Node, f: &str| {
        n.child_by_field_name(f)
            .is_some_and(|c| c.id() == node.id())
    };
    match parent.kind() {
        "call" => field(parent, "method"),
        "method" | "singleton_method" => field(parent, "name"),
        "optional_parameter" | "keyword_parameter" => field(parent, "name"),
        _ => false,
    }
}

/// Whether the reference `node` reads its variable and whether it writes it.
fn access(node: Node, ancestors: &[Node]) -> (bool, bool) {
    let Some(&parent) = ancestors.last() else {
        return (true, false);
    };
    let is_left = |p: Node| {
        p.child_by_field_name("left")
            .is_some_and(|l| l.id() == node.id())
    };
    match parent.kind() {
        "assignment" if is_left(parent) => (false, true),
        "operator_assignment" if is_left(parent) => (true, true),
        "left_assignment_list" | "destructured_left_assignment" | "exception_variable" => {
            (false, true)
        }
        _ => (true, false),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DeclKind, Model};
    use crate::lang::Lang;
    use std::time::{Duration, Instant};

    fn ruby(src: &str, check: impl FnOnce(&Model)) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Ruby.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let model = super::build(
            tree.root_node(),
            src.as_bytes(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        check(&model);
    }

    /// The `n`th declaration called `name`, as (kind, reads, writes).
    fn decl(m: &Model, name: &str, n: usize) -> (DeclKind, u32, u32) {
        let d = m.decls.iter().filter(|d| d.name == name).nth(n).unwrap();
        (d.kind, d.reads, d.writes)
    }

    fn count(m: &Model, name: &str) -> usize {
        m.decls.iter().filter(|d| d.name == name).count()
    }

    #[test]
    fn the_first_assignment_declares_and_the_rest_are_that_variable() {
        let src = "def f(a)\n  x = 1\n  x = x + a\n  x += 2\n  x\nend\n";
        ruby(src, |m| {
            assert_eq!(count(m, "x"), 1);
            // One write that declares it, one `=`, one `+=` (which reads too).
            assert_eq!(decl(m, "x", 0), (DeclKind::Var, 3, 3));
            assert_eq!(decl(m, "a", 0), (DeclKind::Param, 1, 0));
            assert_eq!(m.functions.len(), 1);
            assert_eq!(m.functions[0].params.len(), 1);
        });
    }

    #[test]
    fn a_name_is_a_call_until_it_is_assigned() {
        let src = "def f\n  puts x\n  x = 1\n  puts x\n  x.size\nend\n";
        ruby(src, |m| {
            // The first `x` and the methods `puts` and `size` are no uses.
            assert_eq!(decl(m, "x", 0), (DeclKind::Var, 2, 1));
            assert_eq!(count(m, "puts"), 0);
        });
    }

    #[test]
    fn a_method_sees_none_of_the_locals_around_it() {
        let src = "x = 1\ndef f\n  x\n  y = 2\nend\nclass A\n  z = 3\n  def g; z; end\nend\n";
        ruby(src, |m| {
            // The file's `x` is not read by `f`; nor the class's `z` by `g`.
            assert_eq!(decl(m, "x", 0), (DeclKind::Var, 0, 1));
            assert_eq!(decl(m, "z", 0), (DeclKind::Var, 0, 1));
            assert_eq!(count(m, "y"), 1);
        });
    }

    #[test]
    fn a_block_sees_its_surroundings_and_hides_with_its_parameters() {
        let src = "def f(items)\n  total = 0\n  items.each do |item, total|\n    puts item\n    total\n  end\n  items.map { |i| i + total }\nend\n";
        ruby(src, |m| {
            // The outer `total` is read only by the `map` block.
            assert_eq!(decl(m, "total", 0).1, 1);
            assert_eq!(decl(m, "total", 1), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "item", 0), (DeclKind::Param, 1, 0));
        });
    }

    #[test]
    fn a_variable_set_in_a_block_is_the_outer_one_if_there_is_one() {
        let src = "def f(xs)\n  n = 0\n  xs.each { |x| n += x; m = x }\n  n\nend\n";
        ruby(src, |m| {
            assert_eq!(count(m, "n"), 1);
            assert_eq!(count(m, "m"), 1);
            assert_eq!(decl(m, "n", 0), (DeclKind::Var, 2, 2));
        });
    }

    #[test]
    fn destructuring_for_rescue_and_element_writes() {
        let src = "def f(rows)\n  a, (b, *c) = rows\n  for i in rows do puts i end\n  h = {}\n  h[:k] = 1\n  h.name = 2\nrescue => e\n  puts e\nend\n";
        ruby(src, |m| {
            for name in ["a", "b", "c", "i", "e"] {
                assert_eq!(count(m, name), 1, "{name}");
            }
            // The element and attribute writes are uses of `h`, as in PHP's.
            assert_eq!(decl(m, "h", 0), (DeclKind::Var, 2, 1));
        });
    }
}
