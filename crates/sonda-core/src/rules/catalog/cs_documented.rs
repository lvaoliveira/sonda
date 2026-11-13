//! C# rule checks rewritten from SonarQube's documentation of their keys,
//! when the earlier check covered part of it (ADR-0007): every documented
//! case, examples and exceptions. The rules are declared with the others;
//! this module holds their checks.

use super::cs::{cs_has_modifier, same_code, unparenthesized};
use super::cs_bugs::attribute_names;
use super::cs_types::walk_tree;
use super::java_security::text;
use crate::semantic::cs_infer::{Constant, Conversion, Found, Infer, Ty, arguments};
use crate::semantic::{DeclKind, Model};
use tree_sitter::Node;

// ---------------------------------------------------- S2342

/// Whether a name matches `^([A-Z]{1,3}[a-z0-9]+)*([A-Z]{2})?$`, the
/// documented default for enums.
fn enum_name_matches(name: &[u8]) -> bool {
    let n = name.len();
    let upper = |i: usize| name.get(i).is_some_and(u8::is_ascii_uppercase);
    let lower = |i: usize| {
        name.get(i)
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    };
    // reachable[i]: the groups can end at i.
    let mut reachable = vec![false; n + 1];
    reachable[0] = true;
    for i in 0..n {
        if !reachable[i] {
            continue;
        }
        for caps in 1..=3 {
            if !(0..caps).all(|k| upper(i + k)) {
                break;
            }
            let mut j = i + caps;
            while lower(j) {
                j += 1;
                reachable[j] = true;
            }
        }
    }
    reachable[n] || (n >= 2 && reachable[n - 2] && upper(n - 2) && upper(n - 1))
}

/// Enum names that don't match the documented default: the pattern above,
/// ending in "s" for a `[Flags]` enum.
pub(super) fn misnamed_enum<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = declaration.child_by_field_name("name")?;
    let flags = attribute_names(declaration, src)
        .iter()
        .any(|(_, a)| *a == b"Flags");
    let t = text(name, src);
    let ok = if flags {
        t.strip_suffix(b"s").is_some_and(enum_name_matches)
    } else {
        enum_name_matches(t)
    };
    (!ok).then_some(name)
}

// ---------------------------------------------------- S3240

/// Whether the file uses a C# 8 or later feature, so the project's language
/// version has `??=`: .NET Framework projects default to C# 7.3, and sonda
/// doesn't read the project file.
fn csharp8(root: Node, src: &[u8]) -> bool {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        let evidence = match n.kind() {
            "preproc_nullable"
            | "file_scoped_namespace_declaration"
            | "record_declaration"
            | "switch_expression"
            | "recursive_pattern"
            | "negated_pattern"
            | "and_pattern"
            | "or_pattern"
            | "range_expression"
            | "implicit_object_creation_expression"
            | "with_expression"
            | "raw_string_literal"
            | "collection_expression" => true,
            "assignment_expression" => n
                .child_by_field_name("operator")
                .is_some_and(|o| text(o, src) == b"??="),
            "accessor_declaration" => text(n, src).starts_with(b"init"),
            "local_declaration_statement" => n.children(&mut n.walk()).any(|c| c.kind() == "using"),
            "local_function_statement" => cs_has_modifier(n, "static", src),
            // `string?`: a nullable reference type.
            "nullable_type" => n
                .named_child(0)
                .is_some_and(|t| matches!(text(t, src), b"string" | b"object")),
            _ => false,
        };
        if evidence {
            return true;
        }
        stack.extend(n.named_children(&mut n.walk()));
    }
    false
}

/// `x = value;`, alone or as a block's only statement: the assignment.
fn single_assignment(statement: Node) -> Option<Node> {
    let statement = if statement.kind() == "block" {
        let mut c = statement.walk();
        let mut inner = statement
            .named_children(&mut c)
            .filter(|n| n.kind() != "comment");
        let only = inner.next()?;
        if inner.next().is_some() {
            return None;
        }
        only
    } else {
        statement
    };
    statement.named_child(0).filter(|a| {
        statement.kind() == "expression_statement" && a.kind() == "assignment_expression"
    })
}

/// Whether an assignment's operator is a plain `=`.
fn plain(assignment: Node, src: &[u8]) -> bool {
    assignment
        .child_by_field_name("operator")
        .is_some_and(|o| text(o, src) == b"=")
}

/// `a == null`, `null == a` or `a is null`: the subject.
fn null_check<'t>(condition: Node<'t>, src: &[u8], equal: bool) -> Option<Node<'t>> {
    let c = unparenthesized(condition);
    match c.kind() {
        "binary_expression" => {
            let op = text(c.child_by_field_name("operator")?, src);
            if op != if equal { &b"=="[..] } else { b"!=" } {
                return None;
            }
            let (l, r) = (
                c.child_by_field_name("left")?,
                c.child_by_field_name("right")?,
            );
            match (l.kind(), r.kind()) {
                (_, "null_literal") => Some(l),
                ("null_literal", _) => Some(r),
                _ => None,
            }
        }
        "is_pattern_expression" if equal => {
            let pattern = c.child_by_field_name("pattern")?;
            (pattern.kind() == "constant_pattern"
                && pattern.named_child(0)?.kind() == "null_literal")
                .then(|| c.child_by_field_name("expression"))
                .flatten()
        }
        _ => None,
    }
}

/// The documented shapes simpler syntax replaces: an if/else assigning one
/// variable (a conditional, or `??` when it tests for null), `a != null ?
/// a : b`, `null ?? b`, and, where the file shows C# 8, `if (a == null) a =
/// b;` and `a = a ?? b` (`??=`).
pub(super) fn verbose_conditions<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let (Some(root), Some(infer)) = (m.root, Infer::new(m, src)) else {
        return Vec::new();
    };
    let modern = std::cell::OnceCell::new();
    let modern = || *modern.get_or_init(|| csharp8(root, src));
    let mut found = Vec::new();
    walk_tree(m, |n, _| {
        let verbose = match n.kind() {
            "if_statement" => verbose_if(&infer, n, src, &modern),
            "conditional_expression" => super::cs_opt2::is_null_coalescing_shape(n, src),
            "binary_expression" => verbose_coalescing(n, src, &modern),
            _ => false,
        };
        if verbose {
            found.push(n);
        }
    });
    found
}

/// `c ? a : b` and `a ?? b` need one value to convert to the other's type:
/// before C# 9, `c ? new A() : new B()` doesn't compile.
fn compatible(infer: &Infer, a: Node, b: Node) -> bool {
    let (Some(x), Some(y)) = (infer.type_of(a), infer.type_of(b)) else {
        return false;
    };
    let implicit = |from: &Ty, to: &Ty| {
        matches!(
            infer.conversion(from, to),
            Some(Conversion::Identity | Conversion::Implicit)
        )
    };
    implicit(&x, &y) || implicit(&y, &x)
}

/// `if (c) x = a; else x = b;`, a conditional expression; or `if (x == null)
/// x = a;`, a `??=` from C# 8 on.
fn verbose_if(infer: &Infer, n: Node, src: &[u8], modern: &dyn Fn() -> bool) -> bool {
    let Some(then) = n.child_by_field_name("consequence") else {
        return false;
    };
    let Some(a) = single_assignment(then).filter(|a| plain(*a, src)) else {
        return false;
    };
    let Some(target) = a.child_by_field_name("left") else {
        return false;
    };
    let Some(otherwise) = n.child_by_field_name("alternative") else {
        let checked = n
            .child_by_field_name("condition")
            .and_then(|c| null_check(c, src, true));
        return checked.is_some_and(|s| same_code(s, target, src)) && modern();
    };
    let Some(b) = single_assignment(otherwise).filter(|b| plain(*b, src)) else {
        return false;
    };
    let same_target = b
        .child_by_field_name("left")
        .is_some_and(|t| same_code(t, target, src));
    let values = a
        .child_by_field_name("right")
        .zip(b.child_by_field_name("right"));
    same_target && values.is_some_and(|(x, y)| compatible(infer, x, y))
}

/// `null ?? b`, or `a = a ?? b`, a `??=` from C# 8 on.
fn verbose_coalescing(n: Node, src: &[u8], modern: &dyn Fn() -> bool) -> bool {
    let coalesces = n
        .child_by_field_name("operator")
        .is_some_and(|o| text(o, src) == b"??");
    if !coalesces {
        return false;
    }
    let left = n.child_by_field_name("left").map(unparenthesized);
    if left.is_some_and(|l| l.kind() == "null_literal") {
        return true;
    }
    let assigned = n
        .parent()
        .filter(|p| p.kind() == "assignment_expression" && plain(*p, src))
        .filter(|p| p.child_by_field_name("right").map(|r| r.id()) == Some(n.id()))
        .and_then(|p| p.child_by_field_name("left"));
    matches!((assigned, left), (Some(t), Some(l)) if same_code(t, l, src) && modern())
}

// ---------------------------------------------------- S3257

/// The type a value assigned or declared here must have, when written: a
/// declaration's explicit type, an assignment's target, or `+=` and `-=`,
/// whose target has the value's own delegate type. None in other places,
/// such as an argument, where an overload may need the explicit form.
fn required_type(infer: &Infer, value: Node) -> Option<Required> {
    let parent = value.parent()?;
    match parent.kind() {
        "variable_declarator" => {
            let declaration = parent.parent()?;
            let ty = declaration.child_by_field_name("type")?;
            if ty.kind() == "implicit_type" {
                return None;
            }
            infer.written(ty).map(Required::Type)
        }
        "assignment_expression" => {
            if parent.child_by_field_name("right")?.id() != value.id() {
                return None;
            }
            let op = parent.child_by_field_name("operator")?;
            match infer.text_of(op) {
                "+=" | "-=" => Some(Required::Combined),
                "=" => infer
                    .type_of(parent.child_by_field_name("left")?)
                    .map(Required::Type),
                _ => None,
            }
        }
        _ => None,
    }
}

enum Required {
    Type(Ty),
    /// `+=` or `-=`: a delegate of the value's own type.
    Combined,
}

/// The documented verbose forms, where the context gives the type: empty
/// object initializers, an array's element type its elements all have,
/// an array's size next to its elements, `new D(lambda)` and `new
/// int?(v)`, lambda parameter types, and an anonymous method's unused
/// parameters.
pub(super) fn verbose_declarations<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |n, _| {
        let at = match n.kind() {
            "object_creation_expression" => verbose_creation(&infer, m, n).then_some(n),
            "array_creation_expression" => verbose_array(&infer, n).then_some(n),
            "lambda_expression" => verbose_lambda_params(&infer, n),
            "anonymous_method_expression" => verbose_anonymous_params(&infer, m, n, src),
            _ => None,
        };
        found.extend(at);
    });
    found
}

/// `new List<int>() { }`, `int? i = new int?(5)`, or a delegate created
/// around a lambda or a method where its type is required anyway.
fn verbose_creation(infer: &Infer, m: &Model, n: Node) -> bool {
    let empty = n
        .child_by_field_name("initializer")
        .is_some_and(|i| i.named_child_count() == 0);
    if empty {
        return true;
    }
    let Some(ty) = n.child_by_field_name("type").and_then(|t| infer.written(t)) else {
        return false;
    };
    let Some(args) = n.child_by_field_name("arguments") else {
        return false;
    };
    let values: Vec<Node> = args
        .named_children(&mut args.walk())
        .filter(|a| a.kind() == "argument")
        .filter_map(|a| a.named_child(0))
        .collect();
    let [value] = values.as_slice() else {
        return false;
    };
    let required = required_type(infer, n);
    if ty.is("System.Nullable`1") {
        return matches!(&required, Some(Required::Type(t)) if *t == ty);
    }
    let wraps = matches!(
        value.kind(),
        "lambda_expression" | "anonymous_method_expression"
    ) || value.kind() == "identifier"
        && m.decl_of(*value)
            .is_some_and(|d| matches!(d.kind, DeclKind::Method | DeclKind::Function));
    let fits = match &required {
        Some(Required::Combined) => true,
        Some(Required::Type(t)) => *t == ty,
        None => false,
    };
    infer.delegate(&ty) && wraps && fits
}

/// `new int[3] { 1, 2, 3 }`, or `new int[] { 1, 2, 3 }` with every element
/// already an int.
fn verbose_array(infer: &Infer, n: Node) -> bool {
    let (Some(ty), Some(init)) = (
        n.child_by_field_name("type"),
        n.named_children(&mut n.walk())
            .find(|c| c.kind() == "initializer_expression"),
    ) else {
        return false;
    };
    let Some(rank) = ty.child_by_field_name("rank") else {
        return false;
    };
    if rank.named_child_count() > 0 {
        return true;
    }
    let Some(element) = ty
        .child_by_field_name("type")
        .and_then(|t| infer.written(t))
    else {
        return false;
    };
    let elements: Vec<Node> = init.named_children(&mut init.walk()).collect();
    !elements.is_empty()
        && elements
            .iter()
            .all(|e| infer.type_of(*e).as_ref() == Some(&element))
}

/// Whether the context requires a delegate of `n`'s type anyway.
fn delegate_required(infer: &Infer, n: Node) -> bool {
    match required_type(infer, n) {
        Some(Required::Combined) => true,
        Some(Required::Type(t)) => infer.delegate(&t),
        None => false,
    }
}

/// A lambda's parameter list, when every parameter's type is written and
/// the delegate type gives them anyway. Typed, without modifiers,
/// attributes or defaults; `ref`, `out`, `in` and `scoped` are tokens of
/// their own.
fn verbose_lambda_params<'t>(infer: &Infer, n: Node<'t>) -> Option<Node<'t>> {
    let params = n
        .child_by_field_name("parameters")
        .filter(|p| p.kind() == "parameter_list")?;
    let list: Vec<Node> = params
        .named_children(&mut params.walk())
        .filter(|p| p.kind() == "parameter")
        .collect();
    let plain = !list.is_empty()
        && list.iter().all(|p| {
            p.child_by_field_name("type")
                .is_some_and(|t| !matches!(t.kind(), "ref_type" | "scoped_type"))
                && p.named_child_count() == 2
                && p.child_count() == 2
        });
    (plain && delegate_required(infer, n)).then_some(params)
}

/// An anonymous method's parameter list, when none of its parameters is
/// used (nor `out`) and the delegate type gives them anyway.
fn verbose_anonymous_params<'t>(
    infer: &Infer,
    m: &Model,
    n: Node<'t>,
    src: &[u8],
) -> Option<Node<'t>> {
    let params = n
        .named_children(&mut n.walk())
        .find(|c| c.kind() == "parameter_list")?;
    let list: Vec<Node> = params
        .named_children(&mut params.walk())
        .filter(|p| p.kind() == "parameter")
        .collect();
    let unused = !list.is_empty()
        && list.iter().all(|p| {
            let out = p
                .named_children(&mut p.walk())
                .any(|c| c.kind() == "modifier" && text(c, src) == b"out");
            !out && p.child_by_field_name("name").is_some_and(|name| {
                !m.refs.iter().any(|r| {
                    r.decl
                        .and_then(|d| m.decls.get(d))
                        .is_some_and(|d| d.node.id() == name.id())
                })
            })
        });
    (unused && delegate_required(infer, n)).then_some(params)
}

// ---------------------------------------------------- S3898

/// Structs that don't implement `IEquatable<T>`. Record structs implement
/// it already; ref structs, and structs whose other parts may list it,
/// are left alone.
pub(super) fn struct_without_iequatable<'t>(name: Node<'t>, src: &[u8]) -> bool {
    let Some(declaration) = name.parent() else {
        return false;
    };
    // `ref` is a token of its own, `partial` a modifier.
    let is_ref = declaration
        .children(&mut declaration.walk())
        .any(|c| c.kind() == "ref");
    if is_ref || cs_has_modifier(declaration, "partial", src) {
        return false;
    }
    let lists = declaration
        .named_children(&mut declaration.walk())
        .filter(|c| c.kind() == "base_list")
        .any(|b| {
            b.named_children(&mut b.walk())
                .any(|t| super::cs::simple_name(t, src) == b"IEquatable")
        });
    !lists
}

// ---------------------------------------------------- S3906 / S3908

/// A delegate type's signature: return type, and each parameter's type and
/// name. A type may be unknown.
struct Signature<'s> {
    returns_void: Option<bool>,
    params: Vec<(Option<Ty>, &'s str)>,
}

/// The signature of the delegate type an event is declared with.
fn delegate_signature<'s>(infer: &'s Infer, ty: &Ty) -> Option<Signature<'s>> {
    if let Some(key) = ty.key() {
        let p = dotnet_type(key).filter(|p| p.kind == "delegate")?;
        let invoke = p
            .members
            .iter()
            .find(|m| m.kind == "method" && m.name == "Invoke")?;
        return Some(Signature {
            returns_void: Some(invoke.ty == "System.Void"),
            params: invoke
                .params
                .iter()
                .map(|x| {
                    let t = Ty::parse(&x.ty).map(|t| t.with_type_arguments(ty.args()));
                    (t, x.name.as_str())
                })
                .collect(),
        });
    }
    let node = infer.local_type_node(ty)?;
    if node.kind() != "delegate_declaration" {
        return None;
    }
    let returns = node.child_by_field_name("type")?;
    let list = node.child_by_field_name("parameters")?;
    Some(Signature {
        returns_void: Some(infer.text_of(returns) == "void"),
        params: list
            .named_children(&mut list.walk())
            .filter(|p| p.kind() == "parameter")
            .map(|p| {
                (
                    p.child_by_field_name("type").and_then(|t| infer.written(t)),
                    p.child_by_field_name("name")
                        .map_or("", |n| infer.text_of(n)),
                )
            })
            .collect(),
    })
}

fn dotnet_type(key: &str) -> Option<&'static crate::semantic::dotnet::PlatformType> {
    crate::semantic::dotnet::platform().get(key)
}

/// Whether a type is EventArgs or derives from it; None when its bases
/// don't all resolve.
fn event_args(infer: &Infer, ty: &Ty) -> Option<bool> {
    if infer
        .supertypes(ty)
        .iter()
        .any(|s| s.is("System.EventArgs"))
    {
        return Some(true);
    }
    infer.complete(ty).then_some(false)
}

/// The events of a file, with the node of their name and their type.
fn events<'t>(m: &Model<'t>) -> Vec<(Node<'t>, Node<'t>)> {
    let mut out = Vec::new();
    walk_tree(m, |n, _| match n.kind() {
        "event_field_declaration" => {
            let Some(declaration) = n
                .named_children(&mut n.walk())
                .find(|c| c.kind() == "variable_declaration")
            else {
                return;
            };
            let Some(ty) = declaration.child_by_field_name("type") else {
                return;
            };
            for d in declaration
                .named_children(&mut declaration.walk())
                .filter(|c| c.kind() == "variable_declarator")
            {
                if let Some(name) = d.child_by_field_name("name") {
                    out.push((name, ty));
                }
            }
        }
        "event_declaration" => {
            if let (Some(name), Some(ty)) =
                (n.child_by_field_name("name"), n.child_by_field_name("type"))
            {
                out.push((name, ty));
            }
        }
        _ => {}
    });
    out
}

/// Events whose delegate type doesn't have the documented handler
/// signature: void, `(object sender, EventArgs e)` or a type derived from
/// EventArgs. A part whose type doesn't resolve isn't held against it.
pub(super) fn events_with_wrong_signature<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    events(m)
        .into_iter()
        .filter(|(_, ty)| {
            let Some(sig) = infer
                .written(*ty)
                .and_then(|t| delegate_signature(&infer, &t))
            else {
                return false;
            };
            let [(sender, sender_name), (args, args_name)] = sig.params.as_slice() else {
                return true;
            };
            sig.returns_void == Some(false)
                || *sender_name != "sender"
                || *args_name != "e"
                || sender.as_ref().is_some_and(|t| !t.is("System.Object"))
                || args
                    .as_ref()
                    .is_some_and(|t| event_args(&infer, t) == Some(false))
        })
        .map(|(name, _)| name)
        .collect()
}

/// Delegates the file declares in the old `(object sender, TEventArgs e)`
/// shape, returning void, and uses for an event: `EventHandler<TEventArgs>`
/// does the same.
pub(super) fn old_style_event_handlers<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let used: Vec<Ty> = events(m)
        .into_iter()
        .filter_map(|(_, ty)| infer.written(ty))
        .collect();
    let mut found = Vec::new();
    walk_tree(m, |n, _| {
        if n.kind() != "delegate_declaration" || n.child_by_field_name("type_parameters").is_some()
        {
            return;
        }
        let Some(name) = n.child_by_field_name("name") else {
            return;
        };
        let Some(ty) = infer.written(name) else {
            return;
        };
        if !used.contains(&ty) {
            return;
        }
        let Some(sig) = delegate_signature(&infer, &ty) else {
            return;
        };
        let shaped = sig.returns_void == Some(true)
            && matches!(sig.params.as_slice(), [(Some(s), _), (Some(a), _)]
                if s.is("System.Object") && event_args(&infer, a) == Some(true));
        if shaped {
            found.push(name);
        }
    });
    found
}

// ---------------------------------------------------- S1694

/// Abstract classes whose members are all abstract methods, properties,
/// events or indexers, and whose bases, if any, are interfaces: an
/// interface would do. A field, constructor or implemented member is
/// inheritable behavior, the documented exception.
pub(super) fn interface_shaped_abstract_classes<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |class, _| {
        if class.kind() != "class_declaration" || !cs_has_modifier(class, "abstract", src) {
            return;
        }
        let bases_are_interfaces = class
            .named_children(&mut class.walk())
            .filter(|c| c.kind() == "base_list")
            .flat_map(|b| b.named_children(&mut b.walk()).collect::<Vec<_>>())
            .all(|b| {
                infer
                    .written(b)
                    .is_some_and(|t| infer.interface(&t) == Some(true))
            });
        let Some(body) = class.child_by_field_name("body") else {
            return;
        };
        let members: Vec<Node> = body
            .named_children(&mut body.walk())
            .filter(|c| c.kind() != "comment")
            .collect();
        let all_abstract = !members.is_empty()
            && members.iter().all(|m| {
                matches!(
                    m.kind(),
                    "method_declaration"
                        | "property_declaration"
                        | "event_declaration"
                        | "indexer_declaration"
                ) && cs_has_modifier(*m, "abstract", src)
            });
        // Other parts may implement members.
        let partial = cs_has_modifier(class, "partial", src);
        if bases_are_interfaces
            && all_abstract
            && !partial
            && let Some(name) = class.child_by_field_name("name")
        {
            found.push(name);
        }
    });
    found
}

// ---------------------------------------------------- S3218

/// The members of a type, its nested types apart: their name nodes, and
/// each one's type, when written.
fn member_names<'t>(body: Node<'t>) -> Vec<(Node<'t>, Option<Node<'t>>)> {
    let mut out = Vec::new();
    for member in body.named_children(&mut body.walk()) {
        match member.kind() {
            k if k.starts_with("preproc") => out.extend(member_names(member)),
            "field_declaration" | "event_field_declaration" => {
                let ty = super::cs_more::declared_type(member);
                out.extend(
                    super::cs_more::declarators(member)
                        .into_iter()
                        .filter_map(|d| d.child_by_field_name("name"))
                        .map(|n| (n, ty)),
                );
            }
            "property_declaration" | "event_declaration" => {
                out.extend(
                    member
                        .child_by_field_name("name")
                        .map(|n| (n, member.child_by_field_name("type"))),
                );
            }
            "method_declaration" => {
                out.extend(member.child_by_field_name("name").map(|n| (n, None)));
            }
            _ => {}
        }
    }
    out
}

const TYPE_DECLARATIONS: &[&str] = &[
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "record_struct_declaration",
    "interface_declaration",
    "enum_declaration",
    "delegate_declaration",
];

/// A type's static members and constants, which its nested types see by
/// simple name.
fn visible_names<'s>(body: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut out = Vec::new();
    for member in body.named_children(&mut body.walk()) {
        if member.kind().starts_with("preproc") {
            out.extend(visible_names(member, src));
            continue;
        }
        if !(cs_has_modifier(member, "static", src) || cs_has_modifier(member, "const", src)) {
            continue;
        }
        let names = match member.kind() {
            "field_declaration" | "event_field_declaration" => super::cs_more::declarators(member)
                .into_iter()
                .filter_map(|d| d.child_by_field_name("name"))
                .collect(),
            "property_declaration" | "method_declaration" | "event_declaration" => {
                member.child_by_field_name("name").into_iter().collect()
            }
            _ => Vec::new(),
        };
        out.extend(names.into_iter().map(|n| text(n, src)));
    }
    out
}

/// Members of nested types named like a static member of a type they're
/// in, at any depth: inside, the name means the inner one. A member named
/// after its own type is left alone.
pub(super) fn shadowing_inner_members<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(root) = m.root else {
        return Vec::new();
    };
    let mut found = Vec::new();
    // (type declaration, the names its enclosing types make visible)
    let mut stack: Vec<(Node<'t>, Vec<&[u8]>)> = vec![(root, Vec::new())];
    while let Some((n, outer)) = stack.pop() {
        let is_type = TYPE_DECLARATIONS.contains(&n.kind());
        let body = if is_type {
            n.child_by_field_name("body")
        } else {
            Some(n)
        };
        let Some(body) = body else {
            continue;
        };
        if is_type && !outer.is_empty() {
            found.extend(shadowing_members(body, &outer, src));
        }
        let mut inner = outer.clone();
        if is_type {
            inner.extend(visible_names(body, src));
        }
        let next = if is_type { inner } else { outer };
        push_nested(body, &next, &mut stack);
    }
    found.sort_by_key(|n| n.start_byte());
    found
}

/// The members of a nested type named like a name of an enclosing type,
/// other than `public Address Address`, a member typed after it: C#
/// resolves the name either way.
fn shadowing_members<'t>(body: Node<'t>, outer: &[&[u8]], src: &[u8]) -> Vec<Node<'t>> {
    member_names(body)
        .into_iter()
        .filter(|(name, ty)| {
            let n = text(*name, src);
            outer.contains(&n) && ty.is_none_or(|t| super::cs::simple_name(t, src) != n)
        })
        .map(|(name, _)| name)
        .collect()
}

/// The type declarations and namespaces in `body`, with the names visible
/// in them, for `shadowing_inner_members` to look at next.
fn push_nested<'t, 's>(
    body: Node<'t>,
    names: &[&'s [u8]],
    stack: &mut Vec<(Node<'t>, Vec<&'s [u8]>)>,
) {
    for c in body.named_children(&mut body.walk()) {
        let nests = TYPE_DECLARATIONS.contains(&c.kind())
            || c.kind().starts_with("preproc")
            || matches!(
                c.kind(),
                "namespace_declaration" | "file_scoped_namespace_declaration" | "declaration_list"
            );
        if !nests {
            continue;
        }
        if c.kind() == "namespace_declaration" {
            if let Some(b) = c.child_by_field_name("body") {
                stack.push((b, names.to_vec()));
            }
        } else {
            stack.push((c, names.to_vec()));
        }
    }
}

// ---------------------------------------------------- S3241

/// Return types whose value a call uses without naming it: awaited, or
/// iterated.
const USED_BY_SHAPE: &[&[u8]] = &[
    b"void",
    b"Task",
    b"ValueTask",
    b"IEnumerable",
    b"IEnumerator",
    b"IAsyncEnumerable",
];

/// Private methods every call of which drops the value they return.
/// Overloads are told apart by resolving each call; when one doesn't
/// resolve, or the name is used otherwise, none of them is reported.
/// Methods of partial types, which other files may call, are left alone.
pub(super) fn unused_private_returns<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |class, _| {
        if !checked_class(class, src) {
            return;
        }
        let Some(body) = class.child_by_field_name("body") else {
            return;
        };
        let methods: Vec<Node> = body
            .named_children(&mut body.walk())
            .filter(|c| c.kind() == "method_declaration")
            .collect();
        let mut names: Vec<&[u8]> = methods
            .iter()
            .filter_map(|m| m.child_by_field_name("name").map(|n| text(n, src)))
            .collect();
        names.sort();
        names.dedup();
        // The identifiers of the body, by name: one walk for every method.
        let mut occurrences: Option<Occurrences> = None;
        for name in names {
            let group: Vec<Node> = methods
                .iter()
                .copied()
                .filter(|m| {
                    m.child_by_field_name("name")
                        .is_some_and(|n| text(n, src) == name)
                })
                .collect();
            let candidates = droppable_candidates(&group, src);
            if candidates.is_empty() {
                continue;
            }
            let occurrences = occurrences.get_or_insert_with(|| identifier_occurrences(body, src));
            let named = occurrences.get(name).map_or(&[][..], Vec::as_slice);
            if let Some(uses) = name_uses(&infer, &group, named, src) {
                push_always_dropped(&candidates, &group, &uses, &mut found);
            }
        }
    });
    found
}

/// A class, struct or record that isn't partial: other files may call a
/// partial type's methods.
fn checked_class(class: Node, src: &[u8]) -> bool {
    matches!(
        class.kind(),
        "class_declaration" | "struct_declaration" | "record_declaration"
    ) && !cs_has_modifier(class, "partial", src)
}

/// The methods of `group` whose value may go unused: private, returning
/// something not used by its shape, and not an explicit interface member.
fn droppable_candidates<'t>(group: &[Node<'t>], src: &[u8]) -> Vec<Node<'t>> {
    group
        .iter()
        .copied()
        .filter(|method| {
            let returns = method
                .child_by_field_name("returns")
                .map_or(&b"void"[..], |t| super::cs::simple_name(t, src));
            let explicit = method
                .named_children(&mut method.walk())
                .any(|c| c.kind() == "explicit_interface_specifier");
            !USED_BY_SHAPE.contains(&returns)
                && !explicit
                && !["public", "protected", "internal"]
                    .iter()
                    .chain(&["override", "virtual", "abstract", "partial", "extern"])
                    .any(|w| cs_has_modifier(*method, w, src))
        })
        .collect()
}

/// A type body's identifiers, by name.
type Occurrences<'s, 't> = std::collections::HashMap<&'s [u8], Vec<Node<'t>>>;

fn identifier_occurrences<'s, 't>(body: Node<'t>, src: &'s [u8]) -> Occurrences<'s, 't> {
    let mut occurrences = Occurrences::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        stack.extend(n.named_children(&mut n.walk()));
        if n.kind() == "identifier" {
            occurrences.entry(text(n, src)).or_default().push(n);
        }
    }
    occurrences
}

/// What one mention of a method's name is.
enum NameUse {
    /// Not this type's method: its own declaration, or another type's.
    Other,
    /// Can't tell which method it is, or a method group: report none.
    Open,
    /// A call of method `.0` of the group; whether its value is dropped.
    Call(usize, bool),
}

/// Each call of a method of `group` among the name's `occurrences`: the
/// method it binds to, and whether its value is dropped. None when a use
/// leaves it open.
fn name_uses(
    infer: &Infer,
    group: &[Node],
    occurrences: &[Node],
    src: &[u8],
) -> Option<Vec<(usize, bool)>> {
    let mut uses = Vec::new();
    for &n in occurrences {
        match use_of(infer, n, group, src) {
            NameUse::Other => {}
            NameUse::Open => return None,
            NameUse::Call(target, dropped) => uses.push((target, dropped)),
        }
    }
    Some(uses)
}

fn use_of(infer: &Infer, n: Node, group: &[Node], src: &[u8]) -> NameUse {
    let parent = n.parent();
    // A declaration's own name.
    if parent.is_some_and(|p| {
        p.kind() == "method_declaration" && p.child_by_field_name("name") == Some(n)
    }) {
        return NameUse::Other;
    }
    let accessed = parent.filter(|p| {
        p.kind() == "member_access_expression" && p.child_by_field_name("name") == Some(n)
    });
    let callee = accessed.unwrap_or(n);
    let call = callee.parent().filter(|c| {
        c.kind() == "invocation_expression" && c.child_by_field_name("function") == Some(callee)
    });
    let Some(call) = call else {
        // `other.Name` of another type, or a method group of this one.
        let own = accessed
            .and_then(|a| a.child_by_field_name("expression"))
            .and_then(|e| infer.type_of(e))
            .zip(infer.enclosing_type(n))
            .is_some_and(|(a, b)| a == b);
        return if accessed.is_some() && !own {
            NameUse::Other
        } else {
            NameUse::Open
        };
    };
    let dropped = call
        .parent()
        .is_some_and(|s| s.kind() == "expression_statement");
    // One method of that name: a bare or `this.` call is it.
    let this_call = accessed
        .and_then(|a| a.child_by_field_name("expression"))
        .is_none_or(|e| e.kind() == "this_expression" || text(e, src) == b"this");
    if group.len() == 1 && this_call {
        return NameUse::Call(0, dropped);
    }
    let bound = infer.resolve_with(call, &arguments(call));
    let resolved = bound.is_some();
    let target = match bound.map(|b| b.method) {
        Some(Found::Local(d)) => group.iter().position(|g| d.declarator == Some(*g)),
        _ => None,
    };
    match target {
        Some(target) => NameUse::Call(target, dropped),
        // Another type's method of the same name.
        None if accessed.is_some() && resolved => NameUse::Other,
        None => NameUse::Open,
    }
}

/// The candidates called at least once, whose value every call drops.
fn push_always_dropped<'t>(
    candidates: &[Node<'t>],
    group: &[Node<'t>],
    uses: &[(usize, bool)],
    found: &mut Vec<Node<'t>>,
) {
    for method in candidates {
        let index = group.iter().position(|g| g == method).unwrap_or(usize::MAX);
        let calls: Vec<bool> = uses
            .iter()
            .filter(|(t, _)| *t == index)
            .map(|(_, d)| *d)
            .collect();
        if !calls.is_empty()
            && calls.iter().all(|d| *d)
            && let Some(returns) = method.child_by_field_name("returns")
        {
            found.push(returns);
        }
    }
}

// ---------------------------------------------------- S4070

/// An enum member's value: literals, shifts, `|`, `&`, `^`, `~`, `+`, `-`
/// and other members of the same enum. None for what it can't evaluate.
fn enum_value(
    expr: Node,
    src: &[u8],
    members: &[(&[u8], Option<i128>)],
    depth: u8,
) -> Option<i128> {
    if depth > 16 {
        return None;
    }
    let d = depth + 1;
    match expr.kind() {
        "integer_literal" => {
            let t = std::str::from_utf8(text(expr, src))
                .ok()?
                .replace('_', "")
                .to_ascii_lowercase();
            let t = t.trim_end_matches(['u', 'l']);
            if let Some(h) = t.strip_prefix("0x") {
                i128::from_str_radix(h, 16).ok()
            } else if let Some(b) = t.strip_prefix("0b") {
                i128::from_str_radix(b, 2).ok()
            } else {
                t.parse().ok()
            }
        }
        "parenthesized_expression" | "cast_expression" => {
            let inner = expr
                .child_by_field_name("value")
                .or_else(|| expr.named_children(&mut expr.walk()).last())?;
            enum_value(inner, src, members, d)
        }
        "identifier" | "member_access_expression" => {
            let name = expr.child_by_field_name("name").unwrap_or(expr);
            let name = text(name, src);
            members
                .iter()
                .find(|(n, _)| *n == name)
                .and_then(|(_, v)| *v)
        }
        "prefix_unary_expression" => {
            let v = enum_value(expr.named_child(0)?, src, members, d)?;
            match text(expr, src).first()? {
                b'~' => Some(!v),
                b'-' => Some(-v),
                b'+' => Some(v),
                _ => None,
            }
        }
        "binary_expression" => {
            let l = enum_value(expr.child_by_field_name("left")?, src, members, d)?;
            let r = enum_value(expr.child_by_field_name("right")?, src, members, d)?;
            Some(match text(expr.child_by_field_name("operator")?, src) {
                b"|" => l | r,
                b"&" => l & r,
                b"^" => l ^ r,
                b"+" => l + r,
                b"-" => l - r,
                b"<<" => l.checked_shl(u32::try_from(r).ok()?)?,
                b">>" => l >> u32::try_from(r).ok()?,
                _ => return None,
            })
        }
        _ => None,
    }
}

/// Whether a declaration is visible outside its assembly: it and every
/// type around it public, or protected (not `private protected`).
fn externally_visible(declaration: Node, src: &[u8]) -> bool {
    std::iter::successors(Some(declaration), |n| n.parent())
        .filter(|d| d.kind().ends_with("_declaration") && !d.kind().contains("namespace"))
        .all(|d| {
            cs_has_modifier(d, "public", src)
                || cs_has_modifier(d, "protected", src) && !cs_has_modifier(d, "private", src)
        })
}

/// Externally visible `[Flags]` enums with a member that is neither 0, a
/// power of two, nor a combination of the other members. Enums whose
/// values it can't all evaluate are left alone.
pub(super) fn misflagged_enum<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let flags = attribute_names(declaration, src)
        .iter()
        .any(|(_, a)| *a == b"Flags");
    if !flags || !externally_visible(declaration, src) {
        return None;
    }
    let body = declaration.child_by_field_name("body")?;
    let mut members: Vec<(&[u8], Option<i128>)> = Vec::new();
    let mut next = Some(0i128);
    for m in body.named_children(&mut body.walk()) {
        if m.kind() != "enum_member_declaration" {
            continue;
        }
        let name = text(m.child_by_field_name("name")?, src);
        let value = match m.child_by_field_name("value") {
            Some(v) => enum_value(v, src, &members, 0),
            None => next,
        };
        members.push((name, value));
        next = value.map(|v| v + 1);
    }
    let values: Vec<i128> = members.iter().map(|(_, v)| *v).collect::<Option<_>>()?;
    let wrong = values.iter().enumerate().any(|(i, &v)| {
        if v == 0 || (v > 0 && (v & (v - 1)) == 0) {
            return false;
        }
        // The other members whose bits it holds, together.
        let covered = values
            .iter()
            .enumerate()
            .filter(|&(j, &w)| j != i && w != 0 && w & !v == 0)
            .fold(0, |acc, (_, &w)| acc | w);
        covered != v
    });
    wrong
        .then(|| declaration.child_by_field_name("name"))
        .flatten()
}

// ---------------------------------------------------- S5332

/// A URL's host, past any `user:password@`.
fn url_host(url: &[u8]) -> Option<String> {
    let rest = &url[url.windows(3).position(|w| w == b"://")? + 3..];
    let authority_end = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b'?' | b'#' | b'\\'))
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = match authority.iter().rposition(|&b| b == b'@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let host = &host[..host.iter().position(|&b| b == b':').unwrap_or(host.len())];
    let host = String::from_utf8_lossy(host).to_ascii_lowercase();
    (!host.is_empty() && !host.contains(['$', '{', '%', '<', '[', ' '])).then_some(host)
}

/// Clear-text protocols: an `http`, `ftp` or `telnet` URL to a host the
/// public internet reaches (not a private, loopback, documentation or XML
/// namespace one), an `SmtpClient` whose `EnableSsl` isn't set, and a
/// Telnet client.
pub(super) fn cleartext_protocols<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |n, ancestors| {
        let cleartext = match n.kind() {
            "string_literal" | "verbatim_string_literal" => cleartext_url(n, src),
            "object_creation_expression" => cleartext_client(&infer, n, ancestors, src),
            _ => false,
        };
        if cleartext {
            found.push(n);
        }
    });
    found
}

/// An `http://`, `ftp://` or `telnet://` URL to a public host.
fn cleartext_url(n: Node, src: &[u8]) -> bool {
    let Some(value) = super::cs::cs_string_value(n, src) else {
        return false;
    };
    let lower = value.to_ascii_lowercase();
    let scheme = [&b"http://"[..], b"ftp://", b"telnet://"]
        .iter()
        .any(|p| lower.starts_with(p));
    scheme
        && (placeholder_host(value)
            || url_host(value).is_some_and(|h| {
                !super::java_security::is_private_host(&h)
                    && !super::java_security::is_namespace_host(&h)
                    && h != "tempuri.org"
                    && h != "schema.org"
                    && !h.starts_with("schemas.")
            }))
}

/// `http://[host]:[port]/api`: a placeholder for whatever host is
/// configured, which may be a public one (measured on SonarQube 26.7). An
/// IPv6 address, `[::1]`, isn't one.
fn placeholder_host(url: &[u8]) -> bool {
    let Some(at) = url.windows(3).position(|w| w == b"://") else {
        return false;
    };
    let rest = &url[at + 3..];
    rest.strip_prefix(b"[").is_some_and(|inner| {
        inner
            .iter()
            .position(|&b| b == b']')
            .is_some_and(|close| close > 0 && !inner[..close].contains(&b':'))
    })
}

/// A Telnet client, or an SmtpClient whose `EnableSsl` is set neither in
/// its initializer nor later in the same body.
fn cleartext_client(infer: &Infer, n: Node, ancestors: &[Node], src: &[u8]) -> bool {
    let Some(ty) = n.child_by_field_name("type") else {
        return false;
    };
    if text(ty, src)
        .to_ascii_lowercase()
        .windows(6)
        .any(|w| w == b"telnet")
    {
        return true;
    }
    let smtp = infer
        .written(ty)
        .is_some_and(|t| t.is("System.Net.Mail.SmtpClient"));
    if !smtp {
        return false;
    }
    let in_initializer = n
        .child_by_field_name("initializer")
        .is_some_and(|i| text(i, src).windows(9).any(|w| w == b"EnableSsl"));
    let body = ancestors.iter().rev().find(|a| {
        matches!(
            a.kind(),
            "block" | "arrow_expression_clause" | "declaration_list" | "compilation_unit"
        )
    });
    let later = body.is_some_and(|b| text(*b, src).windows(10).any(|w| w == b".EnableSsl"));
    !in_initializer && !later
}

// ---------------------------------------------------- S6585

/// The types whose ToString takes a date or time format.
const DATE_TYPES: &[&str] = &[
    "System.DateTime",
    "System.DateTimeOffset",
    "System.TimeSpan",
    "System.DateOnly",
    "System.TimeOnly",
];

/// `ToString` of a date, time or time span with a hard-coded custom format:
/// a constant string other than a one-letter standard format.
pub(super) fn hardcoded_date_formats<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |call, _| {
        if call.kind() != "invocation_expression" {
            return;
        }
        let Some(function) = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "member_access_expression")
        else {
            return;
        };
        if function.child_by_field_name("name").map(|n| text(n, src)) != Some(b"ToString") {
            return;
        }
        let dated = function
            .child_by_field_name("expression")
            .and_then(|e| infer.type_of(e))
            .is_some_and(|t| DATE_TYPES.iter().any(|k| t.is(k)));
        let Some(format) = arguments(call)
            .first()
            .copied()
            .filter(|a| a.name.is_none())
        else {
            return;
        };
        let custom = matches!(
            infer.constant(format.value, None),
            Some(crate::semantic::cs_infer::Constant::Str(f)) if f.chars().count() > 1
        );
        if dated && custom {
            found.push(call);
        }
    });
    found
}

// ---------------------------------------------------- S5856

const REGEX: &str = "System.Text.RegularExpressions.Regex";

/// The `RegexOptions` that change how a pattern reads or what it may use.
const EXPLICIT_CAPTURE: i128 = 4;
const IGNORE_PATTERN_WHITESPACE: i128 = 32;
const ECMASCRIPT: i128 = 256;
const NON_BACKTRACKING: i128 = 1024;

/// The `Regex` members that take a pattern.
const PATTERN_TAKERS: &[&[u8]] = &[
    b"Regex",
    b"IsMatch",
    b"Match",
    b"Matches",
    b"Replace",
    b"Split",
    b"Count",
    b"EnumerateMatches",
    b"EnumerateSplits",
];

/// A string constant, `+` concatenations of them included.
fn string_constant(infer: &Infer, expr: Node) -> Option<String> {
    if expr.kind() == "binary_expression" && expr.child_by_field_name("operator")?.kind() == "+" {
        let left = string_constant(infer, expr.child_by_field_name("left")?)?;
        return Some(left + &string_constant(infer, expr.child_by_field_name("right")?)?);
    }
    match infer.constant(expr, None)? {
        Constant::Str(s) => Some(s),
        _ => None,
    }
}

/// An options constant, `|` combinations of them included.
fn flags_constant(infer: &Infer, expr: Node) -> Option<i128> {
    match expr.kind() {
        "binary_expression" if expr.child_by_field_name("operator")?.kind() == "|" => Some(
            flags_constant(infer, expr.child_by_field_name("left")?)?
                | flags_constant(infer, expr.child_by_field_name("right")?)?,
        ),
        "parenthesized_expression" => flags_constant(infer, expr.named_child(0)?),
        _ => match infer.constant(expr, None)? {
            Constant::Int(v) => Some(v),
            _ => None,
        },
    }
}

/// Where a call puts its pattern and options. When the call binds, by
/// its method; when it doesn't (an argument's type unknown), and it is
/// made on the `Regex` type itself, by the overloads taking a pattern,
/// should they all agree.
fn pattern_arguments<'t>(
    infer: &Infer<'_, 't>,
    call: Node<'t>,
) -> Option<(Node<'t>, Option<Node<'t>>)> {
    let args = arguments(call);
    if let Some(b) = infer.resolve_with(call, &args) {
        if !matches!(&b.method, Found::Platform { declaring, .. } if declaring.name == REGEX) {
            return None;
        }
        let argument = |name: &str| {
            args.iter()
                .zip(&b.targets)
                .find(|(_, k)| b.params.get(**k).is_some_and(|p| p.name == name))
                .map(|(a, _)| a.value)
        };
        return Some((argument("pattern")?, argument("options")));
    }
    let on_regex = match call.kind() {
        "object_creation_expression" => call.child_by_field_name("type"),
        _ => call
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("expression"))
            .filter(|e| infer.type_of(*e).is_none()),
    }
    .and_then(|t| infer.written(t))
    .is_some_and(|t| t.is(REGEX));
    if !on_regex || args.iter().any(|a| a.name.is_some()) {
        return None;
    }
    let lists: Vec<_> = infer
        .candidate_params(call, args.len())
        .into_iter()
        .filter(|ps| ps.iter().take(args.len()).any(|p| p.name == "pattern"))
        .collect();
    let agreed = |name: &str| {
        let mut at = lists
            .iter()
            .map(|ps| ps.iter().take(args.len()).position(|p| p.name == name));
        let first = at.next()?;
        at.all(|k| k == first).then_some(first)
    };
    let pattern = agreed("pattern")??;
    let options = agreed("options")?;
    Some((
        args.get(pattern)?.value,
        options.and_then(|k| args.get(k)).map(|a| a.value),
    ))
}

/// Patterns passed to `Regex` that its parser rejects, and negative
/// lookarounds with `RegexOptions.NonBacktracking`, which throw too.
/// Patterns and options must be constants; under `ECMAScript` the syntax
/// differs, so those aren't judged.
pub(super) fn invalid_regexes<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    use crate::regex::dotnet::{Options, Verdict, check};
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |call, _| {
        if !matches!(
            call.kind(),
            "invocation_expression" | "object_creation_expression"
        ) || !super::cs_inferred::call_name(call, src)
            .is_some_and(|n| PATTERN_TAKERS.contains(&n))
        {
            return;
        }
        let Some((pattern, options)) = pattern_arguments(&infer, call) else {
            return;
        };
        let Some(text) = string_constant(&infer, pattern) else {
            return;
        };
        let options = match options {
            Some(o) => match flags_constant(&infer, o) {
                Some(v) => v,
                None => return,
            },
            None => 0,
        };
        if options & ECMASCRIPT != 0 {
            return;
        }
        let reading = Options {
            x: options & IGNORE_PATTERN_WHITESPACE != 0,
            n: options & EXPLICIT_CAPTURE != 0,
        };
        let rejected = match check(&text, reading) {
            Verdict::Invalid => true,
            Verdict::Valid(f) => f.negative_lookaround && options & NON_BACKTRACKING != 0,
            Verdict::Unknown => false,
        };
        if rejected {
            found.push(pattern);
        }
    });
    found
}

// ---------------------------------------------------- S2930

/// The types SonarQube documents tracking, by key.
const TRACKED_DISPOSABLES: &[&str] = &[
    "FluentAssertions.Execution.AssertionScope",
    "System.Drawing.Bitmap",
    "System.Drawing.Image",
    "System.IO.FileStream",
    "System.IO.StreamReader",
    "System.IO.StreamWriter",
    "System.Net.Sockets.TcpClient",
    "System.Net.Sockets.UdpClient",
    "System.Net.WebClient",
];

/// Whether a file imports a namespace.
fn imports(root: Node, namespace: &[u8], src: &[u8]) -> bool {
    root.named_children(&mut root.walk()).any(|c| {
        c.kind() == "using_directive"
            && c.named_child(c.named_child_count().saturating_sub(1) as u32)
                .is_some_and(|n| text(n, src) == namespace)
    })
}

/// Whether a written type is one the documentation tracks. System.Drawing
/// and FluentAssertions come in packages, not the platform's packs: their
/// types are told by name, in a file that imports their namespace.
fn tracked_type(infer: &Infer, root: Node, ty: Node, src: &[u8]) -> bool {
    if let Some(t) = infer.written(ty) {
        return t.key().is_some_and(|k| TRACKED_DISPOSABLES.contains(&k));
    }
    let written = text(ty, src);
    TRACKED_DISPOSABLES.iter().any(|k| {
        let (ns, name) = k.rsplit_once('.').unwrap_or(("", k));
        written == k.as_bytes() || written == name.as_bytes() && imports(root, ns.as_bytes(), src)
    })
}

/// The documented factories: `File.Create`, `File.Open`, `Image.FromFile`,
/// `Image.FromStream`.
fn tracked_factory(infer: &Infer, root: Node, call: Node, src: &[u8]) -> bool {
    let Some(function) = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")
    else {
        return false;
    };
    let (Some(owner), Some(name)) = (
        function.child_by_field_name("expression"),
        function.child_by_field_name("name").map(|n| text(n, src)),
    ) else {
        return false;
    };
    match name {
        b"Create" | b"Open" => infer.written(owner).is_some_and(|t| t.is("System.IO.File")),
        b"FromFile" | b"FromStream" => {
            tracked_type(infer, root, owner, src)
                && matches!(super::cs::simple_name(owner, src), b"Image")
        }
        _ => false,
    }
}

/// A new tracked object: `new FileStream(...)` or a documented factory.
fn creates_tracked(infer: &Infer, root: Node, value: Node, src: &[u8]) -> bool {
    match value.kind() {
        "object_creation_expression" => value
            .child_by_field_name("type")
            .is_some_and(|t| tracked_type(infer, root, t, src)),
        "invocation_expression" => tracked_factory(infer, root, value, src),
        _ => false,
    }
}

/// Whether an object is created from another disposable one, such as a
/// reader over a stream, which disposing the stream takes care of. An
/// argument whose type doesn't resolve may be one.
fn wraps_disposable(infer: &Infer, value: Node) -> bool {
    arguments(value).iter().any(|a| {
        infer.type_of(a.value).is_none_or(|t| {
            infer
                .supertypes(&t)
                .iter()
                .any(|s| s.is("System.IDisposable") || s.is("System.IAsyncDisposable"))
        })
    })
}

/// Whether one of these uses disposes, closes, aliases, returns or passes
/// the object on.
fn any_released(uses: &[Node], src: &[u8]) -> bool {
    uses.iter().any(|u| {
        matches!(
            super::cs_flow::released(*u, src),
            super::cs_flow::Fate::Released
        )
    })
}

/// Private fields and local variables of the documented types, created with
/// `new` or a documented factory, that nothing disposes, closes, aliases,
/// returns or passes on. Locals declared with `using`, and those created
/// from another disposable object, are left alone, as documented.
pub(super) fn undisposed_resources<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let (Some(root), Some(infer)) = (m.root, Infer::new(m, src)) else {
        return Vec::new();
    };
    let mut uses: Vec<Vec<Node<'t>>> = vec![Vec::new(); m.decls.len()];
    for r in &m.refs {
        if let Some(d) = r.decl {
            uses[d].push(r.node);
        }
    }
    let mut found = Vec::new();
    for (i, d) in m.decls.iter().enumerate() {
        let Some(declarator) = d.declarator.filter(|x| x.kind() == "variable_declarator") else {
            continue;
        };
        let initial = (declarator.named_child_count() > 1)
            .then(|| declarator.named_child(declarator.named_child_count() as u32 - 1))
            .flatten();
        let undisposed = match d.kind {
            DeclKind::Let => undisposed_local(&infer, root, declarator, initial, &uses[i], src),
            DeclKind::Field => undisposed_field(&infer, root, m, d, declarator, initial, src),
            _ => false,
        };
        if undisposed {
            found.push(d.node);
        }
    }
    found.sort_by_key(|n| n.start_byte());
    found
}

/// A local created as a tracked resource, outside `using var x = ...` and
/// `using (var x = ...)`, that nothing releases nor wraps.
fn undisposed_local(
    infer: &Infer,
    root: Node,
    declarator: Node,
    initial: Option<Node>,
    uses: &[Node],
    src: &[u8],
) -> bool {
    let Some(value) = initial.filter(|v| creates_tracked(infer, root, *v, src)) else {
        return false;
    };
    let statement = declarator.parent().and_then(|v| v.parent());
    let using = statement.is_none_or(|s| {
        s.kind() != "local_declaration_statement"
            || s.children(&mut s.walk()).any(|c| c.kind() == "using")
    });
    !using && !wraps_disposable(infer, value) && !any_released(uses, src)
}

/// A private field of a tracked type, created by its initializer or by an
/// assignment, that nothing releases.
fn undisposed_field<'t>(
    infer: &Infer,
    root: Node,
    m: &Model<'t>,
    d: &crate::semantic::Decl<'t>,
    declarator: Node<'t>,
    initial: Option<Node>,
    src: &[u8],
) -> bool {
    let Some(declaration) = declarator.parent().and_then(|v| v.parent()) else {
        return false;
    };
    let private = !["public", "protected", "internal"]
        .iter()
        .any(|w| cs_has_modifier(declaration, w, src));
    let typed = d.ty.is_some_and(|t| tracked_type(infer, root, t, src));
    let Some(class) = declaration
        .parent()
        .filter(|p| p.kind() == "declaration_list")
    else {
        return false;
    };
    if !private || !typed {
        return false;
    }
    let occurrences = field_occurrences(m, d, class, src);
    let created = initial.is_some_and(|v| creates_tracked(infer, root, v, src))
        || occurrences.iter().any(|o| {
            o.parent()
                .filter(|a| {
                    a.kind() == "assignment_expression" && a.child_by_field_name("left") == Some(*o)
                })
                .and_then(|a| a.child_by_field_name("right"))
                .is_some_and(|v| creates_tracked(infer, root, v, src))
        });
    created && !any_released(&occurrences, src)
}

/// A field's uses in its class: the name alone, or `this.name`.
fn field_occurrences<'t>(
    m: &Model<'t>,
    d: &crate::semantic::Decl<'t>,
    class: Node<'t>,
    src: &[u8],
) -> Vec<Node<'t>> {
    let name = d.name.as_bytes();
    let mut occurrences = Vec::new();
    let mut stack = vec![class];
    while let Some(n) = stack.pop() {
        stack.extend(n.named_children(&mut n.walk()));
        if n.kind() != "identifier" || text(n, src) != name || n.id() == d.node.id() {
            continue;
        }
        let this = n.parent().filter(|p| {
            p.kind() == "member_access_expression"
                && p.child_by_field_name("name") == Some(n)
                && p.child_by_field_name("expression")
                    .is_some_and(|e| text(e, src) == b"this")
        });
        match this {
            Some(access) => occurrences.push(access),
            None if m.decl_of(n).is_some_and(|x| std::ptr::eq(x, d)) => occurrences.push(n),
            None => {}
        }
    }
    occurrences
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;
    use super::enum_name_matches;

    #[test]
    fn enum_names_as_documented() {
        for ok in ["Foo", "BackColor", "GetID", "GetHtml", "IO", "Http2"] {
            assert!(enum_name_matches(ok.as_bytes()), "{ok}");
        }
        for bad in ["foo", "GetHTML", "Back_Color", "ABCDe"] {
            assert!(!enum_name_matches(bad.as_bytes()), "{bad}");
        }
        let src = "using System;\npublic enum foo { FooValue = 0 }\npublic enum Foo { FooValue = 0 }\n[Flags]\npublic enum Option { None = 0, Option1 = 1 }\n[Flags]\npublic enum Options { None = 0, Option1 = 1 }";
        assert_eq!(flagged("cs/flags-enum-name-plural", src), [2, 5]);
    }

    #[test]
    fn simplest_conditions_as_documented() {
        let src = "class A { void F(object a, object b, bool condition) {\nobject x;\n\
            if (a != null) { x = a; } else { x = b; }\n\
            x = a != null ? a : b;\n\
            x = (a == null) ? new object() : a;\n\
            if (condition) { x = a; } else { x = b; }\n\
            if (a == null) a = new object();\n\
            var y = null ?? new object();\n\
            a = a ?? new object();\n\
            if (condition) { x = a; } else { b = a; }\n\
            } }";
        // `??=` needs C# 8, which nothing in this file shows.
        assert_eq!(flagged("cs/use-null-coalescing", src), [3, 4, 5, 6, 8]);
        // Neither converts to the other: `c ? new B1() : new B2()` needs C# 9.
        let siblings = "class Base { } class B1 : Base { } class B2 : Base { }\nclass A { void F(bool c) { Base x; if (c) { x = new B1(); } else { x = new B2(); } } }";
        assert!(flagged("cs/use-null-coalescing", siblings).is_empty());
        let modern = format!("#nullable enable\n{src}");
        assert_eq!(
            flagged("cs/use-null-coalescing", &modern),
            [4, 5, 6, 7, 8, 9, 10]
        );
    }

    #[test]
    fn concise_declarations_as_documented() {
        let src = "using System;\nusing System.Collections.Generic;\nclass Class {\nprivate event EventHandler MyEvent;\n\
            void F() {\n\
            var l = new List<int>() {};\n\
            var o = new object() {};\n\
            var ints = new int[] {1, 2, 3};\n\
            ints = new int[3] {1, 2, 3};\n\
            int? i = new int?(5);\n\
            var j = new int?(5);\n\
            Func<int, int> f1 = (int k) => 1;\n\
            MyEvent += new EventHandler((a, b) => { });\n\
            var longs = new long[] {1, 2};\n\
            EventHandler h = delegate (object s, EventArgs e) { };\n\
            Use((int k) => 1);\n\
            } void Use(Func<int, int> f) { } }";
        assert_eq!(
            flagged("cs/explicit-delegate-creation", src),
            [6, 7, 8, 9, 10, 12, 13, 15]
        );
        // A lambda with a `ref` parameter must keep its types.
        let by_ref =
            "delegate int R(ref int x);\nclass A { R r; void F() { r = (ref int x) => x; } }";
        assert!(flagged("cs/explicit-delegate-creation", by_ref).is_empty());
    }

    #[test]
    fn iequatable_as_documented() {
        let src = "using System;\nstruct MyStruct { public int Value { get; set; } }\nstruct Ok : IEquatable<Ok> { public bool Equals(Ok o) => true; }\nrecord struct R(int X);\nref struct S { }\npartial struct P { }";
        assert_eq!(flagged("cs/struct-without-iequatable", src), [2]);
    }

    #[test]
    fn event_handlers_as_documented() {
        let src = "using System;\npublic class AlarmEventArgs : EventArgs { }\n\
            public delegate void AlarmEventHandler(object s);\n\
            public delegate void GoodHandler(object sender, AlarmEventArgs e);\n\
            public delegate int Counting(object sender, AlarmEventArgs e);\n\
            public class Foo {\n\
            public event AlarmEventHandler AlarmEvent;\n\
            public event GoodHandler Good;\n\
            public event Counting Count;\n\
            public event Action<int> Changed;\n\
            public event EventHandler<AlarmEventArgs> Ok;\n\
            public event EventHandler<int> Bad;\n\
            public event Unknown Open;\n\
            }";
        assert_eq!(flagged("cs/event-handler-signature", src), [7, 9, 10, 12]);
        // GoodHandler is the old style EventHandler<T> replaces.
        assert_eq!(flagged("cs/custom-event-handler-delegate", src), [4]);
    }

    #[test]
    fn abstract_classes_as_documented() {
        let src = "using System;\npublic abstract class Animal { public abstract void Move(); public abstract void Feed(); }\n\
            public abstract class Lamp { private bool switchLamp = false; public abstract void Glow(); public void FlipSwitch() { switchLamp = !switchLamp; } }\n\
            public abstract class Shape : IDisposable { protected abstract double Area(); public abstract void Dispose(); }\n\
            public abstract class Derived : Lamp { public abstract void Dim(); }\n\
            public abstract class Fields { protected int count; public abstract void Count(); }\n\
            public abstract partial class Parted { public abstract void Run(); }";
        assert_eq!(flagged("cs/abstract-class-only-abstract", src), [2, 4]);
    }

    #[test]
    fn inner_members_as_documented() {
        let src = "class Outer {\npublic static int A;\npublic static class Address { }\npublic class Inner {\npublic int A;\npublic Address Address { get; set; }\npublic string Other;\nclass Deeper { int A; }\n#if DEBUG\nint A2; double A;\n#endif\n}\npublic int Instance;\nclass Other { int Instance; }\n}";
        // Static members, at any depth, `#if` included; not nested types,
        // nor instance members.
        assert_eq!(flagged("cs/inner-member-shadows-outer", src), [5, 8, 10]);
    }

    #[test]
    fn unused_returns_as_documented() {
        let src = "class SomeClass {\nprivate int PrivateMethod() => 42;\npublic void PublicMethod() { PrivateMethod(); }\n\
            private int Pick(int x) => x;\nprivate int Pick(string s) => 0;\n\
            void G() { Pick(1); var y = Pick(\"a\"); }\n\
            private int Used() => 1;\nvoid H(SomeClass other) { Used(); var z = other.Used(); }\n\
            }";
        assert_eq!(flagged("cs/unused-private-return", src), [2, 4]);
    }

    #[test]
    fn non_flags_enums_as_documented() {
        let src = "using System;\nnamespace MyLibrary {\n\
            [Flags] public enum Color { None = 0, Red = 1, Orange = 3, Yellow = 4 }\n\
            [Flags] public enum Days { None = 0, Monday = 1, Tuesday = 2, Wednesday = 4, All = Monday | Tuesday | Wednesday }\n\
            [Flags] public enum Implicit { None, One, Two, Three }\n\
            [Flags] public enum Shifted { A = 1 << 0, B = 1 << 1, Both = A | B }\n\
            [Flags] public enum Gap { A = 1, B = 2, C = 5 }\n\
            [Flags] internal enum Hidden { Red = 1, Orange = 3, Yellow = 4 }\n\
            internal class Box { [Flags] public enum Inner { Red = 1, Orange = 3, Yellow = 4 } }\n\
            }";
        assert_eq!(flagged("cs/non-flags-enum-marked-flags", src), [3, 7]);
    }

    #[test]
    fn cleartext_protocols_as_documented() {
        let src = "using System.Net.Mail;\nclass A { void F(int port) {\n\
            var urlHttp = \"http://sonar.com\";\n\
            var urlFtp = \"ftp://anonymous@sonar.com\";\n\
            var urlTelnet = \"telnet://anonymous@sonar.com\";\n\
            var ok = \"https://sonar.com\" + \"sftp://anonymous@sonar.com\" + \"ssh://anonymous@sonar.com\";\n\
            var local = \"http://localhost/x\" + \"http://example.com\" + \"http://www.w3.org/2000/svg\" + \"http://10.0.0.1\" + \"http://schemas.microsoft.com/x\";\n\
            using var smtp = new SmtpClient(\"host\", 25);\n\
            using var secure = new SmtpClient(\"host\", 25) { EnableSsl = true };\n\
            using var telnet = new MyTelnet.Client(\"host\", port);\n\
            } void G() { var later = new SmtpClient(\"h\"); later.EnableSsl = true; } }";
        assert_eq!(flagged("cs/cleartext-url", src), [3, 4, 5, 8, 10]);
    }

    #[test]
    fn date_formats_as_documented() {
        let src = "using System;\nusing System.Globalization;\nclass A { const string F = \"yyyy\"; void PrintTime(TimeSpan ts, string s) {\n\
            Console.WriteLine(DateTime.UtcNow.ToString(\"dd/MM/yyyy HH:mm:ss\"));\n\
            Console.WriteLine(DateTime.UtcNow.ToString(CultureInfo.InvariantCulture));\n\
            Console.WriteLine(DateTime.UtcNow.ToString(\"o\"));\n\
            Console.WriteLine(ts.ToString(\"hh\\\\:mm\"));\n\
            Console.WriteLine(DateTime.UtcNow.ToString(F));\n\
            Console.WriteLine(s.ToString());\n\
            } }";
        assert_eq!(flagged("cs/hardcoded-date-format", src), [4, 7, 8]);
    }

    #[test]
    fn invalid_regexes_as_documented() {
        let src = "using System.Text.RegularExpressions;\nclass A { void Regexes(string input) {\n\
            var regex = new Regex(\"[A\");\n\
            var match = Regex.Match(input, \"[A\");\n\
            var negativeLookahead = new Regex(\"a(?!b)\", RegexOptions.NonBacktracking);\n\
            var negativeLookbehind = new Regex(\"(?<!a)b\", RegexOptions.NonBacktracking);\n\
            var regex2 = new Regex(\"[A-Z]\");\n\
            var match2 = Regex.Match(input, \"[A-Z]\");\n\
            var negativeLookahead2 = new Regex(\"a(?!b)\");\n\
            var negativeLookbehind2 = new Regex(\"(?<!a)b\");\n\
            } }";
        assert_eq!(flagged("cs/invalid-regex", src), [3, 4, 5, 6]);
    }

    #[test]
    fn invalid_regexes_read_as_dotnet() {
        let src = "using System.Text.RegularExpressions;\nclass B { const string Open = \"(\";\n\
            void F(string input, RegexOptions o) {\n\
            _ = new Regex(@\"(?<open>\\()[^()]*(?<close-open>\\))\");\n\
            _ = new Regex(@\"[a-z-[aeiou]]\\p{IsGreek}\");\n\
            _ = Regex.IsMatch(input, pattern: Open + \"a\");\n\
            _ = new Regex(\"a b # [ comment\", RegexOptions.IgnorePatternWhitespace | RegexOptions.IgnoreCase);\n\
            _ = new Regex(@\"(a)\\1\", RegexOptions.ExplicitCapture);\n\
            _ = new Regex(@\"\\1\", RegexOptions.ECMAScript);\n\
            _ = new Regex(\"[A\", o);\n\
            _ = new Regex(@\"(?=a)b\", RegexOptions.NonBacktracking);\n\
            _ = Regex.Replace(input, \"a**\", \"b\");\n\
            _ = new System.Text.RegularExpressions.Regex(@\"\\p{Alpha}\");\n\
            _ = input.Replace(\"[A\", \"\");\n\
            _ = Unknown.Where(u => Regex.IsMatch(u.Name, \"Method\\\\d(\"));\n\
            _ = Unknown.Where(u => Regex.IsMatch(u.Name, \"Method\\\\d\"));\n\
            } }";
        // Options that aren't constants, and ECMAScript's syntax, aren't judged.
        assert_eq!(flagged("cs/invalid-regex", src), [6, 8, 12, 13, 15]);
    }

    #[test]
    fn controller_responsibilities_as_documented() {
        let src = "using Microsoft.Extensions.Logging;\n\
            [ApiController] public class MediaController : ControllerBase { readonly IMovies movies; readonly IPhotos photos; readonly ILogger<MediaController> log;\n\
            public MediaController(IMovies m, IPhotos p, ILogger<MediaController> l) { movies = m; photos = p; log = l; }\n\
            public IActionResult Movie() { log.LogInformation(\"m\"); return Ok(movies.Get()); } public IActionResult Photo() { log.LogInformation(\"p\"); return Ok(photos.Get()); } }\n\
            public class MvcController : Controller { readonly IMovies movies; readonly IPhotos photos; public MvcController(IMovies m, IPhotos p) { movies = m; photos = p; }\n\
            public IActionResult Movie() => Ok(movies.Get()); public IActionResult Photo() => Ok(photos.Get()); }\n\
            [ApiController] public class Primary(IMovies movies, IPhotos photos) : ControllerBase { public IActionResult A() => Ok(movies.Get()); public IActionResult B() => Ok(photos.Get()); }\n\
            [ApiController] public class Shared : ControllerBase { readonly IMovies movies; readonly IPhotos photos; readonly IDb db; public Shared(IMovies m, IPhotos p, IDb d) { movies = m; photos = p; db = d; }\n\
            public IActionResult A() => Ok(movies.Get(db)); public IActionResult B() => Ok(photos.Get(db)); }";
        // Not Primary: the semantic model doesn't declare a primary
        // constructor's parameters yet.
        assert_eq!(flagged("cs/controller-mixed-responsibilities", src), [2]);
    }

    #[test]
    fn disposables_as_documented() {
        let src = "using System;\nusing System.IO;\nusing System.Text;\nusing System.Drawing;\n\
            public class ResourceHolder {\n\
            private FileStream fs;\n\
            private FileStream closed;\n\
            public StreamWriter Shared;\n\
            public void OpenResource(string path) { this.fs = new FileStream(path, FileMode.Open); closed = File.Open(path, FileMode.Open); }\n\
            public void Close() { closed.Dispose(); }\n\
            public void WriteToFile(string path, string text) {\n\
            var fs = new FileStream(path, FileMode.Open);\n\
            var bytes = Encoding.UTF8.GetBytes(text);\n\
            fs.Write(bytes, 0, bytes.Length);\n\
            }\n\
            public Stream Returned(string path) { var fs = new FileStream(path, FileMode.Open); return fs; }\n\
            public void ReadFromStream(Stream s) { var sr = new StreamReader(s); }\n\
            public void Image(string p) { var img = System.Drawing.Image.FromFile(p); var bmp = new Bitmap(p); }\n\
            public void Kept(string p) { using var fs = new FileStream(p, FileMode.Open); var ms = new MemoryStream(); }\n\
            }";
        assert_eq!(flagged("cs/undisposed-local", src), [6, 12, 18, 18]);
    }
}
