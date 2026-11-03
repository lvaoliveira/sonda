//! C# rule checks on inferred types (ADR-0022, steps 2 and 3): what a
//! receiver or an argument evaluates to, and the overload a call binds to,
//! through the platform's declarations (`semantic/cs_infer.rs`). The rules
//! are declared with the others; this module holds their checks. A call
//! whose types don't resolve gives no finding.

use super::cs::{cs_has_modifier, unparenthesized};
use super::cs_bugs::{attribute_names, cs_call_arguments};
use super::cs_more::{declarators, is_test_method};
use super::cs_types::{enumerable_calls, walk_tree};
use super::java_security::text;
use super::java_smells::count_word;
use crate::semantic::cs_infer::{
    Arg, Bound, Constant, Conversion, Found, Infer, Param, Ty, arguments,
};
use crate::semantic::{DeclKind, Model, dotnet};
use std::collections::HashSet;
use std::sync::OnceLock;
use tree_sitter::Node;

const STRING: &str = "System.String";
const TASK: &str = "System.Threading.Tasks.Task";
const TASK_OF: &str = "System.Threading.Tasks.Task`1";

fn is_task(t: &Ty) -> bool {
    t.is(TASK) || t.is(TASK_OF)
}

/// The method or local function a node is in, from its ancestors: None
/// inside a lambda or anonymous method, which runs on its own.
fn enclosing_function<'t>(ancestors: &[Node<'t>]) -> Option<Node<'t>> {
    ancestors
        .iter()
        .rev()
        .copied()
        .find_map(|a| match a.kind() {
            "method_declaration"
            | "local_function_statement"
            | "constructor_declaration"
            | "accessor_declaration"
            | "operator_declaration"
            | "conversion_operator_declaration" => Some(Some(a)),
            "lambda_expression" | "anonymous_method_expression" => Some(None),
            _ => None,
        })?
}

fn is_async(function: Node, src: &[u8]) -> bool {
    cs_has_modifier(function, "async", src)
}

fn in_test<'t>(ancestors: &[Node<'t>], src: &[u8]) -> bool {
    ancestors
        .iter()
        .any(|a| a.kind() == "method_declaration" && is_test_method(*a, src))
}

/// The name, receiver and arguments of `receiver.Name(arguments)`.
fn member_call<'t, 's>(
    call: Node<'t>,
    src: &'s [u8],
) -> Option<(&'s [u8], Node<'t>, Vec<Node<'t>>)> {
    let function = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")?;
    let name = function.child_by_field_name("name")?;
    let name = if name.kind() == "generic_name" {
        name.named_child(0)?
    } else {
        name
    };
    Some((
        text(name, src),
        function.child_by_field_name("expression")?,
        cs_call_arguments(call),
    ))
}

// ---------------------------------------------------- S1449

/// Culture-dependent string operations called without a culture:
/// `ToLower()`, `ToUpper()`, `IndexOf` and `LastIndexOf` with a string,
/// `string.Compare` and `CompareTo`, and `ToString` on floating-point and
/// date values without a format provider. Test code isn't checked, as
/// SonarQube checks this key on main code only.
pub(super) fn culture_dependent_calls<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |call, ancestors| {
        if call.kind() != "invocation_expression" {
            return;
        }
        let Some((name, _, args)) = member_call(call, src) else {
            return;
        };
        if !matches!(
            name,
            b"ToLower"
                | b"ToUpper"
                | b"IndexOf"
                | b"LastIndexOf"
                | b"Compare"
                | b"CompareTo"
                | b"ToString"
        ) {
            return;
        }
        let Some(c) = infer.call(call) else {
            return;
        };
        let Some(on) = c.receiver.as_ref() else {
            return;
        };
        let arg_types: Option<Vec<Ty>> = args.iter().map(|a| infer.type_of(*a)).collect();
        let states_culture = |types: &[Ty]| {
            types.iter().any(|t| {
                t.is("System.Globalization.CultureInfo")
                    || t.is("System.StringComparison")
                    || t.is("System.IFormatProvider")
                    || t.is("System.Globalization.CompareOptions")
            })
        };
        let dependent = match name {
            b"ToLower" | b"ToUpper" => on.is(STRING) && args.is_empty(),
            b"CompareTo" => on.is(STRING) && args.len() == 1,
            b"IndexOf" | b"LastIndexOf" => {
                on.is(STRING)
                    && arg_types.as_ref().is_some_and(|t| {
                        t.first().is_some_and(|f| f.is(STRING)) && !states_culture(t)
                    })
            }
            // `string.Compare(a, b)`, static on String.
            b"Compare" => {
                on.is(STRING)
                    && arg_types
                        .as_ref()
                        .is_some_and(|t| t.len() >= 2 && !states_culture(t))
            }
            b"ToString" => {
                [
                    "System.Single",
                    "System.Double",
                    "System.DateTime",
                    "System.DateTimeOffset",
                ]
                .iter()
                .any(|k| on.is(k))
                    && arg_types.as_ref().is_some_and(|t| match t.as_slice() {
                        [] => true,
                        [format] => format.is(STRING),
                        _ => false,
                    })
            }
            _ => false,
        };
        if dependent && !in_test(ancestors, src) {
            found.push(call);
        }
    });
    found
}

// ---------------------------------------------------- S1858

/// `ToString()` on a string, on a reference-type operand of a string
/// concatenation, or on a reference-type argument to `string.Format`.
/// Value types are left alone: without the call they would be boxed.
pub(super) fn redundant_to_string<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |call, ancestors| {
        if call.kind() != "invocation_expression" {
            return;
        }
        let Some((b"ToString", receiver, args)) = member_call(call, src) else {
            return;
        };
        if !args.is_empty() {
            return;
        }
        let Some(ty) = infer.type_of(receiver) else {
            return;
        };
        if ty.is(STRING) {
            found.push(call);
            return;
        }
        if infer.value_type(&ty) != Some(false) {
            return;
        }
        let Some(parent) = ancestors.last() else {
            return;
        };
        let concatenated = parent.kind() == "binary_expression"
            && parent
                .child_by_field_name("operator")
                .is_some_and(|o| text(o, src) == b"+")
            && ["left", "right"].iter().any(|f| {
                parent
                    .child_by_field_name(f)
                    // Another `x.ToString()` is only a string while it stays.
                    .filter(|o| {
                        *o != call && !matches!(member_call(*o, src), Some((b"ToString", _, _)))
                    })
                    .and_then(|o| infer.type_of(o))
                    .is_some_and(|t| t.is(STRING))
            });
        // `string.Format(format, x.ToString())`: an argument after the format.
        let formatted = parent.kind() == "argument"
            && ancestors.len() >= 3
            && ancestors[ancestors.len() - 3].kind() == "invocation_expression"
            && {
                let format_call = ancestors[ancestors.len() - 3];
                let list = ancestors[ancestors.len() - 2];
                let position = list
                    .named_children(&mut list.walk())
                    .filter(|a| a.kind() == "argument")
                    .position(|a| a == *parent);
                let first_is_provider = cs_call_arguments(format_call)
                    .first()
                    .and_then(|a| infer.type_of(*a))
                    .is_some_and(|t| {
                        t.is("System.IFormatProvider") || t.is("System.Globalization.CultureInfo")
                    });
                let format_at = usize::from(first_is_provider);
                position.is_some_and(|p| p > format_at)
                    && infer.call(format_call).is_some_and(|c| {
                        !c.extension
                            && c.methods.iter().all(|f| {
                                matches!(f, Found::Platform { declaring, member, .. }
                                    if declaring.name == STRING && member.name == "Format")
                            })
                    })
            };
        if concatenated || formatted {
            found.push(call);
        }
    });
    found
}

// ---------------------------------------------------- S4462

/// Blocking on a task: `.Result`, `.Wait(...)` and
/// `.GetAwaiter().GetResult()` on a Task, `Task.WaitAny` and `Task.WaitAll`,
/// and `Thread.Sleep` in an async method. Main methods, tasks started by
/// `Task.Run` or `Task.Factory.StartNew`, and test code (SonarQube checks
/// this key on main code only) are left out.
pub(super) fn blocking_on_tasks<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    // `Task.Run(...)` and `Task.Factory.StartNew(...)`, through `.GetAwaiter()`.
    let started = |mut task: Node| {
        if task.kind() == "invocation_expression"
            && let Some((b"GetAwaiter", inner, _)) = member_call(task, src)
        {
            task = inner;
        }
        task.kind() == "invocation_expression"
            && task.child_by_field_name("function").is_some_and(|f| {
                let t = text(f, src);
                t.ends_with(b"Task.Run") || t.ends_with(b"Task.Factory.StartNew")
            })
    };
    let mut found = Vec::new();
    walk_tree(m, |node, ancestors| {
        let blocks = match node.kind() {
            "member_access_expression" => {
                let invoked = ancestors.last().is_some_and(|p| {
                    p.kind() == "invocation_expression" && p.child_by_field_name("function") == Some(node)
                });
                !invoked
                    && node
                        .child_by_field_name("name")
                        .is_some_and(|n| text(n, src) == b"Result")
                    && node.child_by_field_name("expression").is_some_and(|r| {
                        !started(r) && infer.type_of(r).is_some_and(|t| t.is(TASK_OF))
                    })
            }
            "invocation_expression" => match member_call(node, src) {
                Some((b"Wait", r, _)) => !started(r) && infer.type_of(r).is_some_and(|t| is_task(&t)),
                Some((b"GetResult", r, _)) => {
                    matches!(member_call(r, src), Some((b"GetAwaiter", task, a)) if a.is_empty()
                        && !started(task)
                        && infer.type_of(task).is_some_and(|t| is_task(&t)))
                }
                Some((b"WaitAny" | b"WaitAll", _, _)) => infer.call(node).is_some_and(|c| {
                    c.methods
                        .iter()
                        .all(|f| matches!(f, Found::Platform { declaring, .. } if declaring.name == TASK))
                }),
                Some((b"Sleep", _, _)) => {
                    enclosing_function(ancestors).is_some_and(|f| is_async(f, src))
                        && infer.call(node).is_some_and(|c| {
                            c.methods.iter().all(|f| {
                                matches!(f, Found::Platform { declaring, .. } if declaring.name == "System.Threading.Thread")
                            })
                        })
                }
                _ => false,
            },
            _ => false,
        };
        if !blocks || in_test(ancestors, src) {
            return;
        }
        let main = ancestors.iter().any(|a| {
            a.kind() == "method_declaration"
                && a.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"Main")
        });
        if !main {
            found.push(node);
        }
    });
    found
}

// ---------------------------------------------------- S6966

/// A method's parameter types as written: the platform's keys, or the
/// file's type text without whitespace.
fn parameter_types(method: &Found, src: &[u8]) -> Option<Vec<String>> {
    match method {
        Found::Platform { member, .. } => {
            Some(member.params.iter().map(|p| p.ty.clone()).collect())
        }
        Found::Local(d) => {
            let list = d.declarator?.child_by_field_name("parameters")?;
            Some(
                list.named_children(&mut list.walk())
                    .filter(|p| p.kind() == "parameter")
                    .map(|p| {
                        p.child_by_field_name("type")
                            .map(|t| {
                                String::from_utf8_lossy(text(t, src))
                                    .replace(char::is_whitespace, "")
                            })
                            .unwrap_or_default()
                    })
                    .collect(),
            )
        }
    }
}

/// DbDataReader methods whose async versions don't help: SonarQube's
/// documented exception.
const DATA_READER_METHODS: &[&[u8]] = &[
    b"IsDBNull",
    b"GetFieldValue",
    b"GetValue",
    b"GetBytes",
    b"GetChars",
    b"GetStream",
    b"GetTextReader",
];

/// In an async method, calls of a method whose type also has an awaitable
/// version, `NameAsync`, taking the same parameters and a cancellation
/// token at most. Platform versions count only when .NET Standard 2.0 has
/// them, so every target framework does (ADR-0022): `File.ReadAllLinesAsync`
/// and `CancellationTokenSource.CancelAsync` came later, and recommending
/// them takes knowing the project's target.
pub(super) fn sync_calls_in_async<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |call, ancestors| {
        if call.kind() != "invocation_expression"
            || !enclosing_function(ancestors).is_some_and(|f| is_async(f, src))
        {
            return;
        }
        // `x.Load(...)`, or `Load(...)` on the type it's written in.
        let (name, args) = match member_call(call, src) {
            Some((name, _, args)) => (name, args),
            None => match call.child_by_field_name("function") {
                Some(f) if f.kind() == "identifier" => (text(f, src), cs_call_arguments(call)),
                _ => return,
            },
        };
        if name.ends_with(b"Async") {
            return;
        }
        let Some(c) = infer.call(call).filter(|c| !c.extension) else {
            return;
        };
        let Some(receiver) = c.receiver.clone().or_else(|| infer.enclosing_type(call)) else {
            return;
        };
        let receiver = &receiver;
        if DATA_READER_METHODS.contains(&name)
            && infer
                .supertypes(receiver)
                .iter()
                .any(|t| t.is("System.Data.Common.DbDataReader"))
        {
            return;
        }
        let name = String::from_utf8_lossy(name);
        let awaitable: Vec<Found> = infer
            .members(receiver, &format!("{name}Async"), Some(args.len()))
            .into_iter()
            .filter(|f| match f {
                Found::Platform { member, .. } => member.has("ns20"),
                Found::Local(_) => true,
            })
            .collect();
        // Every overload the call may be has an awaitable version.
        let covered = c.methods.iter().all(|sync| {
            let Some(params) = parameter_types(sync, src) else {
                return false;
            };
            awaitable.iter().any(|a| {
                parameter_types(a, src).is_some_and(|mut p| {
                    if p.len() == params.len() + 1
                        && p.last().is_some_and(|t| t.ends_with("CancellationToken"))
                    {
                        p.pop();
                    }
                    p == params
                })
            })
        });
        if !awaitable.is_empty() && covered {
            found.push(call);
        }
    });
    found
}

// ---------------------------------------------------- S1905

/// The type the context of an expression asks for, when the expression is
/// all of a variable's initializer (not `var`), the right side of a plain
/// assignment, or what a non-async member with a declared type returns.
fn context_type(infer: &Infer, node: Node, ancestors: &[Node], src: &[u8]) -> Option<Ty> {
    let mut child = node;
    let mut up = ancestors.iter().rev().copied();
    let mut parent = up.next()?;
    while parent.kind() == "parenthesized_expression" {
        child = parent;
        parent = up.next()?;
    }
    match parent.kind() {
        "variable_declarator" => {
            if parent.child_by_field_name("name") == Some(child) {
                return None;
            }
            let ty = up.next()?.child_by_field_name("type")?;
            (ty.kind() != "implicit_type")
                .then(|| infer.written(ty))
                .flatten()
        }
        "assignment_expression" => {
            if parent.child_by_field_name("right") != Some(child)
                || parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| text(o, src) != b"=")
            {
                return None;
            }
            infer.type_of(parent.child_by_field_name("left")?)
        }
        "return_statement" | "arrow_expression_clause" => {
            let owner = if parent.kind() == "arrow_expression_clause" {
                up.next()?
            } else {
                up.find(|a| {
                    matches!(
                        a.kind(),
                        "method_declaration"
                            | "local_function_statement"
                            | "accessor_declaration"
                            | "operator_declaration"
                            | "conversion_operator_declaration"
                            | "lambda_expression"
                            | "anonymous_method_expression"
                    )
                })?
            };
            let owner = if owner.kind() == "accessor_declaration" {
                // A getter returns its property's type.
                if !text(owner, src).trim_ascii_start().starts_with(b"get") {
                    return None;
                }
                ancestors
                    .iter()
                    .rev()
                    .find(|a| matches!(a.kind(), "property_declaration" | "indexer_declaration"))
                    .copied()?
            } else {
                owner
            };
            if is_async(owner, src)
                || !matches!(
                    owner.kind(),
                    "method_declaration"
                        | "local_function_statement"
                        | "property_declaration"
                        | "indexer_declaration"
                        | "operator_declaration"
                        | "conversion_operator_declaration"
                )
            {
                return None;
            }
            infer.written(
                owner
                    .child_by_field_name("returns")
                    .or_else(|| owner.child_by_field_name("type"))?,
            )
        }
        _ => None,
    }
}

/// Casts that change nothing. To the type the value already has, anywhere,
/// but to float or double of a computed value, which the cast rounds; to a
/// type it converts to implicitly (a base class, an interface, a wider
/// number, boxing), where its context asks for that type anyway. And
/// `Cast<T>()` on a sequence of T, or `OfType<T>()` on one of a value type
/// T, which drops no element. `(T)default` is left alone, as documented.
pub(super) fn redundant_casts<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |cast, ancestors| {
        if cast.kind() != "cast_expression" {
            return;
        }
        let (Some(ty), Some(value)) = (
            cast.child_by_field_name("type"),
            cast.child_by_field_name("value"),
        ) else {
            return;
        };
        let inner = unparenthesized(value);
        if matches!(inner.kind(), "default_expression" | "null_literal") {
            return;
        }
        let (Some(target), Some(source)) = (infer.written(ty), infer.type_of(value)) else {
            return;
        };
        let redundant = match infer.conversion(&source, &target) {
            Some(Conversion::Identity) => {
                let rounds = (target.is("System.Single") || target.is("System.Double"))
                    && !matches!(
                        inner.kind(),
                        "identifier"
                            | "member_access_expression"
                            | "real_literal"
                            | "integer_literal"
                    );
                !rounds
            }
            Some(Conversion::Implicit) => {
                context_type(&infer, cast, ancestors, src).as_ref() == Some(&target)
            }
            _ => false,
        };
        if redundant {
            found.push(cast);
        }
    });
    for (call, receiver) in enumerable_calls(m, src, &[("Cast", 0), ("OfType", 0)]) {
        let Some((name, _, _)) = member_call(call, src) else {
            continue;
        };
        let target = call
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("name"))
            .filter(|g| g.kind() == "generic_name")
            .and_then(|g| g.named_child(1))
            .filter(|args| args.named_child_count() == 1)
            .and_then(|args| args.named_child(0))
            .and_then(|t| infer.written(t));
        let (Some(target), Some(element)) = (target, infer.element_type(&receiver)) else {
            continue;
        };
        // OfType drops nulls, which only a value type has none of.
        let keeps_all = name == b"Cast"
            || (infer.value_type(&target) == Some(true) && !target.is("System.Nullable`1"));
        if target == element && keeps_all {
            found.push(call);
        }
    }
    found
}

// ---------------------------------------------------- S3217

/// `foreach (T x in xs)` where xs's elements only convert to T with a cast
/// the loop makes silently: a downcast, unboxing, a numeric narrowing.
/// Collections of objects and conversion operators are left alone, as
/// documented.
pub(super) fn foreach_explicit_conversions<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |each, _| {
        if each.kind() != "foreach_statement" {
            return;
        }
        let (Some(ty), Some(collection)) = (
            each.child_by_field_name("type"),
            each.child_by_field_name("right"),
        ) else {
            return;
        };
        if ty.kind() == "implicit_type" {
            return;
        }
        let Some(element) = infer
            .type_of(collection)
            .and_then(|c| infer.element_type(&c))
        else {
            return;
        };
        if element.is("System.Object") {
            return;
        }
        if let Some(target) = infer.written(ty)
            && infer.conversion(&element, &target) == Some(Conversion::Explicit)
        {
            found.push(each);
        }
    });
    found
}

// ---------------------------------------------------- S3172

/// Whether an expression evaluates to a delegate.
fn is_delegate(infer: &Infer, expr: Node) -> bool {
    matches!(
        unparenthesized(expr).kind(),
        "lambda_expression" | "anonymous_method_expression"
    ) || infer.type_of(expr).is_some_and(|t| infer.delegate(&t))
}

/// Whether an expression is a chain of delegates: `a + b`, or a local
/// variable initialized with one and never assigned anything else.
fn is_delegate_chain(m: &Model, infer: &Infer, expr: Node, src: &[u8], depth: u8) -> bool {
    let expr = unparenthesized(expr);
    if depth > 8 {
        return false;
    }
    if expr.kind() == "binary_expression" {
        return expr
            .child_by_field_name("operator")
            .is_some_and(|o| text(o, src) == b"+")
            && ["left", "right"].iter().all(|f| {
                expr.child_by_field_name(f).is_some_and(|o| {
                    is_delegate(infer, o) || is_delegate_chain(m, infer, o, src, depth + 1)
                })
            });
    }
    if expr.kind() != "identifier" {
        return false;
    }
    let Some(d) = m.decl_of(expr) else {
        return false;
    };
    let Some(value) = d
        .declarator
        .filter(|v| d.kind == DeclKind::Let && v.kind() == "variable_declarator")
        .and_then(|v| v.named_child(v.named_child_count().checked_sub(1)? as u32))
        .filter(|v| *v != d.node)
    else {
        return false;
    };
    let reassigned = m.refs.iter().any(|r| {
        r.write
            && r.decl.is_some_and(|x| std::ptr::eq(&m.decls[x], d))
            && r.node.parent().is_some_and(|p| {
                p.kind() == "assignment_expression"
                    && p.child_by_field_name("operator")
                        .is_some_and(|o| text(o, src) == b"=")
            })
    });
    !reassigned
        && value.kind() == "binary_expression"
        && is_delegate_chain(m, infer, value, src, depth + 1)
}

/// `a - (b + c)` and `a -= b + c` on delegates, also through a variable
/// holding `b + c`: a chain is only removed where it appears whole.
pub(super) fn subtracted_delegate_chains<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |node, _| {
        if !matches!(node.kind(), "binary_expression" | "assignment_expression")
            || !node
                .child_by_field_name("operator")
                .is_some_and(|o| matches!(text(o, src), b"-" | b"-="))
        {
            return;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        if is_delegate_chain(m, &infer, right, src, 0) && is_delegate(&infer, left) {
            found.push(node);
        }
    });
    found
}

// ---------------------------------------------------- S5034

fn is_value_task(t: &Ty) -> bool {
    t.is("System.Threading.Tasks.ValueTask") || t.is("System.Threading.Tasks.ValueTask`1")
}

const LOOPS: &[&str] = &[
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
];

/// How an occurrence of a ValueTask variable uses it.
enum TaskUse<'t> {
    /// Awaited, `AsTask()`, or read with `.Result` or
    /// `.GetAwaiter().GetResult()` (blocking): the node to report.
    Consumed { at: Node<'t>, blocking: bool },
    /// `IsCompleted` or `IsCompletedSuccessfully` read.
    Checked,
    /// Passed on or stored: consumed somewhere this rule can't see.
    Escapes,
}

fn task_use<'t>(name: Node<'t>, src: &[u8]) -> TaskUse<'t> {
    let Some(parent) = name.parent() else {
        return TaskUse::Escapes;
    };
    match parent.kind() {
        "await_expression" => TaskUse::Consumed {
            at: parent,
            blocking: false,
        },
        "member_access_expression" if parent.child_by_field_name("expression") == Some(name) => {
            let member = parent
                .child_by_field_name("name")
                .map_or(&b""[..], |n| text(n, src));
            let call = parent
                .parent()
                .filter(|c| c.kind() == "invocation_expression");
            match member {
                b"IsCompleted" | b"IsCompletedSuccessfully" => TaskUse::Checked,
                b"Result" => TaskUse::Consumed {
                    at: parent,
                    blocking: true,
                },
                b"AsTask" => TaskUse::Consumed {
                    at: call.unwrap_or(parent),
                    blocking: false,
                },
                b"ConfigureAwait" => TaskUse::Consumed {
                    at: call.unwrap_or(parent),
                    blocking: false,
                },
                b"GetAwaiter" => match get_result(call, src) {
                    Some(at) => TaskUse::Consumed { at, blocking: true },
                    None => TaskUse::Escapes,
                },
                _ => TaskUse::Escapes,
            }
        }
        _ => TaskUse::Escapes,
    }
}

/// `x.GetAwaiter().GetResult()`, given the `x.GetAwaiter()` call.
fn get_result<'t>(get_awaiter: Option<Node<'t>>, src: &[u8]) -> Option<Node<'t>> {
    let access = get_awaiter?
        .parent()
        .filter(|p| p.kind() == "member_access_expression")?;
    (text(access.child_by_field_name("name")?, src) == b"GetResult")
        .then(|| access.parent())
        .flatten()
        .filter(|c| c.kind() == "invocation_expression")
}

/// Whether two uses of a variable never both run: in different branches of
/// an `if`, a `switch` or `?:`, or the first in a branch that leaves.
fn exclusive(first: Node, second: Node) -> bool {
    let mut path: Vec<Node> = Vec::new();
    let mut n = Some(first);
    while let Some(x) = n {
        path.push(x);
        n = x.parent();
    }
    let mut child = second;
    let Some(common) = (|| {
        let mut x = second;
        loop {
            let p = x.parent()?;
            if path.contains(&p) {
                child = x;
                return Some(p);
            }
            x = p;
        }
    })() else {
        return false;
    };
    let first_side = path.iter().take_while(|x| **x != common).last().copied();
    let branches = match common.kind() {
        "if_statement" | "conditional_expression" => ["consequence", "alternative"]
            .iter()
            .filter_map(|f| common.child_by_field_name(f))
            .collect::<Vec<_>>(),
        "switch_body" | "switch_expression" => common.named_children(&mut common.walk()).collect(),
        _ => Vec::new(),
    };
    if first_side.is_some_and(|f| f != child && branches.contains(&f) && branches.contains(&child))
    {
        return true;
    }
    // `return await vt;`, or a branch ending in return or throw.
    path.iter().take_while(|x| **x != common).any(|x| {
        matches!(
            x.kind(),
            "return_statement" | "throw_statement" | "throw_expression"
        ) || (x.kind() == "block"
            && x.named_child(x.named_child_count().saturating_sub(1) as u32)
                .is_some_and(|l| {
                    matches!(
                        l.kind(),
                        "return_statement"
                            | "throw_statement"
                            | "break_statement"
                            | "continue_statement"
                            | "goto_statement"
                    )
                }))
    })
}

/// ValueTasks consumed twice, by `await`, `AsTask()`, `.Result` or
/// `.GetAwaiter().GetResult()` in any mix, and read with `.Result` or
/// `GetResult()` before `IsCompleted` or `IsCompletedSuccessfully` says
/// it's done: always on one a call just returned. Uses in a loop aren't
/// counted, as documented; nor are variables assigned twice or passed on.
pub(super) fn value_task_misuse<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    // Per variable: its uses, in source order.
    let mut uses: std::collections::HashMap<usize, Vec<Node<'t>>> =
        std::collections::HashMap::new();
    for r in &m.refs {
        let Some(d) = r.decl else {
            continue;
        };
        let decl = &m.decls[d];
        if !matches!(decl.kind, DeclKind::Let | DeclKind::Param) {
            continue;
        }
        uses.entry(d).or_default().push(r.node);
    }
    for (d, names) in uses {
        let decl = &m.decls[d];
        // Typing a variable costs more than looking at how it's used.
        if !names
            .iter()
            .any(|n| matches!(task_use(*n, src), TaskUse::Consumed { .. }))
        {
            continue;
        }
        let Some(ty) = infer.type_of(decl.node).or_else(|| {
            decl.ty
                .filter(|t| t.kind() != "implicit_type")
                .and_then(|t| infer.written(t))
        }) else {
            continue;
        };
        if !is_value_task(&ty) || m.refs.iter().any(|r| r.decl == Some(d) && r.write) {
            continue;
        }
        let in_loop = |n: Node| {
            let mut x = n.parent();
            while let Some(p) = x {
                if p.start_byte() <= decl.node.start_byte() && decl.node.end_byte() <= p.end_byte()
                {
                    return false;
                }
                if LOOPS.contains(&p.kind()) {
                    return true;
                }
                x = p.parent();
            }
            false
        };
        let mut consumed: Vec<Node<'t>> = Vec::new();
        let mut checked = false;
        let mut escapes = false;
        let mut unchecked_reads: Vec<Node<'t>> = Vec::new();
        for name in names {
            if name == decl.node {
                continue;
            }
            match task_use(name, src) {
                TaskUse::Escapes => escapes = true,
                TaskUse::Checked => checked = true,
                TaskUse::Consumed { at, blocking } => {
                    if blocking && !checked {
                        unchecked_reads.push(at);
                    }
                    if !in_loop(name) {
                        consumed.push(at);
                    }
                }
            }
        }
        if escapes {
            continue;
        }
        found.extend(unchecked_reads);
        for (i, later) in consumed.iter().enumerate().skip(1) {
            if consumed[..i]
                .iter()
                .any(|earlier| !exclusive(*earlier, *later))
                && !found.contains(later)
            {
                found.push(*later);
            }
        }
    }
    // `GetAsync().Result`: a ValueTask a call just returned isn't known done.
    walk_tree(m, |access, _| {
        if access.kind() != "member_access_expression" {
            return;
        }
        let Some(receiver) = access
            .child_by_field_name("expression")
            .filter(|r| r.kind() == "invocation_expression")
        else {
            return;
        };
        let member = access
            .child_by_field_name("name")
            .map_or(&b""[..], |n| text(n, src));
        let at = match member {
            b"Result" => Some(access),
            b"GetAwaiter" => get_result(access.parent(), src),
            _ => None,
        };
        if let Some(at) = at
            && infer.type_of(receiver).is_some_and(|t| is_value_task(&t))
        {
            found.push(at);
        }
    });
    found.sort_by_key(|n| n.start_byte());
    found.dedup();
    found
}

// ---------------------------------------------------- S1312

/// The logging frameworks' logger types SonarQube documents, by namespace,
/// besides Microsoft.Extensions.Logging's, which the platform declares.
const LOGGERS: &[(&str, &[&str])] = &[
    ("Serilog", &["ILogger"]),
    ("NLog", &["Logger", "ILogger"]),
    ("log4net", &["ILog"]),
    ("Castle.Core.Logging", &["ILogger"]),
];

/// Whether a written type is one of the documented frameworks' loggers:
/// named in full, or by a name exactly one framework in scope declares.
fn is_logger(infer: &Infer, ty: Node, src: &[u8]) -> bool {
    let written = std::str::from_utf8(text(ty, src)).unwrap_or_default();
    let written = written.trim_start_matches("global::");
    if LOGGERS
        .iter()
        .any(|(ns, names)| names.iter().any(|n| written == format!("{ns}.{n}")))
    {
        return true;
    }
    let mut frameworks = 0;
    if infer.written(ty).is_some_and(|t| {
        t.is("Microsoft.Extensions.Logging.ILogger")
            || t.is("Microsoft.Extensions.Logging.ILogger`1")
    }) {
        frameworks += 1;
    }
    if ty.kind() == "identifier" && !infer.declares(written) {
        frameworks += LOGGERS
            .iter()
            .filter(|(ns, names)| infer.in_scope(ns, ty.start_byte()) && names.contains(&written))
            .count();
    }
    frameworks == 1
}

/// Logger fields that aren't private, static and readonly, whatever
/// creates them, as SonarQube documents for the service locator pattern
/// this key is meant for.
pub(super) fn loose_logger_fields<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |field, ancestors| {
        if field.kind() != "field_declaration"
            || ancestors
                .iter()
                .rev()
                .find(|a| a.kind().ends_with("_declaration"))
                .is_some_and(|t| t.kind() == "interface_declaration")
        {
            return;
        }
        let Some(ty) = field
            .named_children(&mut field.walk())
            .find(|c| c.kind() == "variable_declaration")
            .and_then(|v| v.child_by_field_name("type"))
        else {
            return;
        };
        let tidy = cs_has_modifier(field, "static", src)
            && cs_has_modifier(field, "readonly", src)
            && !["public", "protected", "internal"]
                .iter()
                .any(|w| cs_has_modifier(field, w, src));
        if !tidy && is_logger(&infer, ty, src) {
            found.extend(declarators(field).into_iter().next());
        }
    });
    found
}

// ---------------------------------------------------- S1698

/// `a == b` and `a != b` comparing references where values were likely
/// meant: on an interface some class overriding Equals implements, or on
/// a class overriding Equals without an `==` operator. Left alone, as
/// documented: System.Type, comparisons inside an Equals override, with
/// null, or with an operand cast to object.
pub(super) fn reference_equality_where_equals_overridden<'t>(
    m: &Model<'t>,
    src: &[u8],
) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    walk_tree(m, |node, ancestors| {
        if node.kind() != "binary_expression"
            || !node
                .child_by_field_name("operator")
                .is_some_and(|o| matches!(text(o, src), b"==" | b"!="))
        {
            return;
        }
        let in_equals = ancestors.iter().any(|a| {
            a.kind() == "method_declaration"
                && a.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"Equals")
                && cs_has_modifier(*a, "override", src)
        });
        if in_equals {
            return;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        let excluded = |o: Node| {
            let o = unparenthesized(o);
            matches!(o.kind(), "null_literal" | "default_expression")
                || (o.kind() == "cast_expression"
                    && o.child_by_field_name("type")
                        .is_some_and(|t| infer.written(t).is_some_and(|t| t.is("System.Object"))))
        };
        if excluded(left) || excluded(right) {
            return;
        }
        let (Some(a), Some(b)) = (infer.type_of(left), infer.type_of(right)) else {
            return;
        };
        let reference = |t: &Ty| {
            infer.value_type(t) == Some(false)
                && !infer.supertypes(t).iter().any(|s| s.is("System.Type"))
                && !infer.has_equality_operator(t)
        };
        if !reference(&a) || !reference(&b) {
            return;
        }
        let value_like = |t: &Ty| match infer.interface(t) {
            Some(true) => infer.implemented_with_equals(t),
            Some(false) => infer.overrides_equals(t) == Some(true),
            None => false,
        };
        if value_like(&a) || value_like(&b) {
            found.push(node);
        }
    });
    found
}

// ---------------------------------------------------- S2325

/// Methods ASP.NET calls on its application object by name, which can't be
/// static, as documented.
const APPLICATION_EVENTS: &[&[u8]] = &[
    b"Application_AuthenticateRequest",
    b"Application_BeginRequest",
    b"Application_End",
    b"Application_EndRequest",
    b"Application_Error",
    b"Application_Init",
    b"Application_Start",
    b"Session_End",
    b"Session_Start",
];

/// Framework base classes whose public methods the framework calls on an
/// instance (actions, page handlers, hub methods), which can't be static.
const INSTANCE_ENTRY_POINTS: &[&str] = &[
    "Microsoft.AspNetCore.Mvc.ControllerBase",
    "Microsoft.AspNetCore.Mvc.RazorPages.PageModel",
    "Microsoft.AspNetCore.Mvc.ViewComponent",
    "Microsoft.AspNetCore.Components.ComponentBase",
    "Microsoft.AspNetCore.SignalR.Hub",
];

/// Whether a method or property's body uses its object: `this`, `base`,
/// an instance member of its type, a primary constructor parameter, or a
/// member it inherits. Unknown names in a type with bases that don't all
/// resolve count as used, as do inherited members it can't tell apart.
fn uses_instance(
    m: &Model,
    infer: &Infer,
    member: Node,
    owner: &Ty,
    primary: &[&[u8]],
    by_position: &[usize],
    src: &[u8],
) -> bool {
    let body = text(member, src);
    if count_word(body, b"this") > 0 || count_word(body, b"base") > 0 {
        return true;
    }
    let inherited = |name: &str| infer.inherited_instance_member(owner, name) != Some(false);
    let instance = |scope, name: &str| {
        m.decls_named(scope, name).iter().any(|&d| {
            let d = &m.decls[d];
            matches!(
                d.kind,
                DeclKind::Field | DeclKind::Property | DeclKind::Method
            ) && !d.is_static
        })
    };
    let first = by_position.partition_point(|&i| m.refs[i].node.start_byte() < member.start_byte());
    let inside = by_position[first..]
        .iter()
        .map(|&i| &m.refs[i])
        .take_while(|r| r.node.start_byte() < member.end_byte());
    for r in inside {
        match r.decl {
            Some(d) => {
                let d = &m.decls[d];
                if m.scopes[d.scope].kind == crate::semantic::ScopeKind::Type
                    && instance(d.scope, &r.name)
                {
                    return true;
                }
            }
            None => {
                if primary.contains(&r.name.as_bytes()) || inherited(&r.name) {
                    return true;
                }
            }
        }
    }
    // `Process<T>(x)`: a generic method's name isn't recorded as a reference.
    let mut stack = vec![member];
    while let Some(n) = stack.pop() {
        if n.kind() == "generic_name"
            && n.parent().is_some_and(|p| {
                p.kind() == "invocation_expression" && p.child_by_field_name("function") == Some(n)
            })
            && let Some(name) = n.named_child(0)
        {
            let name = std::str::from_utf8(text(name, src)).unwrap_or_default();
            let scope = m
                .type_scopes
                .iter()
                .filter(|(t, _)| {
                    t.start_byte() <= member.start_byte() && member.end_byte() <= t.end_byte()
                })
                .max_by_key(|(t, _)| t.start_byte())
                .map(|(_, s)| *s);
            if scope.is_some_and(|s| instance(s, name)) || inherited(name) {
                return true;
            }
        }
        stack.extend(n.named_children(&mut n.walk()));
    }
    false
}

/// Methods and properties that use no instance data, of any accessibility,
/// as documented. Left out: what can't be static (overrides, virtual,
/// abstract and interface members, explicit and implicit interface
/// implementations, the documented ASP.NET application events, and the
/// public methods of controllers, pages, components and hubs, which the
/// framework calls on an instance), partial types, members with
/// attributes, test code, types whose base class doesn't resolve, and
/// public members of types implementing an interface that doesn't.
pub(super) fn could_be_static<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut by_position: Vec<usize> = (0..m.refs.len()).collect();
    by_position.sort_by_key(|&i| m.refs[i].node.start_byte());
    for (declaration, _) in &m.type_scopes {
        if !matches!(
            declaration.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) || ["partial", "static"]
            .iter()
            .any(|w| cs_has_modifier(*declaration, w, src))
        {
            continue;
        }
        let (Some(name), Some(body)) = (
            declaration.child_by_field_name("name"),
            declaration.child_by_field_name("body"),
        ) else {
            continue;
        };
        let Some(owner) = infer.enclosing_type(name) else {
            continue;
        };
        // An unknown base class may declare what a name means, or be
        // Windows Forms' or WPF's, whose event handlers are documented
        // exceptions. Unknown interfaces only matter to public members.
        if !infer.base_classes_known(&owner) {
            continue;
        }
        let entry_points = infer
            .supertypes(&owner)
            .iter()
            .any(|s| INSTANCE_ENTRY_POINTS.iter().any(|k| s.is(k)));
        let primary: Vec<&[u8]> = declaration
            .named_children(&mut declaration.walk())
            .filter(|c| c.kind() == "parameter_list")
            .flat_map(|l| l.named_children(&mut l.walk()).collect::<Vec<_>>())
            .filter_map(|p| p.child_by_field_name("name"))
            .map(|n| text(n, src))
            .collect();
        for member in body.named_children(&mut body.walk()) {
            let Some(member_name) = member.child_by_field_name("name") else {
                continue;
            };
            let has_body = match member.kind() {
                "method_declaration" => member.child_by_field_name("body").is_some(),
                "property_declaration" => {
                    member
                        .child_by_field_name("value")
                        .is_some_and(|v| v.kind() == "arrow_expression_clause")
                        || member.child_by_field_name("accessors").is_some_and(|list| {
                            let accessors: Vec<Node> =
                                list.named_children(&mut list.walk()).collect();
                            !accessors.is_empty()
                                && accessors.iter().all(|a| {
                                    a.child_by_field_name("body").is_some()
                                        && !text(*a, src).trim_ascii_start().starts_with(b"init")
                                })
                        })
                }
                _ => continue,
            };
            let public = cs_has_modifier(member, "public", src);
            let label = std::str::from_utf8(text(member_name, src)).unwrap_or_default();
            let eligible = has_body
                && ![
                    "static", "virtual", "abstract", "override", "extern", "partial", "new",
                ]
                .iter()
                .any(|w| cs_has_modifier(member, w, src))
                && attribute_names(member, src).is_empty()
                && !member
                    .named_children(&mut member.walk())
                    .any(|c| c.kind() == "explicit_interface_specifier")
                && !APPLICATION_EVENTS.contains(&label.as_bytes())
                && !(public && entry_points)
                && !(member.kind() == "method_declaration" && is_test_method(member, src))
                && !(public && infer.interface_declares(&owner, label) != Some(false));
            if eligible && !uses_instance(m, &infer, member, &owner, &primary, &by_position, src) {
                found.push(member_name);
            }
        }
    }
    found
}

// ---------------------------------------------------- S3242

/// What a method does with a parameter, when all it does is reach members.
enum Reach {
    /// `p.Name(...)` with this many arguments, or `p.Name` for None.
    Member(String, Option<usize>, usize),
    /// `foreach (... in p)`.
    Enumerated,
    /// `p == null` and the like, which any type allows.
    Compared,
}

/// How a method uses a parameter, each occurrence; None when one does
/// more than reach a member: passed on, assigned, cast, written through.
fn reaches(m: &Model, param: usize, refs: &[usize], src: &[u8]) -> Option<Vec<Reach>> {
    let decl = &m.decls[param];
    let mut out = Vec::new();
    for u in refs
        .iter()
        .map(|&i| m.refs[i].node)
        .filter(|n| *n != decl.node)
    {
        let parent = u.parent()?;
        match parent.kind() {
            "member_access_expression" if parent.child_by_field_name("expression") == Some(u) => {
                let name = parent.child_by_field_name("name")?;
                if name.kind() != "identifier" {
                    return None;
                }
                let outer = parent.parent()?;
                let written = match outer.kind() {
                    "assignment_expression" => outer.child_by_field_name("left") == Some(parent),
                    "prefix_unary_expression" | "postfix_unary_expression" => true,
                    _ => false,
                };
                if written {
                    return None;
                }
                let arguments = (outer.kind() == "invocation_expression"
                    && outer.child_by_field_name("function") == Some(parent))
                .then(|| cs_call_arguments(outer).len());
                out.push(Reach::Member(
                    String::from_utf8_lossy(text(name, src)).into_owned(),
                    arguments,
                    outer.start_byte(),
                ));
            }
            "foreach_statement" if parent.child_by_field_name("right") == Some(u) => {
                out.push(Reach::Enumerated);
            }
            "binary_expression"
                if parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| matches!(text(o, src), b"==" | b"!="))
                    && ["left", "right"].iter().any(|f| {
                        parent
                            .child_by_field_name(f)
                            .is_some_and(|o| unparenthesized(o).kind() == "null_literal")
                    }) =>
            {
                out.push(Reach::Compared);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// What a parameter's uses resolve to on a type: per use, the signatures
/// of the members found, or the extension methods; None when one doesn't
/// resolve, or resolves to a static member.
enum Resolved {
    Members(Vec<(Vec<Ty>, Ty)>),
    Extensions(Vec<*const crate::semantic::dotnet::PlatformMember>),
    Elements(Ty),
    Anything,
}

/// Whether two types resolve a parameter's uses alike: the same members,
/// overloads in any order, the same extension methods, the same elements.
fn same_resolution(a: &[Resolved], b: &[Resolved]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|pair| match pair {
            (Resolved::Members(x), Resolved::Members(y)) => {
                x.len() == y.len() && x.iter().all(|s| y.contains(s))
            }
            (Resolved::Extensions(x), Resolved::Extensions(y)) => x == y,
            (Resolved::Elements(x), Resolved::Elements(y)) => x == y,
            (Resolved::Anything, Resolved::Anything) => true,
            _ => false,
        })
}

fn resolve_reaches(infer: &Infer, ty: &Ty, uses: &[Reach]) -> Option<(Vec<Resolved>, bool)> {
    let mut out = Vec::new();
    // Whether one use needs more than Object's members.
    let mut specific = false;
    for u in uses {
        out.push(match u {
            Reach::Compared => Resolved::Anything,
            Reach::Enumerated => {
                specific = true;
                Resolved::Elements(infer.element_type(ty)?)
            }
            Reach::Member(name, arguments, byte) => {
                let found = infer.members(ty, name, *arguments);
                if found.is_empty() {
                    let n = (*arguments)?;
                    let methods = infer.extension_methods(ty, name, n, *byte);
                    if methods.is_empty() {
                        return None;
                    }
                    specific = true;
                    let mut ptrs: Vec<_> = methods.into_iter().map(|m| m as *const _).collect();
                    ptrs.sort();
                    Resolved::Extensions(ptrs)
                } else {
                    let mut signatures = Vec::new();
                    for f in &found {
                        match f {
                            Found::Platform {
                                declaring, member, ..
                            } => {
                                if member.has("static") {
                                    return None;
                                }
                                specific |= declaring.name != "System.Object";
                            }
                            Found::Local(d) => {
                                if d.is_static {
                                    return None;
                                }
                                specific = true;
                            }
                        }
                        signatures.push(infer.signature(f)?);
                    }
                    Resolved::Members(signatures)
                }
            }
        });
    }
    Some((out, specific))
}

/// Parameters declared with a type whose base class or interface has every
/// member the method uses: `ReadStream(FileStream s)` that only calls
/// `s.ReadByte()`, which Stream declares. A parameter used for anything
/// else (passed on, assigned, cast, written through) is left alone, as are
/// `params` arrays and parameters with attributes, which may only fit
/// their type, and those of methods that can't change their signature (overrides,
/// virtual and abstract methods, interface implementations, the public
/// methods of controllers and pages, which bind parameters by their
/// declared type) and of overloaded ones, which could then clash. Value
/// types aren't reported, nor Object as the base: one boxes, the other
/// says nothing.
pub(super) fn parameters_with_base_types<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut by_decl: Vec<Vec<usize>> = vec![Vec::new(); m.decls.len()];
    for (i, r) in m.refs.iter().enumerate() {
        if let Some(d) = r.decl {
            by_decl[d].push(i);
        }
    }
    for f in &m.functions {
        let method = f.node;
        if method.kind() != "method_declaration"
            || method.child_by_field_name("body").is_none()
            || [
                "override", "virtual", "abstract", "extern", "partial", "new",
            ]
            .iter()
            .any(|w| cs_has_modifier(method, w, src))
            || method
                .named_children(&mut method.walk())
                .any(|c| c.kind() == "explicit_interface_specifier")
        {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        let label = std::str::from_utf8(text(name, src)).unwrap_or_default();
        let Some(owner) = infer.enclosing_type(name) else {
            continue;
        };
        let public = cs_has_modifier(method, "public", src);
        if public
            && (infer.interface_declares(&owner, label) != Some(false)
                || infer
                    .supertypes(&owner)
                    .iter()
                    .any(|s| INSTANCE_ENTRY_POINTS.iter().any(|k| s.is(k))))
        {
            continue;
        }
        let overloaded = m
            .scopes
            .get(f.scope)
            .and_then(|s| s.parent)
            .is_some_and(|scope| m.decls_named(scope, label).len() > 1);
        if overloaded {
            continue;
        }
        for decls in &f.params {
            let [param] = decls[..] else {
                continue;
            };
            let decl = &m.decls[param];
            let Some(written) = decl.ty else {
                continue;
            };
            // A `params` array is declared on the list itself; attributes
            // such as [DynamicallyAccessedMembers] may only fit this type.
            let Some(declaring) = decl.declarator.filter(|d| d.kind() == "parameter") else {
                continue;
            };
            if ["ref", "out", "in", "this", "scoped"]
                .iter()
                .any(|w| cs_has_modifier(declaring, w, src))
                || declaring
                    .named_children(&mut declaring.walk())
                    .any(|c| c.kind() == "attribute_list")
            {
                continue;
            }
            let Some(uses) = reaches(m, param, &by_decl[param], src) else {
                continue;
            };
            let Some(ty) = infer.written(written) else {
                continue;
            };
            if infer.value_type(&ty) != Some(false) || !infer.complete(&ty) {
                continue;
            }
            let Some((own, true)) = resolve_reaches(&infer, &ty, &uses) else {
                continue;
            };
            let general = infer.supertypes(&ty).into_iter().skip(1).any(|base| {
                !base.is("System.Object")
                    && !base.is("System.ValueType")
                    && resolve_reaches(&infer, &base, &uses).is_some_and(|(theirs, specific)| {
                        specific && same_resolution(&theirs, &own)
                    })
            });
            if general {
                found.push(written);
            }
        }
    }
    found
}

// ---------------------------------------------------- overloads (step 3)

/// Whether two found methods are the same declaration.
fn same_method(a: &Found, b: &Found) -> bool {
    match (a, b) {
        (Found::Platform { member: x, .. }, Found::Platform { member: y, .. }) => {
            std::ptr::eq(*x, *y)
        }
        (Found::Local(x), Found::Local(y)) => std::ptr::eq(*x, *y),
        _ => false,
    }
}

/// Whether every target framework has a platform method: .NET Standard 2.0
/// declares it, so a call binds to it the same everywhere, and recommending
/// it is safe (ADR-0022). Methods of the file's own always qualify.
fn on_every_target(found: &Found) -> bool {
    match found {
        Found::Platform { member, .. } => member.has("ns20"),
        Found::Local(_) => true,
    }
}

/// An overload of the method a call binds to that takes the same
/// parameters plus one whose type `extra` accepts: the documented
/// `StringComparison` and `IFormatProvider` overloads. One every target has
/// and that isn't obsolete.
fn overload_with_one_more<'m, 't>(
    infer: &Infer<'m, 't>,
    b: &Bound<'m, 't>,
    extra: impl Fn(&Ty) -> bool,
) -> bool {
    let key = |p: &Param| (p.ty.clone(), p.modifier.map(str::to_string));
    let mine: Vec<_> = b.params.iter().map(key).collect();
    infer.overloads(&b.method).iter().any(|o| {
        let obsolete = matches!(o, Found::Platform { member, .. } if member.has("Obsolete"));
        if same_method(o, &b.method)
            || obsolete
            || !on_every_target(o)
            || infer.is_static(o) != infer.is_static(&b.method)
        {
            return false;
        }
        let Some(params) = infer.params(o) else {
            return false;
        };
        params.len() == mine.len() + 1
            && (0..params.len()).any(|k| {
                params[k].ty.as_ref().is_some_and(&extra)
                    && params
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != k)
                        .map(|(_, p)| key(p))
                        .eq(mine.iter().cloned())
            })
    })
}

/// The name a call goes by: the method's, or the type's for `new`.
fn call_name<'s>(call: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let name = match call.kind() {
        "object_creation_expression" => {
            let ty = call.child_by_field_name("type")?;
            match ty.kind() {
                "qualified_name" => ty.child_by_field_name("name")?,
                _ => ty,
            }
        }
        _ => {
            let f = call.child_by_field_name("function")?;
            match f.kind() {
                "member_access_expression" => f.child_by_field_name("name")?,
                _ => f,
            }
        }
    };
    let name = if name.kind() == "generic_name" {
        name.named_child(0)?
    } else {
        name
    };
    Some(text(name, src))
}

/// The names of the platform's methods with an overload taking a parameter
/// of one of these types, and of types whose constructors have one: a call
/// by another name, to no method of the file's, can't have such an
/// overload.
fn overload_names(
    types: &[&str],
    cell: &'static OnceLock<HashSet<&'static str>>,
) -> &'static HashSet<&'static str> {
    cell.get_or_init(|| {
        let mut out = HashSet::new();
        for t in dotnet::platform().types() {
            for m in &t.members {
                let takes = m.params.iter().any(|p| types.contains(&p.ty.as_str()));
                match m.kind.as_str() {
                    "method" if takes => {
                        out.insert(m.name.as_str());
                    }
                    "constructor" if takes => {
                        let simple = t.name.rsplit('.').next().unwrap_or(&t.name);
                        out.insert(simple.split('`').next().unwrap_or(simple));
                    }
                    _ => {}
                }
            }
        }
        out
    })
}

/// Whether a call may bind to a method with an overload taking one of
/// some types: its name is in `names` (`overload_names`), or one of the
/// file's methods' (`method_names`).
fn may_have_overload(
    call: Node,
    src: &[u8],
    names: &HashSet<&'static str>,
    local: &HashSet<&str>,
) -> bool {
    call_name(call, src)
        .and_then(|n| std::str::from_utf8(n).ok())
        .is_some_and(|name| names.contains(name) || local.contains(name))
}

/// The names of the methods a file declares.
fn method_names<'a>(m: &'a Model) -> HashSet<&'a str> {
    m.decls
        .iter()
        .filter(|d| d.kind == DeclKind::Method)
        .map(|d| d.name.as_str())
        .collect()
}

/// The calls of a file that `wanted` keeps, with what they bind to:
/// invocations, and object creations when `creations`.
fn resolved_calls<'t>(
    m: &Model<'t>,
    src: &[u8],
    creations: bool,
    wanted: impl for<'m> Fn(&Infer<'m, 't>, Node<'t>, &[Arg<'t>]) -> bool,
    mut f: impl for<'m> FnMut(&Infer<'m, 't>, Node<'t>, Vec<Arg<'t>>, Bound<'m, 't>),
) {
    let Some(infer) = Infer::new(m, src) else {
        return;
    };
    walk_tree(m, |call, _| {
        let kind = call.kind();
        if kind != "invocation_expression" && !(creations && kind == "object_creation_expression") {
            return;
        }
        let args = arguments(call);
        if !wanted(&infer, call, &args) {
            return;
        }
        if let Some(b) = infer.resolve_with(call, &args) {
            f(&infer, call, args, b);
        }
    });
}

// ---------------------------------------------------- S2234

/// Calls passing variables named after the method's parameters in another
/// order than those parameters': two such arguments, each after one whose
/// namesake comes later.
pub(super) fn arguments_out_of_order<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let variables = |args: &[Arg]| {
        args.iter()
            .filter(|a| a.name.is_none() && a.value.kind() == "identifier")
            .count()
    };
    let mut found = Vec::new();
    resolved_calls(
        m,
        src,
        false,
        |infer, call, args| {
            variables(args) >= 2
                && infer
                    .candidate_params(call, args.len())
                    .iter()
                    .any(|params| out_of_order(args, params, src))
        },
        |_, call, args, b| {
            if out_of_order(&args, &b.params[usize::from(b.extension)..], src) {
                found.push(call);
            }
        },
    );
    found
}

/// Whether two positional variables are named after parameters in the
/// other order.
fn out_of_order(args: &[Arg], params: &[Param], src: &[u8]) -> bool {
    let namesakes: Vec<usize> = args
        .iter()
        .filter(|a| a.name.is_none() && a.value.kind() == "identifier")
        .filter_map(|a| {
            let name = text(a.value, src);
            params.iter().position(|p| p.name.as_bytes() == name)
        })
        .collect();
    namesakes
        .iter()
        .enumerate()
        .any(|(i, k)| namesakes[i + 1..].iter().any(|later| later < k))
}

// ---------------------------------------------------- S3254

/// Arguments equal to their parameter's default, that the call can leave
/// out and still bind to the same method: named ones, and positional ones
/// with only such arguments, or named ones, after them. Parameters whose
/// value an attribute may supply (`[CallerMemberName]`) are left alone.
pub(super) fn default_values_passed<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    let defaults = |params: &[Param]| params.iter().any(|p| p.default.is_some() && !p.attributed);
    let constant = |infer: &Infer, a: &Arg| {
        a.value.kind() == "default_expression" || infer.constant(a.value, None).is_some()
    };
    resolved_calls(
        m,
        src,
        false,
        |infer, call, args| {
            args.iter().any(|a| constant(infer, a))
                && infer
                    .candidate_params(call, args.len())
                    .iter()
                    .any(|p| defaults(p))
        },
        |infer, call, args, b| {
            let redundant: Vec<bool> = args
                .iter()
                .zip(&b.targets)
                .map(|(a, &t)| {
                    let p = &b.params[t];
                    a.modifier.is_none()
                        && p.optional
                        && !p.attributed
                        && p.default.as_ref().is_some_and(|d| {
                            infer
                                .constant(a.value, p.ty.as_ref())
                                .is_some_and(|c| c.same(d))
                        })
                })
                .collect();
            // Positional arguments go from the end: each with those after it.
            let mut trailing = true;
            for i in (0..args.len()).rev() {
                if !redundant[i] {
                    trailing &= args[i].name.is_some();
                    continue;
                }
                if args[i].name.is_none() && !trailing {
                    continue;
                }
                let rest: Vec<Arg> = args
                    .iter()
                    .enumerate()
                    .filter(|(j, a)| {
                        let with_it = args[i].name.is_none() && a.name.is_none() && *j > i;
                        *j != i && !(with_it && redundant[*j])
                    })
                    .map(|(_, a)| *a)
                    .collect();
                let same = infer
                    .resolve_with(call, &rest)
                    .is_some_and(|r| same_method(&r.method, &b.method));
                if same {
                    found.push(args[i].node);
                }
            }
        },
    );
    found.sort_by_key(|n| n.start_byte());
    found
}

// ---------------------------------------------------- S4005

/// What SonarQube documents as a URI parameter's name.
fn names_uri(name: &str) -> bool {
    ["uri", "Uri", "urn", "Urn", "url", "Url"]
        .iter()
        .any(|w| name.contains(w))
}

/// Calls passing a string to a parameter named for a URI, when the type
/// declaring the method has the same overload with a `System.Uri` there.
pub(super) fn string_uri_arguments<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    static NAMES: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let local = method_names(m);
    let names = overload_names(&["System.Uri"], &NAMES);
    let mut found = Vec::new();
    let wanted = |_: &Infer, call: Node, _: &[Arg]| may_have_overload(call, src, names, &local);
    resolved_calls(m, src, false, wanted, |infer, call, _, b| {
        if !on_every_target(&b.method) {
            return;
        }
        let uri_at = |k: usize| {
            let p = &b.params[k];
            p.ty.as_ref().is_some_and(|t| t.is(STRING)) && names_uri(p.name)
        };
        let key = |p: &Param| (p.ty.clone(), p.modifier.map(str::to_string));
        let replaced = b.targets.iter().copied().filter(|&k| uri_at(k)).any(|k| {
            infer.overloads(&b.method).iter().any(|o| {
                let obsolete =
                    matches!(o, Found::Platform { member, .. } if member.has("Obsolete"));
                if same_method(o, &b.method)
                    || obsolete
                    || !on_every_target(o)
                    || infer.is_static(o) != infer.is_static(&b.method)
                {
                    return false;
                }
                infer.params(o).is_some_and(|ps| {
                    ps.len() == b.params.len()
                        && ps.iter().zip(&b.params).enumerate().all(|(i, (x, y))| {
                            if i == k {
                                x.ty.as_ref().is_some_and(|t| t.is("System.Uri"))
                                    && x.modifier == y.modifier
                            } else {
                                key(x) == key(y)
                            }
                        })
                })
            })
        });
        if replaced {
            found.push(call);
        }
    });
    found
}

// ---------------------------------------------------- S4056

/// Members SonarQube leaves out by name, and those whose documentation
/// says the provider is reserved or ignored, by declaring type, name and
/// parameter types.
const PROVIDER_IGNORED: &[(&str, &str, &[&str])] = &[
    ("System.Activator", "CreateInstance", &[]),
    ("System.Resources.ResourceManager", "GetObject", &[]),
    ("System.Resources.ResourceManager", "GetString", &[]),
    ("System.Boolean", "ToString", &[]),
    ("System.Char", "ToString", &[]),
    ("System.String", "ToString", &[]),
    ("System.Guid", "ToString", &["System.String"]),
    ("System.Convert", "ToString", &["System.Boolean"]),
    ("System.Convert", "ToString", &["System.Char"]),
    ("System.Convert", "ToString", &["System.String"]),
    ("System.Convert", "ToBoolean", &["System.String"]),
    ("System.Convert", "ToChar", &["System.String"]),
    // The base types ignore it, values of other types may not.
    ("System.Convert", "ToBoolean", &["System.Object"]),
    ("System.Convert", "ToChar", &["System.Object"]),
];

/// Calls of a member that has an overload taking the same parameters plus
/// an `IFormatProvider` or `CultureInfo`, made without one. Constructors
/// too, as the documentation says members.
pub(super) fn format_provider_overloads<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    const PROVIDERS: &[&str] = &["System.IFormatProvider", "System.Globalization.CultureInfo"];
    static NAMES: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let local = method_names(m);
    let names = overload_names(PROVIDERS, &NAMES);
    let mut found = Vec::new();
    let wanted = |_: &Infer, call: Node, _: &[Arg]| may_have_overload(call, src, names, &local);
    resolved_calls(m, src, true, wanted, |infer, call, args, b| {
        if !on_every_target(&b.method)
            || b.params.iter().any(|p| {
                p.ty.as_ref()
                    .is_some_and(|t| PROVIDERS.iter().any(|k| t.is(k)))
            })
        {
            return;
        }
        if let Found::Platform {
            declaring, member, ..
        } = &b.method
        {
            let types: Vec<&str> = member.params.iter().map(|p| p.ty.as_str()).collect();
            let ignored = PROVIDER_IGNORED.iter().any(|(t, n, ps)| {
                declaring.name == *t && member.name == *n && (ps.is_empty() || types == *ps)
            });
            if ignored {
                return;
            }
            let arg_type = || args.first().and_then(|a| infer.type_of(a.value));
            match (
                declaring.name.as_str(),
                member.name.as_str(),
                types.as_slice(),
            ) {
                // Used only when the value is IConvertible or IFormattable.
                ("System.Convert", "ToString", ["System.Object"]) => {
                    let formats = arg_type().is_some_and(|t| {
                        infer
                            .supertypes(&t)
                            .iter()
                            .any(|s| s.is("System.IConvertible") || s.is("System.IFormattable"))
                    });
                    if !formats {
                        return;
                    }
                }
                // Ignored for custom formats: report standard ones only.
                ("System.TimeSpan", "ToString", ["System.String"]) => {
                    let standard = args
                        .first()
                        .and_then(|a| infer.constant(a.value, None))
                        .is_some_and(|c| matches!(c, Constant::Str(f) if f.chars().count() == 1));
                    if !standard {
                        return;
                    }
                }
                _ => {}
            }
        }
        if overload_with_one_more(infer, &b, |t| PROVIDERS.iter().any(|k| t.is(k))) {
            found.push(call);
        }
    });
    found
}

// ---------------------------------------------------- S4058

/// Calls of a string method that has an overload taking the same
/// parameters plus a `StringComparison`, made without one.
pub(super) fn string_comparison_overloads<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    static NAMES: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let local = method_names(m);
    let names = overload_names(&["System.StringComparison"], &NAMES);
    let mut found = Vec::new();
    let wanted = |_: &Infer, call: Node, _: &[Arg]| may_have_overload(call, src, names, &local);
    resolved_calls(m, src, false, wanted, |infer, call, _, b| {
        let on_string =
            matches!(&b.method, Found::Platform { declaring, .. } if declaring.name == STRING);
        if on_string
            && on_every_target(&b.method)
            && overload_with_one_more(infer, &b, |t| t.is("System.StringComparison"))
        {
            found.push(call);
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    #[test]
    fn culture_dependent_string_operations() {
        let src = "using System;\nusing System.Globalization;\nclass A { void F(string s, double d, DateTime t, char c) {\n\
            _ = s.ToLower();\n\
            _ = s.ToLower(CultureInfo.InvariantCulture);\n\
            _ = s.ToUpperInvariant();\n\
            _ = s.IndexOf(\"x\");\n\
            _ = s.IndexOf(\"x\", StringComparison.Ordinal);\n\
            _ = s.IndexOf(c);\n\
            _ = string.Compare(s, \"x\");\n\
            _ = string.Compare(s, \"x\", StringComparison.Ordinal);\n\
            _ = s.CompareTo(\"x\");\n\
            _ = d.ToString();\n\
            _ = d.ToString(\"N2\");\n\
            _ = d.ToString(CultureInfo.InvariantCulture);\n\
            _ = t.ToString();\n\
            _ = c.ToString();\n\
            _ = unknown.ToLower();\n\
        } }";
        assert_eq!(
            flagged("cs/culture-sensitive-case", src),
            [4, 7, 10, 12, 13, 14, 16]
        );
        // SonarQube checks this key on main code only.
        let test = "using NUnit.Framework;\nclass T { [Test] public void F(string s) { _ = s.ToLower(); } }";
        assert!(flagged("cs/culture-sensitive-case", test).is_empty());
    }

    #[test]
    fn redundant_to_string_as_documented() {
        let src = "using System;\nclass A { void F(string s, object o, int n) {\n\
            _ = \"fee fie foe \" + s.ToString();\n\
            _ = \"\" + o.ToString();\n\
            _ = string.Format(\"{0}\", o.ToString());\n\
            _ = string.Format(\"{0}\", n.ToString());\n\
            _ = \"\" + n.ToString();\n\
            _ = o.ToString();\n\
            _ = o.ToString() + o.ToString();\n\
            _ = string.Format(o.ToString(), 1);\n\
        } }";
        assert_eq!(flagged("cs/redundant-to-string", src), [3, 4, 5]);
    }

    #[test]
    fn blocking_on_tasks_as_documented() {
        let src = "using System.Threading;\nusing System.Threading.Tasks;\nclass A {\n\
            static async Task DelayAsync() { await Task.Delay(1000); }\n\
            void Test(Task<int> t) {\n\
              var delay = DelayAsync();\n\
              delay.Wait();\n\
              _ = t.Result;\n\
              t.GetAwaiter().GetResult();\n\
              Task.WaitAll(delay, t);\n\
              _ = Task.Run(() => 1).Result;\n\
              Thread.Sleep(10);\n\
            }\n\
            async Task Later() { Thread.Sleep(10); await Task.Yield(); }\n\
            static void Main() { DelayAsync().Wait(); }\n\
        }";
        assert_eq!(flagged("cs/blocking-async-call", src), [7, 8, 9, 10, 14]);
    }

    #[test]
    fn sync_calls_with_awaitable_versions() {
        let src = "using System.IO;\nusing System.Data.Common;\nusing System.Threading.Tasks;\nclass A {\n\
            async Task Examples(Stream stream, byte[] array, DbDataReader reader) {\n\
              stream.Read(array, 0, 1024);\n\
              File.ReadAllLines(\"path\");\n\
              await stream.ReadAsync(array, 0, 1024);\n\
              reader.IsDBNull(0);\n\
              stream.Seek(0, SeekOrigin.Begin);\n\
              await Task.Run(() => File.ReadAllLines(\"path\"));\n\
            }\n\
            void NotAsync(Stream stream, byte[] array) { stream.Read(array, 0, 1024); }\n\
        }";
        // File.ReadAllLinesAsync isn't in .NET Standard 2.0.
        assert_eq!(flagged("cs/blocking-call-in-async", src), [6]);
        let local = "using System.Threading;\nusing System.Threading.Tasks;\nclass A {\n\
            string Load(string id) => id;\n\
            Task<string> LoadAsync(string id, CancellationToken ct = default) => Task.FromResult(id);\n\
            string Find(int id) => \"\";\n\
            Task<string> FindAsync(string name) => Task.FromResult(name);\n\
            async Task F(CancellationTokenSource cts) { Load(\"a\"); Find(1); cts.Cancel(); await Task.Yield(); }\n\
        }";
        // Find's awaitable version takes a name, not an id; CancelAsync is .NET 8's.
        assert_eq!(flagged("cs/blocking-call-in-async", local), [8]);
    }

    #[test]
    fn collection_methods_on_inferred_receivers() {
        let src = "using System.Linq;\nusing System.Collections.Generic;\nusing System.Collections.Immutable;\nclass A {\n\
            List<int> Get() => new List<int>();\n\
            void F(IEnumerable<int> e, IQueryable<int> q, ImmutableList<int> im, LinkedList<int> ll, SortedSet<int> set, IReadOnlyList<int> ro) {\n\
              _ = Get().FirstOrDefault(x => x > 1);\n\
              _ = e.ToList().Any(x => x > 1);\n\
              _ = im.All(x => x > 1);\n\
              _ = e.Any(x => x > 1);\n\
              _ = q.ToList().Exists(x => x > 1);\n\
              _ = ll.First();\n\
              _ = ll.Last();\n\
              _ = set.Max();\n\
              _ = ro.First();\n\
              _ = ro.ElementAt(2);\n\
              _ = e.First();\n\
              _ = ro.First(x => x > 1);\n\
            }\n\
        }";
        assert_eq!(flagged("cs/use-list-find", src), [7]);
        assert_eq!(flagged("cs/use-list-exists", src), [8]);
        assert_eq!(flagged("cs/use-list-true-for-all", src), [9]);
        assert_eq!(flagged("cs/linked-list-first-last", src), [12, 13]);
        assert_eq!(flagged("cs/set-min-max", src), [14]);
        // LinkedList isn't indexable; IReadOnlyList is.
        assert_eq!(flagged("cs/indexing-instead-of-linq", src), [15, 16]);
    }

    #[test]
    fn redundant_casts_as_documented() {
        let src = "using System.Collections.Generic;\nusing System.Linq;\nclass Base { }\nclass Derived : Base { }\nclass A {\n\
            int F(int i) { return (int)(i + 42); }\n\
            IEnumerable<int> G(IEnumerable<int> coll) { return coll.Reverse().OfType<int>(); }\n\
            bool H() { bool b = (bool)default; return b; }\n\
            Base I(Derived d) { Base b = (Base)d; return b; }\n\
            object J(Derived d) => (Base)d;\n\
            void K(Derived d) { M((Base)d); }\n\
            long L(int i) { long l = (long)i; return l; }\n\
            float N(float f, float g) { return (float)(f * g); }\n\
            IEnumerable<string> O(List<string> s) => s.OfType<string>();\n\
            IEnumerable<string> P(List<string> s) => s.Cast<string>();\n\
            void Q(int i) { var l = (long)i; }\n\
        }";
        assert_eq!(flagged("cs/redundant-cast", src), [6, 7, 9, 12, 15]);
    }

    #[test]
    fn foreach_conversions_as_documented() {
        let src = "using System;\nusing System.Collections.Generic;\nclass Fruit { }\nclass Orange : Fruit { }\nstruct Money { public static explicit operator Money(int v) => new Money(); }\nclass A { void F(List<Fruit> fruits, List<object> objs, List<long> longs, List<int> ints, IComparable[] cs) {\n\
            foreach (Orange o in fruits) { }\n\
            foreach (string s in objs) { }\n\
            foreach (int n in longs) { }\n\
            foreach (long n in ints) { }\n\
            foreach (Money m in ints) { }\n\
            foreach (string s in cs) { }\n\
            foreach (Fruit f in fruits) { }\n\
            foreach (Orange o in unknown) { }\n\
        } }";
        assert_eq!(flagged("cs/foreach-explicit-conversion", src), [7, 9, 12]);
    }

    #[test]
    fn delegate_chains_as_documented() {
        let src = "using System;\nclass A { void F(Action first, Action second, Action third, Action fourth) {\n\
            Action chain1234 = first + second + third + fourth;\n\
            Action chain12 = chain1234 - third - fourth;\n\
            Action chain14 = first + fourth;\n\
            Action chain23 = chain1234 - chain14;\n\
            chain23 = chain1234 - (first + fourth);\n\
            chain23 -= first + fourth;\n\
            int x = 1 - (2 + 3);\n\
        } }";
        assert_eq!(flagged("cs/delegate-chain-subtraction", src), [6, 7, 8]);
    }

    #[test]
    fn value_tasks_as_documented() {
        let src = "using System.Threading.Tasks;\nclass A {\nValueTask<int> GetAsync() => default;\nasync Task F(bool c) {\n\
            ValueTask<int> vt = GetAsync();\n\
            int r = await vt;\n\
            r = await vt;\n\
            int v = GetAsync().GetAwaiter().GetResult();\n\
            ValueTask<int> once = GetAsync();\n\
            if (c) { r = await once; } else { r = await once; }\n\
            ValueTask<int> t2 = GetAsync();\n\
            if (t2.IsCompleted) { r = t2.Result; }\n\
            ValueTask<int> t3 = GetAsync();\n\
            var task = t3.AsTask();\n\
            var task2 = t3.AsTask();\n\
            ValueTask<int> inLoop = GetAsync();\n\
            for (int i = 0; i < 2; i++) { r = await inLoop; }\n\
            r = await GetAsync().ConfigureAwait(false);\n\
            ValueTask<int> early = GetAsync();\n\
            if (c) { return; }\n\
            if (c) return await early;\n\
            r = await early;\n\
            ValueTask<int> blocked = GetAsync();\n\
            r = blocked.Result;\n\
        } }";
        assert_eq!(flagged("cs/value-task-misuse", src), [7, 8, 15, 24]);
    }

    #[test]
    fn logger_fields_of_documented_frameworks() {
        let src = "using log4net;\nusing Microsoft.Extensions.Logging;\nclass A {\n\
            private static readonly ILog ok = LogManager.GetLogger(typeof(A));\n\
            public ILog pub;\n\
            private ILog notStatic;\n\
            static readonly ILog defaultPrivate = null;\n\
            private readonly ILogger<A> injected;\n\
            private readonly Logger other;\n\
            public Serilog.ILogger full;\n\
        }";
        assert_eq!(flagged("cs/logger-not-static-readonly", src), [5, 6, 8, 10]);
        // Two imported frameworks declaring ILogger: C# itself can't tell.
        let ambiguous =
            "using Serilog;\nusing Microsoft.Extensions.Logging;\nclass B { public ILogger x; }";
        assert!(flagged("cs/logger-not-static-readonly", ambiguous).is_empty());
        // In the framework's own namespace, its names need no using.
        let inside = "namespace Serilog.Tests;\nclass C { ILogger _log = null!; }";
        assert_eq!(flagged("cs/logger-not-static-readonly", inside), [2]);
    }

    #[test]
    fn reference_equality_as_documented() {
        let src = "using System;\npublic interface IMyInterface { }\npublic interface IPlain { }\n\
            public class MyClass : IMyInterface { public override bool Equals(object obj) => true; public override int GetHashCode() => 0; }\n\
            public class Plain : IPlain { }\n\
            public class WithOp { public override bool Equals(object o) => true; public override int GetHashCode() => 0; public static bool operator ==(WithOp a, WithOp b) => true; public static bool operator !=(WithOp a, WithOp b) => false; }\n\
            class P { void M(IMyInterface a, IMyInterface b, IPlain c, IPlain d, MyClass e, MyClass f, Type t, Type u, WithOp g, WithOp h, Plain i, Plain j, IComparable k, IComparable l) {\n\
            _ = a == b;\n\
            _ = c == d;\n\
            _ = e != f;\n\
            _ = t == u;\n\
            _ = g == h;\n\
            _ = a == null;\n\
            _ = (object)a == b;\n\
            _ = i == j;\n\
            _ = k == l;\n\
            }\n\
            public override bool Equals(object o) { var x = o as MyClass; return x == x; }\n\
            public override int GetHashCode() => 0;\n\
            }";
        // IComparable: String implements it and overrides Equals.
        assert_eq!(flagged("cs/equality-on-equals-type", src), [8, 10, 16]);
    }

    #[test]
    fn could_be_static_as_documented() {
        let src = "using System;\npublic class Utilities {\n\
            public int MagicNum { get { return 42; } }\n\
            private static string magicWord = \"please\";\n\
            public string MagicWord { get { return magicWord; } set { magicWord = value; } }\n\
            public int Sum(int a, int b) { return a + b; }\n\
            private int count;\n\
            public int Count() => count;\n\
            public int Auto { get; set; }\n\
            public void Application_Start() { }\n\
            public override string ToString() => \"u\";\n\
            int Twice<T>(T v) => 2;\n\
            int Call() => Twice<int>(1);\n\
            }\n\
            public class Disposer : IDisposable { public void Dispose() { } }\n\
            public class Failure : Exception { public string Describe() => Message; public int Code() => 7; }\n\
            public class Unknown : ThirdPartyBase { public int F() => 1; }\n\
            public class Point(int x) { public int X() => x; }\n\
            public class Home : Microsoft.AspNetCore.Mvc.Controller { public int Index() => 1; }\n\
            public class Service : Exception, IUnknownService { private int Helper() => 1; public int Api() => 2; }";
        // Service's public Api may implement IUnknownService; Helper can't.
        assert_eq!(flagged("cs/could-be-static", src), [3, 5, 6, 12, 16, 20]);
    }

    #[test]
    fn parameters_with_base_types_as_documented() {
        let src = "using System.IO;\nusing System.Collections.Generic;\nusing System.Linq;\npublic class Foo {\n\
            public void ReadStream(FileStream stream) { int a; while ((a = stream.ReadByte()) != -1) { } }\n\
            public void Name(FileStream stream) { _ = stream.Name; }\n\
            void Pass(FileStream stream) { Use(stream); }\n\
            void Use(Stream s) { s.Flush(); }\n\
            int Positive(List<int> xs) => xs.Count(x => x > 0);\n\
            void Over(List<int> xs) { foreach (var x in xs) { } }\n\
            void Over(int[] xs) { }\n\
            void Str(string s) { _ = s.Length; }\n\
            void Obj(FileStream s) { _ = s.ToString(); }\n\
            void Null(FileStream s) { if (s != null) { s.Flush(); } }\n\
            void Write(List<int> xs) { xs.Capacity = 4; }\n\
            void Many(params string[] names) { foreach (var n in names) { } }\n\
            void Annotated([NotNull] List<int> xs) { foreach (var x in xs) { } }\n\
            }";
        assert_eq!(flagged("cs/parameter-could-be-enumerable", src), [5, 9, 14]);
    }
    #[test]
    fn argument_order_as_documented() {
        let src = "using System.IO;\nclass A { public double Divide(int divisor, int dividend) { return divisor / dividend; }\n\
            void F(string path1, string path2) { int divisor = 15; int dividend = 5;\n\
            _ = Divide(dividend, divisor);\n\
            _ = Divide(divisor, dividend);\n\
            _ = Divide(dividend, 5);\n\
            _ = Divide(divisor: dividend, dividend: divisor);\n\
            _ = Path.Combine(path2, path1);\n\
            _ = Path.Combine(path1, path2);\n\
            } }";
        assert_eq!(flagged("cs/argument-order", src), [4, 8]);
    }

    #[test]
    fn default_values_as_documented() {
        let src = "using System;\nusing System.Runtime.CompilerServices;\nclass A { public void M(int x, int y = 5, int z = 7) { }\n\
            void Log(string m, [CallerMemberName] string caller = \"\") { }\n\
            void P(int a, bool b = false) { } void P(int a) { }\n\
            void F(string s, object o) {\n\
            M(1, 5);\n\
            M(1, z: 7);\n\
            M(1);\n\
            M(1, 5, 8);\n\
            M(1, y: 6);\n\
            Log(\"x\", \"\");\n\
            P(1, false);\n\
            _ = s.Split(',', StringSplitOptions.None);\n\
            ArgumentNullException.ThrowIfNull(o, null);\n\
            M(1, 5,\n7);\n\
            } }";
        assert_eq!(
            flagged("cs/default-argument-passed", src),
            [7, 8, 14, 16, 17]
        );
    }

    #[test]
    fn uri_overloads_as_documented() {
        let src = "using System;\nusing System.Net.Http;\nnamespace MyLibrary { public class Foo {\n\
            public void FetchResource(string uriString) { } public void FetchResource(Uri uri) { }\n\
            public string ReadResource(string uriString, string name, bool isLocal) { return name; } public string ReadResource(Uri uri, string name, bool isLocal) { return name; }\n\
            public void Named(string name) { } public void Named(Uri name) { }\n\
            public void Main(HttpClient client) {\n\
            FetchResource(\"http://www.mysite.com\");\n\
            ReadResource(\"http://www.mysite.com\", \"foo-resource\", true);\n\
            FetchResource(new Uri(\"http://www.mysite.com\"));\n\
            Named(\"x\");\n\
            client.GetAsync(\"http://www.mysite.com\");\n\
            } } }";
        assert_eq!(flagged("cs/string-uri-argument", src), [8, 9, 12]);
    }

    #[test]
    fn format_providers_as_documented() {
        let src = "using System;\nusing System.Globalization;\nusing System.IO;\nusing System.Resources;\nusing System.Text;\n\
            class Foo { void Bar(string string1, string string2, string string3, bool b, Guid g, TimeSpan t, object o, ResourceManager rm, StringBuilder sb) {\n\
            if (string.Compare(string1, string2, false) == 0) { Console.WriteLine(string3.ToLower()); }\n\
            _ = string.Compare(string1, string2, false, CultureInfo.InvariantCulture); _ = string3.ToLower(CultureInfo.CurrentCulture);\n\
            _ = int.Parse(string1);\n\
            _ = b.ToString(); _ = g.ToString(\"N\"); _ = Convert.ToString(true); _ = rm.GetString(\"x\");\n\
            _ = Convert.ToString(5);\n\
            _ = t.ToString(\"c\");\n\
            _ = t.ToString(\"hh\\\\:mm\"); _ = Convert.ToString(o);\n\
            _ = new StringWriter();\n\
            sb.AppendFormat(\"{0}\", 1);\n\
            } }";
        assert_eq!(
            flagged("cs/culture-overload", src),
            [7, 7, 9, 11, 12, 14, 15]
        );
    }

    #[test]
    fn string_comparisons_as_documented() {
        let src = "using System;\nnamespace MyLibrary { public class Foo { public bool HaveSameNames(string name1, string name2) {\n\
            _ = string.Compare(name1, name2) == 0;\n\
            _ = string.Compare(name1, name2, StringComparison.OrdinalIgnoreCase) == 0;\n\
            _ = name1.Equals(name2);\n\
            _ = string.Equals(name1, name2);\n\
            _ = name1.StartsWith(\"x\");\n\
            _ = name1.StartsWith('x'); _ = name1.Contains(\"x\"); _ = name1.IndexOf('c'); _ = name1.CompareTo(name2);\n\
            return name1.EndsWith(name2, StringComparison.Ordinal);\n\
            } } }";
        assert_eq!(flagged("cs/string-comparison-overload", src), [3, 5, 6, 7]);
    }
}
