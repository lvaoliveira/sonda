//! C# rule checks on inferred types (ADR-0022, step 2): what a receiver or
//! an argument evaluates to, through the platform's declarations
//! (`semantic/cs_infer.rs`). The rules are declared with the others; this
//! module holds their checks. A call whose types don't resolve gives no
//! finding.

use super::cs::cs_has_modifier;
use super::cs_bugs::cs_call_arguments;
use super::cs_more::is_test_method;
use super::cs_types::walk_tree;
use super::java_security::text;
use crate::semantic::Model;
use crate::semantic::cs_infer::{Found, Infer, Ty};
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
}
