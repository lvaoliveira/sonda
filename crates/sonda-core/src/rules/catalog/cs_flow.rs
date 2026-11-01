//! C# rules about values within a method and about the assembly, batch 13
//! (ADR-0007, ADR-0015): dead stores, disposables and StringBuilders that
//! are never released or read, and assembly attributes. The value rules
//! follow a local through the statements of the block that declares it,
//! without a control-flow graph (ADR-0008's S2 and S3): a statement that
//! mentions the local in any other way counts as reading it, so they only
//! report what straight-line code proves. Partial methods and the neutral
//! resources language need the whole project and live in `common.rs`.

use super::cs::{cs_statements, simple_name, unparenthesized};
use super::cs_bugs::cs_call_arguments;
use super::cs_types::{expression_type, walk_tree};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::{contains_ignoring_case, text};
use super::java_smells::count_word;
use super::*;
use crate::semantic::{DeclKind, Model};

/// Rules that are off unless `rules.enabled` lists them: those whose keys
/// are outside SonarQube's default profile.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "cs/parameter-could-be-enumerable",
    "cs/string-uri-argument",
    "cs/localizable-literal",
    "cs/assembly-cls-compliant",
    "cs/assembly-com-visible",
];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/undisposed-local",
        name: "Disposable objects created in a method should be disposed",
        description: "A stream, connection or client that is neither disposed, returned nor handed to \
                      someone else keeps its file handle or socket until the garbage collector finalizes it.",
        message: "Dispose of this object, ideally with a using declaration.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[related("S2930")],
        check: Check::Semantic {
            langs: CSHARP,
            find: undisposed_locals,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(string p) { var reader = new StreamReader(p); return reader.ReadToEnd(); } }",
            good: "class A { string F(string p) { using var reader = new StreamReader(p); return reader.ReadToEnd(); } }",
        }),
    },
    Rule {
        id: "cs/recursive-generic-inheritance",
        name: "Generic types should not inherit from expansions of themselves",
        description: "`class D<T> : C<D<D<T>>>` makes the runtime build ever larger types when loading D, and \
                      fails with TypeLoadException.",
        message: "Use the type's own type parameters in its base type.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S3464")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) (type_parameter_list) (base_list)) \
                     (interface_declaration name: (identifier) (type_parameter_list) (base_list))] @match",
            filter: Some(Find(expanding_self_reference)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class C<T> { } class D<T> : C<D<D<T>>> { }",
            good: "class C<T> { } class D<T> : C<D<T>> { }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/dead-store",
        name: "Values assigned to locals should be used",
        description: "A value overwritten or dropped before anything reads it was computed for nothing, or the \
                      code that should read it is missing.",
        message: "Remove this assignment: the value is never read.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S1854")],
        check: Check::Semantic {
            langs: CSHARP,
            find: dead_stores,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int y) { int x = Compute(); x = 200; return x + y; } }",
            good: "class A { int F(int y) { int x = 200; return x + y; } }",
        }),
    },
    Rule {
        id: "cs/string-builder-never-read",
        name: "StringBuilder contents should be used",
        description: "A StringBuilder that is appended to but never turned into a string, passed on or \
                      returned only costs time.",
        message: "Use this StringBuilder's contents, or remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3063")],
        check: Check::Semantic {
            langs: CSHARP,
            find: unread_string_builders,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(string[] xs) { var sb = new StringBuilder(); foreach (var x in xs) { sb.Append(x); } } }",
            good: "class A { string F(string[] xs) { var sb = new StringBuilder(); foreach (var x in xs) { sb.Append(x); } return sb.ToString(); } }",
        }),
    },
    Rule {
        id: "cs/assembly-version-missing",
        name: "Assemblies should have version information",
        description: "A hand-written AssemblyInfo without AssemblyVersion ships as version 0.0.0.0, which \
                      breaks binding redirects and support. SDK-style projects generate it instead.",
        message: "Add [assembly: AssemblyVersion(\"...\")].",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[related("S3904")],
        check: Check::Query {
            langs: CSHARP,
            query: "(compilation_unit (global_attribute)) @match",
            filter: Some(Find(missing_assembly_version)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[assembly: AssemblyTitle(\"Lib\")]\n[assembly: AssemblyProduct(\"Lib\")]\nnamespace Lib { }",
            good: "[assembly: AssemblyTitle(\"Lib\")]\n[assembly: AssemblyVersion(\"1.0.0.0\")]\nnamespace Lib { }",
        }),
    },
    Rule {
        id: "cs/assembly-cls-compliant",
        name: "Assemblies should state their CLS compliance",
        description: "CLSCompliant tells callers in other .NET languages whether they can use every public \
                      member.",
        message: "Add [assembly: CLSCompliant(true)] (or false).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S3990")],
        check: Check::Query {
            langs: CSHARP,
            query: "(compilation_unit (global_attribute)) @match",
            filter: Some(Find(missing_cls_compliant)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[assembly: AssemblyTitle(\"Lib\")]\nnamespace Lib { }",
            good: "[assembly: AssemblyTitle(\"Lib\")]\n[assembly: CLSCompliant(true)]\nnamespace Lib { }",
        }),
    },
    Rule {
        id: "cs/assembly-com-visible",
        name: "Assemblies should state their COM visibility",
        description: "Without ComVisible, an assembly's public types are visible to COM clients by default.",
        message: "Add [assembly: ComVisible(false)] (or true).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S3992")],
        check: Check::Query {
            langs: CSHARP,
            query: "(compilation_unit (global_attribute)) @match",
            filter: Some(Find(missing_com_visible)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[assembly: AssemblyTitle(\"Lib\")]\nnamespace Lib { }",
            good: "[assembly: AssemblyTitle(\"Lib\")]\n[assembly: ComVisible(false)]\nnamespace Lib { }",
        }),
    },
    Rule {
        id: "cs/parameter-could-be-enumerable",
        name: "Parameters should be declared with the most general type they need",
        description: "A List<T> or array parameter that is only enumerated could be an IEnumerable<T>, which \
                      accepts more callers.",
        message: "Declare this parameter as IEnumerable<T>: it's only enumerated.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S3242")],
        check: Check::Semantic {
            langs: CSHARP,
            find: parameters_only_enumerated,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int Sum(List<int> xs) { var s = 0; foreach (var x in xs) { s += x; } return s; } }",
            good: "class A { int Sum(IEnumerable<int> xs) { var s = 0; foreach (var x in xs) { s += x; } return s; } }",
        }),
    },
    Rule {
        id: "cs/string-uri-argument",
        name: "System.Uri overloads should be called instead of string ones",
        description: "When a method has string and Uri overloads, the Uri one parses and validates the address.",
        message: "Pass a System.Uri to call the Uri overload.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S4005")],
        check: Check::Semantic {
            langs: CSHARP,
            find: string_passed_to_uri_overload,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Fetch(string url) { } void Fetch(Uri url) { } void F() { Fetch(\"https://a.example\"); } }",
            good: "class A { void Fetch(string url) { } void Fetch(Uri url) { } void F() { Fetch(new Uri(\"https://a.example\")); } }",
        }),
    },
    Rule {
        id: "cs/localizable-literal",
        name: "Literals should not be passed where text is localized",
        description: "A literal given as a Text, Message or Caption, or written to the console, shows the same \
                      words to every user.",
        message: "Load this text from a resource.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S4055")],
        check: Check::Semantic {
            langs: CSHARP,
            find: localizable_literals,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(Label label) { label.Text = \"Hello\"; } }",
            good: "class A { void F(Label label) { label.Text = Resources.Hello; } }",
        }),
    },
];

// ---------------------------------------------------- dead stores

/// Values whose assignment is a way of saying "nothing yet".
fn is_default_value(value: Node, src: &[u8]) -> bool {
    let value = unparenthesized(value);
    matches!(
        value.kind(),
        "null_literal" | "boolean_literal" | "default_expression"
    ) || matches!(
        text(value, src),
        b"0" | b"1" | b"-1" | b"\"\"" | b"string.Empty" | b"String.Empty" | b"0L" | b"0.0"
    )
}

/// `x = value;` as a whole statement, value not mentioning x.
fn plain_write<'t>(statement: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    if statement.kind() != "expression_statement" {
        return None;
    }
    let assignment = statement
        .named_child(0)
        .filter(|a| a.kind() == "assignment_expression")?;
    let left = assignment.child_by_field_name("left")?;
    let right = assignment.child_by_field_name("right")?;
    (operator_text(assignment, src) == b"="
        && left.kind() == "identifier"
        && text(left, src) == name
        && count_word(text(right, src), name) == 0)
        .then_some(assignment)
}

fn captures(statement: Node) -> bool {
    find_in_scope(statement, &[], |n| {
        matches!(
            n.kind(),
            "lambda_expression" | "anonymous_method_expression" | "local_function_statement"
        )
    })
    .is_some()
}

fn dead_stores<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |block, _| {
        if !matches!(block.kind(), "block" | "switch_section") {
            return;
        }
        let statements = cs_statements(block);
        if statements.len() > 500 || statements.iter().any(|s| s.kind() == "labeled_statement") {
            return;
        }
        for (start, declaration) in statements.iter().enumerate() {
            if declaration.kind() != "local_declaration_statement"
                || text(*declaration, src).starts_with(b"using")
            {
                continue;
            }
            let Some(variables) = declaration
                .named_child(0)
                .filter(|v| v.kind() == "variable_declaration")
            else {
                continue;
            };
            // `ref int r = ref a[0]` writes through r.
            if variables
                .child_by_field_name("type")
                .is_some_and(|t| t.kind() == "ref_type")
            {
                continue;
            }
            let mut cursor = variables.walk();
            let declarators: Vec<Node<'t>> = variables
                .named_children(&mut cursor)
                .filter(|d| d.kind() == "variable_declarator")
                .collect();
            for declarator in declarators {
                let Some(name) = declarator.child_by_field_name("name").map(|n| text(n, src))
                else {
                    continue;
                };
                if name == b"_" {
                    continue;
                }
                let mentions: Vec<Node<'t>> = statements[start + 1..]
                    .iter()
                    .copied()
                    .filter(|s| count_word(text(*s, src), name) > 0)
                    .collect();
                // A lambda may read it later, whenever it runs.
                if mentions.iter().any(|s| captures(*s)) {
                    continue;
                }
                // The pending write, and whether it may be reported.
                let initial = (declarator.named_child_count() > 1)
                    .then(|| declarator.named_child(declarator.named_child_count() as u32 - 1))
                    .flatten()
                    .map(|v| (declarator, !is_default_value(v, src)));
                let mut pending = initial;
                for statement in mentions {
                    match plain_write(statement, name, src) {
                        Some(write) => {
                            if let Some((node, true)) = pending {
                                found.push(node);
                            }
                            let value = write.child_by_field_name("right");
                            pending =
                                Some((write, value.is_some_and(|v| !is_default_value(v, src))));
                        }
                        None => pending = None,
                    }
                }
                if let Some((node, true)) = pending
                    && node.kind() == "assignment_expression"
                {
                    found.push(node);
                }
            }
        }
    });
    found
}

// ---------------------------------------------------- disposables

/// The types SonarQube documents for this rule: they hold a file handle,
/// a socket or native memory.
const DISPOSABLES: &[&[u8]] = &[
    b"FileStream",
    b"StreamReader",
    b"StreamWriter",
    b"BinaryReader",
    b"BinaryWriter",
    b"WebClient",
    b"Socket",
    b"TcpClient",
    b"TcpListener",
    b"UdpClient",
    b"Image",
    b"Bitmap",
];

const OPENERS: &[&[u8]] = &[
    b"File.Open",
    b"File.OpenRead",
    b"File.OpenWrite",
    b"File.Create",
    b"File.OpenText",
    b"File.CreateText",
    b"File.AppendText",
];

/// What happens to a local at one of its uses.
enum Fate {
    Released,
    Used,
}

/// Whether a use of a local disposes of it or hands it on: `x.Dispose()`,
/// `return x`, `F(x)`, `field = x`, `new T(x)`, `using (x)`.
fn released(name: Node, src: &[u8]) -> Fate {
    let Some(parent) = name.parent() else {
        return Fate::Used;
    };
    match parent.kind() {
        "member_access_expression" if parent.child_by_field_name("expression") == Some(name) => {
            let member = parent
                .child_by_field_name("name")
                .map_or(&b""[..], |n| text(n, src));
            if matches!(member, b"Dispose" | b"DisposeAsync" | b"Close") {
                Fate::Released
            } else {
                Fate::Used
            }
        }
        "conditional_access_expression" => {
            if contains_ignoring_case(text(parent, src), b"Dispose")
                || contains_ignoring_case(text(parent, src), b"Close")
            {
                Fate::Released
            } else {
                Fate::Used
            }
        }
        "argument"
        | "return_statement"
        | "arrow_expression_clause"
        | "yield_statement"
        | "using_statement"
        | "initializer_expression"
        | "anonymous_object_creation_expression"
        | "tuple_expression" => Fate::Released,
        "assignment_expression" if parent.child_by_field_name("right") == Some(name) => {
            Fate::Released
        }
        "variable_declarator" => Fate::Released,
        _ => Fate::Used,
    }
}

fn undisposed_locals<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut uses: Vec<Vec<Node<'t>>> = vec![Vec::new(); m.decls.len()];
    for r in &m.refs {
        if let Some(d) = r.decl {
            uses[d].push(r.node);
        }
    }
    m.decls
        .iter()
        .enumerate()
        .filter(|(i, d)| {
            let Some(declarator) = d
                .declarator
                .filter(|x| d.kind == DeclKind::Let && x.kind() == "variable_declarator")
            else {
                return false;
            };
            let Some(value) = (declarator.named_child_count() > 1)
                .then(|| declarator.named_child(declarator.named_child_count() as u32 - 1))
                .flatten()
            else {
                return false;
            };
            let creates = match value.kind() {
                "object_creation_expression" => value
                    .child_by_field_name("type")
                    .is_some_and(|t| DISPOSABLES.contains(&simple_name(t, src))),
                "invocation_expression" => value
                    .child_by_field_name("function")
                    .is_some_and(|f| OPENERS.contains(&text(f, src))),
                _ => false,
            };
            if !creates {
                return false;
            }
            // `using var x = ...` and `using (var x = ...)`.
            let statement = declarator.parent().and_then(|v| v.parent());
            if statement.is_none_or(|s| {
                s.kind() != "local_declaration_statement"
                    || text(s, src).starts_with(b"using")
                    || text(s, src).starts_with(b"await using")
            }) {
                return false;
            }
            !uses[*i]
                .iter()
                .any(|u| matches!(released(*u, src), Fate::Released))
        })
        .map(|(_, d)| d.node)
        .collect()
}

// ---------------------------------------------------- StringBuilder

const BUILDER_MUTATORS: &[&[u8]] = &[
    b"Append",
    b"AppendLine",
    b"AppendFormat",
    b"AppendJoin",
    b"Insert",
    b"Remove",
    b"Replace",
    b"Clear",
    b"EnsureCapacity",
];

/// Whether a use of a StringBuilder only appends to it: `sb.Append(x)` or a
/// chain of such calls, as a statement.
fn only_appends(name: Node, src: &[u8]) -> bool {
    let mut node = name;
    loop {
        let Some(access) = node.parent().filter(|p| {
            p.kind() == "member_access_expression"
                && p.child_by_field_name("expression") == Some(node)
        }) else {
            return false;
        };
        if !access
            .child_by_field_name("name")
            .is_some_and(|n| BUILDER_MUTATORS.contains(&text(n, src)))
        {
            return false;
        }
        let Some(call) = access
            .parent()
            .filter(|c| c.kind() == "invocation_expression")
        else {
            return false;
        };
        match call.parent() {
            Some(s) if s.kind() == "expression_statement" => return true,
            Some(p) if p.kind() == "member_access_expression" => node = call,
            _ => return false,
        }
    }
}

fn unread_string_builders<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut uses: Vec<Vec<Node<'t>>> = vec![Vec::new(); m.decls.len()];
    for r in &m.refs {
        if let Some(d) = r.decl {
            uses[d].push(r.node);
        }
    }
    m.decls
        .iter()
        .enumerate()
        .filter(|(i, d)| {
            let creates = d
                .declarator
                .filter(|x| {
                    d.kind == DeclKind::Let
                        && x.kind() == "variable_declarator"
                        && x.named_child_count() > 1
                })
                .and_then(|x| x.named_child(x.named_child_count() as u32 - 1))
                .is_some_and(|v| {
                    v.kind() == "object_creation_expression"
                        && v.child_by_field_name("type")
                            .is_some_and(|t| simple_name(t, src) == b"StringBuilder")
                });
            creates && !uses[*i].is_empty() && uses[*i].iter().all(|u| only_appends(*u, src))
        })
        .map(|(_, d)| d.node)
        .collect()
}

// ---------------------------------------------------- types and assemblies

fn expanding_self_reference<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = text(declaration.child_by_field_name("name")?, src);
    let mut cursor = declaration.walk();
    let own: Vec<&[u8]> = declaration
        .named_children(&mut cursor)
        .find(|c| c.kind() == "type_parameter_list")
        .map(|l| {
            let mut c = l.walk();
            l.named_children(&mut c)
                .filter_map(|p| p.child_by_field_name("name"))
                .map(|n| text(n, src))
                .collect()
        })
        .unwrap_or_default();
    let mut c = declaration.walk();
    let bases = declaration
        .named_children(&mut c)
        .find(|c| c.kind() == "base_list")?;
    // `D<T>` in its own base list is fine (`Comparable<D<T>>`); `D<D<T>>`
    // or `D<List<T>>` grows with every level.
    find_in_scope(bases, &[], |n| {
        n.kind() == "generic_name"
            && simple_name(n, src) == name
            && n.named_child(1).is_some_and(|args| {
                let mut ac = args.walk();
                let given: Vec<&[u8]> =
                    args.named_children(&mut ac).map(|a| text(a, src)).collect();
                given.len() == own.len() && given != own
            })
    })
}

/// The first assembly attribute of a hand-written AssemblyInfo that lacks
/// `wanted`.
fn assembly_info_without<'t>(unit: Node<'t>, wanted: &str, src: &[u8]) -> Option<Node<'t>> {
    let source = std::str::from_utf8(src).ok()?;
    let (names, _) = crate::analysis::cs_assembly_attributes(source, unit);
    if !crate::analysis::is_classic_assembly_info(&names) || names.contains(&wanted) {
        return None;
    }
    let mut cursor = unit.walk();
    unit.named_children(&mut cursor)
        .find(|n| n.kind() == "global_attribute")
}

fn missing_assembly_version<'t>(unit: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assembly_info_without(unit, "AssemblyVersion", src)
}

fn missing_cls_compliant<'t>(unit: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assembly_info_without(unit, "CLSCompliant", src)
}

fn missing_com_visible<'t>(unit: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assembly_info_without(unit, "ComVisible", src)
}

// ---------------------------------------------------- opt-in API rules

const ENUMERATING: &[&[u8]] = &[
    b"Where",
    b"Select",
    b"SelectMany",
    b"Any",
    b"All",
    b"Count",
    b"First",
    b"FirstOrDefault",
    b"Last",
    b"LastOrDefault",
    b"Single",
    b"SingleOrDefault",
    b"Sum",
    b"Min",
    b"Max",
    b"Average",
    b"OrderBy",
    b"OrderByDescending",
    b"GroupBy",
    b"ToList",
    b"ToArray",
    b"ToDictionary",
    b"Distinct",
    b"Skip",
    b"Take",
    b"Contains",
    b"Aggregate",
];

fn parameters_only_enumerated<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut uses: Vec<Vec<Node<'t>>> = vec![Vec::new(); m.decls.len()];
    for r in &m.refs {
        if let Some(d) = r.decl {
            uses[d].push(r.node);
        }
    }
    m.decls
        .iter()
        .enumerate()
        .filter(|(i, d)| {
            let Some(ty) = d.ty.filter(|_| d.kind == DeclKind::Param) else {
                return false;
            };
            let concrete = ty.kind() == "array_type"
                || (ty.kind() == "generic_name"
                    && matches!(
                        simple_name(ty, src),
                        b"List" | b"IList" | b"ICollection" | b"Collection" | b"HashSet"
                    ));
            // Overrides and implementations can't change their signature.
            let method = d
                .declarator
                .and_then(|p| p.parent())
                .and_then(|l| l.parent());
            let free = method.is_some_and(|m| {
                m.kind() == "method_declaration"
                    && !["override", "public", "protected"]
                        .iter()
                        .any(|w| super::cs::cs_has_modifier(m, w, src))
            });
            concrete
                && free
                && !uses[*i].is_empty()
                && uses[*i].iter().all(|u| {
                    let Some(parent) = u.parent() else {
                        return false;
                    };
                    match parent.kind() {
                        "foreach_statement" => parent.child_by_field_name("right") == Some(*u),
                        "member_access_expression" => {
                            parent
                                .child_by_field_name("name")
                                .is_some_and(|n| ENUMERATING.contains(&text(n, src)))
                                && parent
                                    .parent()
                                    .is_some_and(|c| c.kind() == "invocation_expression")
                        }
                        _ => false,
                    }
                })
        })
        .filter_map(|(_, d)| d.ty)
        .collect()
}

fn names_uri(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    [&b"uri"[..], b"url", b"urn"]
        .iter()
        .any(|w| lower.windows(w.len()).any(|x| x == *w))
}

fn string_passed_to_uri_overload<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |call, _| {
        if call.kind() != "invocation_expression" {
            return;
        }
        let Some(function) = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "identifier")
        else {
            return;
        };
        let Some(target) = m.decl_of(function).filter(|d| d.kind == DeclKind::Method) else {
            return;
        };
        let args = cs_call_arguments(call);
        // Each overload's parameters: (type, name).
        let overloads: Vec<Vec<(Vec<u8>, Vec<u8>)>> = m
            .decls_named(target.scope, &target.name)
            .iter()
            .filter_map(|d| m.decls[*d].declarator)
            .map(|method| {
                let list = method.child_by_field_name("parameters");
                let mut out = Vec::new();
                if let Some(list) = list {
                    let mut c = list.walk();
                    for p in list
                        .named_children(&mut c)
                        .filter(|p| p.kind() == "parameter")
                    {
                        let ty = p
                            .child_by_field_name("type")
                            .map_or(Vec::new(), |t| simple_name(t, src).to_vec());
                        let name = p
                            .child_by_field_name("name")
                            .map_or(Vec::new(), |n| text(n, src).to_vec());
                        out.push((ty, name));
                    }
                }
                out
            })
            .filter(|ps| ps.len() == args.len())
            .collect();
        for (i, arg) in args.iter().enumerate() {
            let string_overload = overloads
                .iter()
                .any(|ps| ps[i].0 == b"string" && names_uri(&ps[i].1));
            let uri_overload = overloads.iter().any(|ps| ps[i].0 == b"Uri");
            let is_string = expression_type(m, *arg, src).as_deref() == Some(&b"string"[..]);
            if string_overload && uri_overload && is_string {
                found.push(*arg);
            }
        }
    });
    found
}

const LOCALIZED_NAMES: &[&[u8]] = &[b"text", b"message", b"caption"];

fn localizable_literals<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |literal, ancestors| {
        if !matches!(literal.kind(), "string_literal" | "verbatim_string_literal") {
            return;
        }
        // Words, not keys, codes or separators: two letters or more, and a
        // space or a capital first letter.
        let value = text(literal, src).trim_ascii_start();
        let value = value
            .strip_prefix(b"@")
            .unwrap_or(value)
            .strip_prefix(b"\"")
            .unwrap_or(value);
        let letters = value.iter().filter(|b| b.is_ascii_alphabetic()).count();
        if letters < 2
            || !(value.contains(&b' ') || value.first().is_some_and(u8::is_ascii_uppercase))
        {
            return;
        }
        let Some(parent) = ancestors.last() else {
            return;
        };
        let named_like = |name: &[u8]| {
            LOCALIZED_NAMES
                .iter()
                .any(|w| contains_ignoring_case(name, w))
        };
        let localized = match parent.kind() {
            // F(text: "...")
            "argument" => {
                parent
                    .child_by_field_name("name")
                    .is_some_and(|n| named_like(text(n, src)))
                    || ancestors.len() >= 3 && {
                        let call = ancestors[ancestors.len() - 3];
                        call.kind() == "invocation_expression"
                            && call.child_by_field_name("function").is_some_and(|f| {
                                matches!(text(f, src), b"Console.Write" | b"Console.WriteLine")
                            })
                            && cs_call_arguments(call).first() == Some(&literal)
                    }
            }
            // label.Text = "...", or Text = "..." in an initializer.
            "assignment_expression" => {
                parent.child_by_field_name("right") == Some(literal)
                    && parent
                        .child_by_field_name("left")
                        .is_some_and(|l| named_like(simple_name(l, src)))
            }
            _ => false,
        };
        if localized {
            found.push(literal);
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn class(body: &str) -> String {
        format!("namespace N;\nclass A {{\n{body}\n}}\n")
    }

    #[test]
    fn dead_stores() {
        let src = class(
            "int F(int y, bool c) {\nint x = Compute();\nx = 200;\nint z = 0;\nz = 5;\nint w = Compute();\nif (c) { w = 1; }\nint v = Load();\nv = v + 1;\nint u = Read();\nu = 3;\nUse(u);\nint t = Calc();\nt = 9;\nint s = Get();\nAction a = () => Use(s);\ns = 2;\na();\nreturn x + y + z + w + v;\n}",
        );
        assert_eq!(flagged("cs/dead-store", &src), [4, 12, 15, 16]);
    }

    #[test]
    fn disposables_and_builders() {
        let src = class(
            "string F(string p) {\nvar r1 = new StreamReader(p);\nvar r2 = new StreamReader(p);\nr2.Dispose();\nusing var r3 = new StreamReader(p);\nvar r4 = File.OpenRead(p);\nvar r5 = new StreamReader(p);\nvar r6 = new StreamReader(p);\nKeep(r6);\nvar ms = new MemoryStream();\nvar cts = new CancellationTokenSource();\nvar sb = new StringBuilder();\nsb.Append(p).Append(p);\nvar sb2 = new StringBuilder();\nsb2.Append(p);\nUse(sb2.ToString());\nvar sb3 = new StringBuilder();\nsb3.AppendLine(p);\nKeep(sb3);\nreturn r5.ReadToEnd() + r4.Length;\n}",
        );
        assert_eq!(flagged("cs/undisposed-local", &src), [4, 8, 9]);
        assert_eq!(flagged("cs/string-builder-never-read", &src), [14]);
    }

    #[test]
    fn types_and_assemblies() {
        let src = "[assembly: AssemblyTitle(\"Lib\")]\n[assembly: AssemblyProduct(\"Lib\")]\nnamespace N {\nclass C<T> { }\nclass D<T> : C<D<D<T>>> { }\nclass E<T> : C<E<T>> { }\nclass F<T> : IComparable<F<T>> { }\n}";
        assert_eq!(flagged("cs/recursive-generic-inheritance", src), [5]);
        assert_eq!(flagged("cs/assembly-version-missing", src), [1]);
        assert_eq!(flagged("cs/assembly-cls-compliant", src), [1]);
        assert_eq!(flagged("cs/assembly-com-visible", src), [1]);
        let sdk = "[assembly: InternalsVisibleTo(\"Tests\")]\nnamespace N { }";
        assert_eq!(flagged("cs/assembly-version-missing", sdk), [0usize; 0]);
    }

    #[test]
    fn opt_in_apis() {
        let src = class(
            "int Sum(List<int> xs) { var s = 0; foreach (var x in xs) { s += x; } return s; }\nint Count(List<int> xs) { xs.Add(1); return xs.Count; }\npublic int Pub(List<int> xs) => xs.Sum();\nvoid Fetch(string url) { }\nvoid Fetch(Uri url) { }\nvoid G(Label label, string u) {\nFetch(\"https://a.example\");\nFetch(u);\nlabel.Text = \"Hello there\";\nlabel.Name = \"Hello there\";\nShow(message: \"Saved your file\");\nConsole.WriteLine(\"Done with it\");\nConsole.WriteLine(\"k\");\n}",
        );
        assert_eq!(flagged("cs/parameter-could-be-enumerable", &src), [3]);
        assert_eq!(flagged("cs/string-uri-argument", &src), [9, 10]);
        assert_eq!(flagged("cs/localizable-literal", &src), [11, 13, 14]);
    }
}
