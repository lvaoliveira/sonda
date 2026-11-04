//! C# rules about values within a method and about the assembly, batch 13
//! (ADR-0007, ADR-0015): dead stores, disposables and StringBuilders that
//! are never released or read, and assembly attributes. The value rules
//! follow a local through the statements of the block that declares it,
//! without a control-flow graph (ADR-0008's S2 and S3): a statement that
//! mentions the local in any other way counts as reading it, so they only
//! report what straight-line code proves. Partial methods and the neutral
//! resources language need the whole project and live in `common.rs`.

use super::cs::simple_name;
use super::java_bugs::find_in_scope;
use super::java_security::{contains_ignoring_case, text};
use super::prelude::*;
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
        name: "IDisposables should be disposed",
        description: "A FileStream, reader, writer, socket client, WebClient or image kept in a private field or \
                      a local and never disposed holds its file handle, socket or unmanaged memory until the \
                      garbage collector finalizes it.",
        message: "Dispose of this object, with a using declaration or in Dispose.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2930")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_documented::undisposed_resources,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "using System.IO;\nclass ResourceHolder { private FileStream fs; public void OpenResource(string path) { this.fs = new FileStream(path, FileMode.Open); } }",
            good: "using System;\nusing System.IO;\nclass ResourceHolder : IDisposable { private FileStream fs; public void OpenResource(string path) { this.fs = new FileStream(path, FileMode.Open); } public void Dispose() { this.fs.Dispose(); } }",
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
        description: "A parameter whose uses only need members a base class or interface of its type declares, \
                      such as a FileStream that's only read like any Stream, could be declared with that type, \
                      which accepts more callers.",
        message: "Declare this parameter with a base type: only that type's members are used.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3242")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::parameters_with_base_types,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "using System.IO;\nclass Foo { public void ReadStream(FileStream stream) { int a; while ((a = stream.ReadByte()) != -1) { } } }",
            good: "using System.IO;\nclass Foo { public void ReadStream(Stream stream) { int a; while ((a = stream.ReadByte()) != -1) { } } }",
        }),
    },
    Rule {
        id: "cs/string-uri-argument",
        name: "System.Uri arguments should be used instead of strings",
        description: "When a method's string parameter named for a URI has an overload taking a System.Uri \
                      there, the Uri one avoids parsing and encoding errors.",
        message: "Pass a System.Uri to call the Uri overload.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4005")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::string_uri_arguments,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "using System;\nclass Foo { void FetchResource(string uriString) { } void FetchResource(Uri uri) { } void Main() { FetchResource(\"http://www.mysite.com\"); } }",
            good: "using System;\nclass Foo { void FetchResource(string uriString) { } void FetchResource(Uri uri) { } void Main() { FetchResource(new Uri(\"http://www.mysite.com\")); } }",
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
        sonar: &[exact("S4055")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::localizable_literals,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Label { public string Text { get; set; } }\nclass A { void F(Label label) { label.Text = \"Hello\"; } }",
            good: "class Label { public string Text { get; set; } }\nclass A { void F(Label label) { label.Text = Resources.Hello; } }",
        }),
    },
];

// ---------------------------------------------------- dead stores

// ---------------------------------------------------- disposables

/// What happens to a local at one of its uses.
pub(super) enum Fate {
    Released,
    Used,
}

/// Whether a use of a local disposes of it or hands it on: `x.Dispose()`,
/// `return x`, `F(x)`, `field = x`, `new T(x)`, `using (x)`.
pub(super) fn released(name: Node, src: &[u8]) -> Fate {
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

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn class(body: &str) -> String {
        format!("namespace N;\nclass A {{\n{body}\n}}\n")
    }

    #[test]
    fn disposables_and_builders() {
        let src = class(
            "string F(string p) {\nvar r1 = new StreamReader(p);\nvar r2 = new StreamReader(p);\nr2.Dispose();\nusing var r3 = new StreamReader(p);\nvar r4 = File.OpenRead(p);\nvar r5 = new StreamReader(p);\nvar r6 = new StreamReader(p);\nKeep(r6);\nvar ms = new MemoryStream();\nvar cts = new CancellationTokenSource();\nvar sb = new StringBuilder();\nsb.Append(p).Append(p);\nvar sb2 = new StringBuilder();\nsb2.Append(p);\nUse(sb2.ToString());\nvar sb3 = new StringBuilder();\nsb3.AppendLine(p);\nKeep(sb3);\nreturn r5.ReadToEnd() + r4.Length;\n}",
        );
        // File.OpenRead isn't among the documented factories.
        assert_eq!(flagged("cs/undisposed-local", &src), [4, 9]);
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
        // Add and Count are ICollection<int>'s, and Sum IEnumerable<int>'s.
        assert_eq!(flagged("cs/parameter-could-be-enumerable", &src), [3, 4, 5]);
        assert_eq!(flagged("cs/string-uri-argument", &src), [9, 10]);
        // Label and Show aren't declared; one letter is text too, as the
        // documentation leaves out none.
        assert_eq!(flagged("cs/localizable-literal", &src), [14, 15]);
    }
}
