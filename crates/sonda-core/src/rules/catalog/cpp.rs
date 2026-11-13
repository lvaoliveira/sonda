//! C++ rules, compared with SonarCloud's analyses of C++ projects (SonarQube
//! 26.7 here has no C/C++ analyzer to measure on): each one's conditions and
//! position are inferred from what SonarCloud reported, and not.

use super::java_security::text;
use super::prelude::*;

/// Off: SonarCloud reports about a third of what this finds, and nothing
/// visible tells its reports from the rest (an else, nesting, use in the
/// body); C++ can't be measured on SonarQube 26.7.
pub(super) static OFF_BY_DEFAULT: &[&str] = &["cpp/init-statement"];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "cpp/inline-constexpr",
        name: "constexpr functions should not be declared inline",
        description: "A constexpr function is implicitly inline; saying it again is noise.",
        message: "Remove the \"inline\" specifier; \"constexpr\" implies it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S5408")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(function_definition) (declaration declarator: (function_declarator)) (field_declaration declarator: (function_declarator))] @match",
            filter: Some(Keep(inline_and_constexpr)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "inline constexpr int twice(int x) { return 2 * x; }",
            good: "constexpr int twice(int x) { return 2 * x; }",
        }),
    },
    Rule {
        id: "cpp/redundant-virtual",
        name: "virtual should not be repeated on overrides",
        description: "A function marked override or final is virtual already.",
        message: "Drop the \"virtual\" specifier; \"override\" says it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3471")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(function_definition) (field_declaration declarator: (function_declarator)) (declaration declarator: (function_declarator))] @match",
            filter: Some(Keep(virtual_override)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "struct B { virtual void f(); };\nstruct D : B { virtual void f() override; };",
            good: "struct B { virtual void f(); };\nstruct D : B { void f() override; };",
        }),
    },
    Rule {
        id: "cpp/unscoped-enum",
        name: "Scoped enumerations should be preferred",
        description: "An unscoped enum's names leak into the enclosing scope and convert to int silently.",
        message: "Replace this \"enum\" with \"enum class\".",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3642")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(enum_specifier body: (enumerator_list)) @match",
            filter: Some(Keep(unscoped_enum)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "enum Color { kRed, kGreen };",
            good: "enum class Color { kRed, kGreen };",
        }),
    },
    Rule {
        id: "cpp/typedef",
        name: "using should be preferred to typedef",
        description: "`using A = B;` reads left to right and works for templates; typedef does neither.",
        message: "Replace this \"typedef\" with a \"using\" alias.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5416")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(type_definition) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "typedef unsigned char byte_t;",
            good: "using byte_t = unsigned char;",
        }),
    },
    Rule {
        id: "cpp/deprecated-code",
        name: "Deprecated code should be removed",
        description: "Code marked [[deprecated]] is meant to go; this is a reminder that it hasn't.",
        message: "Remove this deprecated code once nothing uses it.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 10,
        sonar: &[exact("S1133")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(declaration (attribute_declaration)) (field_declaration (attribute_declaration)) (function_definition (attribute_declaration))] @match",
            filter: Some(Find(deprecated_declarator)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "[[deprecated(\"use g\")]] void f();",
            good: "void g();",
        }),
    },
    Rule {
        id: "cpp/nested-conditional",
        name: "Conditional operators should not be nested",
        description: "Nested ?: expressions are hard to read; an if or a separate variable says it better.",
        message: "Extract this nested conditional operator into an independent statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3358")],
        check: Check::Query {
            langs: C_CPP,
            query: "(conditional_expression) @match",
            filter: Some(FindAll(nested_conditionals)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "int f(int a) { return a < 0 ? -1 : a > 0 ? 1 : 0; }",
            good: "int f(int a) { if (a < 0) { return -1; } return a > 0 ? 1 : 0; }",
        }),
    },
    Rule {
        id: "cpp/implicit-constructor",
        name: "Single-argument constructors should be explicit",
        description: "A constructor taking one argument converts that argument to the class silently.",
        message: "Add the \"explicit\" keyword to this constructor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1709")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(function_definition) (declaration) (field_declaration)] @match",
            filter: Some(Keep(implicit_converting_constructor)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "class Meters { public: Meters(double v) : v_(v) {} private: double v_; };",
            good: "class Meters { public: explicit Meters(double v) : v_(v) {} private: double v_; };",
        }),
    },
    Rule {
        id: "cpp/default-special-member",
        name: "=default should be used for trivial special member functions",
        description: "An empty constructor or destructor written out does what `= default` says.",
        message: "Use \"=default\" instead of this empty implementation.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3490")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(function_definition body: (compound_statement)) @match",
            filter: Some(Keep(trivial_special_member)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "class A { public: A() {} virtual ~A() {} };",
            good: "class A { public: A() = default; virtual ~A() = default; };",
        }),
    },
    Rule {
        id: "cpp/empty-function",
        name: "Functions should not be empty",
        description: "An empty function leaves readers guessing whether something is missing; a comment \
                      inside says it's on purpose.",
        message: "Add a nested comment explaining why this function is empty, or complete it.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1186")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(function_definition body: (compound_statement)) @match",
            filter: Some(Keep(empty_non_special_function)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "struct A { virtual void begin() {} };",
            good: "struct A { virtual void begin() { /* nothing to set up */ } };",
        }),
    },
    Rule {
        id: "cpp/one-declaration-per-statement",
        name: "Each identifier should be declared in its own statement",
        description: "`int* a, b;` makes only a a pointer; one declaration per statement avoids the trap.",
        message: "Define each identifier in a dedicated statement.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1659")],
        check: Check::Query {
            langs: C_CPP,
            query: "[(declaration) (field_declaration)] @match",
            filter: Some(Keep(declares_several)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f() { int a = 1, b = 2; }",
            good: "void f() { int a = 1; int b = 2; }",
        }),
    },
    Rule {
        id: "cpp/mergeable-if",
        name: "Collapsible if statements should be merged",
        description: "An if holding only another if, neither with an else, is one condition with &&.",
        message: "Merge this \"if\" statement with the enclosing one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1066")],
        check: Check::Query {
            langs: C_CPP,
            query: "(if_statement) @match",
            filter: Some(Find(mergeable_inner_if)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f(int a, int b) { if (a) { if (b) { g(); } } }",
            good: "void f(int a, int b) { if (a && b) { g(); } }",
        }),
    },
    Rule {
        id: "cpp/nesting-depth",
        name: "Control flow statements should not be nested too deeply",
        description: "if, for, while, do and switch nested more than three deep hide the main path.",
        message: "Refactor this code to not nest more than 3 if, for, do, while or switch statements.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S134")],
        check: Check::Query {
            langs: C_CPP,
            // A range-for at the fourth level isn't matched (the query is C's
            // too); it counts as a level around others.
            query: "[(if_statement) (for_statement) (while_statement) (do_statement) (switch_statement)] @match",
            filter: Some(Keep(nested_too_deeply)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f(int a) { if (a) { for (;;) { while (a) { if (a > 2) { g(); } } } } }",
            good: "void f(int a) { if (a) { g(); } }",
        }),
    },
    Rule {
        id: "cpp/assignment-in-expression",
        name: "Assignments should not be made from within expressions",
        description: "An assignment inside another expression, `a = b = c` or `f(x = 1)`, is easy to misread.",
        message: "Extract the assignment from this expression.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1121")],
        check: Check::Query {
            langs: C_CPP,
            query: "(assignment_expression) @match",
            filter: Some(Keep(assignment_in_expression)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f(int* a) { a[0] = a[1] = 0; }",
            good: "void f(int* a) { a[1] = 0; a[0] = 0; }",
        }),
    },
    Rule {
        id: "cpp/redundant-static",
        name: "Redundant static specifiers should be removed",
        description: "A constexpr variable at namespace scope, and anything in an unnamed namespace, already \
                      has internal linkage.",
        message: "Remove the redundant \"static\" specifier.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3609")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(declaration) (function_definition)] @match",
            filter: Some(Keep(redundant_static)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "static constexpr int kSize = 6;",
            good: "constexpr int kSize = 6;",
        }),
    },
    Rule {
        id: "cpp/make-unique",
        name: "std::make_unique should be used to construct std::unique_ptr",
        description: "make_unique says the type once and can't leak if another argument throws.",
        message: "Use \"std::make_unique\" to construct \"std::unique_ptr\".",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5950")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(call_expression arguments: (argument_list . (new_expression))) @match",
            filter: Some(Keep(unique_ptr_from_new)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "auto p = std::unique_ptr<Widget>(new Widget(1));",
            good: "auto p = std::make_unique<Widget>(1);",
        }),
    },
    Rule {
        id: "cpp/init-statement",
        name: "Variables used only by an if or switch should be declared in its init-statement",
        description: "`if (auto x = f(); x > 0)` keeps x's scope to the statement that uses it.",
        message: "Use the init-statement to declare this variable inside the statement.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6004")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(if_statement) (switch_statement)] @match",
            filter: Some(Keep(could_use_init_statement)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "int f() { int x = g(); if (x > 0) { return x; } return 0; }",
            good: "int f() { if (int x = g(); x > 0) { return x; } return 0; }",
        }),
    },
    Rule {
        id: "cpp/c-style-array",
        name: "C-style arrays should not be used",
        description: "std::array and std::vector know their size and don't decay to pointers.",
        message: "Replace this C-style array with \"std::array\" (fixed size) or \"std::vector\".",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S5945")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(declaration) (field_declaration)] @match",
            filter: Some(Keep(declares_c_array)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f() { int buf[16]; g(buf); }",
            good: "void f() { std::array<int, 16> buf; g(buf.data()); }",
        }),
    },
    Rule {
        id: "cpp/redundant-type",
        name: "auto should be used when the type is written on the right",
        description: "A cast or a `new` already names the type; repeating it on the left is noise.",
        message: "Replace the redundant type with \"auto\".",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S5827")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(declaration declarator: (init_declarator)) @match",
            filter: Some(Keep(type_repeated_on_the_right)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f(const void* p) { const char* c = static_cast<const char*>(p); }",
            good: "void f(const void* p) { const auto* c = static_cast<const char*>(p); }",
        }),
    },
    Rule {
        id: "cpp/mutable-global",
        name: "Global variables should be const",
        description: "A mutable global can change from anywhere, which makes code hard to reason about and \
                      to use from several threads.",
        message: "Make this global variable const.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5421")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(translation_unit (declaration) @match) (namespace_definition body: (declaration_list (declaration) @match))]",
            filter: Some(Find(mutable_global)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "static int counter = 0;",
            good: "static const int kLimit = 10;",
        }),
    },
];

/// Its direct children's texts: specifiers and qualifiers.
fn has_word(node: Node, word: &[u8], src: &[u8]) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| {
        matches!(
            c.kind(),
            "storage_class_specifier"
                | "type_qualifier"
                | "virtual"
                | "explicit_function_specifier"
        ) && text(c, src) == word
            || c.kind() == word_kind(word)
    })
}

fn word_kind(word: &[u8]) -> &'static str {
    match word {
        b"virtual" => "virtual",
        b"inline" => "inline",
        _ => "",
    }
}

fn inline_and_constexpr(node: Node, src: &[u8]) -> bool {
    has_word(node, b"inline", src) && has_word(node, b"constexpr", src)
}

/// The function declarator of a definition or declaration.
fn function_declarator(node: Node) -> Option<Node> {
    let mut d = node.child_by_field_name("declarator")?;
    for _ in 0..8 {
        if d.kind() == "function_declarator" {
            return Some(d);
        }
        // Through `&` and `*` declarators, whose inner one isn't a field.
        d = d.child_by_field_name("declarator").or_else(|| {
            matches!(d.kind(), "reference_declarator" | "pointer_declarator")
                .then(|| d.named_children(&mut d.walk()).last())
                .flatten()
        })?;
    }
    None
}

fn virtual_override(node: Node, src: &[u8]) -> bool {
    has_word(node, b"virtual", src)
        && function_declarator(node).is_some_and(|d| {
            let mut cursor = d.walk();
            d.named_children(&mut cursor).any(|c| {
                c.kind() == "virtual_specifier" && matches!(text(c, src), b"override" | b"final")
            })
        })
}

fn unscoped_enum(node: Node, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    !node
        .children(&mut cursor)
        .any(|c| matches!(text(c, src), b"class" | b"struct"))
}

fn deprecated_declarator<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    let deprecated = node.named_children(&mut cursor).any(|c| {
        c.kind() == "attribute_declaration" && text(c, src).windows(10).any(|w| w == b"deprecated")
    });
    deprecated.then(|| node.child_by_field_name("declarator"))?
}

/// Each conditional nested in this one, with none between them; not in a
/// lambda.
fn nested_conditionals<'t>(node: Node<'t>, _: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    let mut stack: Vec<Node<'t>> = node.named_children(&mut node.walk()).collect();
    while let Some(n) = stack.pop() {
        match n.kind() {
            "conditional_expression" => found.push(n),
            "lambda_expression" => {}
            _ => stack.extend(n.named_children(&mut n.walk())),
        }
    }
    found
}

/// The class a member declaration is in, and its name.
fn enclosing_class<'s>(node: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    // Through a member template's `template <...>`.
    let mut member = node;
    while let Some(p) = member
        .parent()
        .filter(|p| p.kind() == "template_declaration")
    {
        member = p;
    }
    let list = member
        .parent()
        .filter(|p| p.kind() == "field_declaration_list")?;
    let class = list.parent()?;
    // `class A<int>`, a specialization, is A's.
    matches!(class.kind(), "class_specifier" | "struct_specifier")
        .then(|| class.child_by_field_name("name"))
        .flatten()
        .map(|n| {
            let t = text(n, src);
            t.split(|b| *b == b'<').next().unwrap_or(t)
        })
}

/// The name a declarator declares, its last identifier.
fn declared_name<'s>(declarator: Node, src: &'s [u8]) -> &'s [u8] {
    let t = text(declarator, src);
    let t = t.split(|b| *b == b'<').next().unwrap_or(t);
    t.rsplit(|b| *b == b':').next().unwrap_or(t)
}

/// A constructor of `class` (its declarator names the class), in the class
/// or defined outside it as `C::C(...)`.
fn constructor_of<'t>(node: Node<'t>, src: &[u8]) -> Option<(Node<'t>, Vec<Node<'t>>)> {
    let d = function_declarator(node)?;
    let name = d.child_by_field_name("declarator")?;
    let n = text(name, src);
    let class = match enclosing_class(node, src) {
        Some(c) => c,
        None => {
            // `C::C(...)` outside the class.
            let mut parts = n.rsplitn(2, |b| *b == b':');
            let last = parts.next()?;
            let scope = parts.next()?.strip_suffix(b":")?;
            let scope = scope.rsplit(|b| *b == b':').next().unwrap_or(scope);
            if last != scope {
                return None;
            }
            scope
        }
    };
    if declared_name(name, src) != class || n.starts_with(b"~") {
        return None;
    }
    let params = d.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let list: Vec<Node> = params
        .named_children(&mut cursor)
        .filter(|p| {
            matches!(
                p.kind(),
                "parameter_declaration"
                    | "optional_parameter_declaration"
                    | "variadic_parameter_declaration"
            )
        })
        .collect();
    Some((node, list))
}

fn implicit_converting_constructor(node: Node, src: &[u8]) -> bool {
    if has_word(node, b"explicit", src) || {
        let mut c = node.walk();
        node.children(&mut c)
            .any(|x| x.kind() == "explicit_function_specifier")
    } {
        return false;
    }
    // In the class: a definition outside it, `C::C(...)`, isn't reported
    // again (as SonarCloud reports it).
    if enclosing_class(node, src).is_none() {
        return false;
    }
    let Some((_, params)) = constructor_of(node, src) else {
        return false;
    };
    let Some(first) = params.first() else {
        return false;
    };
    // One argument: one parameter, or the others defaulted.
    let callable_with_one = params
        .iter()
        .skip(1)
        .all(|p| p.kind() == "optional_parameter_declaration");
    // Not a copy or move constructor, nor one taking an initializer list.
    let class = enclosing_class(node, src)
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| {
            function_declarator(node)
                .and_then(|d| d.child_by_field_name("declarator"))
                .map(|n| declared_name(n, src).to_vec())
                .unwrap_or_default()
        });
    let ty = first
        .child_by_field_name("type")
        .map_or(&b""[..], |t| text(t, src));
    let simple = ty.split(|b| *b == b'<').next().unwrap_or(ty);
    let simple = simple.rsplit(|b| *b == b':').next().unwrap_or(simple);
    let copy_or_move = simple == class.as_slice();
    let init_list = ty.windows(16).any(|w| w == b"initializer_list");
    callable_with_one
        && first.kind() != "variadic_parameter_declaration"
        && !copy_or_move
        && !init_list
}

fn empty_body(function: Node) -> bool {
    function
        .child_by_field_name("body")
        .is_some_and(|b| b.kind() == "compound_statement" && b.named_child_count() == 0)
}

fn is_special_member(function: Node, src: &[u8]) -> bool {
    let Some(name) =
        function_declarator(function).and_then(|d| d.child_by_field_name("declarator"))
    else {
        return false;
    };
    let n = declared_name(name, src);
    n.starts_with(b"~")
        || text(name, src).contains(&b'~')
        || constructor_of(function, src).is_some()
        || names_a_class_in_the_file(function, n, src)
}

/// Whether a class or struct of this name is declared in the file: a
/// constructor, when a macro kept the parser from seeing the class around it.
fn names_a_class_in_the_file(node: Node, name: &[u8], src: &[u8]) -> bool {
    let mut root = node;
    while let Some(p) = root.parent() {
        root = p;
    }
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "class_specifier" | "struct_specifier")
            && n.child_by_field_name("name").is_some_and(|x| {
                let t = text(x, src);
                t.split(|b| *b == b'<').next() == Some(name)
            })
        {
            return true;
        }
        stack.extend(n.named_children(&mut n.walk()));
    }
    false
}

/// An empty default constructor without an initializer list, or an empty
/// destructor.
fn trivial_special_member(function: Node, src: &[u8]) -> bool {
    if !empty_body(function) {
        return false;
    }
    let mut cursor = function.walk();
    if function
        .children(&mut cursor)
        .any(|c| c.kind() == "field_initializer_list")
    {
        return false;
    }
    let Some(name) =
        function_declarator(function).and_then(|d| d.child_by_field_name("declarator"))
    else {
        return false;
    };
    let destructor = text(name, src).contains(&b'~');
    destructor || constructor_of(function, src).is_some_and(|(_, params)| params.is_empty())
}

fn empty_non_special_function(function: Node, src: &[u8]) -> bool {
    empty_body(function) && !is_special_member(function, src)
}

fn declares_several(node: Node, src: &[u8]) -> bool {
    // Not a for loop's header, nor what the parser recovered from a macro
    // (zlib's `OF((...))`), nor inside a macro's arguments.
    if node.parent().is_some_and(|p| p.kind() == "for_statement")
        || node.has_error()
        || in_macro_arguments(node, src)
    {
        return false;
    }
    let mut cursor = node.walk();
    let declarators = node
        .children_by_field_name("declarator", &mut cursor)
        .filter(|d| d.kind() != "function_declarator")
        .count();
    declarators > 1
}

/// The if alone in an else-less if's body, itself without an else.
fn mergeable_inner_if<'t>(outer: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Not one declaring a variable in its condition (`if (auto t = f())`),
    // nor an `if constexpr`: neither merges with &&.
    let declares = |n: Node| {
        n.child_by_field_name("condition").is_some_and(|c| {
            c.child_by_field_name("initializer").is_some()
                || c.child_by_field_name("value")
                    .is_some_and(|v| v.kind() == "declaration")
        })
    };
    let constexpr = |n: Node| {
        let mut cursor = n.walk();
        n.children(&mut cursor)
            .any(|c| text(c, src) == b"constexpr")
    };
    if outer.child_by_field_name("alternative").is_some() || declares(outer) || constexpr(outer) {
        return None;
    }
    let body = outer.child_by_field_name("consequence")?;
    let inner = if body.kind() == "compound_statement" {
        let mut cursor = body.walk();
        let statements: Vec<Node> = body
            .named_children(&mut cursor)
            .filter(|c| c.kind() != "comment")
            .collect();
        match statements.as_slice() {
            [only] => *only,
            _ => return None,
        }
    } else {
        body
    };
    (inner.kind() == "if_statement"
        && inner.child_by_field_name("alternative").is_none()
        && !declares(inner)
        && !constexpr(inner))
    .then_some(inner)
}

/// The fourth level of nesting: three control statements around it in its
/// function, an else-if counting as its if.
fn nested_too_deeply(statement: Node, _: &[u8]) -> bool {
    const CONTROL: &[&str] = &[
        "if_statement",
        "for_statement",
        "for_range_loop",
        "while_statement",
        "do_statement",
        "switch_statement",
    ];
    let else_if = |n: Node| {
        n.kind() == "if_statement" && n.parent().is_some_and(|e| e.kind() == "else_clause")
    };
    if else_if(statement) {
        return false;
    }
    let mut depth = 0;
    let mut current = statement.parent();
    while let Some(n) = current {
        if matches!(n.kind(), "function_definition" | "lambda_expression") {
            break;
        }
        if CONTROL.contains(&n.kind()) && !else_if(n) {
            depth += 1;
        }
        current = n.parent();
    }
    depth == 3
}

fn assignment_in_expression(assignment: Node, _: &[u8]) -> bool {
    // A default parameter, `T x = nullptr`, read as an assignment; or what
    // the parser recovered from an error.
    let mut up = assignment.parent();
    while let Some(n) = up {
        if n.kind() == "parameter_list"
            || n.is_error()
            || n.has_error() && n.kind() == "declaration"
        {
            return false;
        }
        if n.kind() == "function_definition" {
            break;
        }
        up = n.parent();
    }
    let mut parent = assignment.parent();
    while let Some(p) = parent.filter(|p| p.kind() == "parenthesized_expression") {
        parent = p.parent();
    }
    let Some(parent) = parent else {
        return false;
    };
    match parent.kind() {
        "expression_statement" | "comma_expression" | "for_statement" | "condition_clause" => false,
        // `while ((c = next()) != end)` and the like are left alone.
        "binary_expression" => !parent
            .parent()
            .is_some_and(|g| matches!(g.kind(), "condition_clause" | "parenthesized_expression")),
        _ => true,
    }
}

/// `static` on a namespace-scope constexpr variable, or inside an unnamed
/// namespace.
fn redundant_static(node: Node, src: &[u8]) -> bool {
    if !has_word(node, b"static", src) {
        return false;
    }
    let scope = node.parent();
    let unnamed_namespace = scope
        .filter(|l| l.kind() == "declaration_list")
        .and_then(|l| l.parent())
        .is_some_and(|ns| {
            ns.kind() == "namespace_definition" && ns.child_by_field_name("name").is_none()
        });
    if unnamed_namespace {
        return true;
    }
    let namespace_scope = scope.is_some_and(|s| {
        s.kind() == "translation_unit"
            || s.kind() == "declaration_list"
                && s.parent()
                    .is_some_and(|ns| ns.kind() == "namespace_definition")
    });
    // constexpr, which SonarCloud reports; not plain const (its namespace
    // tables of `static const` data aren't).
    let constant = has_word(node, b"constexpr", src)
        && node.kind() == "declaration"
        && function_declarator(node).is_none();
    namespace_scope && constant
}

/// `std::unique_ptr<T>(new U(...))`.
fn unique_ptr_from_new(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("function").is_some_and(|f| {
        let t = text(f, src);
        let base = t.split(|b| *b == b'<').next().unwrap_or(t);
        matches!(base, b"std::unique_ptr" | b"unique_ptr")
    })
}

/// A declaration of one variable right before the if or switch, used in
/// its condition and nowhere after the statement.
fn could_use_init_statement(statement: Node, src: &[u8]) -> bool {
    let Some(condition) = statement.child_by_field_name("condition") else {
        return false;
    };
    if condition.child_by_field_name("initializer").is_some() {
        return false;
    }
    // An else-if's own condition can't take one.
    if statement
        .parent()
        .is_some_and(|p| p.kind() == "else_clause")
    {
        return false;
    }
    let Some(previous) = statement
        .prev_named_sibling()
        .filter(|p| p.kind() == "declaration")
    else {
        return false;
    };
    let mut cursor = previous.walk();
    let declarators: Vec<Node> = previous
        .children_by_field_name("declarator", &mut cursor)
        .collect();
    let [declarator] = declarators.as_slice() else {
        return false;
    };
    if has_word(previous, b"static", src) {
        return false;
    }
    let name_node = declarator
        .child_by_field_name("declarator")
        .unwrap_or(*declarator);
    let raw = text(name_node, src).trim_ascii();
    let skip = raw
        .iter()
        .take_while(|b| matches!(b, b'*' | b'&' | b' '))
        .count();
    let name = raw[skip..].trim_ascii();
    if name.is_empty() || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_') {
        return false;
    }
    let mentions = |n: Node| {
        let t = text(n, src);
        t.windows(name.len()).enumerate().any(|(i, w)| {
            w == name
                && !t
                    .get(i.wrapping_sub(1))
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                && !t
                    .get(i + name.len())
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        })
    };
    if !mentions(condition) {
        return false;
    }
    let mut next = statement.next_named_sibling();
    while let Some(n) = next {
        if mentions(n) {
            return false;
        }
        next = n.next_named_sibling();
    }
    true
}

/// A variable or member declared as a C-style array, of pointers too, or a
/// `std::unique_ptr<T[]>`: not `extern`, not a character array spelled as a
/// string, not inside a macro's arguments (as SonarCloud reports them).
fn declares_c_array(node: Node, src: &[u8]) -> bool {
    if has_word(node, b"extern", src) || in_macro_arguments(node, src) {
        return false;
    }
    if node
        .child_by_field_name("type")
        .is_some_and(|t| text(t, src).windows(3).any(|w| w == b"[]>"))
    {
        return true;
    }
    let mut cursor = node.walk();
    let declarators: Vec<Node> = node
        .children_by_field_name("declarator", &mut cursor)
        .collect();
    declarators.iter().any(|d| {
        let (inner, value) = if d.kind() == "init_declarator" {
            (
                d.child_by_field_name("declarator"),
                d.child_by_field_name("value"),
            )
        } else {
            (Some(*d), None)
        };
        let spelled_as_string = value.is_some_and(|v| {
            matches!(
                v.kind(),
                "string_literal" | "concatenated_string" | "raw_string_literal"
            )
        });
        !spelled_as_string && inner.is_some_and(declares_array)
    })
}

/// Whether a declarator is an array's, through pointer declarators
/// (`const char* names[]`), not a function's parameters.
fn declares_array(declarator: Node) -> bool {
    let mut d = declarator;
    for _ in 0..8 {
        match d.kind() {
            "array_declarator" => return true,
            "pointer_declarator" | "reference_declarator" | "parenthesized_declarator" => {
                match d
                    .child_by_field_name("declarator")
                    .or_else(|| d.named_children(&mut d.walk()).last())
                {
                    Some(inner) => d = inner,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
    false
}

/// Whether a node is inside an all-capitals macro's arguments, `TEST(...)`
/// aside: code a macro expands, which SonarCloud doesn't report.
fn in_macro_arguments(node: Node, src: &[u8]) -> bool {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "argument_list"
            && let Some(f) = n
                .parent()
                .filter(|c| c.kind() == "call_expression")
                .and_then(|c| c.child_by_field_name("function"))
            && f.kind() == "identifier"
        {
            let name = text(f, src);
            if name.len() > 1
                && name
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || *b == b'_' || b.is_ascii_digit())
            {
                return true;
            }
        }
        if n.kind() == "function_definition" {
            return false;
        }
        current = n.parent();
    }
    false
}

/// `T x = static_cast<T>(...)`, `T* p = (T*)q`, `T* p = new T`: the type is
/// on the right already.
fn type_repeated_on_the_right(declaration: Node, src: &[u8]) -> bool {
    let Some(init) = declaration.child_by_field_name("declarator") else {
        return false;
    };
    let (Some(declarator), Some(value)) = (
        init.child_by_field_name("declarator"),
        init.child_by_field_name("value"),
    ) else {
        return false;
    };
    let Some(ty) = declaration.child_by_field_name("type") else {
        return false;
    };
    if text(ty, src) == b"auto" {
        return false;
    }
    // The declared type with its qualifiers and pointer marks, spaces left
    // out: `const uint32_t*`.
    let mut declared: Vec<u8> = Vec::new();
    let mut cursor = declaration.walk();
    for c in declaration.children(&mut cursor) {
        if c.kind() == "type_qualifier" && text(c, src) == b"const" {
            declared.extend_from_slice(b"const");
        }
    }
    declared.extend(text(ty, src).iter().filter(|b| !b.is_ascii_whitespace()));
    let marks = text(declarator, src)
        .iter()
        .take_while(|b| matches!(b, b'*' | b'&' | b' '))
        .filter(|b| !b.is_ascii_whitespace())
        .copied()
        .collect::<Vec<u8>>();
    declared.extend(&marks);
    let squeeze = |t: &[u8]| -> Vec<u8> {
        t.iter()
            .filter(|b| !b.is_ascii_whitespace())
            .copied()
            .collect()
    };
    match value.kind() {
        "cast_expression" => value
            .child_by_field_name("type")
            .is_some_and(|t| squeeze(text(t, src)) == declared),
        "call_expression" => value.child_by_field_name("function").is_some_and(|f| {
            let t = text(f, src);
            [
                "static_cast<",
                "reinterpret_cast<",
                "dynamic_cast<",
                "const_cast<",
            ]
            .iter()
            .any(|c| t.starts_with(c.as_bytes()))
                && t.iter()
                    .position(|b| *b == b'<')
                    .map(|i| squeeze(&t[i + 1..t.len().saturating_sub(1)]))
                    == Some(declared.clone())
        }),
        "new_expression" => {
            marks == b"*"
                && value
                    .child_by_field_name("type")
                    .is_some_and(|t| squeeze(text(t, src)) == squeeze(text(ty, src)))
                && value.child_by_field_name("declarator").is_none()
        }
        _ => false,
    }
}

/// A namespace-scope variable that isn't const, or a pointer that isn't
/// const at every level.
fn mutable_global<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // `extern` ones too (as SonarCloud reports them); not a function, nor
    // what the parser recovered from an error (a macro it can't expand).
    if function_declarator(declaration).is_some() || declaration.has_error() {
        return None;
    }
    let constant = has_word(declaration, b"const", src) || has_word(declaration, b"constexpr", src);
    let mut cursor = declaration.walk();
    let declarators: Vec<Node<'t>> = declaration
        .children_by_field_name("declarator", &mut cursor)
        .collect();
    declarators.into_iter().find_map(|d| {
        let inner = if d.kind() == "init_declarator" {
            d.child_by_field_name("declarator")?
        } else {
            d
        };
        if matches!(inner.kind(), "function_declarator") {
            return None;
        }
        // `const char* p`: the pointer itself can still change.
        let pointer = inner.kind() == "pointer_declarator";
        let pointer_const = pointer && text(inner, src).windows(5).any(|w| w == b"const");
        let mutable = !constant || (pointer && !pointer_const);
        mutable.then_some(inner)
    })
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged_in(rule: &str, lang: Lang, src: &str) -> Vec<usize> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let path = if lang == Lang::C { "t.c" } else { "t.cpp" };
        analyze(path, lang, src, &rules, &cfg, deadline)
            .unwrap()
            .issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        flagged_in(rule, Lang::Cpp, src)
    }

    /// Shapes inferred from SonarCloud's analyses of qutepart-cpp and
    /// roo_display.
    #[test]
    fn shapes_from_sonarcloud() {
        let classes = "class A {\n public:\n  A() {}\n  A(int x) : x_(x) {}\n  A(const A& o) = default;\n  virtual ~A() {}\n  virtual void f() override;\n  virtual void g() {}\n  void h() { /* nothing */ }\n  template <typename... Args>\n  A(Args&&... args) : x_(0) {}\n private:\n  int x_, y_;\n};\nA::A(double d) : x_(1) {}";
        assert_eq!(flagged("cpp/implicit-constructor", classes), [4]);
        assert_eq!(flagged("cpp/default-special-member", classes), [3, 6]);
        assert_eq!(flagged("cpp/empty-function", classes), [8]);
        assert_eq!(flagged("cpp/redundant-virtual", classes), [7]);
        assert_eq!(flagged("cpp/one-declaration-per-statement", classes), [13]);
        let arrays = "void f() {\n  int buf[16];\n  const char* names[] = {\"a\", \"b\"};\n  static const char mask[] = \"x\" \"y\";\n  std::unique_ptr<int[]> p;\n  EXPECT_DEATH({ int x[] = {1}; }, \"x\");\n}";
        assert_eq!(flagged("cpp/c-style-array", arrays), [2, 3, 5]);
        let ifs = "void f(Theme* t, int a, int b) {\n  if (a) {\n    if (b) {\n      g();\n    }\n  }\n  if (auto theme = t) {\n    if (b) {\n      g();\n    }\n  }\n}";
        assert_eq!(flagged("cpp/mergeable-if", ifs), [3]);
        let globals = "static int counter = 0;\nstatic const char* name = \"x\";\nstatic const char* const fixed = \"y\";\nextern int other;\nconstexpr int kMax = 3;\nstatic constexpr int kSize = 6;\nint twice(int x);";
        assert_eq!(flagged("cpp/mutable-global", globals), [1, 2, 4]);
        assert_eq!(flagged("cpp/redundant-static", globals), [6]);
        let misc = "inline constexpr int twice(int x) { return 2 * x; }\ntypedef unsigned char byte_t;\nenum Color { kRed };\nenum class Mode { kA };\nvoid f(int* a, const void* p) {\n  a[0] = a[1] = 0;\n  const char* c = static_cast<const char*>(p);\n  auto q = std::unique_ptr<int>(new int(1));\n}\nvoid g(int x = 0);";
        assert_eq!(flagged("cpp/inline-constexpr", misc), [1]);
        assert_eq!(flagged("cpp/typedef", misc), [2]);
        assert_eq!(flagged("cpp/unscoped-enum", misc), [3]);
        assert_eq!(flagged("cpp/assignment-in-expression", misc), [6]);
        assert_eq!(flagged("cpp/redundant-type", misc), [7]);
        assert_eq!(flagged("cpp/make-unique", misc), [8]);
        let nesting = "void f(int a) {\n  if (a) {\n    for (;;) {\n      while (a) {\n        if (a > 2) {\n          g();\n        } else if (a > 3) {\n          h();\n        }\n      }\n    }\n  }\n}";
        assert_eq!(flagged("cpp/nesting-depth", nesting), [5]);
        assert_eq!(flagged_in("cpp/nesting-depth", Lang::C, nesting), [5]);
    }

    /// Commented-out code, TODOs, cognitive complexity and parameters in C
    /// and C++, as SonarCloud reports them.
    #[test]
    fn shared_rules_in_cpp() {
        let comments = "// Sample script:\n// int x = 1;\n// f(x);\nint a;\n// plain prose here\nint a2;\n// #endif\nint b;\n/* longhand:\n   x = y;\n*/\nint c; // }";
        // One issue per block, at its first line; a directive or a lone
        // brace is code.
        assert_eq!(
            flagged("common/commented-out-code", comments),
            [1, 7, 9, 12]
        );
        let todos = "/*\n * Search for x.\n * TODO currently not.\n */\nint a; // Fixme: later\n// todo: maybe";
        assert_eq!(flagged("common/todo-comment", todos), [1, 5, 6]);
        // 25 is C and C++'s threshold; a lambda counts in its function.
        let mut deep = String::from("void f(int a) {\n  auto l = [&]() {\n");
        for _ in 0..12 {
            deep.push_str("    if (a) { g(); } else { h(); }\n");
        }
        deep.push_str("  };\n}\n");
        assert_eq!(flagged("common/cognitive-complexity", &deep), [1]);
        let tests = "TEST(Suite, Name) {\n".to_string()
            + &"  if (a) { if (b) { if (c) { g(); } } }\n".repeat(5)
            + "}\n";
        assert!(flagged("common/cognitive-complexity", &tests).is_empty());
        let params = "struct B { virtual void f(int, int, int, int, int, int, int, int); };\nstruct D : B { void f(int a, int b, int c, int d, int e, int f, int g, int h) override {} };\nvoid g(int a, int b, int c, int d, int e, int f, int g, int h) {}";
        assert_eq!(flagged("common/too-many-parameters", params), [3]);
    }
}
