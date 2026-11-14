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
    Rule {
        id: "cpp/initializer-list-constant",
        name: "Members initialized to a constant should use an in-class initializer",
        description: "A member every constructor sets to the same constant reads better, and can't be \
                      forgotten, as `int count_ = 0;` in the class.",
        message: "Initialize this member in the class instead of in the constructor's initializer list.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3230")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(field_initializer) @match",
            filter: Some(Keep(initializes_to_a_constant)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "class A { public: A(int x) : x_(x), count_(0) {} private: int x_; int count_; };",
            good: "class A { public: explicit A(int x) : x_(x) {} private: int x_; int count_ = 0; };",
        }),
    },
    Rule {
        id: "cpp/unused-parameter",
        name: "Unused function parameters should be removed",
        description: "A parameter the body never reads misleads callers; leave it unnamed, or mark it \
                      [[maybe_unused]], when a signature needs it.",
        message: "Remove this unused parameter, make it unnamed, or declare it [[maybe_unused]].",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1172")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(function_definition) (lambda_expression)] @match",
            filter: Some(FindAll(unused_parameters)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "int f(int a, int b) { return a; }",
            good: "int f(int a, int) { return a; }",
        }),
    },
    Rule {
        id: "cpp/manual-memory",
        name: "Memory should not be managed manually",
        description: "`new` and `delete` leak or double-free on the paths a reviewer misses; containers and \
                      smart pointers release what they own.",
        message: "Replace this \"new\" or \"delete\" with an object that manages the memory, such as \
                  std::unique_ptr or a container.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5025")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(new_expression) (delete_expression)] @match",
            filter: Some(Keep(manual_memory)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f() { int* p = new int(1); delete p; }",
            good: "void f() { auto p = std::make_unique<int>(1); }",
        }),
    },
    Rule {
        id: "cpp/old-style-parameters",
        name: "Parameter types should be declared in the parameter list",
        description: "An old-style (K&R) definition declares its parameters' types after the parentheses, \
                      which C23 no longer allows and which hides mismatched calls.",
        message: "Move the declarations of the parameters' types into the parameter list.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1198")],
        check: Check::Query {
            langs: C_CPP,
            query: "(function_definition (declaration) @match)",
            filter: Some(Keep(first_parameter_declaration)),
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "int add(a, b)\nint a;\nint b;\n{ return a + b; }",
            good: "int add(int a, int b) { return a + b; }",
        }),
    },
    Rule {
        id: "cpp/cast-drops-const",
        name: "Casts should not drop const from a string literal",
        description: "A string literal is const; casting it to `char*` invites a write, which is undefined \
                      behaviour.",
        message: "Don't cast away this string literal's const.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S859")],
        check: Check::Query {
            langs: C_CPP,
            query: "(cast_expression value: (string_literal)) @match",
            filter: Some(Keep(casts_to_mutable_chars)),
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "struct s { char* msg; }; void f(struct s* p) { p->msg = (char *)\"bad input\"; }",
            good: "struct s { const char* msg; }; void f(struct s* p) { p->msg = \"bad input\"; }",
        }),
    },
    Rule {
        id: "cpp/operator-hidden-friend",
        name: "Comparison operators should be hidden friends",
        description: "A free `operator==` takes part in every overload resolution in its namespace; a \
                      hidden friend is found only for its class.",
        message: "Make this overloaded operator a hidden friend of its class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2807")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(function_definition declarator: (function_declarator declarator: (operator_name))) @match",
            filter: Some(Keep(free_symmetric_operator)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "struct P { int x; };\nbool operator==(const P& a, const P& b) { return a.x == b.x; }",
            good: "struct P { int x; friend bool operator==(const P& a, const P& b) { return a.x == b.x; } };",
        }),
    },
    Rule {
        id: "cpp/void-pointer",
        name: "void* should not be used",
        description: "A void pointer loses the type it points to; a template, a typed pointer or std::any \
                      keeps it.",
        message: "Replace this use of \"void *\" with a more meaningful type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5008")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(parameter_declaration type: (primitive_type) @t (#eq? @t \"void\") declarator: (pointer_declarator)) (optional_parameter_declaration type: (primitive_type) @t2 (#eq? @t2 \"void\") declarator: (pointer_declarator)) (function_definition type: (primitive_type) @t3 (#eq? @t3 \"void\") declarator: (pointer_declarator declarator: (function_declarator)))] @match",
            filter: Some(Keep(void_pointer_in_a_definition)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void copy(void* dst, int n) {}",
            good: "template <typename T> void copy(T* dst, int n) {}",
        }),
    },
    Rule {
        id: "cpp/switch-fallthrough",
        name: "Switch cases should not fall through without saying so",
        description: "A case that runs on into the next one is easy to mistake for a missing break; \
                      [[fallthrough]] says it's meant.",
        message: "End this case with a break, or mark the fall-through with [[fallthrough]].",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S128")],
        check: Check::Query {
            langs: C_CPP,
            query: "(case_statement) @match",
            filter: Some(Keep(falls_into_next_case)),
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "int f(int x) { int y = 0; switch (x) { case 1: y = 1; case 2: y += 2; break; } return y; }",
            good: "int f(int x) { int y = 0; switch (x) { case 1: y = 1; break; case 2: y += 2; break; } return y; }",
        }),
    },
    Rule {
        id: "cpp/protected-member-variable",
        name: "Member variables should not be protected",
        description: "A protected field is part of the class's interface to every subclass, which can then \
                      break its invariants; protected accessors keep them.",
        message: "Make this class's protected member variables private, with protected accessors if needed.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3656")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "[(class_specifier name: (_) body: (field_declaration_list)) (struct_specifier name: (_) body: (field_declaration_list))] @match",
            filter: Some(Find(class_with_protected_fields)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "class Base { protected: int count_; };",
            good: "class Base { protected: int count() const { return count_; } private: int count_; };",
        }),
    },
    Rule {
        id: "cpp/default-capture",
        name: "Lambdas passed on should name what they capture",
        description: "A lambda that leaves the expression it's written in, with `[&]` or `[=]`, takes \
                      whatever its body happens to mention; naming the captures shows what it holds on \
                      to, and for how long.",
        message: "Capture the variables this lambda uses by name instead of with a default capture.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3608")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(lambda_expression captures: (lambda_capture_specifier (lambda_default_capture))) @match",
            filter: Some(Keep(lambda_passed_on)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f(int n) { run([&]() { return n; }); }",
            good: "void f(int n) { run([n]() { return n; }); }",
        }),
    },
    Rule {
        id: "cpp/loop-variable-outside",
        name: "A loop's counter should be declared in the loop",
        description: "A variable that only the one loop setting it uses reads, and is scoped, better \
                      as `for (int i = 0; ...)`.",
        message: "Declare this loop's variable in its initializer.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5955")],
        check: Check::Query {
            langs: C_CPP,
            query: "(for_statement initializer: (assignment_expression left: (identifier))) @match",
            filter: Some(Keep(counter_declared_outside)),
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "void f(int *a) { int i; for (i = 0; i < 3; i++) a[i] = 0; }",
            good: "void f(int *a) { for (int i = 0; i < 3; i++) a[i] = 0; }",
        }),
    },
    Rule {
        id: "cpp/using-enum",
        name: "Repeated enumerators should come in with \"using enum\"",
        description: "A block that spells out `Mode::kA`, `Mode::kB`, `Mode::kC` reads shorter with \
                      `using enum Mode;` (C++20) at its start.",
        message: "Add \"using enum\" for the enumeration this block names over and over.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6177")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(function_definition body: (compound_statement)) @match",
            filter: Some(FindAll(block_around_an_enums_uses)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "int f(Mode m) { switch (m) { case Mode::kA: return 1; case Mode::kB: return 2; case Mode::kC: return 3; } return 0; }",
            good: "int f(Mode m) { switch (m) { using enum Mode; case kA: return 1; case kB: return 2; case kC: return 3; } return 0; }",
        }),
    },
    Rule {
        id: "cpp/deducible-template-arguments",
        name: "Template arguments a constructor deduces should be left out",
        description: "Since C++17 a class template's arguments come from its constructor's: \
                      `std::vector v(n, Color(0))` says `Color` once.",
        message: "Remove the template arguments; the constructor's arguments deduce them.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6012")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(declaration type: (qualified_identifier name: (template_type)) declarator: (init_declarator value: (argument_list))) @match",
            filter: Some(Keep(arguments_deduce_the_template)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void f() { std::vector<Color> v(8, Color(0)); }",
            good: "void f() { std::vector v(8, Color(0)); }",
        }),
    },
    Rule {
        id: "cpp/pointer-and-count",
        name: "A pointer and its length should be passed as one span",
        description: "A pointer parameter with a separate count can disagree with it; `std::span` \
                      (C++20) carries both.",
        message: "Replace this pointer and its count with a \"std::span\".",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S6188")],
        check: Check::Query {
            langs: CPP_ONLY,
            query: "(function_definition) @match",
            filter: Some(Keep(takes_a_pointer_and_a_count)),
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "int sum(const int* values, int count) { int s = 0; for (int i = 0; i < count; ++i) s += values[i]; return s; }",
            good: "int sum(std::span<const int> values) { int s = 0; for (int v : values) s += v; return s; }",
        }),
    },
    Rule {
        id: "cpp/hidden-inherited-function",
        name: "Member functions should not hide a base's functions",
        description: "A function named like a base's non-virtual one, or overriding only some of a \
                      base's virtual overloads, hides the base's from calls through the derived \
                      class; `using Base::name;` brings them back.",
        message: "Rename this function, or bring the base's functions of this name in with \"using\".",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1242")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "class Base {\n public:\n  void draw(int x);\n};\nclass Shape : public Base {\n public:\n  void draw(int x, int y);\n};",
            good: "class Base {\n public:\n  void draw(int x);\n};\nclass Shape : public Base {\n public:\n  using Base::draw;\n  void draw(int x, int y);\n};",
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

/// A member's initializer that doesn't depend on the constructor's
/// parameters, the first such one for that member in the class: the same
/// value every time, which an in-class initializer states once.
fn initializes_to_a_constant(init: Node, src: &[u8]) -> bool {
    let Some(constructor) = init.parent().and_then(|list| list.parent()) else {
        return false;
    };
    let Some(member) = independent_member(init, &parameter_names(constructor, src), src) else {
        return false;
    };
    let scope = class_scope(constructor, src);
    let container = match constructor.parent() {
        Some(t) if t.kind() == "template_declaration" => t.parent(),
        p => p,
    };
    let Some(container) = container else {
        return true;
    };
    let mut cursor = container.walk();
    for earlier in container.named_children(&mut cursor) {
        let earlier = if earlier.kind() == "template_declaration" {
            match earlier
                .named_children(&mut earlier.walk())
                .find(|c| c.kind() == "function_definition")
            {
                Some(f) => f,
                None => continue,
            }
        } else {
            earlier
        };
        if earlier.start_byte() >= constructor.start_byte() {
            break;
        }
        if earlier.kind() != "function_definition" || class_scope(earlier, src) != scope {
            continue;
        }
        let params = parameter_names(earlier, src);
        let Some(list) = earlier
            .named_children(&mut earlier.walk())
            .find(|c| c.kind() == "field_initializer_list")
        else {
            continue;
        };
        if list
            .named_children(&mut list.walk())
            .any(|other| independent_member(other, &params, src) == Some(member))
        {
            return false;
        }
    }
    true
}

/// The member a `member_(value)` initializer sets, when the value uses
/// none of the constructor's parameters: not a base class, which starts
/// with a capital.
fn independent_member<'s>(init: Node, params: &[&[u8]], src: &'s [u8]) -> Option<&'s [u8]> {
    let name = init
        .named_child(0)
        .filter(|n| n.kind() == "field_identifier")?;
    let member = text(name, src);
    if member.first().is_some_and(u8::is_ascii_uppercase) {
        return None;
    }
    let args = init
        .named_children(&mut init.walk())
        .find(|c| matches!(c.kind(), "argument_list" | "initializer_list"))?;
    let template_params = template_parameter_names(init, src);
    let mut stack = vec![args];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "this" | "lambda_expression" => return None,
            // `ns::kValue`, `Type::Default()`: named constants.
            "qualified_identifier" => {}
            "identifier" => {
                let name = text(n, src);
                if params.contains(&name)
                    || !(constant_name(name) || template_params.contains(&name))
                {
                    return None;
                }
            }
            _ => stack.extend(n.named_children(&mut n.walk())),
        }
    }
    Some(member)
}

/// `kSize` or `MAX_SIZE`: how constants are named, unlike members and
/// locals.
fn constant_name(name: &[u8]) -> bool {
    let k_prefixed = name.len() > 1 && name[0] == b'k' && name[1].is_ascii_uppercase();
    let all_caps = name
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_');
    k_prefixed || all_caps
}

/// The names of the template parameters around a node.
fn template_parameter_names<'s>(node: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names = Vec::new();
    let mut up = node.parent();
    while let Some(n) = up {
        if let Some(params) = (n.kind() == "template_declaration")
            .then(|| n.child_by_field_name("parameters"))
            .flatten()
        {
            let mut stack = vec![params];
            while let Some(p) = stack.pop() {
                if matches!(p.kind(), "identifier" | "type_identifier") {
                    names.push(text(p, src));
                } else if let Some(d) = p.child_by_field_name("declarator") {
                    stack.push(d);
                } else {
                    stack.extend(p.named_children(&mut p.walk()));
                }
            }
        }
        up = n.parent();
    }
    names
}

/// The names of a function's parameters.
fn parameter_names<'s>(function: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let Some(params) =
        function_declarator(function).and_then(|d| d.child_by_field_name("parameters"))
    else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut stack: Vec<Node> = params.named_children(&mut params.walk()).collect();
    while let Some(n) = stack.pop() {
        if n.kind() == "identifier" {
            names.push(text(n, src));
        } else if let Some(d) = n.child_by_field_name("declarator") {
            stack.push(d);
        } else if !matches!(
            n.kind(),
            "parameter_declaration" | "optional_parameter_declaration"
        ) {
            stack.extend(
                n.named_children(&mut n.walk())
                    .filter(|c| c.kind() == "identifier"),
            );
        }
    }
    names
}

/// `A` for an out-of-class `A::A(...)`, empty inside the class.
fn class_scope<'s>(function: Node, src: &'s [u8]) -> &'s [u8] {
    function_declarator(function)
        .and_then(|d| d.child_by_field_name("declarator"))
        .filter(|n| n.kind() == "qualified_identifier")
        .and_then(|n| n.child_by_field_name("scope"))
        .map_or(&b""[..], |n| text(n, src))
}

/// Each named parameter the body never mentions: not of a virtual function
/// or an override, whose signature isn't its own, nor [[maybe_unused]].
fn unused_parameters<'t>(function: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let (Some(body), params) = (
        function.child_by_field_name("body"),
        if function.kind() == "lambda_expression" {
            function
                .child_by_field_name("declarator")
                .and_then(|d| d.child_by_field_name("parameters"))
        } else {
            function_declarator(function).and_then(|d| d.child_by_field_name("parameters"))
        },
    ) else {
        return Vec::new();
    };
    let Some(params) = params else {
        return Vec::new();
    };
    // `Class::method(...)` defines a member declared elsewhere, whose
    // signature the declaration (perhaps a virtual one) fixes; `f<T>(...)`
    // specializes a template, whose signature the template fixes.
    if function_declarator(function)
        .and_then(|d| d.child_by_field_name("declarator"))
        .is_some_and(|n| matches!(n.kind(), "qualified_identifier" | "template_function"))
    {
        return Vec::new();
    }
    if function.kind() == "function_definition"
        && (has_word(function, b"virtual", src)
            || function_declarator(function).is_some_and(|d| {
                d.named_children(&mut d.walk()).any(|c| {
                    c.kind() == "virtual_specifier"
                        && matches!(text(c, src), b"override" | b"final")
                })
            }))
    {
        return Vec::new();
    }
    let body_text = text(body, src);
    let mentions = |name: &[u8]| {
        body_text.windows(name.len()).enumerate().any(|(i, w)| {
            w == name
                && !body_text
                    .get(i.wrapping_sub(1))
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                && !body_text
                    .get(i + name.len())
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        })
    };
    // A constructor's initializer list reads its parameters too.
    let initializers = function
        .named_children(&mut function.walk())
        .find(|c| c.kind() == "field_initializer_list")
        .map_or(&b""[..], |l| text(l, src));
    params
        .named_children(&mut params.walk())
        .filter(|p| {
            matches!(
                p.kind(),
                "parameter_declaration" | "optional_parameter_declaration"
            )
        })
        // `T* PROGMEM name`: a macro the parser takes for the name.
        .filter(|p| !p.has_error() && p.next_sibling().is_none_or(|n| !n.is_error()))
        .filter(|p| !text(*p, src).windows(12).any(|w| w == b"maybe_unused"))
        .filter_map(|p| {
            let mut d = p.child_by_field_name("declarator")?;
            for _ in 0..6 {
                if d.kind() == "identifier" {
                    break;
                }
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| d.named_children(&mut d.walk()).last())?;
            }
            (d.kind() == "identifier").then_some(d)
        })
        .filter(|name| {
            let n = text(*name, src);
            !mentions(n) && !initializers.windows(n.len()).any(|w| w == n)
        })
        .collect()
}

/// The smallest block holding every use of an enumeration's values in a
/// function that uses them three times or more: `Mode::kA` and
/// `Mode::Error`, a capitalized value under a capitalized scope, not a type
/// nor a function called.
fn block_around_an_enums_uses<'t>(function: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(body) = function.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut uses: Vec<(&[u8], Vec<Node<'t>>)> = Vec::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if matches!(n.kind(), "function_definition" | "lambda_expression") {
            continue;
        }
        if n.kind() == "qualified_identifier" {
            if let Some(scope) = enumerator_scope(n, src) {
                match uses.iter_mut().find(|(s, _)| *s == scope) {
                    Some((_, nodes)) => nodes.push(n),
                    None => uses.push((scope, vec![n])),
                }
            }
            continue;
        }
        stack.extend(n.named_children(&mut n.walk()));
    }
    let mut blocks = Vec::new();
    for (_, nodes) in uses.iter().filter(|(_, nodes)| nodes.len() >= 3) {
        let mut up = nodes[0].parent();
        while let Some(b) = up {
            if b.kind() == "compound_statement"
                && nodes
                    .iter()
                    .all(|n| b.start_byte() <= n.start_byte() && n.end_byte() <= b.end_byte())
            {
                blocks.push(b);
                break;
            }
            up = b.parent();
        }
    }
    blocks.sort_by_key(|b| b.start_byte());
    blocks
}

/// `Scope` of a `Scope::Value` that reads as an enumerator: both
/// capitalized (`kValue` counts), used as a value.
fn enumerator_scope<'s>(id: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let name = id
        .child_by_field_name("name")
        .filter(|n| n.kind() == "identifier")?;
    let scope = id.child_by_field_name("scope")?;
    if id.parent().is_some_and(|p| {
        p.kind() == "call_expression" && p.child_by_field_name("function") == Some(id)
    }) {
        return None;
    }
    let capitalized = |t: &[u8]| {
        t.first().is_some_and(u8::is_ascii_uppercase)
            || (t.len() > 1 && t[0] == b'k' && t[1].is_ascii_uppercase())
    };
    let scope_text = text(scope, src);
    let last = scope_text
        .rsplit(|b| *b == b':')
        .next()
        .unwrap_or(scope_text);
    let name_text = text(name, src);
    (last.first().is_some_and(u8::is_ascii_uppercase)
        && capitalized(name_text)
        && !name_text.iter().all(|b| b.is_ascii_uppercase() || *b == b'_' || b.is_ascii_digit())
        // Qt's enumerations live in classes: `QStyle::State_Selected`.
        && !(last.len() > 1 && last[0] == b'Q' && last[1].is_ascii_uppercase())
        && last != b"Qt")
        .then_some(scope_text)
}

/// `std::vector<T> v(n, T(...))` or `v(n, t)` with a local `T t`, and
/// `std::uniform_int_distribution<int>` (or `<>`) from int literals: the
/// constructor's arguments give the same template argument.
fn arguments_deduce_the_template(declaration: Node, src: &[u8]) -> bool {
    let Some(ty) = declaration.child_by_field_name("type") else {
        return false;
    };
    if ty
        .child_by_field_name("scope")
        .is_none_or(|s| text(s, src) != b"std")
    {
        return false;
    }
    let Some(template) = ty.child_by_field_name("name") else {
        return false;
    };
    let class = template
        .child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src));
    let Some(targs) = template.child_by_field_name("arguments") else {
        return false;
    };
    let targs: Vec<&[u8]> = targs
        .named_children(&mut targs.walk())
        .map(|a| text(a, src))
        .collect();
    let Some(args) = declaration
        .child_by_field_name("declarator")
        .and_then(|d| d.child_by_field_name("value"))
    else {
        return false;
    };
    let args: Vec<Node> = args
        .named_children(&mut args.walk())
        .filter(|a| a.kind() != "comment")
        .collect();
    let int_literal = |a: Node| {
        let a = if a.kind() == "unary_expression" {
            a.named_child(0).unwrap_or(a)
        } else {
            a
        };
        a.kind() == "number_literal" && text(a, src).iter().all(u8::is_ascii_digit)
    };
    match class {
        b"uniform_int_distribution" => {
            args.len() == 2
                && (targs.is_empty()
                    || (targs == [&b"int"[..]] && args.iter().all(|a| int_literal(*a))))
        }
        b"vector" if targs.len() == 1 && args.len() == 2 => {
            let t = targs[0];
            let value = args[1];
            match value.kind() {
                "call_expression" => value
                    .child_by_field_name("function")
                    .is_some_and(|f| text(f, src) == t),
                "identifier" => local_declared_as(declaration, text(value, src), t, src),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Whether a declaration before `at`, in its function, declares `name` as
/// a `ty`.
fn local_declared_as(at: Node, name: &[u8], ty: &[u8], src: &[u8]) -> bool {
    let mut up = at.parent();
    while let Some(block) = up {
        let mut cursor = block.walk();
        for d in block.named_children(&mut cursor) {
            if d.start_byte() >= at.start_byte() {
                break;
            }
            if d.kind() == "declaration"
                && d.child_by_field_name("type")
                    .is_some_and(|t| text(t, src) == ty)
            {
                let mut c = d.walk();
                if d.children_by_field_name("declarator", &mut c).any(|v| {
                    let v = if v.kind() == "init_declarator" {
                        v.child_by_field_name("declarator")
                    } else {
                        Some(v)
                    };
                    v.is_some_and(|v| v.kind() == "identifier" && text(v, src) == name)
                }) {
                    return true;
                }
            }
        }
        if block.kind() == "function_definition" {
            break;
        }
        up = block.parent();
    }
    false
}

/// A definition taking a pointer and an integer named for its length
/// (`count`, `size`, `pixel_count`), that reads the pointer only as
/// `p[i]` in a loop bounded by that length: what a span holds.
fn takes_a_pointer_and_a_count(function: Node, src: &[u8]) -> bool {
    let (Some(params), Some(body)) = (
        function_declarator(function).and_then(|d| d.child_by_field_name("parameters")),
        function.child_by_field_name("body"),
    ) else {
        return false;
    };
    let mut pointers = Vec::new();
    let mut counts = Vec::new();
    let mut cursor = params.walk();
    for p in params.named_children(&mut cursor) {
        let (Some(ty), Some(declarator)) = (
            p.child_by_field_name("type"),
            p.child_by_field_name("declarator"),
        ) else {
            continue;
        };
        let ty = text(ty, src);
        if declarator.kind() == "pointer_declarator" {
            if let Some(name) = declarator
                .child_by_field_name("declarator")
                .filter(|d| d.kind() == "identifier")
            {
                pointers.push(text(name, src));
            }
        } else if declarator.kind() == "identifier" && !pointers.is_empty() {
            let name = text(declarator, src);
            let integer = ty.starts_with(b"int")
                || ty.starts_with(b"uint")
                || ty == b"size_t"
                || ty == b"unsigned";
            if integer
                && (matches!(name, b"count" | b"size" | b"len" | b"length")
                    || name.ends_with(b"_count")
                    || name.ends_with(b"_size"))
            {
                counts.push(name);
            }
        }
    }
    let bounded_by_a_count = |n: Node| {
        n.kind() == "for_statement"
            && n.child_by_field_name("condition").is_some_and(|c| {
                c.kind() == "binary_expression"
                    && c.child_by_field_name("operator")
                        .is_some_and(|o| text(o, src) == b"<")
                    && c.child_by_field_name("right")
                        .is_some_and(|r| counts.contains(&text(r, src)))
            })
    };
    let mut has_loop = false;
    let mut indexed = vec![false; pointers.len()];
    let mut other_use = vec![false; pointers.len()];
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        has_loop |= bounded_by_a_count(n);
        if n.kind() == "identifier"
            && let Some(k) = pointers.iter().position(|p| *p == text(n, src))
        {
            let subscripted = n.parent().is_some_and(|p| {
                p.kind() == "subscript_expression" && p.child_by_field_name("argument") == Some(n)
            });
            if subscripted {
                indexed[k] = true;
            } else {
                other_use[k] = true;
            }
        }
        stack.extend(n.named_children(&mut n.walk()));
    }
    has_loop && (0..pointers.len()).any(|k| indexed[k] && !other_use[k])
}

/// A default-capture lambda that leaves its expression: passed to a call,
/// or stored in a local that is; not one in a constructor's initializer
/// list, nor one only called where it's defined.
fn lambda_passed_on(lambda: Node, src: &[u8]) -> bool {
    let mut up = lambda.parent();
    while let Some(n) = up {
        if n.kind() == "field_initializer_list" {
            return false;
        }
        if n.kind() == "function_definition" {
            break;
        }
        up = n.parent();
    }
    let Some(parent) = lambda.parent() else {
        return false;
    };
    if parent.kind() == "argument_list" {
        return true;
    }
    if parent.kind() != "init_declarator" {
        return false;
    }
    let Some(name) = parent
        .child_by_field_name("declarator")
        .filter(|d| d.kind() == "identifier")
    else {
        return false;
    };
    let name = text(name, src);
    let Some(scope) = parent.parent().and_then(|d| d.parent()) else {
        return false;
    };
    let mut stack = vec![scope];
    while let Some(n) = stack.pop() {
        if n.kind() == "identifier"
            && n.start_byte() > lambda.end_byte()
            && text(n, src) == name
            && n.parent().is_some_and(|p| p.kind() == "argument_list")
        {
            return true;
        }
        stack.extend(n.named_children(&mut n.walk()));
    }
    false
}

/// `for (i = 0; ...)` where the function declares `i` and uses it only in
/// that loop, the one loop that sets it.
fn counter_declared_outside(for_loop: Node, src: &[u8]) -> bool {
    let Some(name) = for_loop
        .child_by_field_name("initializer")
        .and_then(|a| a.child_by_field_name("left"))
        .map(|v| text(v, src))
    else {
        return false;
    };
    let mut up = for_loop.parent();
    let body = loop {
        match up {
            Some(n) if n.kind() == "function_definition" => break n.child_by_field_name("body"),
            Some(n) => up = n.parent(),
            None => return false,
        }
    };
    let Some(body) = body else {
        return false;
    };
    let sets_it = |n: Node| {
        n.kind() == "for_statement"
            && n.child_by_field_name("initializer").is_some_and(|a| {
                a.kind() == "assignment_expression"
                    && a.child_by_field_name("left")
                        .is_some_and(|l| text(l, src) == name)
            })
    };
    let mut declared = false;
    let mut loops = 0;
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if sets_it(n) {
            loops += 1;
            continue;
        }
        if n.kind() == "declaration" {
            let mut cursor = n.walk();
            for d in n.children_by_field_name("declarator", &mut cursor) {
                let id = if d.kind() == "init_declarator" {
                    d.child_by_field_name("declarator")
                } else {
                    Some(d)
                };
                if id.is_some_and(|id| id.kind() == "identifier" && text(id, src) == name) {
                    if d.kind() == "init_declarator" {
                        return false;
                    }
                    declared = true;
                }
            }
            continue;
        }
        if n.kind() == "identifier" && text(n, src) == name {
            return false;
        }
        stack.extend(n.named_children(&mut n.walk()));
    }
    declared && loops == 1
}

/// A `void*` parameter or return type of a function defined here: not a
/// declaration (the definition is reported), nor an `operator new` or
/// `operator delete`, whose signatures the language fixes.
fn void_pointer_in_a_definition(node: Node, src: &[u8]) -> bool {
    if node.kind() == "function_definition" {
        return !allocation_operator(function_declarator(node), src);
    }
    if in_macro_arguments(node, src) {
        return false;
    }
    let Some(declarator) = node.parent().and_then(|list| list.parent()) else {
        return false;
    };
    if declarator.kind() != "function_declarator" {
        return true;
    }
    if allocation_operator(Some(declarator), src) {
        return false;
    }
    let mut up = declarator.parent();
    while let Some(n) = up {
        match n.kind() {
            "pointer_declarator" | "reference_declarator" => up = n.parent(),
            kind => return kind == "function_definition",
        }
    }
    false
}

/// `operator new`, `operator delete` and their array forms.
fn allocation_operator(declarator: Option<Node>, src: &[u8]) -> bool {
    declarator
        .and_then(|d| d.child_by_field_name("declarator"))
        .is_some_and(|n| {
            let t = text(n, src);
            n.kind() == "operator_name"
                && (t.ends_with(b"new") || t.ends_with(b"delete") || t.ends_with(b"[]"))
        })
}

/// `new` and `delete`, not a placement `new` and not inside a macro's
/// arguments.
fn manual_memory(node: Node, src: &[u8]) -> bool {
    if in_macro_arguments(node, src) {
        return false;
    }
    node.kind() != "new_expression"
        || !(node.child_by_field_name("placement").is_some()
            || node.has_error()
            || under_error(node)
            || handed_to_an_owner(node)
            || given_a_parent(node, src))
}

/// Inside a parse error, such as code disabled by `#if 0`.
fn under_error(node: Node) -> bool {
    let mut up = node.parent();
    while let Some(n) = up {
        if n.is_error() {
            return true;
        }
        up = n.parent();
    }
    false
}

/// `owner(new T)` or `owner.reset(new T)`: the new object goes straight
/// into a call or a declared object, which takes it over.
fn handed_to_an_owner(new: Node) -> bool {
    new.parent().is_some_and(|args| {
        args.kind() == "argument_list"
            && args
                .parent()
                .is_some_and(|p| matches!(p.kind(), "call_expression" | "init_declarator"))
    })
}

/// `new QTimer(this)`: a Qt object given a parent, which deletes it.
fn given_a_parent(new: Node, src: &[u8]) -> bool {
    let Some(args) = new.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let mut has_args = false;
    for arg in args.named_children(&mut cursor) {
        has_args = true;
        if arg.kind() == "this" {
            return true;
        }
    }
    let name = new
        .child_by_field_name("type")
        .map(|t| text(t, src))
        .unwrap_or_default();
    has_args && name.len() > 1 && name[0] == b'Q' && name[1].is_ascii_uppercase()
}

/// An old-style definition's first parameter declaration.
fn first_parameter_declaration(declaration: Node, _: &[u8]) -> bool {
    declaration
        .prev_named_sibling()
        .is_none_or(|p| p.kind() != "declaration")
}

/// `(char *)"text"`: a cast to a pointer to non-const characters.
fn casts_to_mutable_chars(cast: Node, src: &[u8]) -> bool {
    cast.child_by_field_name("type").is_some_and(|t| {
        let t = text(t, src);
        t.contains(&b'*') && !t.windows(5).any(|w| w == b"const")
    })
}

/// A comparison or equality operator defined outside the classes it
/// compares, taking two parameters.
fn free_symmetric_operator(function: Node, src: &[u8]) -> bool {
    // Not in a class: a member, or a friend already.
    let mut up = function.parent();
    while let Some(n) = up {
        if matches!(n.kind(), "field_declaration_list" | "friend_declaration") {
            return false;
        }
        up = n.parent();
    }
    let Some(d) = function_declarator(function) else {
        return false;
    };
    let op = d
        .child_by_field_name("declarator")
        .map_or(&b""[..], |n| text(n, src));
    let comparison = [
        &b"operator=="[..],
        b"operator!=",
        b"operator<",
        b"operator>",
        b"operator<=",
        b"operator>=",
    ]
    .iter()
    .any(|o| {
        let squeezed: Vec<u8> = op
            .iter()
            .filter(|b| !b.is_ascii_whitespace())
            .copied()
            .collect();
        squeezed == *o
    });
    let two = d.child_by_field_name("parameters").is_some_and(|p| {
        p.named_children(&mut p.walk())
            .filter(|c| c.kind() == "parameter_declaration")
            .count()
            == 2
    });
    comparison && two
}

/// A case whose statements don't end in a jump, followed by another case.
fn falls_into_next_case(case: Node, src: &[u8]) -> bool {
    let Some(next) = case.next_named_sibling() else {
        return false;
    };
    if next.kind() != "case_statement" {
        return false;
    }
    let statements: Vec<Node> = case
        .named_children(&mut case.walk())
        .filter(|c| c.kind() != "comment" && Some(*c) != case.child_by_field_name("value"))
        .collect();
    let Some(last) = statements.last() else {
        // `case 1: case 2:` share one body.
        return false;
    };
    !ends_in_jump(*last, src) && !only_jumps(next)
}

/// `case X: return;` or `default: break;`: falling into it does what a
/// jump would.
fn only_jumps(case: Node) -> bool {
    let mut statements = case
        .named_children(&mut case.walk())
        .filter(|c| c.kind() != "comment" && Some(*c) != case.child_by_field_name("value"))
        .collect::<Vec<_>>();
    while statements.len() == 1 && statements[0].kind() == "compound_statement" {
        let block = statements[0];
        statements = block
            .named_children(&mut block.walk())
            .filter(|c| c.kind() != "comment")
            .collect();
    }
    statements.len() == 1
        && matches!(
            statements[0].kind(),
            "break_statement"
                | "return_statement"
                | "continue_statement"
                | "goto_statement"
                | "throw_statement"
        )
}

fn ends_in_jump(statement: Node, src: &[u8]) -> bool {
    match statement.kind() {
        "break_statement" | "return_statement" | "continue_statement" | "goto_statement"
        | "throw_statement" => true,
        "expression_statement" => {
            let t = text(statement, src);
            // `[[fallthrough]];`, `exit(1);`, `abort();`
            t.windows(11).any(|w| w == b"fallthrough")
                || t.starts_with(b"exit(")
                || t.starts_with(b"abort(")
                || t.starts_with(b"std::abort(")
        }
        "attributed_statement" => text(statement, src)
            .windows(11)
            .any(|w| w == b"fallthrough"),
        "compound_statement" => statement
            .named_children(&mut statement.walk())
            .filter(|c| c.kind() != "comment")
            .last()
            .is_some_and(|l| ends_in_jump(l, src)),
        // A switch with a default whose every case leaves the function.
        "switch_statement" => statement.child_by_field_name("body").is_some_and(|body| {
            let cases: Vec<Node> = body
                .named_children(&mut body.walk())
                .filter(|c| c.kind() == "case_statement")
                .collect();
            cases
                .iter()
                .any(|c| c.child_by_field_name("value").is_none())
                && cases.iter().all(|c| {
                    c.named_children(&mut c.walk())
                        .filter(|s| {
                            s.kind() != "comment" && Some(*s) != c.child_by_field_name("value")
                        })
                        .last()
                        .is_none_or(|l| l.kind() != "break_statement" && ends_in_jump(l, src))
                })
        }),
        "if_statement" => {
            statement
                .child_by_field_name("consequence")
                .is_some_and(|c| ends_in_jump(c, src))
                && statement
                    .child_by_field_name("alternative")
                    .and_then(|e| e.named_child(0))
                    .is_some_and(|e| ends_in_jump(e, src))
        }
        _ => false,
    }
}

/// A class with a non-static data member under `protected:`.
fn class_with_protected_fields<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = class.child_by_field_name("body")?;
    let mut access = if class.kind() == "class_specifier" {
        &b"private"[..]
    } else {
        &b"public"[..]
    };
    for member in body.named_children(&mut body.walk()) {
        match member.kind() {
            "access_specifier" => {
                let t = text(member, src).trim_ascii_end();
                access = t.strip_suffix(b":").unwrap_or(t).trim_ascii_end();
            }
            "field_declaration"
                if access == b"protected"
                    && function_declarator(member).is_none()
                    && !has_word(member, b"static", src) =>
            {
                return class.child_by_field_name("name");
            }
            _ => {}
        }
    }
    None
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

    /// The second batch of shapes, from the same two analyses.
    #[test]
    fn more_shapes_from_sonarcloud() {
        // The first constructor setting a member to a value that doesn't
        // depend on its parameters: literals, named constants, template
        // parameters, value-initialization.
        let inits = "template <int W>\nclass A {\n public:\n  A(int a) : a_(a), b_(0), c_(kSize), d_(W), e_() {}\n  A(double) : a_(1), b_(0), c_(other_), d_(f(x_)) {}\n private:\n  int a_, b_, c_, d_, e_;\n};";
        assert_eq!(
            flagged("cpp/initializer-list-constant", inits),
            [4, 4, 4, 4, 5]
        );
        let params = "struct S { void m(int x); virtual void v(int x) {} };\nvoid S::m(int x) {}\ntemplate <> int pick<1>(int x) { return 0; }\nstatic int read(const char* PROGMEM p) { return 0; }\nint add(int a, int b, int c) { return a + b; }\nauto l = [](int x, int y) { return x; };";
        assert_eq!(flagged("cpp/unused-parameter", params), [5, 6]);
        let memory = "struct W : QWidget {\n  W() : t_(new QTimer(this)), q_(new Thing()) {\n    a_ = new QAction(\"x\", menu);\n    p_.reset(new Thing());\n    v_.emplace_back(new Thing());\n    std::unique_ptr<Thing> u(new Thing());\n    Thing* raw = new Thing();\n    delete raw;\n  }\n};";
        assert_eq!(flagged("cpp/manual-memory", memory), [2, 7, 8]);
        let voids = "void f(void* p);\nvoid f(void* p) {}\nvoid* g(int n) { return nullptr; }\nvoid* operator new(size_t n) { return malloc(n); }\nvoid operator delete(void* p) noexcept {}";
        assert_eq!(flagged("cpp/void-pointer", voids), [2, 3]);
        let cases = "int f(int k, int m) {\n  switch (k) {\n    case 1:\n      g();\n    case 2:\n      h();\n    case 3: {\n      switch (m) {\n        case 0: return 1;\n        default: return 2;\n      }\n    }\n    case 4:\n      g();\n    default:\n      break;\n  }\n  return 0;\n}";
        assert_eq!(flagged("cpp/switch-fallthrough", cases), [3, 5]);
        let protected_fields = "class P {\n protected:\n  int count_;\n  void f();\n};\nclass Q {\n protected:\n  void g();\n};";
        assert_eq!(
            flagged("cpp/protected-member-variable", protected_fields),
            [1]
        );
        let operators = "struct V { bool operator==(const V&) const; };\nbool operator<(const V& a, const V& b) { return true; }\nstruct F { friend bool operator==(const F&, const F&) { return true; } };";
        assert_eq!(flagged("cpp/operator-hidden-friend", operators), [2]);
        let old = "int sum(a, b)\n  int a;\n  int b;\n{ return a + b; }\nvoid w() { char* s = (char*)\"text\"; const char* t = (const char*)\"x\"; }";
        assert_eq!(flagged_in("cpp/old-style-parameters", Lang::C, old), [2]);
        assert_eq!(flagged_in("cpp/cast-drops-const", Lang::C, old), [5]);
    }

    /// The third batch, from the same two analyses.
    #[test]
    fn third_batch_from_sonarcloud() {
        // Passed on, directly or by name; not one only called here.
        let lambdas = "void f(int n) {\n  run([&]() { return n; });\n  auto l = [=]() { return n; };\n  l();\n  auto k = [&]() { return n; };\n  run(k);\n}";
        assert_eq!(flagged("cpp/default-capture", lambdas), [2, 5]);
        // Only the variable set by one loop and used nowhere else.
        let loops = "void f(int *a) {\n  int i, j;\n  for (i = 0; i < 3; i++) a[i] = 0;\n  for (j = 0; j < 3; j++) a[j] = 1;\n  for (j = 0; j < 3; j++) a[j] = 2;\n}";
        assert_eq!(flagged_in("cpp/loop-variable-outside", Lang::C, loops), [3]);
        // At the smallest block around three uses; not a Qt class's values,
        // nor two uses.
        let enums = "int f(Mode m) {\n  switch (m) {\n    case Mode::kA: return 1;\n    case Mode::kB: return 2;\n    case Mode::kC: return 3;\n  }\n  return 0;\n}\nvoid g() { h(QStyle::A, QStyle::B, QStyle::C); x(Mode::kA, Mode::kB); }";
        assert_eq!(flagged("cpp/using-enum", enums), [2]);
        let deduced = "void f(int n) {\n  std::vector<Color> a(8, Color(0));\n  Color c;\n  std::vector<Color> b(8, c);\n  std::vector<uint8_t> d(8, 128);\n  std::uniform_int_distribution<int> e(0, 6);\n  std::uniform_int_distribution<int16_t> g(0, 6);\n  std::uniform_int_distribution<> h(0, n);\n}";
        assert_eq!(
            flagged("cpp/deducible-template-arguments", deduced),
            [2, 4, 6, 8]
        );
        // Only indexed, in a loop the count bounds; not passed on.
        let spans = "void a(Color* p, int count) {\n  for (int i = 0; i < count; ++i) p[i] = 0;\n}\nvoid b(Color* p, int count) {\n  for (int i = 0; i < count; ++i) p[i] = 0;\n  g(p);\n}";
        assert_eq!(flagged("cpp/pointer-and-count", spans), [1]);
    }
}
