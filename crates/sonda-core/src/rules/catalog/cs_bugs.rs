//! C# bug rules (ADR-0007, ADR-0015, batch 2). Queries stay cheap on deep
//! trees: see the notes in `js_modern.rs`.

use super::cs::{
    CS_SCOPE_STOPS, cs_has_modifier, cs_statements, cs_string_value, operand, same_code,
    simple_name,
};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::text;
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "cs/equals-without-hashcode",
        name: "Equals(object) and GetHashCode() should be overridden together",
        description: "Objects that are equal must have equal hash codes, or dictionaries and hash sets lose them. \
                      Overriding only one of the two breaks that.",
        message: "Override both Equals(object) and GetHashCode(), or neither.",
        category: Bug,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S1206")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration body: (declaration_list)) (struct_declaration body: (declaration_list))] @match",
            filter: Some(Find(unpaired_equality_override)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class P { int id; public override bool Equals(object o) => o is P p && p.id == id; }",
            good: "class P { int id; public override bool Equals(object o) => o is P p && p.id == id; public override int GetHashCode() => id; }",
        }),
    },
    Rule {
        id: "cs/single-iteration-loop",
        name: "Loops should be able to run more than once",
        description: "A loop whose body always ends with `break`, `return` or `throw`, and never continues, runs \
                      at most once: it's an `if` in disguise, or the jump is a mistake.",
        message: "Make this jump conditional, or replace the loop with an if statement.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1751")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(while_statement body: (block)) (for_statement body: (block)) \
                     (foreach_statement body: (block)) (do_statement body: (block))] @match",
            filter: Some(Find(unconditional_loop_exit)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int[] xs) { foreach (var x in xs) { return x; } return 0; } }",
            good: "class A { int F(int[] xs) { foreach (var x in xs) { if (x > 0) { return x; } } return 0; } }",
        }),
    },
    Rule {
        id: "cs/unused-new-object",
        name: "Objects should not be created only to be dropped",
        description: "An object created and never used costs an allocation for nothing. If the constructor is run \
                      for its side effects, a method says that better.",
        message: "Use this object, or move what its constructor does into a method.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1848")],
        check: Check::Query {
            langs: CSHARP,
            query: "(expression_statement (object_creation_expression) @match)",
            filter: Some(Keep(creates_non_exception)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { new Report(); } }",
            good: "class A { void F() { var r = new Report(); r.Save(); } }",
        }),
    },
    Rule {
        id: "cs/collection-own-argument",
        name: "A collection should not be passed to its own methods",
        description: "`list.AddRange(list)` doubles the list, `xs.Union(xs)` and `xs.Intersect(xs)` give back \
                      `xs`, and `xs.SequenceEqual(xs)` is always true. Another collection was probably meant.",
        message: "Pass a different collection to this method.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2114")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "AddRange" "InsertRange" "Concat" "Union" "Except" "Intersect"
                                     "SequenceEqual" "UnionWith" "ExceptWith" "IntersectWith"
                                     "SymmetricExceptWith" "SetEquals" "IsSubsetOf" "IsSupersetOf"
                                     "IsProperSubsetOf" "IsProperSupersetOf" "Overlaps")) @match"#,
            filter: Some(Keep(passes_itself)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(List<int> xs) { xs.AddRange(xs); } }",
            good: "class A { void F(List<int> xs, List<int> ys) { xs.AddRange(ys); } }",
        }),
    },
    Rule {
        id: "cs/self-referencing-property",
        name: "Properties should not read or write themselves",
        description: "A getter that returns its own property, or a setter that assigns it, calls itself forever \
                      and ends in a StackOverflowException, which can't be caught.",
        message: "Read or write the backing field instead of the property itself.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[related("S2190")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration name: (identifier)) @match",
            filter: Some(Find(self_referencing_accessor)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int count; public int Count { get { return Count; } set { count = value; } } }",
            good: "class A { int count; public int Count { get { return count; } set { count = value; } } }",
        }),
    },
    Rule {
        id: "cs/for-loop-never-runs",
        name: "A for loop's condition should be true at the start",
        description: "When the counter starts past the end condition, the loop body never runs.",
        message: "Correct the start value or the condition: this loop never runs.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2252")],
        check: Check::Query {
            langs: CSHARP,
            query: "(for_statement initializer: (variable_declaration) condition: (binary_expression)) @match",
            filter: Some(Find(condition_false_at_start)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { for (int i = 10; i < 5; i++) { G(i); } } }",
            good: "class A { void F() { for (int i = 0; i < 5; i++) { G(i); } } }",
        }),
    },
    Rule {
        id: "cs/format-string-arguments",
        name: "Composite format strings should match their arguments",
        description: "A placeholder such as `{2}` with fewer than three arguments, or an unbalanced brace, makes \
                      `string.Format` throw a FormatException at run time.",
        message: "Fix this format string: a placeholder has no argument, or a brace isn't escaped.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2275")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "Format" "Write" "WriteLine" "AppendFormat")) @match"#,
            filter: Some(Find(broken_format_string)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(int a, int b) { return string.Format(\"{0} of {1} ({2})\", a, b); } }",
            good: "class A { string F(int a, int b) { return string.Format(\"{0} of {1}, {{done}}\", a, b); } }",
        }),
    },
    Rule {
        id: "cs/flags-enum-values",
        name: "[Flags] enum members should be powers of two",
        description: "Flags are combined bit by bit. A member that isn't 0 or a power of two, including one given \
                      the next number implicitly, overlaps others, so `HasFlag` gives wrong answers.",
        message: "Give this member a power-of-two value, or define it as a combination such as 'A | B'.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2345")],
        check: Check::Query {
            langs: CSHARP,
            query: "(enum_declaration (attribute_list) body: (enum_member_declaration_list)) @match",
            filter: Some(Find(non_flag_member)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Flags] enum Access { None = 0, Read = 1, Write = 2, Execute = 3 }",
            good: "[Flags] enum Access { None = 0, Read = 1, Write = 2, Execute = 4, All = Read | Write | Execute }",
        }),
    },
    Rule {
        id: "cs/lock-on-shared-object",
        name: "Locks should not be taken on publicly reachable objects",
        description: "`this`, `typeof(...)` and string literals can be locked by code outside the class, which \
                      can deadlock with it.",
        message: "Lock on a private readonly object instead.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2551")],
        check: Check::Query {
            langs: CSHARP,
            query: "(lock_statement) @match",
            filter: Some(Keep(locks_shared_object)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { lock (this) { G(); } } }",
            good: "class A { private readonly object sync = new object(); void F() { lock (sync) { G(); } } }",
        }),
    },
    Rule {
        id: "cs/nan-comparison",
        name: "Values should not be compared with NaN",
        description: "NaN is not equal to anything, itself included, so `x == double.NaN` is always false.",
        message: "Use double.IsNaN() or float.IsNaN() instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2688")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(compares_with_nan)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(double d) { return d == double.NaN; } }",
            good: "class A { bool F(double d) { return double.IsNaN(d); } }",
        }),
    },
    Rule {
        id: "cs/thread-static-initializer",
        name: "[ThreadStatic] fields should not be initialized inline",
        description: "The initializer runs once, on the thread that loads the class; every other thread sees \
                      the field's default value.",
        message: "Initialize this field lazily on each thread instead, or use ThreadLocal<T>.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2996")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (attribute_list)) @match",
            filter: Some(Find(initialized_thread_static)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { [ThreadStatic] static int depth = 1; }",
            good: "class A { [ThreadStatic] static int depth; }",
        }),
    },
    Rule {
        id: "cs/thread-static-instance-field",
        name: "[ThreadStatic] should only be used on static fields",
        description: "The attribute does nothing on an instance field, so the field is shared between threads \
                      after all.",
        message: "Make this field static, or remove [ThreadStatic].",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3005")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (attribute_list)) @match",
            filter: Some(Keep(is_instance_thread_static)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { [ThreadStatic] int depth; }",
            good: "class A { [ThreadStatic] static int depth; }",
        }),
    },
    Rule {
        id: "cs/returned-disposed",
        name: "Objects disposed by 'using' should not be returned",
        description: "`using` disposes the object when the block ends, so the caller gets an object that is \
                      already disposed.",
        message: "Remove 'using' here and let the caller dispose this object.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2997")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(using_statement (variable_declaration) body: (_)) (block (local_declaration_statement))] @match",
            filter: Some(Find(returns_disposed)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Stream F(string p) { using (var s = File.OpenRead(p)) { return s; } } }",
            good: "class A { Stream F(string p) { var s = File.OpenRead(p); return s; } }",
        }),
    },
    Rule {
        id: "cs/base-object-equality",
        name: "base.Equals() and base.GetHashCode() should not be used when the base is object",
        description: "In a class that derives straight from `object`, `base.Equals` compares references and \
                      `base.GetHashCode` hashes the reference, which undoes overriding them.",
        message: "Compare and hash this class's own fields instead of calling the object implementation.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3249"), exact("S3397")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(class_declaration body: (declaration_list (method_declaration name: (identifier) @n
                        (#any-of? @n "Equals" "GetHashCode")) @match))"#,
            filter: Some(Find(base_object_call)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class P { int id; public override int GetHashCode() { return base.GetHashCode(); } public override bool Equals(object o) => o is P p && p.id == id; }",
            good: "class P { int id; public override int GetHashCode() { return id; } public override bool Equals(object o) => o is P p && p.id == id; }",
        }),
    },
    Rule {
        id: "cs/static-field-order",
        name: "Static fields should not be initialized from fields declared after them",
        description: "Static initializers run in declaration order, so a field initialized from one declared \
                      later reads that one's default value.",
        message: "Move this field's declaration after the field it reads, or initialize both in a static constructor.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3263")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration body: (declaration_list)) (struct_declaration body: (declaration_list))] @match",
            filter: Some(Find(reads_later_static_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { static int Twice = Once * 2; static int Once = 21; }",
            good: "class A { static int Once = 21; static int Twice = Once * 2; }",
        }),
    },
    Rule {
        id: "cs/caller-info-parameter-position",
        name: "Caller information parameters should come last",
        description: "`[CallerMemberName]` and its siblings only work when the caller leaves the argument out. \
                      A later parameter makes callers pass it, which overrides the real value.",
        message: "Move this caller information parameter after the other parameters.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3343")],
        check: Check::Query {
            langs: CSHARP,
            query: "(parameter_list (parameter (attribute_list))) @match",
            filter: Some(Find(misplaced_caller_info)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Log([CallerMemberName] string caller = \"\", string message = \"\") { } }",
            good: "class A { void Log(string message, [CallerMemberName] string caller = \"\") { } }",
        }),
    },
    Rule {
        id: "cs/one-way-returns-value",
        name: "One-way service operations should not return a value",
        description: "The client doesn't wait for a one-way operation, so a return value never reaches it and \
                      WCF rejects the contract.",
        message: "Make this operation return void, or remove IsOneWay = true.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3598")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list) returns: (_)) @match",
            filter: Some(Find(one_way_with_result)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "interface S { [OperationContract(IsOneWay = true)] int Send(string m); }",
            good: "interface S { [OperationContract(IsOneWay = true)] void Send(string m); }",
        }),
    },
    Rule {
        id: "cs/pure-void-method",
        name: "[Pure] should not mark void methods",
        description: "A pure method has no side effects, so a void one does nothing. Callers and analyzers that \
                      trust the attribute will drop calls to it.",
        message: "Remove [Pure], or return the computed value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3603")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list) returns: (predefined_type)) @match",
            filter: Some(Find(pure_void_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { [Pure] void Check(int x) { G(x); } }",
            good: "class A { [Pure] bool Check(int x) { return x > 0; } }",
        }),
    },
    Rule {
        id: "cs/dangerous-get-handle",
        name: "SafeHandle.DangerousGetHandle() should not be called",
        description: "The raw handle can be released and recycled while it's still in use, so the code may end \
                      up using another resource's handle.",
        message: "Pass the SafeHandle itself, or use DangerousAddRef and DangerousRelease around this call.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S3869")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        (#eq? @n "DangerousGetHandle")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { IntPtr F(SafeFileHandle h) { return h.DangerousGetHandle(); } }",
            good: "class A { SafeFileHandle F(SafeFileHandle h) { return h; } }",
        }),
    },
    Rule {
        id: "cs/type-outside-namespace",
        name: "Types should be declared in a namespace",
        description: "Types in the global namespace collide with every other library that does the same.",
        message: "Move this type into a namespace.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3903")],
        check: Check::Query {
            langs: CSHARP,
            query: "(compilation_unit) @match",
            filter: Some(Find(global_type_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Helper { }",
            good: "namespace Shop; class Helper { }",
        }),
    },
    Rule {
        id: "cs/serialization-callback-signature",
        name: "Serialization callbacks should have the expected signature",
        description: "The serializer only calls `[OnSerializing]` and the other callbacks when they are \
                      non-public, return void and take one StreamingContext; otherwise it throws or skips them.",
        message: "Make this method non-public, return void and take a single StreamingContext.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3927")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list)) @match",
            filter: Some(Find(bad_serialization_callback)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { [OnDeserialized] public void Restore() { } }",
            good: "class A { [OnDeserialized] private void Restore(StreamingContext context) { Init(); } }",
        }),
    },
    Rule {
        id: "cs/exception-not-thrown",
        name: "Exceptions should not be created without being thrown",
        description: "Creating an exception does nothing until it's thrown; the `throw` was probably forgotten.",
        message: "Throw this exception, or remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S3984")],
        check: Check::Query {
            langs: CSHARP,
            query: "(expression_statement (object_creation_expression) @match)",
            filter: Some(Keep(creates_exception)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { if (x < 0) { new ArgumentOutOfRangeException(nameof(x)); } } }",
            good: "class A { void F(int x) { if (x < 0) { throw new ArgumentOutOfRangeException(nameof(x)); } } }",
        }),
    },
    Rule {
        id: "cs/overwritten-element",
        name: "Collection elements should not be overwritten right away",
        description: "Writing the same index or key twice in a row discards the first value; a different index \
                      was probably meant.",
        message: "Remove the first assignment, or correct the index.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4143")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block (expression_statement (assignment_expression left: (element_access_expression)))) @match",
            filter: Some(Find(overwritten_element)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int[] a) { a[0] = 1; a[0] = 2; } }",
            good: "class A { void F(int[] a) { a[0] = 1; a[1] = 2; } }",
        }),
    },
    Rule {
        id: "cs/task-returns-null",
        name: "Methods returning Task should not return null",
        description: "Callers await the result, and awaiting null throws a NullReferenceException.",
        message: "Return Task.CompletedTask or Task.FromResult(...) instead of null.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4586")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration returns: [(identifier) (generic_name) (qualified_name)]) @match",
            filter: Some(Find(task_null)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Task Save() { if (done) { return null; } return Write(); } }",
            good: "class A { Task Save() { if (done) { return Task.CompletedTask; } return Write(); } }",
        }),
    },
    Rule {
        id: "cs/only-private-constructors",
        name: "Classes should not have only private constructors and no way to create them",
        description: "With every constructor private and no static member or nested type to call one, nothing \
                      can create the class.",
        message: "Make a constructor accessible, or make the class static.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3453")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(uncreatable_class_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Config { private Config() { } public int Port { get; set; } }",
            good: "class Config { private Config() { } public static Config Default { get; } = new Config(); }",
        }),
    },
    Rule {
        id: "cs/to-char-array-in-foreach",
        name: "Strings should be iterated directly, not through ToCharArray()",
        description: "A string is already a sequence of characters; `ToCharArray()` copies it for nothing.",
        message: "Iterate the string itself and remove ToCharArray().",
        category: Bug,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3456")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(foreach_statement right: (invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list) @a
                        (#eq? @n "ToCharArray")) @match)"#,
            filter: Some(Keep(no_call_arguments)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(string s) { int n = 0; foreach (var c in s.ToCharArray()) { n += c; } return n; } }",
            good: "class A { int F(string s) { int n = 0; foreach (var c in s) { n += c; } return n; } }",
        }),
    },
];

// ---------------------------------------------------- helpers

/// The attributes on a declaration, by their simple name.
pub(super) fn attribute_names<'t, 's>(
    declaration: Node<'t>,
    src: &'s [u8],
) -> Vec<(Node<'t>, &'s [u8])> {
    let mut out = Vec::new();
    let mut cursor = declaration.walk();
    for list in declaration
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "attribute_list")
    {
        let mut inner = list.walk();
        for attr in list
            .named_children(&mut inner)
            .filter(|a| a.kind() == "attribute")
        {
            if let Some(name) = attr.child_by_field_name("name") {
                let n = simple_name(name, src);
                out.push((attr, n.strip_suffix(b"Attribute").unwrap_or(n)));
            }
        }
    }
    out
}

/// The attribute with this simple name (with or without `Attribute`).
pub(super) fn find_attribute<'t>(
    declaration: Node<'t>,
    name: &str,
    src: &[u8],
) -> Option<Node<'t>> {
    let mut cursor = declaration.walk();
    let lists: Vec<Node<'t>> = declaration
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "attribute_list")
        .collect();
    lists.into_iter().find_map(|list| {
        let mut inner = list.walk();
        let attrs: Vec<Node<'t>> = list.named_children(&mut inner).collect();
        attrs.into_iter().find(|a| {
            a.kind() == "attribute"
                && a.child_by_field_name("name").is_some_and(|n| {
                    let s = simple_name(n, src);
                    s == name.as_bytes() || s.strip_suffix(b"Attribute") == Some(name.as_bytes())
                })
        })
    })
}

/// An attribute's arguments: (name if `Name = value` or `name: value`, value).
pub(super) fn attribute_arguments<'t>(attribute: Node<'t>) -> Vec<(Option<Node<'t>>, Node<'t>)> {
    let mut cursor = attribute.walk();
    let Some(list) = attribute
        .named_children(&mut cursor)
        .find(|c| c.kind() == "attribute_argument_list")
    else {
        return Vec::new();
    };
    let mut inner = list.walk();
    let args: Vec<Node<'t>> = list
        .named_children(&mut inner)
        .filter(|a| a.kind() == "attribute_argument")
        .collect();
    args.into_iter()
        .filter_map(|a| {
            let name = a.child_by_field_name("name");
            let mut c = a.walk();
            let value = a
                .named_children(&mut c)
                .filter(|v| Some(*v) != name && v.kind() != "comment")
                .last()?;
            Some((name, value))
        })
        .collect()
}

/// A call's argument expressions, in order.
pub(super) fn cs_call_arguments<'t>(call: Node<'t>) -> Vec<Node<'t>> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    let args: Vec<Node<'t>> = list
        .named_children(&mut cursor)
        .filter(|a| a.kind() == "argument")
        .collect();
    // `this` and `base` are unnamed tokens: such an argument has no named
    // child, so it stands for itself and positions stay right.
    args.into_iter()
        .map(|a| {
            let mut c = a.walk();
            a.named_children(&mut c)
                .filter(|v| v.kind() != "comment" && Some(*v) != a.child_by_field_name("name"))
                .last()
                .unwrap_or(a)
        })
        .collect()
}

/// The integer value of a decimal, hex or binary literal.
pub(super) fn cs_integer(node: Node, src: &[u8]) -> Option<u64> {
    if node.kind() != "integer_literal" {
        return None;
    }
    let raw = String::from_utf8_lossy(text(node, src))
        .replace('_', "")
        .to_ascii_lowercase();
    let digits = raw.trim_end_matches(['u', 'l']);
    if let Some(hex) = digits.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = digits.strip_prefix("0b") {
        u64::from_str_radix(bin, 2).ok()
    } else {
        digits.parse().ok()
    }
}

fn type_members(body: Node) -> Vec<Node> {
    cs_statements(body)
}

fn parameter_count(method: Node) -> usize {
    method.child_by_field_name("parameters").map_or(0, |p| {
        let mut cursor = p.walk();
        p.named_children(&mut cursor)
            .filter(|c| c.kind() == "parameter")
            .count()
    })
}

fn method_named<'t>(
    members: &[Node<'t>],
    name: &[u8],
    params: usize,
    src: &[u8],
) -> Option<Node<'t>> {
    members.iter().copied().find(|m| {
        m.kind() == "method_declaration"
            && cs_has_modifier(*m, "override", src)
            && m.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == name)
            && parameter_count(*m) == params
    })
}

// ---------------------------------------------------- filters

fn unpaired_equality_override<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = type_members(declaration.child_by_field_name("body")?);
    let equals = method_named(&members, b"Equals", 1, src);
    let hash = method_named(&members, b"GetHashCode", 0, src);
    match (equals, hash) {
        (Some(m), None) | (None, Some(m)) => m.child_by_field_name("name"),
        _ => None,
    }
}

const LOOP_KINDS: &[&str] = &[
    "while_statement",
    "for_statement",
    "foreach_statement",
    "do_statement",
];

fn unconditional_loop_exit<'t>(node: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = node.child_by_field_name("body")?;
    let last = *cs_statements(body).last()?;
    if !matches!(
        last.kind(),
        "break_statement" | "return_statement" | "throw_statement"
    ) {
        return None;
    }
    // A `continue` for this loop (not a nested one) can start another round.
    let stops: Vec<&str> = CS_SCOPE_STOPS.iter().chain(LOOP_KINDS).copied().collect();
    let continues = find_in_scope(body, &stops, |n| {
        matches!(n.kind(), "continue_statement" | "goto_statement")
    })
    .is_some();
    (!continues).then_some(last)
}

fn creates_exception(node: Node, src: &[u8]) -> bool {
    node.child_by_field_name("type")
        .is_some_and(|t| simple_name(t, src).ends_with(b"Exception"))
}

fn creates_non_exception(node: Node, src: &[u8]) -> bool {
    !creates_exception(node, src) && !is_lambda_body(node)
}

/// `() => { new Parser("bad"); }`: the usual way to test that a
/// constructor throws, in Assert.Throws and its kin.
fn is_lambda_body(creation: Node) -> bool {
    let Some(block) = creation
        .parent()
        .and_then(|statement| statement.parent())
        .filter(|b| b.kind() == "block")
    else {
        return false;
    };
    cs_statements(block).len() == 1
        && block.parent().is_some_and(|f| {
            matches!(
                f.kind(),
                "lambda_expression" | "anonymous_method_expression"
            )
        })
}

fn passes_itself(node: Node, src: &[u8]) -> bool {
    let receiver = node
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("expression"));
    let args = cs_call_arguments(node);
    match (receiver, args.as_slice()) {
        (Some(r), [a]) => same_code(r, *a, src),
        _ => false,
    }
}

fn self_referencing_accessor<'t>(property: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // `int IShape.Size => Size;` reads the class's own Size, not itself.
    let mut cursor = property.walk();
    if property
        .named_children(&mut cursor)
        .any(|c| c.kind() == "explicit_interface_specifier")
    {
        return None;
    }
    let name = text(property.child_by_field_name("name")?, src);
    let is_self = |n: Node| {
        let t = text(n, src);
        t == name || t.strip_prefix(b"this.") == Some(name)
    };
    let returns_self = |body: Node<'t>| -> Option<Node<'t>> {
        match body.kind() {
            "arrow_expression_clause" => operand(body).filter(|e| is_self(*e)),
            "block" => {
                let stmts = cs_statements(body);
                match stmts.as_slice() {
                    [s] if s.kind() == "return_statement" => operand(*s).filter(|e| is_self(*e)),
                    _ => None,
                }
            }
            _ => None,
        }
    };
    let assigns_self = |body: Node<'t>| -> Option<Node<'t>> {
        let expr = match body.kind() {
            "arrow_expression_clause" => operand(body)?,
            "block" => match cs_statements(body).as_slice() {
                [s] if s.kind() == "expression_statement" => operand(*s)?,
                _ => return None,
            },
            _ => return None,
        };
        (expr.kind() == "assignment_expression"
            && operator_text(expr, src) == b"="
            && expr.child_by_field_name("left").is_some_and(is_self))
        .then_some(expr)
    };
    // `int P => P;`. The same field holds an initializer (`= 5`).
    if let Some(value) = property
        .child_by_field_name("value")
        .filter(|v| v.kind() == "arrow_expression_clause")
    {
        return returns_self(value);
    }
    let accessors = property.child_by_field_name("accessors")?;
    let mut cursor = accessors.walk();
    let list: Vec<Node<'t>> = accessors
        .named_children(&mut cursor)
        .filter(|a| a.kind() == "accessor_declaration")
        .collect();
    list.into_iter().find_map(|accessor| {
        let body = accessor.child_by_field_name("body")?;
        match accessor.child_by_field_name("name").map(|k| text(k, src)) {
            Some(b"get") => returns_self(body),
            Some(b"set" | b"init") => assigns_self(body),
            _ => None,
        }
    })
}

fn condition_false_at_start<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let init = node.child_by_field_name("initializer")?;
    let mut cursor = init.walk();
    let declarators: Vec<Node> = init
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "variable_declarator")
        .collect();
    let [declarator] = declarators.as_slice() else {
        return None;
    };
    let counter = text(declarator.child_by_field_name("name")?, src);
    let mut c = declarator.walk();
    let start = declarator
        .named_children(&mut c)
        .filter(|v| v.kind() == "integer_literal")
        .last()
        .and_then(|v| cs_integer(v, src))?;
    let condition = node.child_by_field_name("condition")?;
    let left = condition.child_by_field_name("left")?;
    let right = condition.child_by_field_name("right")?;
    let op = operator_text(condition, src);
    let (bound, op) = if text(left, src) == counter {
        (cs_integer(right, src)?, op)
    } else if text(right, src) == counter {
        let flipped: &[u8] = match op {
            b"<" => b">",
            b"<=" => b">=",
            b">" => b"<",
            b">=" => b"<=",
            other => other,
        };
        (cs_integer(left, src)?, flipped)
    } else {
        return None;
    };
    let holds = match op {
        b"<" => start < bound,
        b"<=" => start <= bound,
        b">" => start > bound,
        b">=" => start >= bound,
        _ => return None,
    };
    (!holds).then_some(condition)
}

fn broken_format_string<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = call.child_by_field_name("function")?;
    let receiver = function.child_by_field_name("expression")?;
    let method = text(function.child_by_field_name("name")?, src);
    let receiver_name = simple_name(receiver, src);
    let applies = match method {
        b"Format" => matches!(receiver_name, b"string" | b"String"),
        b"Write" | b"WriteLine" => receiver_name == b"Console",
        _ => true, // AppendFormat
    };
    if !applies {
        return None;
    }
    let args = cs_call_arguments(call);
    // The format is the first argument, or the second after an IFormatProvider.
    let position = args
        .iter()
        .take(2)
        .position(|a| cs_string_value(*a, src).is_some())?;
    let format = args[position];
    let rest = &args[position + 1..];
    // Console.Write("{x}") with no arguments prints the braces as they are.
    if method != b"Format" && method != b"AppendFormat" && rest.is_empty() {
        return None;
    }
    // A single argument may be an object[] that supplies all of them.
    if let [only] = rest
        && matches!(
            only.kind(),
            "identifier"
                | "member_access_expression"
                | "invocation_expression"
                | "element_access_expression"
                | "array_creation_expression"
                | "implicit_array_creation_expression"
                | "collection_expression"
        )
    {
        return None;
    }
    let value = cs_string_value(format, src)?;
    let verbatim = format.kind() == "verbatim_string_literal";
    match max_placeholder(value, verbatim) {
        Err(()) => Some(format),
        Ok(Some(max)) if max >= rest.len() => Some(format),
        Ok(_) => None,
    }
}

/// The highest placeholder index in a composite format string, or Err for
/// an unbalanced brace. Escape sequences in a regular string literal are
/// left as they are: they can't produce braces.
fn max_placeholder(value: &[u8], _verbatim: bool) -> Result<Option<usize>, ()> {
    let mut max = None;
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'{' if value.get(i + 1) == Some(&b'{') => i += 2,
            b'}' if value.get(i + 1) == Some(&b'}') => i += 2,
            b'}' => return Err(()),
            b'{' => {
                let end = value[i..].iter().position(|&b| b == b'}').ok_or(())? + i;
                let inner = &value[i + 1..end];
                let index_part = inner
                    .split(|&b| b == b',' || b == b':')
                    .next()
                    .unwrap_or_default();
                let index: usize = std::str::from_utf8(index_part)
                    .ok()
                    .map(str::trim)
                    .and_then(|s| s.parse().ok())
                    .ok_or(())?;
                max = Some(max.map_or(index, |m: usize| m.max(index)));
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    Ok(max)
}

fn non_flag_member<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_attribute(declaration, "Flags", src)?;
    let body = declaration.child_by_field_name("body")?;
    let mut cursor = body.walk();
    let members: Vec<Node<'t>> = body
        .named_children(&mut cursor)
        .filter(|m| m.kind() == "enum_member_declaration")
        .collect();
    let mut previous: Option<u64> = None;
    for member in members {
        let value = match member.child_by_field_name("value") {
            // Combinations and shifts are fine; only literals are checked.
            Some(v) => cs_integer(v, src),
            None => Some(previous.map_or(0, |p| p.saturating_add(1))),
        };
        if let Some(v) = value
            && v != 0
            && !v.is_power_of_two()
        {
            return member.child_by_field_name("name");
        }
        previous = value;
    }
    None
}

fn locks_shared_object(node: Node, src: &[u8]) -> bool {
    let mut cursor = node.walk();
    let locked = node
        .named_children(&mut cursor)
        .find(|c| c.kind() != "block" && c.kind() != "comment");
    match locked {
        Some(e) => matches!(
            e.kind(),
            "typeof_expression" | "string_literal" | "verbatim_string_literal"
        ),
        // `this` is an unnamed token.
        None => {
            let mut cursor = node.walk();
            node.children(&mut cursor)
                .any(|c| !c.is_named() && text(c, src) == b"this")
        }
    }
}

fn compares_with_nan(node: Node, src: &[u8]) -> bool {
    let is_nan = |n: Option<Node>| {
        n.is_some_and(|n| {
            n.kind() == "member_access_expression"
                && matches!(
                    text(n, src),
                    b"double.NaN"
                        | b"float.NaN"
                        | b"Double.NaN"
                        | b"Single.NaN"
                        | b"System.Double.NaN"
                        | b"System.Single.NaN"
                )
        })
    };
    matches!(
        operator_text(node, src),
        b"==" | b"!=" | b"<" | b"<=" | b">" | b">="
    ) && (is_nan(node.child_by_field_name("left")) || is_nan(node.child_by_field_name("right")))
}

fn field_declarators(field: Node) -> Vec<Node> {
    let mut cursor = field.walk();
    let Some(declaration) = field
        .named_children(&mut cursor)
        .find(|c| c.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let mut inner = declaration.walk();
    declaration
        .named_children(&mut inner)
        .filter(|d| d.kind() == "variable_declarator")
        .collect()
}

/// A declarator's initial value: the named child after its name.
fn declarator_value(declarator: Node) -> Option<Node> {
    let name = declarator.child_by_field_name("name");
    let mut cursor = declarator.walk();
    declarator
        .named_children(&mut cursor)
        .filter(|c| {
            Some(*c) != name && c.kind() != "comment" && c.kind() != "bracketed_argument_list"
        })
        .last()
}

fn initialized_thread_static<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_attribute(field, "ThreadStatic", src)?;
    field_declarators(field)
        .into_iter()
        .find(|d| declarator_value(*d).is_some())
}

fn is_instance_thread_static(field: Node, src: &[u8]) -> bool {
    find_attribute(field, "ThreadStatic", src).is_some() && !cs_has_modifier(field, "static", src)
}

fn returns_disposed<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let returns_one_of = |scope: Node<'t>, names: &[&[u8]]| {
        find_in_scope(scope, CS_SCOPE_STOPS, |n| {
            n.kind() == "return_statement"
                && operand(n)
                    .is_some_and(|e| e.kind() == "identifier" && names.contains(&text(e, src)))
        })
    };
    let names_of = |declaration: Node| -> Vec<&[u8]> {
        let mut cursor = declaration.walk();
        declaration
            .named_children(&mut cursor)
            .filter(|d| d.kind() == "variable_declarator")
            .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
            .collect()
    };
    if node.kind() == "using_statement" {
        let mut cursor = node.walk();
        let declaration = node
            .named_children(&mut cursor)
            .find(|c| c.kind() == "variable_declaration")?;
        return returns_one_of(node.child_by_field_name("body")?, &names_of(declaration));
    }
    // `using var x = ...;` disposes x when the block ends.
    let stmts = cs_statements(node);
    for (i, stmt) in stmts.iter().enumerate() {
        if stmt.kind() != "local_declaration_statement" {
            continue;
        }
        let mut cursor = stmt.walk();
        let is_using = stmt
            .children(&mut cursor)
            .any(|c| !c.is_named() && text(c, src) == b"using");
        if !is_using {
            continue;
        }
        let mut cursor = stmt.walk();
        let Some(declaration) = stmt
            .named_children(&mut cursor)
            .find(|c| c.kind() == "variable_declaration")
        else {
            continue;
        };
        let names = names_of(declaration);
        for later in &stmts[i + 1..] {
            if later.kind() == "return_statement"
                && operand(*later)
                    .is_some_and(|e| e.kind() == "identifier" && names.contains(&text(e, src)))
            {
                return Some(*later);
            }
            if let Some(r) = returns_one_of(*later, &names) {
                return Some(r);
            }
        }
    }
    None
}

fn base_object_call<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let class = method.parent()?.parent()?;
    let mut cursor = class.walk();
    let derives = class
        .named_children(&mut cursor)
        .any(|c| c.kind() == "base_list");
    if derives
        || cs_has_modifier(class, "partial", src)
        || !cs_has_modifier(method, "override", src)
    {
        return None;
    }
    let name = text(method.child_by_field_name("name")?, src);
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                f.kind() == "member_access_expression"
                    && text(f, src).strip_prefix(b"base.") == Some(name)
            })
    })
}

fn reads_later_static_field<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if cs_has_modifier(declaration, "partial", src) {
        return None;
    }
    let members = type_members(declaration.child_by_field_name("body")?);
    // (name, declarator) of static, non-const fields, in declaration order.
    let fields: Vec<(&[u8], Node<'t>)> = members
        .iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && cs_has_modifier(**m, "static", src)
                && !cs_has_modifier(**m, "const", src)
        })
        .flat_map(|m| field_declarators(*m))
        .filter_map(|d| d.child_by_field_name("name").map(|n| (text(n, src), d)))
        .collect();
    for (i, (_, declarator)) in fields.iter().enumerate() {
        let Some(value) = declarator_value(*declarator) else {
            continue;
        };
        let later: Vec<&[u8]> = fields[i + 1..].iter().map(|(n, _)| *n).collect();
        if later.is_empty() {
            break;
        }
        // Lambdas run later, and `X.Name` names another type's member.
        let read = find_in_scope(value, CS_SCOPE_STOPS, |n| {
            n.kind() == "identifier"
                && later.contains(&text(n, src))
                && !n.parent().is_some_and(|p| {
                    p.kind() == "member_access_expression"
                        && p.child_by_field_name("name") == Some(n)
                })
        });
        let read = read.or_else(|| {
            (value.kind() == "identifier" && later.contains(&text(value, src))).then_some(value)
        });
        if read.is_some() {
            return read;
        }
    }
    None
}

const CALLER_INFO: &[&[u8]] = &[
    b"CallerMemberName",
    b"CallerFilePath",
    b"CallerLineNumber",
    b"CallerArgumentExpression",
];

fn misplaced_caller_info<'t>(list: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = list.walk();
    let params: Vec<Node<'t>> = list
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "parameter")
        .collect();
    let is_caller_info = |p: Node| {
        attribute_names(p, src)
            .iter()
            .any(|(_, n)| CALLER_INFO.contains(n))
    };
    let first = params.iter().position(|p| is_caller_info(*p))?;
    params[first..]
        .iter()
        .any(|p| !is_caller_info(*p))
        .then_some(params[first])
}

fn one_way_with_result<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let contract = find_attribute(method, "OperationContract", src)?;
    let one_way = attribute_arguments(contract).iter().any(|(name, value)| {
        name.is_some_and(|n| text(n, src) == b"IsOneWay") && text(*value, src) == b"true"
    });
    let returns = method.child_by_field_name("returns")?;
    (one_way && text(returns, src) != b"void").then(|| method.child_by_field_name("name"))?
}

fn pure_void_name<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_attribute(method, "Pure", src)?;
    if method.child_by_field_name("returns").map(|r| text(r, src)) != Some(b"void") {
        return None;
    }
    // `out` and `ref` parameters are how such a method returns results.
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let has_out = params.named_children(&mut cursor).any(|p| {
        let mut c = p.walk();
        p.named_children(&mut c)
            .any(|m| m.kind() == "modifier" && matches!(text(m, src), b"out" | b"ref"))
    });
    (!has_out).then(|| method.child_by_field_name("name"))?
}

fn global_type_name<'t>(unit: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut cursor = unit.walk();
    let children: Vec<Node<'t>> = unit.named_children(&mut cursor).collect();
    // A file-scoped namespace holds the types after it; top-level statements
    // make a program, where global types are normal.
    if children.iter().any(|c| {
        matches!(
            c.kind(),
            "file_scoped_namespace_declaration" | "global_statement"
        )
    }) {
        return None;
    }
    children
        .into_iter()
        .find(|c| {
            matches!(
                c.kind(),
                "class_declaration"
                    | "struct_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "record_declaration"
                    | "delegate_declaration"
            )
        })
        .and_then(|c| c.child_by_field_name("name"))
}

fn bad_serialization_callback<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let is_callback = attribute_names(method, src).iter().any(|(_, n)| {
        matches!(
            *n,
            b"OnSerializing" | b"OnSerialized" | b"OnDeserializing" | b"OnDeserialized"
        )
    });
    if !is_callback {
        return None;
    }
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let types: Vec<&[u8]> = params
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "parameter")
        .map(|p| {
            p.child_by_field_name("type")
                .map_or(&b""[..], |t| simple_name(t, src))
        })
        .collect();
    let good = !cs_has_modifier(method, "public", src)
        && method.child_by_field_name("returns").map(|r| text(r, src)) == Some(b"void")
        && method.child_by_field_name("type_parameters").is_none()
        && types == [b"StreamingContext"];
    (!good).then(|| method.child_by_field_name("name"))?
}

fn overwritten_element<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let target = |stmt: Node<'t>| -> Option<(Node<'t>, Node<'t>)> {
        let assignment = operand(stmt).filter(|a| a.kind() == "assignment_expression")?;
        if operator_text(assignment, src) != b"=" {
            return None;
        }
        let left = assignment
            .child_by_field_name("left")
            .filter(|l| l.kind() == "element_access_expression")?;
        Some((left, assignment.child_by_field_name("right")?))
    };
    let stmts = cs_statements(block);
    for pair in stmts.windows(2) {
        let (Some((first, _)), Some((second, value))) = (target(pair[0]), target(pair[1])) else {
            continue;
        };
        let index_has_effects = find_in_scope(first, &[], |n| {
            matches!(
                n.kind(),
                "invocation_expression"
                    | "postfix_unary_expression"
                    | "prefix_unary_expression"
                    | "assignment_expression"
            )
        })
        .is_some();
        let reads_it = {
            let t = text(first, src);
            text(value, src).windows(t.len()).any(|w| w == t)
        };
        if same_code(first, second, src) && !index_has_effects && !reads_it {
            return Some(pair[1]);
        }
    }
    None
}

fn task_null<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let returns = method.child_by_field_name("returns")?;
    if simple_name(returns, src) != b"Task" || cs_has_modifier(method, "async", src) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    if body.kind() == "arrow_expression_clause" {
        return operand(body).filter(|e| e.kind() == "null_literal");
    }
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "return_statement" && operand(n).is_some_and(|e| e.kind() == "null_literal")
    })
}

fn uncreatable_class_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if ["static", "abstract", "partial"]
        .iter()
        .any(|m| cs_has_modifier(class, m, src))
    {
        return None;
    }
    let mut cursor = class.walk();
    if class
        .named_children(&mut cursor)
        .any(|c| matches!(c.kind(), "parameter_list" | "attribute_list"))
    {
        // A primary constructor, or an attribute (serializers and DI create
        // classes through reflection).
        return None;
    }
    let members = type_members(class.child_by_field_name("body")?);
    let constructors: Vec<&Node> = members
        .iter()
        .filter(|m| m.kind() == "constructor_declaration" && !cs_has_modifier(**m, "static", src))
        .collect();
    // An attribute such as [JsonConstructor] means a serializer calls it.
    let all_private = !constructors.is_empty()
        && constructors.iter().all(|c| {
            let mut cursor = c.walk();
            let has_attribute = c
                .named_children(&mut cursor)
                .any(|a| a.kind() == "attribute_list");
            !has_attribute
                && !["public", "protected", "internal"]
                    .iter()
                    .any(|m| cs_has_modifier(**c, m, src))
        });
    let has_way_in = members.iter().any(|m| {
        cs_has_modifier(*m, "static", src)
            || matches!(
                m.kind(),
                "class_declaration"
                    | "struct_declaration"
                    | "record_declaration"
                    | "interface_declaration"
            )
    });
    (all_private && !has_way_in).then(|| class.child_by_field_name("name"))?
}

fn no_call_arguments(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0)
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;
    use super::max_placeholder;

    fn method(body: &str) -> String {
        format!("namespace N;\nclass A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn equality_pairs() {
        let src = "namespace N;\nclass A { public override bool Equals(object o) => true; }\nclass B { public override int GetHashCode() => 1; }\nclass C { public override bool Equals(object o) => true; public override int GetHashCode() => 1; }\nclass D { public bool Equals(D o) => true; }";
        assert_eq!(flagged("cs/equals-without-hashcode", src), [2, 3]);
    }

    #[test]
    fn single_iteration_loops() {
        let src = method(
            "foreach (var x in xs) { G(x); break; }\nwhile (a) { if (b) continue; return; }\nfor (;;) { foreach (var y in ys) { continue; } throw new E(); }\nwhile (a) { G(); }\nwhile (a) { if (b) break; }",
        );
        assert_eq!(flagged("cs/single-iteration-loop", &src), [4, 6]);
    }

    #[test]
    fn dropped_objects() {
        let src = method(
            "new Report();\nnew InvalidOperationException();\nvar r = new Report();\nthrow new E();\nAssert.Throws<E>(() => { new Report(null); });",
        );
        assert_eq!(flagged("cs/unused-new-object", &src), [4]);
        assert_eq!(flagged("cs/exception-not-thrown", &src), [5]);
    }

    #[test]
    fn collections_and_properties() {
        let src = "namespace N;\nclass A {\nvoid F() { xs.AddRange(xs); xs.AddRange(ys); }\nint P { get { return P; } }\nint Q { get => q; set => Q = value; }\nint R => R;\nint S { get => this.S; }\nint T { get => t; set { t = value; } }\nint I.U => U;\n}";
        assert_eq!(flagged("cs/collection-own-argument", src), [3]);
        assert_eq!(flagged("cs/self-referencing-property", src), [4, 5, 6, 7]);
    }

    #[test]
    fn loops_that_never_run() {
        let src = method(
            "for (int i = 10; i < 5; i++) { }\nfor (int i = 0; i > 5; i--) { }\nfor (int i = 0; 5 < i; i++) { }\nfor (int i = 0; i < 5; i++) { }\nfor (int i = 0; i < n; i++) { }",
        );
        assert_eq!(flagged("cs/for-loop-never-runs", &src), [4, 5, 6]);
    }

    #[test]
    fn format_strings() {
        assert_eq!(max_placeholder(b"{0} {1,5:N2} {{x}}", false), Ok(Some(1)));
        assert_eq!(max_placeholder(b"{0", false), Err(()));
        assert_eq!(max_placeholder(b"a } b", false), Err(()));
        assert_eq!(max_placeholder(b"no holes", false), Ok(None));
        let src = method(
            "string.Format(\"{0} {1} {2}\", a, b);\nstring.Format(\"{0} {1}\", a, b);\nstring.Format(CultureInfo.InvariantCulture, \"{1}\", 1);\nstring.Format(\"{0} {1}\", args);\nConsole.WriteLine(\"{0}\");\nConsole.WriteLine(\"{1}\", x, y);\nsb.AppendFormat(\"{0} }\", a, b);\nlogger.Format(\"{5}\", a);\nstring.Format(\"{x}\", a, b);",
        );
        assert_eq!(flagged("cs/format-string-arguments", &src), [4, 6, 10, 12]);
    }

    #[test]
    fn flags_enums() {
        let src = "namespace N;\n[Flags] enum A { None, Read, Write, Both }\n[Flags] enum B { None = 0, X = 1, Y = 0x2, Z = 0b100, Both = X | Y }\n[Flags] enum C { X = 3 }\nenum D { A, B, C, E }\n[System.FlagsAttribute] enum E { A = 1, B = 2, C }";
        assert_eq!(flagged("cs/flags-enum-values", src), [2, 4, 6]);
    }

    #[test]
    fn locks_and_nan() {
        let src = method(
            "lock (this) { }\nlock (typeof(A)) { }\nlock (\"k\") { }\nlock (sync) { }\nb = d == double.NaN;\nb = d != float.NaN;\nb = double.IsNaN(d);",
        );
        assert_eq!(flagged("cs/lock-on-shared-object", &src), [4, 5, 6]);
        assert_eq!(flagged("cs/nan-comparison", &src), [8, 9]);
    }

    #[test]
    fn thread_static_fields() {
        let src = "namespace N;\nclass A {\n[ThreadStatic] static int a = 1;\n[ThreadStatic] static int b;\n[ThreadStatic] int c;\n[ThreadStaticAttribute] static int d, e = 2;\n}";
        assert_eq!(flagged("cs/thread-static-initializer", src), [3, 6]);
        assert_eq!(flagged("cs/thread-static-instance-field", src), [5]);
    }

    #[test]
    fn disposed_returns() {
        let src = method(
            "using (var s = Open()) { return s; }\nusing (var t = Open()) { return t.Length; }\nusing var u = Open();\nif (a) { return u; }\nvar v = Open();\nreturn v;",
        );
        assert_eq!(flagged("cs/returned-disposed", &src), [4, 7]);
    }

    #[test]
    fn base_object_equality() {
        let src = "namespace N;\nclass A { public override int GetHashCode() { return base.GetHashCode(); } }\nclass B : C { public override int GetHashCode() { return base.GetHashCode(); } }\nclass D { public override bool Equals(object o) => base.Equals(o); }\npartial class E { public override int GetHashCode() => base.GetHashCode(); }";
        assert_eq!(flagged("cs/base-object-equality", src), [2, 4]);
    }

    #[test]
    fn static_field_order() {
        let src = "namespace N;\nclass A {\nstatic int B = C + 1;\nstatic int C = 1;\nstatic int D = X.C;\nstatic Func<int> E = () => G;\nstatic int G = 2;\nconst int H = I;\nconst int I = 1;\n}\nclass B {\nstatic int J = K;\nstatic int K = 1;\n}";
        assert_eq!(flagged("cs/static-field-order", src), [3, 12]);
    }

    #[test]
    fn caller_info_and_contracts() {
        let src = "namespace N;\ninterface S {\nvoid A([CallerMemberName] string m = \"\", int x = 0);\nvoid B(int x, [CallerMemberName] string m = \"\", [CallerFilePath] string f = \"\");\n[OperationContract(IsOneWay = true)] int C();\n[OperationContract(IsOneWay = true)] void D();\n[OperationContract] int E();\n[Pure] void F(int x);\n[Pure] void G(out int x);\n[Pure] int H();\n}";
        assert_eq!(flagged("cs/caller-info-parameter-position", src), [3]);
        assert_eq!(flagged("cs/one-way-returns-value", src), [5]);
        assert_eq!(flagged("cs/pure-void-method", src), [8]);
    }

    #[test]
    fn handles_and_namespaces() {
        assert_eq!(
            flagged(
                "cs/dangerous-get-handle",
                &method("var p = h.DangerousGetHandle();")
            ),
            [4]
        );
        assert_eq!(
            flagged("cs/type-outside-namespace", "class A { }\nclass B { }"),
            [1]
        );
        assert!(flagged("cs/type-outside-namespace", "namespace N { class A { } }").is_empty());
        assert!(flagged("cs/type-outside-namespace", "namespace N;\nclass A { }").is_empty());
        assert!(flagged("cs/type-outside-namespace", "Run();\nclass A { }").is_empty());
    }

    #[test]
    fn serialization_callbacks() {
        let src = "namespace N;\nclass A {\n[OnDeserialized] public void A1(StreamingContext c) { }\n[OnDeserialized] void A2() { }\n[OnSerializing] int A3(StreamingContext c) => 0;\n[OnSerialized] void A4(StreamingContext c) { }\n[OnDeserializing] private void A5(System.Runtime.Serialization.StreamingContext c) { }\n}";
        assert_eq!(
            flagged("cs/serialization-callback-signature", src),
            [3, 4, 5]
        );
    }

    #[test]
    fn overwritten_elements() {
        let src = method(
            "a[0] = 1;\na[0] = 2;\nd[k] = 1;\nd[k] = d[k] + 1;\nb[i++] = 1;\nb[i++] = 2;\nc[0] = 1;\nG();\nc[0] = 2;",
        );
        assert_eq!(flagged("cs/overwritten-element", &src), [5]);
    }

    #[test]
    fn task_nulls() {
        let src = "namespace N;\nclass A {\nTask F() { return null; }\nTask<int> G() => null;\nasync Task H() { return; }\nTask I() { Func<string> f = () => null; return Task.CompletedTask; }\nSystem.Threading.Tasks.Task J() { return null; }\nstring K() { return null; }\n}";
        assert_eq!(flagged("cs/task-returns-null", src), [3, 4, 7]);
    }

    #[test]
    fn private_constructors() {
        let src = "namespace N;\nclass A { private A() { } }\nclass B { B() { } int X; }\nclass C { private C() { } public static C Make() => new C(); }\nclass D { private D() { } class Inner { } }\nstatic class E { }\nclass F { public F() { } }\n[Serializable] class G { private G() { } }\nclass H { private H() { } public H(int x) { } }\nclass J { [JsonConstructor] private J(int x) { } }";
        assert_eq!(flagged("cs/only-private-constructors", src), [2, 3]);
    }

    #[test]
    fn char_arrays() {
        let src = method(
            "foreach (var c in s.ToCharArray()) { }\nforeach (var c in s) { }\nforeach (var c in s.ToCharArray(0, 2)) { }",
        );
        assert_eq!(flagged("cs/to-char-array-in-foreach", &src), [4]);
    }
}
