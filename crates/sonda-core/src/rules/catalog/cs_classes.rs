//! C# rules about classes and their members, batch 12 (ADR-0007, ADR-0015):
//! overrides and the declarations they override, instance members, the
//! dispose pattern, controllers. Built on the C# semantic model
//! (`semantic/cs.rs`). Rules that compare a declaration with its base types
//! or interfaces are `Check::Structural`: they run on the project index,
//! across files (`cs_project.rs`, ADR-0020). The others here see one file,
//! so those that need another file's types are `related` to their key.
//! Queries stay cheap on deep trees: see the notes in `js_modern.rs`.

use super::cs::{cs_has_modifier, simple_name};
use super::cs_bugs::{attribute_names, cs_call_arguments};
use super::cs_more::members;
use super::cs_types::walk_tree;
use super::java_bugs::find_in_scope;
use super::java_security::{contains_ignoring_case, text};
use super::java_smells::count_word;
use super::*;
use crate::semantic::{DeclId, DeclKind, Model, ScopeId, ScopeKind};
use std::collections::HashMap;

/// Rules that are off unless `rules.enabled` lists them: the one whose key
/// is outside SonarQube's default profile.
pub(super) static OFF_BY_DEFAULT: &[&str] = &["cs/equality-on-equals-type"];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/readonly-generic-field-member-assignment",
        name: "Members of readonly fields of unconstrained generic types should not be assigned",
        description: "If the type argument is a struct, `field.X = 1` sets X on a copy of the readonly field and \
                      is lost.",
        message: "Constrain the type parameter to a class, or don't assign through this readonly field.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2934")],
        check: Check::Semantic {
            langs: CSHARP,
            find: assigns_through_readonly_generic,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Mover<T> where T : IPoint { readonly T point; public Mover(T p) { point = p; } public void Move() { point.X = 1; } }",
            good: "class Mover<T> where T : class, IPoint { readonly T point; public Mover(T p) { point = p; } public void Move() { point.X = 1; } }",
        }),
    },
    Rule {
        id: "cs/shared-part-created-with-new",
        name: "Shared MEF parts should not be created with new",
        description: "A part marked CreationPolicy.Shared is meant to have one instance from the container; \
                      `new` creates another one outside it.",
        message: "Get this shared part from the composition container.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4277")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Export(typeof(IFoo))] [PartCreationPolicy(CreationPolicy.Shared)] class Foo : IFoo { }\nclass P { void F() { var f = new Foo(); } }",
            good: "[Export(typeof(IFoo))] [PartCreationPolicy(CreationPolicy.Shared)] class Foo : IFoo { }\nclass P { void F(IServiceProvider s) { var f = s.GetService(typeof(IFoo)); } }",
        }),
    },
    // ---- Vulnerabilities ----
    Rule {
        id: "cs/deserialization-skips-validation",
        name: "Serializable classes should validate data during deserialization",
        description: "Deserialization doesn't run the regular constructor, so checks done there are bypassed \
                      by a crafted payload unless the deserialization path repeats them.",
        message: "Repeat the constructor's validation in the deserialization path.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S5766")],
        check: Check::Semantic {
            langs: CSHARP,
            find: deserialization_without_validation,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Serializable] class Url : ISerializable { string url; public Url(string u) { if (!u.StartsWith(\"https://\")) { throw new ArgumentException(); } url = u; } protected Url(SerializationInfo info, StreamingContext c) { url = info.GetString(\"url\"); } }",
            good: "[Serializable] class Url : ISerializable { string url; public Url(string u) { if (!u.StartsWith(\"https://\")) { throw new ArgumentException(); } url = u; } protected Url(SerializationInfo info, StreamingContext c) { url = info.GetString(\"url\"); if (!url.StartsWith(\"https://\")) { throw new SerializationException(); } } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/deep-inheritance",
        name: "Inheritance trees should not be too deep",
        description: "Each level of inheritance is more behavior to understand before changing a class; past \
                      five, composition usually fits better.",
        message: "Reduce this class's inheritance depth; it has more than 5 base classes.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[exact("S110")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A1 { } class A2 : A1 { } class A3 : A2 { } class A4 : A3 { } class A5 : A4 { } class A6 : A5 { } class A7 : A6 { }",
            good: "class A1 { } class A2 : A1 { }",
        }),
    },
    Rule {
        id: "cs/parameter-name-mismatch",
        name: "Parameter names should match the declaration they implement",
        description: "Callers using named arguments see the base declaration's names; a different name in an \
                      override or implementation confuses them.",
        message: "Use the parameter name of the declaration this implements.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S927")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "interface IAccount { void Add(int money); } class Account : IAccount { public void Add(int amount) { } }",
            good: "interface IAccount { void Add(int money); } class Account : IAccount { public void Add(int money) { } }",
        }),
    },
    Rule {
        id: "cs/override-changes-default",
        name: "Overrides should not change parameter defaults",
        description: "Defaults come from the static type: the same call passes different values depending on \
                      whether the variable is typed as the base or the derived class.",
        message: "Use the same default value as the base declaration.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1006")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Base { public virtual void Run(int distance = 42) { } } class Derived : Base { public override void Run(int distance = 5) { } }",
            good: "class Base { public virtual void Run(int distance = 42) { } } class Derived : Base { public override void Run(int distance = 42) { } }",
        }),
    },
    Rule {
        id: "cs/argument-order",
        name: "Arguments should be passed in the order of the parameters they're named after",
        description: "`Divide(dividend, divisor)` to a method declared `Divide(divisor, dividend)` is almost \
                      certainly swapped.",
        message: "Check the order of these arguments: they match parameter names in another order.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S2234")],
        check: Check::Semantic {
            langs: CSHARP,
            find: arguments_swapped,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { double Divide(int divisor, int dividend) => divisor / dividend; void F(int divisor, int dividend) { Divide(dividend, divisor); } }",
            good: "class A { double Divide(int divisor, int dividend) => divisor / dividend; void F(int divisor, int dividend) { Divide(divisor, dividend); } }",
        }),
    },
    Rule {
        id: "cs/could-be-static",
        name: "Methods and properties that don't use instance data should be static",
        description: "Making them static shows they don't depend on the object's state, and saves the hidden \
                      `this` argument.",
        message: "Make this member static.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2325")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::could_be_static,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private int Sum(int a, int b) { return a + b; } }",
            good: "class A { private static int Sum(int a, int b) { return a + b; } }",
        }),
    },
    Rule {
        id: "cs/inner-member-shadows-outer",
        name: "Nested type members should not shadow the outer type's static members",
        description: "Inside the nested type, the name means its own member, which readers may take for the \
                      outer one.",
        message: "Rename this member; it shadows a static member of the outer type.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S3218")],
        check: Check::Semantic {
            langs: CSHARP,
            find: shadows_outer_static,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Outer { public static int A; class Inner { public int A; } }",
            good: "class Outer { public static int A; class Inner { public int B; } }",
        }),
    },
    Rule {
        id: "cs/unused-private-return",
        name: "Private methods should not return values that no caller uses",
        description: "When every call discards the result, the return value is dead code.",
        message: "Make this method return void; no caller uses its result.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S3241")],
        check: Check::Semantic {
            langs: CSHARP,
            find: private_returns_unused,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private int Count() => 42; public void F() { Count(); } }",
            good: "class A { private void Count() { } public void F() { Count(); } }",
        }),
    },
    Rule {
        id: "cs/generic-variance",
        name: "Generic type parameters should be co- or contravariant when possible",
        description: "An interface or delegate that only returns T can be `out T`, and one that only takes T can \
                      be `in T`, so it converts like IEnumerable<T> and Action<T> do.",
        message: "Add 'out' or 'in' to this type parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3246")],
        check: Check::Semantic {
            langs: CSHARP,
            find: variance_possible,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "interface ISource<T> { T Next(); }",
            good: "interface ISource<out T> { T Next(); }",
        }),
    },
    Rule {
        id: "cs/override-without-params",
        name: "Overrides should keep params",
        description: "An override inherits `params` from the base declaration whether it says so or not; \
                      leaving it out misleads readers.",
        message: "Add 'params' to this parameter, as in the base declaration.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S3262")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Base { public virtual void Log(params string[] parts) { } } class Derived : Base { public override void Log(string[] parts) { } }",
            good: "class Base { public virtual void Log(params string[] parts) { } } class Derived : Base { public override void Log(params string[] parts) { } }",
        }),
    },
    Rule {
        id: "cs/override-adds-params",
        name: "Overrides should not add params",
        description: "`params` on an override has no effect: callers use the base declaration's signature.",
        message: "Remove 'params': the base declaration doesn't have it.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3600")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Base { public virtual void Log(string[] parts) { } } class Derived : Base { public override void Log(params string[] parts) { } }",
            good: "class Base { public virtual void Log(string[] parts) { } } class Derived : Base { public override void Log(string[] parts) { } }",
        }),
    },
    Rule {
        id: "cs/private-static-only-nested",
        name: "Private static methods only used by a nested type should move there",
        description: "The nested type has the same access to the outer type's static members, and the outer \
                      type gets smaller.",
        message: "Move this method into the nested type that uses it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3398")],
        check: Check::Semantic {
            langs: CSHARP,
            find: static_only_used_nested,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Outer { private static int Twice(int n) => n * 2; class Nested { int F() => Twice(2); } }",
            good: "class Outer { class Nested { private static int Twice(int n) => n * 2; int F() => Twice(2); } }",
        }),
    },
    Rule {
        id: "cs/interface-colliding-members",
        name: "Interfaces should not inherit colliding members without resolving them",
        description: "Two base interfaces with a member of the same name make every use through the derived \
                      interface ambiguous (CS0229): callers must cast.",
        message: "Redeclare the colliding member in this interface with 'new'.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S3444")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "interface IA { int Id { get; } } interface IB { int Id { get; } } interface IC : IA, IB { }",
            good: "interface IA { int Id { get; } } interface IB { int Id { get; } } interface IC : IA, IB { new int Id { get; } }",
        }),
    },
    Rule {
        id: "cs/dispose-pattern",
        name: "IDisposable should be implemented with the dispose pattern",
        description: "A class that derived classes can extend needs `protected virtual Dispose(bool)`, called \
                      by a non-virtual Dispose() and by its finalizer, so each level releases its own \
                      resources once.",
        message: "Implement the dispose pattern: protected virtual Dispose(bool), called by Dispose() and the finalizer.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S3881")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class Holder : IDisposable { public virtual void Dispose() { } }",
            good: "public class Holder : IDisposable { public void Dispose() { Dispose(true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool disposing) { } }",
        }),
    },
    Rule {
        id: "cs/hiding-member-less-visible",
        name: "Inherited members should not be hidden by less visible ones",
        description: "A private method with a base method's signature hides it only inside the class; callers \
                      outside still reach the base method, which is confusing.",
        message: "Rename this method, or make it as visible as the base method.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4015")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Base { public void Run(int n) { } } class Derived : Base { private void Run(int n) { } }",
            good: "class Base { public void Run(int n) { } } class Derived : Base { private void RunLocally(int n) { } }",
        }),
    },
    Rule {
        id: "cs/base-method-hidden",
        name: "Base class methods should not be hidden by wider overloads",
        description: "A derived method taking `object` where the base takes `string` wins overload resolution \
                      for every derived instance, so the base method is never called.",
        message: "Rename this method, or make it an override.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4019")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Base { internal void Write(string s) { } } class Derived : Base { internal void Write(object o) { } }",
            good: "class Base { internal void Write(string s) { } } class Derived : Base { internal void WriteObject(object o) { } }",
        }),
    },
    Rule {
        id: "cs/durable-entity-interface",
        name: "Durable entity interfaces should follow the proxy restrictions",
        description: "Entity proxies only support interfaces of non-generic methods with at most one parameter, \
                      returning void, Task or Task<T>; anything else fails at run time.",
        message: "Change this member to fit the entity interface restrictions.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6424")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "interface ICounter { void Add(int a, int b); }\nclass F { Task G(IDurableEntityClient c, EntityId id) => c.SignalEntityAsync<ICounter>(id, x => x.Add(1, 2)); }",
            good: "interface ICounter { void Add(int amount); }\nclass F { Task G(IDurableEntityClient c, EntityId id) => c.SignalEntityAsync<ICounter>(id, x => x.Add(1)); }",
        }),
    },
    Rule {
        id: "cs/controller-mixed-responsibilities",
        name: "Controllers should not have mixed responsibilities",
        description: "When groups of actions use disjoint sets of injected services, the controller holds \
                      several unrelated responsibilities and can be split.",
        message: "Split this controller: its actions fall into groups that share no dependencies.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[related("S6960")],
        check: Check::Semantic {
            langs: CSHARP,
            find: controller_responsibilities,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class MediaController : ControllerBase { readonly IMovies movies; readonly IPhotos photos; public MediaController(IMovies m, IPhotos p) { movies = m; photos = p; } public IActionResult Movie() => Ok(movies.Get()); public IActionResult Photo() => Ok(photos.Get()); }",
            good: "public class MovieController : ControllerBase { readonly IMovies movies; public MovieController(IMovies m) { movies = m; } public IActionResult Movie() => Ok(movies.Get()); public IActionResult Trailer() => Ok(movies.Trailer()); }",
        }),
    },
    Rule {
        id: "cs/underposting-value-type",
        name: "Value-type properties of action models should be nullable or required",
        description: "When a client leaves a non-nullable int or bool out of the request, the model silently \
                      gets 0 or false; nullable, `required` or [JsonRequired] lets the server tell.",
        message: "Make this property nullable, required, or [JsonRequired].",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6964")],
        check: Check::Structural,
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class Order { public int Quantity { get; set; } }\npublic class OrdersController : ControllerBase { [HttpPost] public IActionResult Create(Order order) => Ok(); }",
            good: "public class Order { public required int Quantity { get; set; } }\npublic class OrdersController : ControllerBase { [HttpPost] public IActionResult Create(Order order) => Ok(); }",
        }),
    },
    Rule {
        id: "cs/equality-on-equals-type",
        name: "== should not compare values of a type that overrides Equals",
        description: "Without an == operator, == compares references even when the class defines value \
                      equality with Equals.",
        message: "Use Equals, or define the == operator.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1698")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::reference_equality_where_equals_overridden,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Money { public override bool Equals(object o) => true; public override int GetHashCode() => 0; }\nclass A { bool F(Money a, Money b) => a == b; }",
            good: "class Money { public override bool Equals(object o) => true; public override int GetHashCode() => 0; }\nclass A { bool F(Money a, Money b) => a.Equals(b); }",
        }),
    },
];

// ---------------------------------------------------- types in this file

/// Each type declared in the file, by name: several for partial types, or
/// one name declared in different namespaces.
fn type_index<'m, 't>(m: &'m Model<'t>) -> HashMap<&'m str, Vec<Node<'t>>> {
    let mut index: HashMap<&str, Vec<Node<'t>>> = HashMap::new();
    for d in m.decls.iter().filter(|d| d.kind == DeclKind::Class) {
        if let Some(declaration) = d.node.parent() {
            index.entry(d.name.as_str()).or_default().push(declaration);
        }
    }
    index
}

fn base_entries(declaration: Node) -> Vec<Node> {
    let mut cursor = declaration.walk();
    let Some(list) = declaration
        .named_children(&mut cursor)
        .find(|c| c.kind() == "base_list")
    else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c).collect()
}

fn looks_like_interface(name: &[u8]) -> bool {
    name.len() > 1 && name[0] == b'I' && name[1].is_ascii_uppercase()
}

/// A declaration's `<T, U>`: a field on some declarations, a plain child
/// on others.
fn type_parameters(declaration: Node) -> Option<Node> {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .find(|c| c.kind() == "type_parameter_list")
}

fn name_of<'s>(node: Node, src: &'s [u8]) -> &'s [u8] {
    node.child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src))
}

struct Param<'t> {
    name: Node<'t>,
    ty: Option<Node<'t>>,
    modifiers: Vec<u8>,
}

/// A method's parameters. `params T[] rest` keeps its type and name on the
/// list itself, after a `params` token.
fn params<'t>(method: Node<'t>, src: &[u8]) -> Vec<Param<'t>> {
    let mut out = Vec::new();
    let Some(list) = method.child_by_field_name("parameters") else {
        return out;
    };
    let mut cursor = list.walk();
    if !cursor.goto_first_child() {
        return out;
    }
    let mut ty = None;
    loop {
        let c = cursor.node();
        match cursor.field_name() {
            Some("type") => ty = Some(c),
            Some("name") => out.push(Param {
                name: c,
                ty: ty.take(),
                modifiers: b"params".to_vec(),
            }),
            _ if c.kind() == "parameter" => {
                if let Some(name) = c.child_by_field_name("name") {
                    let mut pc = c.walk();
                    let modifiers: Vec<u8> = c
                        .named_children(&mut pc)
                        .filter(|x| x.kind() == "modifier")
                        .flat_map(|x| text(x, src).iter().copied().chain(*b" "))
                        .collect();
                    out.push(Param {
                        name,
                        ty: c.child_by_field_name("type"),
                        modifiers,
                    });
                }
            }
            _ => {}
        }
        if !cursor.goto_next_sibling() {
            break;
        }
    }
    out
}

fn methods<'t>(declaration: Node<'t>) -> Vec<Node<'t>> {
    members(declaration)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .collect()
}

/// Classes, structs and records declared in the file.
fn classes<'t>(types: &HashMap<&str, Vec<Node<'t>>>) -> Vec<Node<'t>> {
    let mut all: Vec<Node<'t>> = types
        .values()
        .flatten()
        .copied()
        .filter(|d| {
            matches!(
                d.kind(),
                "class_declaration" | "struct_declaration" | "record_declaration"
            )
        })
        .collect();
    all.sort_by_key(Node::start_byte);
    all
}

// ---------------------------------------------------- filters

fn is_private(declaration: Node, src: &[u8]) -> bool {
    !["public", "protected", "internal"]
        .iter()
        .any(|v| cs_has_modifier(declaration, v, src))
}

/// The scope of the type member (method, accessor...) a scope is in: the
/// outermost function scope below a type scope. None for type-level code
/// such as field initializers.
fn member_scope(m: &Model, mut scope: ScopeId) -> Option<ScopeId> {
    let mut member = None;
    loop {
        if m.scopes[scope].kind == ScopeKind::Type || m.scopes[scope].kind == ScopeKind::Module {
            return member;
        }
        if m.scopes[scope].kind == ScopeKind::Function {
            member = Some(scope);
        }
        scope = m.scopes[scope].parent?;
    }
}

/// The references to each declaration, in source order.
fn refs_by_decl(m: &Model) -> Vec<Vec<usize>> {
    let mut by = vec![Vec::new(); m.decls.len()];
    for (i, r) in m.refs.iter().enumerate() {
        if let Some(d) = r.decl {
            by[d].push(i);
        }
    }
    by
}

fn arguments_swapped<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
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
        // A method of this type, not overloaded.
        let Some(target) = m
            .decl_of(function)
            .filter(|d| d.kind == DeclKind::Method && m.decls_named(d.scope, &d.name).len() == 1)
        else {
            return;
        };
        let Some(method) = target.declarator else {
            return;
        };
        let names: Vec<&[u8]> = params(method, src)
            .iter()
            .map(|p| text(p.name, src))
            .collect();
        let args = cs_call_arguments(call);
        if args.len() != names.len() || args.iter().any(|a| a.kind() != "identifier") {
            return;
        }
        let args: Vec<&[u8]> = args.iter().map(|a| text(*a, src)).collect();
        // An argument named after another position's parameter, whose own
        // parameter's name is among the arguments too: a swap.
        let swapped = args
            .iter()
            .enumerate()
            .any(|(i, a)| *a != names[i] && names.contains(a) && args.contains(&names[i]));
        if swapped {
            found.push(call);
        }
    });
    found
}

fn assigns_through_readonly_generic<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |node, ancestors| {
        if node.kind() != "assignment_expression" {
            return;
        }
        let Some(target) = node
            .child_by_field_name("left")
            .filter(|l| l.kind() == "member_access_expression")
            .and_then(|l| l.child_by_field_name("expression"))
        else {
            return;
        };
        let Some(field) = super::cs_types::decl(m, target).filter(|d| d.kind == DeclKind::Field)
        else {
            return;
        };
        let Some(ty) = field.ty.map(|t| text(t, src)) else {
            return;
        };
        let Some(declaration) = field
            .declarator
            .and_then(|d| d.parent())
            .and_then(|v| v.parent())
        else {
            return;
        };
        let Some(class) = declaration.parent().and_then(|l| l.parent()) else {
            return;
        };
        if !cs_has_modifier(declaration, "readonly", src) {
            return;
        }
        let type_parameter = type_parameters(class).is_some_and(|tp| {
            let mut c = tp.walk();
            tp.named_children(&mut c).any(|p| name_of(p, src) == ty)
        });
        // `where T : class` or a class constraint keeps T a reference type.
        let mut c = class.walk();
        let constrained = class
            .named_children(&mut c)
            .filter(|x| x.kind() == "type_parameter_constraints_clause")
            .filter(|x| x.named_child(0).is_some_and(|n| text(n, src) == ty))
            .any(|x| {
                let mut cc = x.walk();
                x.named_children(&mut cc).skip(1).any(|k| {
                    let t = text(k, src);
                    t == b"class"
                        || t.starts_with(b"class?")
                        || (!looks_like_interface(t)
                            && t != b"struct"
                            && t != b"notnull"
                            && t != b"new()"
                            && t != b"unmanaged")
                })
            });
        // Last, as it costs the node's depth: in a constructor, the readonly
        // field itself is assigned.
        if type_parameter
            && !constrained
            && !ancestors
                .iter()
                .any(|a| a.kind() == "constructor_declaration")
        {
            found.push(node);
        }
    });
    found
}

fn static_member_names<'s>(class: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names = Vec::new();
    for m in members(class) {
        let is_static = cs_has_modifier(m, "static", src) || cs_has_modifier(m, "const", src);
        match m.kind() {
            "field_declaration" if is_static => {
                names.extend(
                    super::cs_more::declarators(m)
                        .into_iter()
                        .filter_map(|d| d.child_by_field_name("name"))
                        .map(|n| text(n, src)),
                );
            }
            "property_declaration" | "method_declaration" | "event_declaration" if is_static => {
                names.push(name_of(m, src))
            }
            _ => {}
        }
    }
    names
}

fn shadows_outer_static<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let types = type_index(m);
    let mut found = Vec::new();
    for outer in classes(&types) {
        let statics = static_member_names(outer, src);
        if statics.is_empty() {
            continue;
        }
        for inner in members(outer).into_iter().filter(|x| {
            matches!(
                x.kind(),
                "class_declaration" | "struct_declaration" | "record_declaration"
            )
        }) {
            for member in members(inner) {
                let names: Vec<Node<'t>> = match member.kind() {
                    "field_declaration" => super::cs_more::declarators(member)
                        .into_iter()
                        .filter_map(|d| d.child_by_field_name("name"))
                        .collect(),
                    "property_declaration" | "method_declaration" | "event_declaration" => {
                        member.child_by_field_name("name").into_iter().collect()
                    }
                    _ => Vec::new(),
                };
                // `public Address Address`: a member named after its own type,
                // a nested type of the outer one, is C#'s usual idiom.
                let own_type = member
                    .child_by_field_name("type")
                    .or_else(|| super::cs_more::declared_type(member))
                    .or_else(|| member.child_by_field_name("returns"))
                    .map(|t| simple_name(t, src));
                found.extend(names.into_iter().filter(|n| {
                    let name = text(*n, src);
                    statics.contains(&name) && name != name_of(inner, src) && own_type != Some(name)
                }));
            }
        }
    }
    found
}

fn private_returns_unused<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let by_decl = refs_by_decl(m);
    let types = type_index(m);
    m.decls
        .iter()
        .enumerate()
        .filter(|(i, d)| {
            let Some(method) = d.declarator.filter(|_| d.kind == DeclKind::Method) else {
                return false;
            };
            let returns = d.ty.map_or(&b"void"[..], |t| simple_name(t, src));
            if matches!(
                returns,
                b"void"
                    | b"Task"
                    | b"ValueTask"
                    | b"IEnumerable"
                    | b"IEnumerator"
                    | b"IAsyncEnumerable"
            ) || !is_private(method, src)
                || ["override", "virtual", "abstract", "partial", "extern"]
                    .iter()
                    .any(|w| cs_has_modifier(method, w, src))
                || by_decl[*i].is_empty()
                || m.decls_named(d.scope, &d.name).len() > 1
            {
                return false;
            }
            let class = method.parent().and_then(|l| l.parent());
            if class.is_none_or(|c| {
                cs_has_modifier(c, "partial", src)
                    || types
                        .get(std::str::from_utf8(name_of(c, src)).unwrap_or_default())
                        .is_some_and(|p| p.len() > 1)
            }) {
                return false;
            }
            // Every use is a call whose result is dropped.
            by_decl[*i].iter().all(|r| {
                let name = m.refs[*r].node;
                let callee = name
                    .parent()
                    .filter(|p| p.kind() == "member_access_expression")
                    .unwrap_or(name);
                callee.parent().is_some_and(|call| {
                    call.kind() == "invocation_expression"
                        && call.child_by_field_name("function") == Some(callee)
                        && call
                            .parent()
                            .is_some_and(|s| s.kind() == "expression_statement")
                })
            })
        })
        .filter_map(|(_, d)| d.ty)
        .collect()
}

/// How a type parameter is used in a member signature: only as the result,
/// only as an input, or otherwise.
#[derive(Clone, Copy, PartialEq)]
enum Use {
    Output,
    Input,
    Other,
}

fn variance_possible<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |declaration, _| {
        if !matches!(
            declaration.kind(),
            "interface_declaration" | "delegate_declaration"
        ) {
            return;
        }
        let Some(list) = type_parameters(declaration) else {
            return;
        };
        let mut c = list.walk();
        let candidates: Vec<Node<'t>> = list
            .named_children(&mut c)
            .filter(|p| {
                p.kind() == "type_parameter"
                    && !matches!(
                        text(*p, src).split(|b| *b == b' ').next(),
                        Some(b"in" | b"out")
                    )
            })
            .collect();
        for candidate in candidates {
            let t = name_of(candidate, src);
            let mut uses: Vec<Use> = Vec::new();
            let classify = |ty: Node, output: bool, uses: &mut Vec<Use>| {
                let n = count_word(text(ty, src), t);
                if n == 0 {
                    return;
                }
                let bare = text(ty, src) == t;
                uses.push(match (bare, output) {
                    (true, true) => Use::Output,
                    (true, false) => Use::Input,
                    _ => Use::Other,
                });
                for _ in 1..n {
                    uses.push(Use::Other);
                }
            };
            // Every mention of T outside these signature positions makes it
            // invariant: base interfaces, constraints, nested generics.
            let mut counted = 0;
            let signatures: Vec<Node<'t>> = if declaration.kind() == "delegate_declaration" {
                vec![declaration]
            } else {
                members(declaration)
            };
            for member in &signatures {
                match member.kind() {
                    "method_declaration" | "delegate_declaration" => {
                        if *member != declaration && type_parameters(*member).is_some() {
                            uses.push(Use::Other);
                        }
                        let result = member
                            .child_by_field_name("returns")
                            .or_else(|| member.child_by_field_name("type"));
                        if let Some(r) = result {
                            classify(r, true, &mut uses);
                            counted += count_word(text(r, src), t);
                        }
                        for p in params(*member, src) {
                            let Some(ty) = p.ty else { continue };
                            counted += count_word(text(ty, src), t);
                            if p.modifiers.windows(3).any(|w| w == b"ref" || w == b"out")
                                || contains_ignoring_case(&p.modifiers, b"in ")
                            {
                                if count_word(text(ty, src), t) > 0 {
                                    uses.push(Use::Other);
                                }
                            } else {
                                classify(ty, false, &mut uses);
                            }
                        }
                    }
                    "property_declaration" => {
                        if let Some(ty) = member.child_by_field_name("type") {
                            let settable =
                                member.child_by_field_name("accessors").is_some_and(|a| {
                                    count_word(text(a, src), b"set") > 0
                                        || count_word(text(a, src), b"init") > 0
                                });
                            counted += count_word(text(ty, src), t);
                            if settable {
                                if count_word(text(ty, src), t) > 0 {
                                    uses.push(Use::Other);
                                }
                            } else {
                                classify(ty, true, &mut uses);
                            }
                        }
                    }
                    _ => {}
                }
            }
            let total = count_word(text(declaration, src), t).saturating_sub(1);
            if total == 0 || counted != total {
                continue;
            }
            if uses.iter().all(|u| *u == Use::Output) || uses.iter().all(|u| *u == Use::Input) {
                found.push(candidate);
            }
        }
    });
    found
}

fn static_only_used_nested<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let by_decl = refs_by_decl(m);
    m.decls
        .iter()
        .enumerate()
        .filter(|(i, d)| {
            if d.kind != DeclKind::Method || !d.is_static || by_decl[*i].is_empty() {
                return false;
            }
            if !d.declarator.is_some_and(|method| is_private(method, src)) {
                return false;
            }
            by_decl[*i].iter().all(|r| {
                // The type the reference is written in.
                let mut scope = m.refs[*r].scope;
                loop {
                    if m.scopes[scope].kind == ScopeKind::Type {
                        break;
                    }
                    match m.scopes[scope].parent {
                        Some(p) => scope = p,
                        None => return false,
                    }
                }
                scope != d.scope && m.within(scope, d.scope)
            })
        })
        .map(|(_, d)| d.node)
        .collect()
}

/// A parameter list's types, as written.
fn signature<'s>(method: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    params(method, src)
        .iter()
        .map(|p| p.ty.map_or(&b""[..], |t| text(t, src)))
        .collect()
}

fn validates(body: Node) -> bool {
    find_in_scope(body, &[], |n| {
        matches!(n.kind(), "throw_statement" | "throw_expression")
    })
    .is_some()
}

fn deserialization_without_validation<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let types = type_index(m);
    let mut found = Vec::new();
    for class in classes(&types) {
        if !attribute_names(class, src)
            .iter()
            .any(|(_, n)| matches!(*n, b"Serializable" | b"SerializableAttribute"))
        {
            continue;
        }
        let ctors: Vec<Node<'t>> = members(class)
            .into_iter()
            .filter(|x| x.kind() == "constructor_declaration")
            .collect();
        let is_deserializing = |c: &Node| {
            signature(*c, src)
                .first()
                .is_some_and(|t| simple_name_bytes(t) == b"SerializationInfo")
        };
        let validating = ctors
            .iter()
            .any(|c| !is_deserializing(c) && c.child_by_field_name("body").is_some_and(validates));
        let callback = members(class).iter().any(|x| {
            attribute_names(*x, src)
                .iter()
                .any(|(_, n)| n.starts_with(b"OnDeserializ"))
        }) || base_entries(class)
            .iter()
            .any(|b| simple_name(*b, src) == b"IDeserializationCallback");
        if !validating || callback {
            continue;
        }
        match ctors.iter().find(|c| is_deserializing(c)) {
            Some(c) if !c.child_by_field_name("body").is_some_and(validates) => {
                found.extend(c.child_by_field_name("name"))
            }
            Some(_) => {}
            // Without one, ISerializable classes can't be deserialized, and
            // the others are filled field by field.
            None if !base_entries(class)
                .iter()
                .any(|b| simple_name(*b, src) == b"ISerializable") =>
            {
                found.extend(class.child_by_field_name("name"))
            }
            None => {}
        }
    }
    found
}

fn simple_name_bytes(ty: &[u8]) -> &[u8] {
    ty.rsplit(|b| *b == b'.').next().unwrap_or(ty)
}

fn is_controller(class: Node, src: &[u8]) -> bool {
    name_of(class, src).ends_with(b"Controller")
        && (base_entries(class)
            .iter()
            .any(|b| matches!(simple_name(*b, src), b"Controller" | b"ControllerBase"))
            || attribute_names(class, src)
                .iter()
                .any(|(_, n)| *n == b"ApiController"))
}

fn controller_responsibilities<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let types = type_index(m);
    let by_decl = refs_by_decl(m);
    let mut found = Vec::new();
    for class in classes(&types)
        .into_iter()
        .filter(|c| is_controller(*c, src))
    {
        // Injected services: fields assigned from constructor parameters.
        let ctor_params: Vec<&[u8]> = members(class)
            .into_iter()
            .filter(|x| x.kind() == "constructor_declaration")
            .flat_map(|c| {
                params(c, src)
                    .into_iter()
                    .map(|p| text(p.name, src))
                    .collect::<Vec<_>>()
            })
            .collect();
        if ctor_params.is_empty() {
            continue;
        }
        let deps: Vec<DeclId> = m
            .decls
            .iter()
            .enumerate()
            .filter(|(_, d)| {
                d.kind == DeclKind::Field
                    && !d.is_static
                    && d.declarator.is_some_and(|x| {
                        class.start_byte() <= x.start_byte() && x.end_byte() <= class.end_byte()
                    })
            })
            .filter(|(i, _)| {
                by_decl[*i].iter().any(|r| {
                    let n = m.refs[*r].node;
                    m.refs[*r].write
                        && n.parent()
                            .and_then(|p| {
                                if p.kind() == "member_access_expression" {
                                    p.parent()
                                } else {
                                    Some(p)
                                }
                            })
                            .and_then(|a| a.child_by_field_name("right"))
                            .is_some_and(|v| ctor_params.contains(&text(v, src)))
                })
            })
            .map(|(i, _)| i)
            .collect();
        if deps.len() < 2 {
            continue;
        }
        // Per method scope, the dependencies it uses, then private helpers'
        // folded into the actions that call them.
        let mut uses: HashMap<ScopeId, Vec<DeclId>> = HashMap::new();
        let mut calls: HashMap<ScopeId, Vec<ScopeId>> = HashMap::new();
        let method_scope: HashMap<DeclId, ScopeId> = m
            .functions
            .iter()
            .filter_map(|f| {
                let name = f.node.child_by_field_name("name")?;
                let d = m.decls.iter().position(|d| d.node == name)?;
                Some((d, f.scope))
            })
            .collect();
        for r in &m.refs {
            let (Some(d), Some(member)) = (r.decl, member_scope(m, r.scope)) else {
                continue;
            };
            if deps.contains(&d) {
                uses.entry(member).or_default().push(d);
            } else if let Some(callee) = method_scope.get(&d) {
                calls.entry(member).or_default().push(*callee);
            }
        }
        let actions: Vec<(Node<'t>, ScopeId)> = methods(class)
            .into_iter()
            .filter(|x| cs_has_modifier(*x, "public", src) && !cs_has_modifier(*x, "static", src))
            .filter_map(|x| {
                m.functions
                    .iter()
                    .find(|f| f.node == x)
                    .map(|f| (x, f.scope))
            })
            .collect();
        let mut sets: Vec<Vec<DeclId>> = actions
            .iter()
            .map(|(_, scope)| {
                let mut set = Vec::new();
                let mut todo = vec![*scope];
                let mut seen = Vec::new();
                while let Some(s) = todo.pop() {
                    if seen.contains(&s) || seen.len() > 64 {
                        continue;
                    }
                    seen.push(s);
                    set.extend(uses.get(&s).into_iter().flatten().copied());
                    todo.extend(calls.get(&s).into_iter().flatten().copied());
                }
                set.sort_unstable();
                set.dedup();
                set
            })
            .collect();
        // Services every action that uses any uses (a logger) say nothing
        // about groups.
        sets.retain(|s| !s.is_empty());
        let shared: Vec<DeclId> = deps
            .iter()
            .copied()
            .filter(|d| sets.iter().all(|s| s.contains(d)))
            .collect();
        for s in &mut sets {
            s.retain(|d| !shared.contains(d));
        }
        sets.retain(|s| !s.is_empty());
        // Group actions that share a service; more than one group: mixed.
        let mut groups: Vec<Vec<DeclId>> = Vec::new();
        for s in sets {
            let (mut joined, rest): (Vec<Vec<DeclId>>, Vec<Vec<DeclId>>) = groups
                .into_iter()
                .partition(|g| g.iter().any(|d| s.contains(d)));
            let mut merged = s;
            for g in joined.drain(..) {
                merged.extend(g);
            }
            merged.sort_unstable();
            merged.dedup();
            groups = rest;
            groups.push(merged);
        }
        if groups.len() > 1 {
            found.extend(class.child_by_field_name("name"));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    #[test]
    fn overrides_and_implementations() {
        let src = "namespace N;\ninterface IAccount { void Add(int money); void Take(int money); }\nclass Account : IAccount { public void Add(int amount) { } public void Take(int _) { } }\nclass Base { public virtual void Run(int distance = 42) { } public virtual void Log(params string[] parts) { } public virtual void Note(string[] parts) { } }\nclass Derived : Base {\npublic override void Run(int distance = 5) { }\npublic override void Log(string[] parts) { }\npublic override void Note(params string[] parts) { }\n}\nclass Other : External { public override void Run(int d = 1) { } }";
        assert_eq!(flagged("cs/parameter-name-mismatch", src), [3]);
        assert_eq!(flagged("cs/override-changes-default", src), [6]);
        assert_eq!(flagged("cs/override-without-params", src), [7]);
        assert_eq!(flagged("cs/override-adds-params", src), [8]);
    }

    #[test]
    fn hiding() {
        let src = "namespace N;\nclass Base { public void Run(int n) { } internal void Write(string s) { } public virtual void V(int n) { } }\nclass Derived : Base {\nprivate void Run(int n) { }\ninternal void Write(object o) { }\nprivate void V(int n) { }\nvoid Other(int n) { }\n}";
        assert_eq!(flagged("cs/hiding-member-less-visible", src), [4]);
        assert_eq!(flagged("cs/base-method-hidden", src), [5]);
    }

    #[test]
    fn fields_and_statics() {
        let src = "namespace N;\nclass Foo {\nprivate int total;\nprivate int kept;\nprivate int cond;\npublic int Sum(int x) { total = x + 5; return total * 2; }\npublic void Keep(int x) { kept += x; }\npublic int Read() => kept;\npublic int C(int x) { if (x > 0) { cond = x; } return cond; }\nprivate int Twice(int a) { return a * 2; }\nprivate int Scaled(int a) { return a * kept; }\nprivate int This(int a) { return this.GetHashCode() + a; }\n}\nclass Derived : Base { private int Helper(int a) => a; }";
        assert_eq!(flagged("cs/could-be-static", src), [10]);
    }

    #[test]
    fn calls_and_returns() {
        let src = "namespace N;\nclass A {\ndouble Divide(int divisor, int dividend) => divisor / dividend;\nprivate int Count() => 42;\nprivate int Used() => 1;\nvoid F(int divisor, int dividend) {\nvar r1 = Divide(dividend, divisor);\nvar r2 = Divide(divisor, dividend);\nCount();\nvar u = Used();\n}\n}";
        assert_eq!(flagged("cs/argument-order", src), [7]);
        assert_eq!(flagged("cs/unused-private-return", src), [4]);
    }

    #[test]
    fn nesting_and_variance() {
        let src = "namespace N;\nclass Outer {\npublic static int A;\nprivate static int Twice(int n) => n * 2;\nprivate static int Both(int n) => n;\nint G() => Both(1);\nclass Inner { public int A; public Item Item { get; set; } int F() => Twice(2) + Both(3); }\nclass Item { }\n}\ninterface ISource<T> { T Next(); }\ninterface ISink<T> { void Put(T item); }\ninterface IBoth<T> { T Get(); void Set(T v); }\ninterface IList2<T> { List<T> All(); }\ninterface IDone<out T> { T Get(); }\ndelegate R Map<X, R>(X x);";
        assert_eq!(flagged("cs/inner-member-shadows-outer", src), [7]);
        assert_eq!(flagged("cs/private-static-only-nested", src), [4]);
        assert_eq!(flagged("cs/generic-variance", src), [10, 11, 15, 15]);
    }

    #[test]
    fn interfaces_and_dispose() {
        let src = "namespace N;\ninterface IA { int Id { get; } }\ninterface IB { int Id { get; } }\ninterface IC : IA, IB { }\ninterface ID : IA, IB { new int Id { get; } }\npublic class H1 : IDisposable { public virtual void Dispose() { } }\npublic class H2 : IDisposable { public void Dispose() { } }\npublic class H3 : IDisposable { public void Dispose() { Dispose(true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool d) { } }\npublic sealed class H4 : IDisposable { public void Dispose() { } }\npublic class H5 : IDisposable { public void Dispose() { Dispose(true); } protected virtual void Dispose(bool d) { } }";
        assert_eq!(flagged("cs/interface-colliding-members", src), [4]);
        assert_eq!(flagged("cs/dispose-pattern", src), [6, 7, 10]);
    }

    #[test]
    fn frameworks() {
        let src = "namespace N;\n[PartCreationPolicy(CreationPolicy.Shared)] class Foo { }\nclass Mover<T> where T : IPoint { readonly T point; T other; public Mover(T p) { point = p; point.X = 0; } public void Move() { point.X = 1; other.X = 2; } }\nclass Safe<T> where T : class, IPoint { readonly T point; public void Move() { point.X = 1; } }\ninterface ICounter { void Add(int a, int b); int Get(); void Reset(); Task<int> Read(int x); }\nclass F { void G(IDurableEntityClient c) { var f = new Foo(); c.SignalEntityAsync<ICounter>(id, x => x.Reset()); } }";
        assert_eq!(flagged("cs/shared-part-created-with-new", src), [6]);
        assert_eq!(
            flagged("cs/readonly-generic-field-member-assignment", src),
            [3]
        );
        assert_eq!(flagged("cs/durable-entity-interface", src), [5, 5]);
    }

    #[test]
    fn controllers_and_models() {
        let src = "namespace N;\npublic class Order { public int Quantity { get; set; } public int? Max { get; set; } public required int Min { get; set; } [JsonRequired] public bool Paid { get; set; } public string Name { get; set; } }\npublic class MediaController : ControllerBase {\nreadonly IMovies movies; readonly IPhotos photos; readonly ILogger log;\npublic MediaController(IMovies m, IPhotos p, ILogger l) { movies = m; photos = p; log = l; }\npublic IActionResult Movie() { log.Info(); return Ok(movies.Get()); }\npublic IActionResult Photo() { log.Info(); return Ok(photos.Get()); }\npublic IActionResult Create(Order order) => Ok();\n}\npublic class MovieController : ControllerBase {\nreadonly IMovies movies; readonly IRatings ratings;\npublic MovieController(IMovies m, IRatings r) { movies = m; ratings = r; }\npublic IActionResult Movie() => Ok(movies.Get());\npublic IActionResult Rate() => Ok(Both());\nprivate object Both() => movies.Get() + ratings.Get();\n}";
        assert_eq!(flagged("cs/controller-mixed-responsibilities", src), [3]);
        assert_eq!(flagged("cs/underposting-value-type", src), [2]);
    }

    #[test]
    fn serialization_and_equality() {
        let src = "namespace N;\n[Serializable] class Url : ISerializable { string url; public Url(string u) { if (u == null) { throw new ArgumentException(); } url = u; } protected Url(SerializationInfo info, StreamingContext c) { url = info.GetString(\"u\"); } }\n[Serializable] class Ok : ISerializable { public Ok(string u) { if (u == null) { throw new ArgumentException(); } } protected Ok(SerializationInfo info, StreamingContext c) { if (info == null) { throw new ArgumentNullException(); } } }\n[Serializable] class Plain { int n; public Plain(int x) { if (x < 0) { throw new ArgumentException(); } n = x; } }\nclass Money { public override bool Equals(object o) => true; public override int GetHashCode() => 0; }\nclass A { bool F(Money a, Money b) => a == b; bool G(Money a) => a == null; }";
        assert_eq!(flagged("cs/deserialization-skips-validation", src), [2, 4]);
        assert_eq!(flagged("cs/equality-on-equals-type", src), [6]);
    }

    #[test]
    fn deep_inheritance() {
        let src = "namespace N;\nclass Options : Options<object> { }\nclass A2 : External { }\nclass A3 : A2 { }\nclass A4 : A3 { }\nclass A5 : A4 { }\nclass A6 : A5 { }\nclass A7 : A6 { }\nclass B : IThing { }";
        assert_eq!(flagged("cs/deep-inheritance", src), [8]);
    }
}
