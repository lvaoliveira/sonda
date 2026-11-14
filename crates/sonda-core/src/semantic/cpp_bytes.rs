//! Where a C++ file manipulates bytes as integers: a bitwise operation whose
//! left operand is an 8-bit unsigned value (`uint8_t`, `unsigned char`), or
//! a `reinterpret_cast` to one's pointer, which `std::byte` (C++17) states
//! better. Part of the file's summary (`cpp_index`): an operand the file
//! shows the type of is decided here; one that is a class's field, often
//! declared in another file, is left to the project pass, which knows the
//! field's type from the index (ADR-0020).

use super::cpp_index::{compact_text, named, node_text, span_of, without_template_arguments};
use super::cs_index::Span;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tree_sitter::Node;

/// A byte-oriented operation. With no `class`, the file shows its operand
/// is a byte; with one, it is that class's `field` (an element of it when
/// `element`), and is a byte when the field is.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct ByteSite {
    pub(crate) span: Span,
    /// The class as written (`Spec`, `ns::Spec`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) class: String,
    /// The namespaces and classes the operation is written in, to resolve
    /// `class` from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) scope: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) field: String,
    /// Or a member function of the class, called: a byte when it returns
    /// one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) method: String,
    /// `field[i]` or `*field`: the field is a byte pointer or array.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) element: bool,
}

/// How many sites a file may record.
const MAX_SITES: usize = 5_000;

/// Whether a type, as written with whitespace removed, is an 8-bit unsigned
/// integer.
pub(crate) fn is_byte(ty: &str) -> bool {
    let ty = ty
        .replace("constexpr", "")
        .replace("const", "")
        .replace("volatile", "")
        .replace("static", "");
    matches!(
        ty.trim_start_matches("std::"),
        "uint8_t" | "unsignedchar" | "uint_least8_t" | "uint_fast8_t"
    )
}

/// Whether a type is a pointer to, or an array of, 8-bit unsigned integers.
pub(crate) fn is_byte_pointer(ty: &str) -> bool {
    ty.strip_suffix('*')
        .or_else(|| ty.strip_suffix("[]"))
        .is_some_and(is_byte)
}

/// Calls known to return a byte: Arduino's flash read.
const BYTE_FUNCTIONS: &[&str] = &["pgm_read_byte", "pgm_read_byte_near", "pgm_read_byte_far"];

struct Finder<'s> {
    src: &'s [u8],
    deadline: Instant,
    /// Functions this file declares returning a byte, by name.
    byte_functions: Vec<&'s str>,
    sites: Vec<ByteSite>,
}

/// The file's byte-oriented operations.
pub(crate) fn sites(root: Node, src: &[u8], deadline: Instant) -> Vec<ByteSite> {
    let mut f = Finder {
        src,
        deadline,
        byte_functions: BYTE_FUNCTIONS.to_vec(),
        sites: Vec::new(),
    };
    f.collect_byte_functions(root);
    f.walk(root, &mut Vec::new(), None);
    f.sites
}

/// A function's parameters and locals: each name, its type, and the bytes
/// where its declaration starts and its block ends.
#[derive(Default)]
struct Locals<'s> {
    decls: Vec<(&'s str, String, usize, usize)>,
}

impl Locals<'_> {
    /// The type of the declaration of `name` that `at` sees: the latest
    /// one before it whose block holds it.
    fn get(&self, name: &str, at: Node) -> Option<&str> {
        let pos = at.start_byte();
        self.decls
            .iter()
            .filter(|(n, _, start, end)| *n == name && *start <= pos && pos <= *end)
            .max_by_key(|(_, _, start, _)| *start)
            .map(|(_, ty, _, _)| ty.as_str())
    }
}

/// What a function body is written in: its class, as written, and the
/// scope to resolve that from.
#[derive(Clone)]
struct Context {
    class: String,
    scope: Vec<String>,
    /// The fields the class's body declares, when the function is in it:
    /// their types need no index.
    fields: Vec<(String, String)>,
}

impl<'s> Finder<'s> {
    fn text(&self, n: Node) -> &'s str {
        node_text(self.src, n)
    }

    fn compact(&self, n: Node) -> String {
        compact_text(self.src, n)
    }

    fn span(&self, n: Node) -> Span {
        span_of(n)
    }

    fn collect_byte_functions(&mut self, root: Node) {
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if matches!(
                n.kind(),
                "function_definition" | "declaration" | "field_declaration"
            ) && let Some(ty) = n.child_by_field_name("type")
                && is_byte(&self.compact(ty))
                && let Some(d) = n.child_by_field_name("declarator")
                && d.kind() == "function_declarator"
                && let Some(name) = d.child_by_field_name("declarator")
            {
                let t = self.text(name);
                self.byte_functions.push(t.rsplit("::").next().unwrap_or(t));
            }
            if n.kind() != "compound_statement" {
                stack.extend(named(n));
            }
        }
    }

    /// Walks to each function body, keeping the namespaces and classes
    /// around it.
    fn walk(&mut self, n: Node, scope: &mut Vec<String>, class: Option<&Context>) {
        if Instant::now() > self.deadline || self.sites.len() >= MAX_SITES {
            return;
        }
        match n.kind() {
            "namespace_definition" => {
                let depth = scope.len();
                match n.child_by_field_name("name") {
                    Some(name) => {
                        scope.extend(self.text(name).split("::").map(|s| s.trim().to_string()))
                    }
                    None => scope.push(String::new()),
                }
                for c in named(n) {
                    self.walk(c, scope, class);
                }
                scope.truncate(depth);
            }
            "class_specifier" | "struct_specifier" => {
                let Some(name) = n.child_by_field_name("name") else {
                    for c in named(n) {
                        self.walk(c, scope, class);
                    }
                    return;
                };
                let simple = match name.kind() {
                    "template_type" | "qualified_identifier" => {
                        name.child_by_field_name("name").unwrap_or(name)
                    }
                    _ => name,
                };
                let context = Context {
                    class: self.text(simple).to_string(),
                    scope: scope.clone(),
                    fields: n
                        .child_by_field_name("body")
                        .map(|body| self.fields(body))
                        .unwrap_or_default(),
                };
                scope.push(context.class.clone());
                for c in named(n) {
                    self.walk(c, scope, Some(&context));
                }
                scope.pop();
            }
            "function_definition" => {
                let owner = self.owner(n, scope, class);
                self.function(n, owner.as_ref());
            }
            _ => {
                for c in named(n) {
                    self.walk(c, scope, class);
                }
            }
        }
    }

    /// The class a function is a member of: the one it's defined in, or the
    /// one its name qualifies (`void Spec::draw()`).
    fn owner(&self, function: Node, scope: &[String], class: Option<&Context>) -> Option<Context> {
        let mut d = function.child_by_field_name("declarator")?;
        while matches!(d.kind(), "pointer_declarator" | "reference_declarator") {
            d = d.child_by_field_name("declarator")?;
        }
        let name = d.child_by_field_name("declarator")?;
        if name.kind() == "qualified_identifier" {
            let scope_text = self.compact(name.child_by_field_name("scope")?);
            return Some(Context {
                class: without_template_arguments(&scope_text),
                scope: scope.to_vec(),
                fields: Vec::new(),
            });
        }
        class.cloned()
    }

    /// The sites in a function's body.
    fn function(&mut self, function: Node, owner: Option<&Context>) {
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let mut types = Locals::default();
        if let Some(params) = function
            .child_by_field_name("declarator")
            .and_then(|d| find_kind(d, "parameter_list"))
        {
            self.declare(params, function.end_byte(), &mut types);
        }
        self.declare(body, function.end_byte(), &mut types);
        // The body, and a constructor's initializer list.
        let mut stack: Vec<Node> = named(function)
            .into_iter()
            .filter(|c| matches!(c.kind(), "compound_statement" | "field_initializer_list"))
            .collect();
        while let Some(n) = stack.pop() {
            if self.sites.len() >= MAX_SITES {
                return;
            }
            let operand = match n.kind() {
                "binary_expression"
                    if n.child_by_field_name("operator")
                        .is_some_and(|o| matches!(self.text(o), "&" | "|" | "^" | "<<" | ">>")) =>
                {
                    n.child_by_field_name("left")
                }
                "assignment_expression"
                    if n.child_by_field_name("operator").is_some_and(|o| {
                        matches!(self.text(o), "&=" | "|=" | "^=" | "<<=" | ">>=")
                    }) =>
                {
                    n.child_by_field_name("left")
                }
                "unary_expression"
                    if n.child_by_field_name("operator")
                        .is_some_and(|o| self.text(o) == "~") =>
                {
                    n.child_by_field_name("argument")
                }
                "call_expression" if self.casts_to_byte_pointer(n) => {
                    self.sites.push(ByteSite {
                        span: self.span(n),
                        ..ByteSite::default()
                    });
                    None
                }
                _ => None,
            };
            if let Some(operand) = operand
                && !self.cast_to_a_byte(n)
                && let Some(mut site) = self.classify(operand, &types, owner)
            {
                site.span = self.span(n);
                self.sites.push(site);
            }
            stack.extend(named(n));
        }
    }

    /// `reinterpret_cast<const uint8_t*>(p)`.
    fn casts_to_byte_pointer(&self, call: Node) -> bool {
        call.child_by_field_name("function").is_some_and(|f| {
            f.kind() == "template_function"
                && f.child_by_field_name("name")
                    .is_some_and(|n| self.text(n) == "reinterpret_cast")
                && f.child_by_field_name("arguments").is_some_and(|a| {
                    is_byte_pointer(
                        self.compact(a)
                            .trim_start_matches('<')
                            .trim_end_matches('>'),
                    )
                })
        })
    }

    /// The data members a class body declares, with their types.
    fn fields(&self, body: Node) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for member in named(body) {
            if member.kind() != "field_declaration" {
                continue;
            }
            let Some(ty) = member.child_by_field_name("type") else {
                continue;
            };
            let before: String =
                String::from_utf8_lossy(&self.src[member.start_byte()..ty.end_byte()])
                    .split_whitespace()
                    .collect();
            let mut cursor = member.walk();
            for d in member.children_by_field_name("declarator", &mut cursor) {
                if let (Some(name), suffix) = declared(d) {
                    out.push((self.text(name).to_string(), before.clone() + &suffix));
                }
            }
        }
        out
    }

    /// `(roo::byte)(x << 4)`: the operation's result goes straight into a
    /// byte type already.
    fn cast_to_a_byte(&self, op: Node) -> bool {
        let mut up = op.parent();
        while let Some(p) = up.filter(|p| p.kind() == "parenthesized_expression") {
            up = p.parent();
        }
        let byte_type = |t: &str| {
            let t = t.trim_start_matches('<').trim_end_matches('>');
            t == "byte" || t.ends_with("::byte")
        };
        up.is_some_and(|p| match p.kind() {
            "cast_expression" => p
                .child_by_field_name("type")
                .is_some_and(|t| byte_type(&self.compact(t))),
            "argument_list" => p
                .parent()
                .and_then(|c| c.child_by_field_name("function"))
                .is_some_and(|f| {
                    f.kind() == "template_function"
                        && f.child_by_field_name("name")
                            .is_some_and(|n| self.text(n) == "static_cast")
                        && f.child_by_field_name("arguments")
                            .is_some_and(|a| byte_type(&self.compact(a)))
                }),
            _ => false,
        })
    }

    /// The local and parameter declarations under `n`, each with the end of
    /// its block (`end` for parameters).
    fn declare(&self, n: Node, end: usize, types: &mut Locals<'s>) {
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            if matches!(
                x.kind(),
                "declaration" | "parameter_declaration" | "optional_parameter_declaration"
            ) {
                self.declare_one(x, end, types);
            }
            if x.kind() != "lambda_expression" {
                stack.extend(named(x));
            }
        }
    }

    /// The names one declaration declares, with their types.
    fn declare_one(&self, x: Node, end: usize, types: &mut Locals<'s>) {
        let Some(ty) = x.child_by_field_name("type") else {
            return;
        };
        // `const` is outside the type: the text before it counts.
        let before: String = String::from_utf8_lossy(&self.src[x.start_byte()..ty.end_byte()])
            .split_whitespace()
            .collect();
        let block_end = if x.kind() == "declaration" {
            block_end(x).unwrap_or(end)
        } else {
            end
        };
        let mut cursor = x.walk();
        for d in x.children_by_field_name("declarator", &mut cursor) {
            if let (Some(name), suffix) = declared(d) {
                types.decls.push((
                    self.text(name),
                    before.clone() + &suffix,
                    x.start_byte(),
                    block_end,
                ));
            }
        }
    }

    /// What `operand` is: a byte the file shows, or a class's field or
    /// member function, whose type the index knows.
    fn classify(&self, operand: Node, types: &Locals, owner: Option<&Context>) -> Option<ByteSite> {
        match operand.kind() {
            "parenthesized_expression" => self.classify(operand.named_child(0)?, types, owner),
            "cast_expression" => {
                is_byte(&self.compact(operand.child_by_field_name("type")?)).then(ByteSite::default)
            }
            "call_expression" => self.classify_call(operand, types, owner),
            "identifier" => match types.get(self.text(operand), operand) {
                Some(ty) => is_byte(ty).then(ByteSite::default),
                None => own_field(owner, self.text(operand), false),
            },
            "field_expression" => self.classify_member(operand, types, owner),
            "subscript_expression" | "pointer_expression" => {
                self.classify_element(operand, types, owner)
            }
            _ => None,
        }
    }

    /// `static_cast<uint8_t>(x)`, a function returning a byte, or a member
    /// function called on a local (`color.r()`).
    fn classify_call(
        &self,
        call: Node,
        types: &Locals,
        owner: Option<&Context>,
    ) -> Option<ByteSite> {
        let f = call.child_by_field_name("function")?;
        if f.kind() == "template_function"
            && f.child_by_field_name("name")
                .is_some_and(|n| self.text(n) == "static_cast")
        {
            let ty = self.compact(f.child_by_field_name("arguments")?);
            return is_byte(ty.trim_start_matches('<').trim_end_matches('>'))
                .then(ByteSite::default);
        }
        let name = self.text(f);
        if self
            .byte_functions
            .contains(&name.rsplit("::").next().unwrap_or(name))
        {
            return Some(ByteSite::default());
        }
        let object = f
            .child_by_field_name("argument")
            .filter(|o| f.kind() == "field_expression" && o.kind() == "identifier")?;
        let class = types.get(self.text(object), object).and_then(class_of)?;
        Some(ByteSite {
            class,
            scope: owner.map(|o| o.scope.clone()).unwrap_or_default(),
            method: self.text(f.child_by_field_name("field")?).to_string(),
            ..ByteSite::default()
        })
    }

    /// `this->field`, or `local.field` of a local whose type is a class.
    fn classify_member(
        &self,
        member: Node,
        types: &Locals,
        owner: Option<&Context>,
    ) -> Option<ByteSite> {
        let object = member.child_by_field_name("argument")?;
        let field = self.text(member.child_by_field_name("field")?);
        if object.kind() == "this" {
            return own_field(owner, field, false);
        }
        if object.kind() != "identifier" {
            return None;
        }
        let class = class_of(types.get(self.text(object), object)?)?;
        Some(ByteSite {
            class,
            scope: owner.map(|o| o.scope.clone()).unwrap_or_default(),
            field: field.to_string(),
            ..ByteSite::default()
        })
    }

    /// `p[i]` or `*p`: an element of a byte pointer or array.
    fn classify_element(
        &self,
        element: Node,
        types: &Locals,
        owner: Option<&Context>,
    ) -> Option<ByteSite> {
        if element.kind() == "pointer_expression"
            && element
                .child_by_field_name("operator")
                .is_none_or(|o| self.text(o) != "*")
        {
            return None;
        }
        let base = element.child_by_field_name("argument")?;
        if base.kind() != "identifier" {
            return None;
        }
        match types.get(self.text(base), base) {
            Some(ty) => is_byte_pointer(ty).then(ByteSite::default),
            None => own_field(owner, self.text(base), true),
        }
    }
}

/// A name the function doesn't declare, read as a field of the class it's
/// a member of: decided here when the class's body around it declares the
/// field, else left to the index.
fn own_field(owner: Option<&Context>, name: &str, element: bool) -> Option<ByteSite> {
    let o = owner?;
    if let Some((_, ty)) = o.fields.iter().find(|(f, _)| f == name) {
        let byte = if element {
            is_byte_pointer(ty)
        } else {
            is_byte(ty)
        };
        return byte.then(ByteSite::default);
    }
    Some(ByteSite {
        class: o.class.clone(),
        scope: o.scope.clone(),
        field: name.to_string(),
        element,
        ..ByteSite::default()
    })
}

/// The end of the block a declaration is in, through `#if` branches, which
/// don't scope.
fn block_end(declaration: Node) -> Option<usize> {
    let mut b = declaration.parent();
    while let Some(p) = b.filter(|p| p.kind().starts_with("preproc")) {
        b = p.parent();
    }
    b.map(|b| b.end_byte())
}

fn find_kind<'t>(n: Node<'t>, kind: &str) -> Option<Node<'t>> {
    if n.kind() == kind {
        return Some(n);
    }
    named(n).into_iter().find_map(|c| find_kind(c, kind))
}

/// The name a declarator declares, and what it adds to the type: `*`, `&`,
/// `[]`.
fn declared(d: Node) -> (Option<Node>, String) {
    let mut suffix = String::new();
    let mut d = d;
    for _ in 0..8 {
        match d.kind() {
            "identifier" | "field_identifier" => return (Some(d), suffix),
            "pointer_declarator" => suffix.push('*'),
            "reference_declarator" => suffix.push('&'),
            "array_declarator" => suffix.push_str("[]"),
            "init_declarator" => {}
            _ => return (None, suffix),
        }
        match d
            .child_by_field_name("declarator")
            .or_else(|| named(d).into_iter().next())
        {
            Some(next) => d = next,
            None => return (None, suffix),
        }
    }
    (None, suffix)
}

/// The class a variable's type names: `Spec` for `constSpec&` or `Spec*`;
/// nothing for a primitive or a template.
fn class_of(ty: &str) -> Option<String> {
    let t = ty
        .replace("const", "")
        .replace("static", "")
        .trim_end_matches(['*', '&'])
        .to_string();
    let first = t.rsplit("::").next()?.chars().next()?;
    (first.is_ascii_uppercase() && !t.contains('<')).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(src: &str) -> Vec<(usize, String, String, bool)> {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_cpp::LANGUAGE.into()).unwrap();
        let tree = p.parse(src, None).unwrap();
        let far = Instant::now() + std::time::Duration::from_secs(60);
        sites(tree.root_node(), src.as_bytes(), far)
            .into_iter()
            .map(|s| (s.span.line, s.class, s.field, s.element))
            .collect()
    }

    #[test]
    fn finds_byte_operations() {
        let src = "uint8_t nibble(int x);\nnamespace g {\nclass Spec { uint8_t q_; };\nstruct W {\n  int f(uint8_t r, const uint8_t* data, Spec& s, int n) {\n    int a = r << 16;\n    int b = data[1] >> 4;\n    int c = nibble(n) & 3;\n    int d = n << 2 | r;\n    int e = s.q_ & 4;\n    int h = mask_ & 1;\n    int i = (uint8_t)n << 1;\n    auto p = reinterpret_cast<const uint8_t*>(&n);\n    return ~r;\n  }\n};\nvoid Spec::g() { q_ |= 1; }\nint h(Color c) { return c.r() >> 4; }\nint k() {\n  { uint8_t b = 1; int x = b >> 1; }\n  { uint16_t b = 2; return b >> 1; }\n}\nstruct Q : Base { Q(uint8_t r) : v_(r << 8), w_((roo::byte)(r << 4)) {} };\n}";
        let mut got = found(src);
        got.sort();
        let at = |l: usize, c: &str, f: &str, e: bool| (l, c.to_string(), f.to_string(), e);
        assert_eq!(
            got,
            [
                at(6, "", "", false),
                at(7, "", "", false),
                at(8, "", "", false),
                at(10, "Spec", "q_", false),
                at(11, "W", "mask_", false),
                at(12, "", "", false),
                at(13, "", "", false),
                at(14, "", "", false),
                at(17, "Spec", "q_", false),
                at(18, "Color", "", false),
                at(20, "", "", false),
                at(23, "", "", false),
            ]
        );
    }
}
