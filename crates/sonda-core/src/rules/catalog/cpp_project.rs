//! C++ rules that need classes from other files of the project (ADR-0020):
//! a member function compared with its bases' functions, a bitwise
//! operation with the type of the field it operates on. They run once per
//! scan, on the index the files' summaries build (`semantic::cpp_index`),
//! and are `Check::Structural` in the catalog.
//!
//! A base outside the project (Qt's, the standard library's) resolves to
//! nothing, and nothing is reported about it.

use crate::semantic::cpp_bytes::{ByteSite, is_byte, is_byte_pointer};
use crate::semantic::cpp_const::MemberBody;
use crate::semantic::cpp_index::{
    ClassDecl, ClassId, FACT, FileIndex, MethodDecl, ProjectIndex, without_template_arguments,
};
use crate::semantic::cs_index::Span;

/// A finding: the rule, the index of the file it's in, and where.
pub(crate) type Finding = (&'static str, usize, Span);

pub(crate) const HIDDEN_FUNCTION: &str = "cpp/hidden-inherited-function";
pub(crate) const BYTE_OPERATION: &str = "cpp/std-byte";
pub(crate) const CONST_FUNCTION: &str = "cpp/const-member-function";
pub(crate) const HIDDEN_FRIEND: &str = "cpp/operator-hidden-friend";

/// The rules this module checks.
pub(crate) const RULES: &[&str] = &[
    HIDDEN_FUNCTION,
    BYTE_OPERATION,
    CONST_FUNCTION,
    HIDDEN_FRIEND,
];

/// Checks the active rules on every file's summary.
pub(crate) fn run<'f>(
    facts: impl Iterator<Item = &'f [(String, String)]>,
    active: &[&str],
) -> Vec<Finding> {
    if !RULES.iter().any(|r| active.contains(r)) {
        return Vec::new();
    }
    // (position in the scanner's list, the file's summary)
    let parsed: Vec<(usize, FileIndex)> = crate::semantic::summaries(facts, FACT);
    let index = ProjectIndex::new(parsed.iter().map(|(_, x)| x).collect());
    let mut found: Vec<Finding> = Vec::new();
    for f in 0..index.files().len() {
        check_file(&index, f, active, &mut found);
    }
    found
        .into_iter()
        .map(|(rule, file, span)| (rule, parsed[file].0, span))
        .collect()
}

/// The active rules' findings in the index's file `f`.
fn check_file(index: &ProjectIndex, f: usize, active: &[&str], found: &mut Vec<Finding>) {
    let file = index.files()[f];
    if active.contains(&HIDDEN_FUNCTION) {
        for c in 0..file.classes.len() {
            hidden_functions(index, (f, c), found);
        }
    }
    if active.contains(&CONST_FUNCTION) {
        found.extend(
            file.bodies
                .iter()
                .filter(|body| could_be_const(index, body))
                .map(|body| (CONST_FUNCTION, f, body.span)),
        );
    }
    if active.contains(&HIDDEN_FRIEND) {
        // A parameter of one of the project's classes, which could befriend
        // it; an enumeration, or a library's type, resolves to nothing.
        found.extend(
            file.operators
                .iter()
                .filter(|site| {
                    site.types
                        .iter()
                        .any(|ty| index.resolve_in(&site.scope, ty, None).is_some())
                })
                .map(|site| (HIDDEN_FRIEND, f, site.span)),
        );
    }
    if active.contains(&BYTE_OPERATION) {
        found.extend(
            file.bytes
                .iter()
                .filter(|site| operates_on_a_byte(index, site))
                .map(|site| (BYTE_OPERATION, f, site.span)),
        );
    }
}

/// A member function whose body changes nothing the index shows is its
/// object's: it writes none of the class's fields (or its bases'), calls
/// only const member functions on the object, and only const functions on
/// its fields, other than through a pointer; and it isn't virtual. When a
/// base is outside the project, a name or call the index can't place could
/// be one of the base's, and counts against it, unless it's spelled like a
/// macro (`QCOMPARE`).
fn could_be_const(index: &ProjectIndex, body: &MemberBody) -> bool {
    if body.escapes {
        return false;
    }
    let Some(class) = index.resolve_declaring(&body.scope, &body.class, &body.name) else {
        return false;
    };
    let chain: Vec<ClassId> = std::iter::once(class)
        .chain(index.ancestors(class))
        .collect();
    let unknown_base = chain.iter().any(|c| {
        index
            .class(*c)
            .bases
            .iter()
            .any(|b| index.resolve(*c, b).is_none())
    });
    let declared = index
        .class(class)
        .methods
        .iter()
        .filter(|m| m.name == body.name);
    if declared
        .clone()
        .any(|m| m.static_ || m.const_ || is_virtual(index, class, m))
    {
        return false;
    }
    let field = |name: &str| {
        chain
            .iter()
            .find_map(|c| index.class(*c).fields.iter().find(|f| f.name == name))
    };
    let unplaced = |name: &str| unknown_base && !spelled_like_a_macro(name);
    // A name it writes is a field, or one the index can't place: either
    // way, not something a const function may write.
    if !body.writes.is_empty() {
        return false;
    }
    // A field passed to a call may be changed through a reference or
    // pointer parameter, unless it's a plain number.
    if body
        .passed
        .iter()
        .any(|p| field(p).is_none_or(|f| !is_scalar(&f.ty)))
    {
        return false;
    }
    let calls_ok = body.calls.iter().all(|c| {
        // A functor member, `setter_(0)`: its call operator may change it.
        if field(c).is_some() {
            return false;
        }
        let own: Vec<&MethodDecl> = chain
            .iter()
            .flat_map(|id| index.class(*id).methods.iter().filter(|m| &m.name == c))
            .collect();
        if own.is_empty() {
            !unplaced(c)
        } else {
            own.iter().any(|m| m.const_ || m.static_)
        }
    });
    calls_ok
        && body
            .member_calls
            .iter()
            .all(|(object, method)| match field(object) {
                Some(f) => field_call_is_const(index, class, &f.ty, method),
                None => false,
            })
}

/// A number or `bool`, passed by value whatever the parameter.
fn is_scalar(ty: &str) -> bool {
    let ty = ty.replace("const", "");
    matches!(
        ty.as_str(),
        "int"
            | "unsigned"
            | "unsignedint"
            | "long"
            | "short"
            | "bool"
            | "char"
            | "float"
            | "double"
            | "size_t"
    ) || ty.starts_with("int") && ty.ends_with("_t")
        || ty.starts_with("uint") && ty.ends_with("_t")
}

/// Whether calling `method` on a field of type `ty`, or on what it points
/// or refers to, leaves it unchanged: a class in the project whose
/// `method` is const.
fn field_call_is_const(index: &ProjectIndex, owner: ClassId, ty: &str, method: &str) -> bool {
    let ty = ty
        .replace("const", "")
        .replace("mutable", "")
        .trim_end_matches(['*', '&'])
        .to_string();
    let Some(class) = index.resolve_in(
        &index.class(owner).scope,
        &without_template_arguments(&ty),
        None,
    ) else {
        return false;
    };
    std::iter::once(class)
        .chain(index.ancestors(class))
        .flat_map(|c| index.class(c).methods.iter())
        .any(|m| m.name == method && (m.const_ || m.static_))
}

/// `QCOMPARE`, `Q_INIT_RESOURCE`: a macro, not a function of a base.
fn spelled_like_a_macro(name: &str) -> bool {
    name.len() > 1
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// A byte-oriented operation whose operand the file shows is a byte, or is
/// a field the index finds declared as one (a byte pointer or array, for
/// an element), or a call to a member function the index finds returns
/// one.
fn operates_on_a_byte(index: &ProjectIndex, site: &ByteSite) -> bool {
    if site.class.is_empty() {
        return true;
    }
    let Some(class) = index.resolve_in(&site.scope, &site.class, None) else {
        return false;
    };
    if !site.method.is_empty() {
        return index.return_type(class, &site.method).is_some_and(is_byte);
    }
    index.field_type(class, &site.field).is_some_and(|ty| {
        if site.element {
            is_byte_pointer(ty)
        } else {
            is_byte(ty)
        }
    })
}

/// A public or protected member function named like functions of its
/// bases, which it hides: a non-virtual one (not private), or virtual
/// overloads it doesn't override each of. Every base counts, as SonarCloud
/// counts them: one an intermediate class hides already is hidden again.
/// Not when `using Base::name;` brings the base's in.
fn hidden_functions(index: &ProjectIndex, id: ClassId, found: &mut Vec<Finding>) {
    let class = index.class(id);
    if class.bases.is_empty() {
        return;
    }
    let ancestors = index.ancestors(id);
    let mut reported_overloads: Vec<&str> = Vec::new();
    for m in &class.methods {
        // A private function hides nothing callers could reach.
        if m.private_ || class.using.contains(&m.name) {
            continue;
        }
        let theirs = bases_functions(index, &ancestors, &m.name);
        if theirs.is_empty() {
            continue;
        }
        if theirs
            .iter()
            .any(|(b, x)| !x.private_ && !is_virtual(index, *b, x))
        {
            found.push((HIDDEN_FUNCTION, id.0, m.span));
        } else if !reported_overloads.contains(&m.name.as_str())
            && leaves_overloads_out(class, &m.name, &theirs)
        {
            reported_overloads.push(&m.name);
            found.push((HIDDEN_FUNCTION, id.0, m.span));
        }
    }
}

/// The functions named `name` that the classes `bases` declare.
fn bases_functions<'a>(
    index: &ProjectIndex<'a>,
    bases: &[ClassId],
    name: &str,
) -> Vec<(ClassId, &'a MethodDecl)> {
    bases
        .iter()
        .flat_map(|b| {
            index
                .class(*b)
                .methods
                .iter()
                .filter(move |x| x.name == name)
                .map(move |x| (*b, x))
        })
        .collect()
}

/// Whether `f`, declared in `base`, is virtual: declared so, or a function
/// with its name and as many parameters is in one of `base`'s bases.
fn is_virtual(index: &ProjectIndex, base: ClassId, f: &MethodDecl) -> bool {
    f.virtual_
        || index.ancestors(base).iter().any(|a| {
            index
                .class(*a)
                .methods
                .iter()
                .any(|y| y.name == f.name && y.virtual_ && y.params.len() == f.params.len())
        })
}

/// Whether `class` overrides only some of its bases' virtual functions
/// named `name`, hiding the rest.
fn leaves_overloads_out(class: &ClassDecl, name: &str, theirs: &[(ClassId, &MethodDecl)]) -> bool {
    let ours: Vec<&MethodDecl> = class.methods.iter().filter(|x| x.name == name).collect();
    theirs
        .iter()
        .any(|(_, x)| !ours.iter().any(|o| o.params == x.params))
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::at;
    use crate::lang::Lang;

    fn flagged(rule: &str, files: &[(&str, &str)]) -> Vec<(String, usize)> {
        crate::analysis::tests::project_flagged(
            rule,
            Lang::Cpp,
            files,
            crate::analysis::cpp_project_rules,
        )
    }

    /// Shapes from SonarCloud's analysis of roo_display, the bases in
    /// another file.
    #[test]
    fn hidden_inherited_functions() {
        let base = (
            "output.h",
            "namespace gfx {\nclass Output {\n public:\n  void setAddress(const Box& b, int mode);\n  virtual void setAddress(int x0, int y0, int mode) = 0;\n  virtual void fill(int color);\n  virtual void fill(int color, int count);\n  void read(int* buf);\n  virtual void read(int* buf, int n) = 0;\n};\n}",
        );
        let derived = (
            "device.cpp",
            "namespace gfx {\nclass Device : public Output {\n public:\n  void setAddress(int x0, int y0, int mode) override;\n  void fill(int color) override;\n private:\n  void read(int* buf, int n) override;\n};\nclass Stream : public Output {\n public:\n  using Output::read;\n  void read(int* buf, int n) override;\n};\nclass Counting : public Stream {\n public:\n  void read(int* buf, int n) override;\n};\nclass Widget : public QWidget {\n public:\n  void updateGeometry();\n};\n}",
        );
        assert_eq!(
            flagged("cpp/hidden-inherited-function", &[base, derived]),
            [
                // A non-virtual overload hidden by an override.
                at("device.cpp", 4),
                // One of two virtual overloads overridden.
                at("device.cpp", 5),
                // Brought in one level up, hidden again below.
                at("device.cpp", 16),
            ]
        );
    }
    /// Shapes from SonarCloud's analysis of roo_display: fields and member
    /// functions declared in a header, operated on in another file.
    #[test]
    fn byte_operations() {
        let header = (
            "spec.h",
            "namespace gfx {\nclass Color {\n public:\n  uint8_t r() const;\n  uint32_t argb() const;\n};\nclass Spec {\n public:\n  void draw(Color c);\n  uint8_t quadrants_;\n  int count_;\n  const uint8_t* mask_;\n};\n}",
        );
        let source = (
            "spec.cpp",
            "namespace gfx {\nvoid Spec::draw(Color c) {\n  int a = quadrants_ & 4;\n  int b = count_ & 4;\n  int d = mask_[0] >> 1;\n  int e = c.r() >> 4;\n  int f = c.argb() >> 4;\n  uint8_t g = 3;\n  int h = (roo::byte)(g << 4);\n  return;\n}\nvoid draw(Spec& s) { int k = s.quadrants_ | 1; }\n}",
        );
        assert_eq!(
            flagged("cpp/std-byte", &[header, source]),
            [
                at("spec.cpp", 3),
                at("spec.cpp", 5),
                at("spec.cpp", 6),
                at("spec.cpp", 12),
            ]
        );
    }
    /// Shapes from SonarCloud's analysis of roo_display: the classes and
    /// enumerations in a header, the operators in another file.
    #[test]
    fn operators_as_hidden_friends() {
        let header = (
            "box.h",
            "namespace gfx {\nclass Box {\n public:\n  bool operator==(const Box&) const;\n};\nenum class Mode { kA, kB };\nstruct F { friend bool operator==(const F&, const F&) { return true; } };\n}",
        );
        let source = (
            "box.cpp",
            "namespace gfx {\nbool operator<(const Box& a, const Box& b) { return true; }\nstd::ostream& operator<<(std::ostream& os, const Box& b) { return os; }\nStream& operator<<(Stream& os, Mode m) { return os; }\nbool operator!=(const Box& a, const Box& b) { return false; }\nQDebug operator<<(QDebug d, const QString& s) { return d; }\nBox operator+(const Box& a, int n) { return a; }\n}",
        );
        assert_eq!(
            flagged("cpp/operator-hidden-friend", &[header, source]),
            [at("box.cpp", 2), at("box.cpp", 3), at("box.cpp", 7)]
        );
    }
    /// The class declared in a header, its member functions defined in
    /// another file: what they write and call decides.
    #[test]
    fn const_member_functions() {
        let header = (
            "box.h",
            "class Inner {\n public:\n  int get() const;\n  void set();\n};\nclass Box {\n public:\n  int area();\n  void grow();\n  int peek();\n  int poke();\n  int sum(int* out);\n  virtual int v();\n  int w_, h_;\n  Inner* in_;\n  int* buf_;\n};",
        );
        let source = (
            "box.cpp",
            "int Box::area() { return w_ * h_; }\nvoid Box::grow() { w_ += 1; }\nint Box::peek() { return in_->get(); }\nint Box::poke() { in_->set(); return 0; }\nint Box::sum(int* out) { int* p = buf_; *p = 1; *out = w_; return 0; }\nint Box::v() { return w_; }",
        );
        assert_eq!(
            flagged("cpp/const-member-function", &[header, source]),
            [at("box.cpp", 1), at("box.cpp", 3)]
        );
    }
}
