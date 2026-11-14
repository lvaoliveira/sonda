//! C++ rules that need classes from other files of the project (ADR-0020):
//! a member function compared with its bases' functions, a bitwise
//! operation with the type of the field it operates on. They run once per
//! scan, on the index the files' summaries build (`semantic::cpp_index`),
//! and are `Check::Structural` in the catalog.
//!
//! A base outside the project (Qt's, the standard library's) resolves to
//! nothing, and nothing is reported about it.

use crate::semantic::cpp_bytes::{ByteSite, is_byte, is_byte_pointer};
use crate::semantic::cpp_index::{ClassDecl, ClassId, FACT, FileIndex, MethodDecl, ProjectIndex};
use crate::semantic::cs_index::Span;

/// A finding: the rule, the index of the file it's in, and where.
pub(crate) type Finding = (&'static str, usize, Span);

pub(crate) const HIDDEN_FUNCTION: &str = "cpp/hidden-inherited-function";
pub(crate) const BYTE_OPERATION: &str = "cpp/std-byte";

/// The rules this module checks.
pub(crate) const RULES: &[&str] = &[HIDDEN_FUNCTION, BYTE_OPERATION];

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
    if active.contains(&BYTE_OPERATION) {
        found.extend(
            file.bytes
                .iter()
                .filter(|site| operates_on_a_byte(index, site))
                .map(|site| (BYTE_OPERATION, f, site.span)),
        );
    }
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
}
