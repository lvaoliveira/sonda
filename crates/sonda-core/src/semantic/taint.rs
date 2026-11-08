//! What taint analysis reports, whatever the language (ADR-0027): a sink a
//! request's value reaches, and the path it took. Each language's engine
//! (`cs_taint`, `js_taint`) produces these; the rules and the report only
//! see this module.

use tree_sitter::Node;

/// The most steps a path keeps: its first and its last half.
pub(crate) const MAX_STEPS: usize = 10;

/// One step of a path: where, and what happened to the value there.
#[derive(Clone, Debug)]
pub(crate) struct Step<'t> {
    pub(crate) node: Node<'t>,
    pub(crate) message: String,
}

/// A source reaching a sink: the sink's expression, and the path, which
/// ends at the sink.
#[derive(Debug)]
pub(crate) struct Finding<'t> {
    pub(crate) sink: Node<'t>,
    pub(crate) steps: Vec<Step<'t>>,
}

/// What a sink is for; a sanitizer clears taint for its own kind only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SinkKind {
    Sql,
    Command,
    Path,
    Redirect,
    Ssrf,
    XPath,
    Ldap,
    /// Code the program runs: `eval`, `new Function`, `vm.runInContext`.
    Code,
}

/// A long path keeps its first and last steps.
pub(crate) fn cap(steps: Vec<Step>) -> Vec<Step> {
    if steps.len() <= MAX_STEPS {
        return steps;
    }
    let half = MAX_STEPS / 2;
    let mut kept: Vec<Step> = steps[..half].to_vec();
    kept.extend_from_slice(&steps[steps.len() - half..]);
    kept
}
