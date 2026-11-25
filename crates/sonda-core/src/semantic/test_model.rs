//! What the binders' tests share: a model built from source, and its
//! declarations looked up by name.

use super::{DeclKind, Model};
use crate::lang::Lang;
use std::time::{Duration, Instant};

/// Builds `lang`'s model of `src` and hands it to `check`.
pub(super) fn with_model(lang: Lang, src: &str, check: impl FnOnce(&Model)) {
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang.grammar()).unwrap();
    let tree = parser.parse(src, None).unwrap();
    let model = super::build(
        lang,
        tree.root_node(),
        src.as_bytes(),
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    check(&model);
}

/// The `n`th declaration called `name`, as (kind, reads, writes).
pub(super) fn decl(m: &Model, name: &str, n: usize) -> (DeclKind, u32, u32) {
    let d = m.decls.iter().filter(|d| d.name == name).nth(n).unwrap();
    (d.kind, d.reads, d.writes)
}

pub(super) fn count(m: &Model, name: &str) -> usize {
    m.decls.iter().filter(|d| d.name == name).count()
}
