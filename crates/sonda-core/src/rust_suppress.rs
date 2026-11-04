//! Suppressions in Rust files ([ADR-0026](../../../docs/adr/0026-rust.md)).
//!
//! SonarQube's Rust rules are Clippy lints under its own keys, and the
//! scanner runs Clippy, so what silences a finding there is Clippy's:
//! `#[allow(clippy::lint)]` and `#[expect(clippy::lint)]` on an item or
//! statement (the thing the attribute is written on), `#![allow(...)]` for the
//! enclosing module or file, either inside `#[cfg_attr(..., allow(...))]`
//! too, and Clippy's groups (`clippy::all`, `clippy::pedantic`...). `// NOSONAR`
//! doesn't silence a Rust finding there, though it does here, as in every
//! other language.

use crate::analysis::SuppressedRegion;
use tree_sitter::Node;

/// SonarQube's Rust rules: the Clippy lint, its SonarQube key, its group, and
/// whether `clippy::all` covers it.
pub(crate) static CLIPPY_LINTS: &[(&str, &str, &str, bool)] = &[
    ("print_stdout", "S106", "restriction", false),
    ("too_many_arguments", "S107", "complexity", true),
    ("else_if_without_else", "S126", "restriction", false),
    ("no_effect", "S905", "complexity", true),
    ("match_bool", "S920", "pedantic", false),
    ("unnecessary_semicolon", "S1116", "pedantic", false),
    ("let_and_return", "S1488", "style", true),
    (
        "redundant_closure_for_method_calls",
        "S1612",
        "pedantic",
        false,
    ),
    ("self_assignment", "S1656", "correctness", true),
    ("never_loop", "S1751", "correctness", true),
    ("eq_op", "S1764", "correctness", true),
    ("string_to_string", "S1858", "restriction", false),
    ("ifs_same_cond", "S1862", "correctness", true),
    ("unreadable_literal", "S2148", "pedantic", false),
    ("erasing_op", "S2185", "correctness", true),
    ("while_float", "S2193", "nursery", false),
    ("absurd_extreme_comparisons", "S2198", "correctness", true),
    ("wildcard_imports", "S2208", "pedantic", false),
    ("ineffective_bit_mask", "S2437", "correctness", true),
    ("invisible_characters", "S2479", "correctness", true),
    ("overly_complex_bool_expr", "S2589", "pedantic", false),
    ("redundant_field_names", "S3498", "style", true),
    ("possible_missing_comma", "S3723", "correctness", true),
    ("invalid_null_ptr_usage", "S3807", "correctness", true),
    ("misnamed_getters", "S4275", "suspicious", true),
    ("unnecessary_cast", "S4325", "complexity", true),
    ("zero_ptr", "S4962", "style", true),
    ("invalid_regex", "S5856", "correctness", true),
    ("approx_constant", "S6164", "correctness", true),
    ("out_of_bounds_indexing", "S6466", "correctness", true),
    ("min_max", "S6913", "correctness", true),
    ("vec_init_then_push", "S7089", "perf", true),
    ("vec_resize_to_zero", "S7200", "correctness", true),
    ("branches_sharing_code", "S7411", "nursery", false),
    ("zst_offset", "S7412", "correctness", true),
    ("async_yields_async", "S7413", "correctness", true),
    ("wrong_transmute", "S7414", "correctness", true),
    ("while_immutable_condition", "S7415", "correctness", true),
    ("derive_ord_xor_partial_ord", "S7417", "correctness", true),
    ("useless_attribute", "S7418", "correctness", true),
    ("unused_io_amount", "S7419", "correctness", true),
    ("unsound_collection_transmute", "S7420", "correctness", true),
    ("unit_return_expecting_ord", "S7421", "correctness", true),
    ("unit_hash", "S7422", "correctness", true),
    ("unit_cmp", "S7423", "correctness", true),
    ("derived_hash_with_manual_eq", "S7424", "correctness", true),
    ("uninit_assumed_init", "S7425", "correctness", true),
    (
        "enum_clike_unportable_variant",
        "S7426",
        "correctness",
        true,
    ),
    ("transmuting_null", "S7427", "correctness", true),
    ("match_str_case_mismatch", "S7428", "correctness", true),
    ("transmute_null_to_fn", "S7429", "correctness", true),
    ("suspicious_splitn", "S7430", "correctness", true),
    ("size_of_in_element_count", "S7431", "correctness", true),
    ("reversed_empty_ranges", "S7432", "correctness", true),
    ("cast_slice_different_sizes", "S7433", "correctness", true),
    ("redundant_comparisons", "S7436", "correctness", true),
    ("almost_swapped", "S7437", "correctness", true),
    ("bad_bit_mask", "S7438", "correctness", true),
    ("impossible_comparisons", "S7439", "correctness", true),
    ("recursive_format_impl", "S7440", "correctness", true),
    ("read_line_without_trim", "S7441", "correctness", true),
    ("panicking_unwrap", "S7442", "correctness", true),
    ("eager_transmute", "S7443", "correctness", true),
    ("panicking_overflow_checks", "S7444", "correctness", true),
    ("option_env_unwrap", "S7445", "correctness", true),
    ("not_unsafe_ptr_arg_deref", "S7446", "correctness", true),
    ("nonsensical_open_options", "S7447", "correctness", true),
    ("non_octal_unix_permissions", "S7448", "correctness", true),
    ("inline_fn_without_body", "S7449", "correctness", true),
    ("let_underscore_lock", "S7450", "correctness", true),
    ("modulo_one", "S7451", "correctness", true),
    ("mut_from_ref", "S7453", "correctness", true),
    ("mistyped_literal_suffixes", "S7454", "correctness", true),
    ("iter_next_loop", "S7455", "correctness", true),
    ("iter_skip_zero", "S7456", "correctness", true),
    ("iterator_step_by_zero", "S7457", "correctness", true),
    (
        "inherent_to_string_shadow_display",
        "S7458",
        "correctness",
        true,
    ),
    ("uninit_vec", "S7459", "correctness", true),
    ("serde_api_misuse", "S7460", "correctness", true),
    (
        "impl_hash_borrow_with_str_and_bytes",
        "S7461",
        "correctness",
        true,
    ),
    ("mem_replace_with_uninit", "S7462", "correctness", true),
    ("inverted_saturating_sub", "S7463", "correctness", true),
    ("infinite_iter", "S7464", "correctness", true),
];

/// The SonarQube keys a `clippy::name` in an `allow` silences: one lint's, or
/// every lint of a group.
fn keys(name: &str) -> Vec<&'static str> {
    CLIPPY_LINTS
        .iter()
        .filter(|(lint, _, group, in_all)| {
            *lint == name || *group == name || (name == "all" && *in_all)
        })
        .map(|(_, key, _, _)| *key)
        .collect()
}

/// The rules Clippy doesn't apply to test code: printing and globbing are
/// how tests are written, and they compare a value with itself on purpose.
pub(crate) const TEST_EXEMPT: &[&str] = &[
    "rs/wildcard-import",
    "rs/print-stdout",
    "rs/identical-operands",
];

/// Whether a file is test code by where it is: under a `tests` directory, or
/// a module file named `tests.rs` or `test.rs`.
pub(crate) fn is_test_file(path: &str) -> bool {
    let mut parts: Vec<&str> = path.split(['/', '\\']).collect();
    let file = parts.pop().unwrap_or_default();
    parts.contains(&"tests") || matches!(file, "tests.rs" | "test.rs")
}

/// The `clippy::name`s in the text of an attribute that allows or expects.
fn clippy_names(attribute: &str) -> Vec<&str> {
    let allows = ["allow", "expect"].iter().any(|a| {
        attribute
            .match_indices(a)
            .any(|(i, _)| attribute[i + a.len()..].trim_start().starts_with('('))
    });
    if !allows {
        return Vec::new();
    }
    attribute
        .match_indices("clippy::")
        .map(|(i, m)| {
            let rest = &attribute[i + m.len()..];
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .collect()
}

/// The regions the file's `allow` and `expect` attributes silence.
pub(crate) fn regions(src: &str, root: Node) -> Vec<SuppressedRegion> {
    let mut regions = Vec::new();
    if !src.contains("clippy::") {
        return regions;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let kind = node.kind();
        if matches!(kind, "attribute_item" | "inner_attribute_item") {
            let names = clippy_names(&src[node.byte_range()]);
            if names.is_empty() {
                continue;
            }
            let Some((start, end)) = extent(node, kind == "inner_attribute_item") else {
                continue;
            };
            for key in names.into_iter().flat_map(keys) {
                regions.push(SuppressedRegion::new(Some(key.to_string()), start, end));
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    regions
}

/// The lines (1-based, both included) an attribute covers: what an outer one
/// is written on, or the module, block or file an inner one is in.
fn extent(attribute: Node, inner: bool) -> Option<(usize, usize)> {
    if inner {
        let parent = attribute.parent()?;
        return Some((
            parent.start_position().row + 1,
            parent.end_position().row + 1,
        ));
    }
    let mut next = attribute.next_named_sibling();
    while let Some(n) = next {
        if !matches!(
            n.kind(),
            "attribute_item" | "line_comment" | "block_comment"
        ) {
            return Some((attribute.start_position().row + 1, n.end_position().row + 1));
        }
        next = n.next_named_sibling();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Lang;

    fn regions_of(src: &str) -> Vec<(String, usize, usize)> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Rust.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let mut found: Vec<_> = regions(src, tree.root_node())
            .into_iter()
            .map(|r| (r.key().unwrap_or_default().to_string(), r.start(), r.end()))
            .collect();
        found.sort();
        found
    }

    #[test]
    fn an_outer_allow_covers_what_it_is_written_on() {
        let src = "#[allow(clippy::self_assignment)]\nfn a() {\n    x = x;\n}\nfn b() {}\n";
        assert_eq!(regions_of(src), [("S1656".to_string(), 1, 4)]);
    }

    #[test]
    fn it_covers_statements_and_skips_other_attributes_and_comments() {
        let src = "fn a() {\n    #[allow(clippy::eq_op)]\n    // why\n    #[rustfmt::skip]\n    let y = x == x;\n    z;\n}\n";
        assert_eq!(regions_of(src), [("S1764".to_string(), 2, 5)]);
    }

    #[test]
    fn an_inner_allow_covers_its_module_or_file() {
        let src = "#![allow(clippy::eq_op)]\nfn a() {}\nmod m {\n    #![allow(clippy::self_assignment)]\n}\n";
        assert_eq!(
            regions_of(src),
            [("S1656".to_string(), 3, 5), ("S1764".to_string(), 1, 6)]
        );
    }

    #[test]
    fn groups_cover_their_lints_and_expect_and_cfg_attr_count() {
        let all = regions_of("#![allow(clippy::all)]\nfn a() {}\n");
        assert!(all.iter().any(|(k, ..)| k == "S1656"), "{all:?}");
        // `else_if_without_else` is a restriction lint: `all` leaves it out.
        assert!(!all.iter().any(|(k, ..)| k == "S126"), "{all:?}");
        let restriction = regions_of("#![allow(clippy::restriction)]\nfn a() {}\n");
        assert!(restriction.iter().any(|(k, ..)| k == "S126"));
        assert_eq!(
            regions_of("#[expect(clippy::eq_op, reason = \"x\")]\nfn a() {}\n").len(),
            1
        );
        assert_eq!(
            regions_of("#[cfg_attr(test, allow(clippy::eq_op))]\nfn a() {}\n").len(),
            1
        );
    }

    #[test]
    fn test_files_are_found_by_where_they_are() {
        assert!(is_test_file("tests/cli.rs"));
        assert!(is_test_file("crate/tests/sub/a.rs"));
        assert!(is_test_file("src/range_set/tests.rs"));
        assert!(is_test_file("src\\tests\\a.rs"));
        assert!(!is_test_file("src/attests.rs"));
        assert!(!is_test_file("src/lib.rs"));
    }

    #[test]
    fn other_attributes_and_lints_silence_nothing() {
        assert!(regions_of("#[allow(unused)]\nfn a() {}\n").is_empty());
        assert!(regions_of("#[warn(clippy::eq_op)]\nfn a() {}\n").is_empty());
        assert!(regions_of("#[allow(clippy::no_such_lint)]\nfn a() {}\n").is_empty());
    }
}
