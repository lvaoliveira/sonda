use serde::Serialize;
use std::path::Path;
use tree_sitter::Language;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    JavaScript,
    TypeScript,
    Tsx,
    Python,
    Java,
    C,
    Cpp,
}

pub(crate) const JS_TS: &[Lang] = &[Lang::JavaScript, Lang::TypeScript, Lang::Tsx];
pub(crate) const TS: &[Lang] = &[Lang::TypeScript, Lang::Tsx];
pub(crate) const PYTHON: &[Lang] = &[Lang::Python];
pub(crate) const JAVA: &[Lang] = &[Lang::Java];
pub(crate) const C_CPP: &[Lang] = &[Lang::C, Lang::Cpp];
pub(crate) const C_ONLY: &[Lang] = &[Lang::C];
/// Every supported language.
pub const ALL: &[Lang] = &[
    Lang::JavaScript,
    Lang::TypeScript,
    Lang::Tsx,
    Lang::Python,
    Lang::Java,
    Lang::C,
    Lang::Cpp,
];

impl Lang {
    /// Detects the language from the file extension. `.h` is treated as C;
    /// C++ headers should use `.hpp`/`.hh`/`.hxx`.
    pub fn from_path(path: &Path) -> Option<Lang> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "js" | "mjs" | "cjs" | "jsx" => Lang::JavaScript,
            "ts" | "mts" | "cts" => Lang::TypeScript,
            "tsx" => Lang::Tsx,
            "py" | "pyi" => Lang::Python,
            "java" => Lang::Java,
            "c" | "h" => Lang::C,
            "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" => Lang::Cpp,
            _ => return None,
        })
    }

    /// Position in `ALL`, a stable one-byte encoding.
    pub(crate) fn index(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_index(index: u8) -> Option<Lang> {
        ALL.get(usize::from(index)).copied()
    }

    pub fn name(self) -> &'static str {
        match self {
            Lang::JavaScript => "javascript",
            Lang::TypeScript => "typescript",
            Lang::Tsx => "tsx",
            Lang::Python => "python",
            Lang::Java => "java",
            Lang::C => "c",
            Lang::Cpp => "cpp",
        }
    }

    pub(crate) fn grammar(self) -> Language {
        match self {
            Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Lang::Python => tree_sitter_python::LANGUAGE.into(),
            Lang::Java => tree_sitter_java::LANGUAGE.into(),
            Lang::C => tree_sitter_c::LANGUAGE.into(),
            Lang::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        }
    }

    pub(crate) fn syntax(self) -> &'static Syntax {
        match self {
            Lang::JavaScript | Lang::TypeScript | Lang::Tsx => &JS_SYNTAX,
            Lang::Python => &PYTHON_SYNTAX,
            Lang::Java => &JAVA_SYNTAX,
            Lang::C | Lang::Cpp => &C_SYNTAX,
        }
    }
}

/// Per-language node kinds used by the structural checks and metrics.
/// `if_statement`, `else_clause` and `elif_clause` are handled specially
/// by the complexity walker and are not listed here.
pub(crate) struct Syntax {
    /// Nodes measured as functions (complexity, length, parameters).
    pub(crate) functions: &'static [&'static str],
    /// Loops, catches and ternaries: +1 cyclomatic, +1 (+nesting) cognitive.
    pub(crate) branches: &'static [&'static str],
    /// Switch/match constructs: +1 (+nesting) cognitive once per switch.
    pub(crate) switches: &'static [&'static str],
    /// Switch cases: +1 cyclomatic each (default cases excluded).
    pub(crate) cases: &'static [&'static str],
    pub(crate) comments: &'static [&'static str],
    /// Subtrees left out of duplication detection (imports and the like).
    pub(crate) dup_ignore: &'static [&'static str],
}

static JS_SYNTAX: Syntax = Syntax {
    functions: &[
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "generator_function",
        "arrow_function",
        "method_definition",
    ],
    branches: &[
        "for_statement",
        "for_in_statement",
        "while_statement",
        "do_statement",
        "catch_clause",
        "ternary_expression",
    ],
    switches: &["switch_statement"],
    cases: &["switch_case"],
    comments: &["comment"],
    dup_ignore: &["import_statement"],
};

static PYTHON_SYNTAX: Syntax = Syntax {
    functions: &["function_definition"],
    branches: &[
        "for_statement",
        "while_statement",
        "except_clause",
        "conditional_expression",
    ],
    switches: &["match_statement"],
    cases: &["case_clause"],
    comments: &["comment"],
    dup_ignore: &[
        "import_statement",
        "import_from_statement",
        "future_import_statement",
    ],
};

static JAVA_SYNTAX: Syntax = Syntax {
    functions: &[
        "method_declaration",
        "constructor_declaration",
        "compact_constructor_declaration",
        "lambda_expression",
    ],
    branches: &[
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
        "catch_clause",
        "ternary_expression",
    ],
    switches: &["switch_expression"],
    cases: &["switch_label"],
    comments: &["line_comment", "block_comment"],
    dup_ignore: &["import_declaration", "package_declaration"],
};

static C_SYNTAX: Syntax = Syntax {
    functions: &["function_definition", "lambda_expression"],
    branches: &[
        "for_statement",
        "for_range_loop",
        "while_statement",
        "do_statement",
        "catch_clause",
        "conditional_expression",
    ],
    switches: &["switch_statement"],
    cases: &["case_statement"],
    comments: &["comment"],
    dup_ignore: &["preproc_include"],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_round_trips_through_all() {
        for (i, &lang) in ALL.iter().enumerate() {
            assert_eq!(usize::from(lang.index()), i);
            assert_eq!(Lang::from_index(lang.index()), Some(lang));
        }
        assert_eq!(Lang::from_index(ALL.len() as u8), None);
    }

    #[test]
    fn detects_languages_by_extension() {
        assert_eq!(Lang::from_path(Path::new("a/b.tsx")), Some(Lang::Tsx));
        assert_eq!(Lang::from_path(Path::new("x.PY")), Some(Lang::Python));
        assert_eq!(Lang::from_path(Path::new("x.hpp")), Some(Lang::Cpp));
        assert_eq!(Lang::from_path(Path::new("Makefile")), None);
    }

    #[test]
    fn every_syntax_node_kind_exists_in_its_grammar() {
        for &lang in ALL {
            let syn = lang.syntax();
            let kinds = syn
                .functions
                .iter()
                .chain(syn.branches)
                .chain(syn.switches)
                .chain(syn.cases)
                .chain(syn.comments)
                .chain(syn.dup_ignore);
            // A kind missing from one dialect (e.g. lambda_expression in C) is fine
            // as long as at least one language sharing this table knows it.
            for kind in kinds {
                let known = ALL
                    .iter()
                    .filter(|l| std::ptr::eq(l.syntax(), syn))
                    .any(|l| l.grammar().id_for_node_kind(kind, true) != 0);
                assert!(known, "{kind} unknown for {lang:?}");
            }
        }
    }
}
