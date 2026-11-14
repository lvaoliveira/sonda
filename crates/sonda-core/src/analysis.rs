use crate::config::Config;
use crate::lang::{Lang, Syntax};
use crate::model::{Category, Digest, FileMetrics, Fingerprint, Issue, Sha256};
use crate::rules::{self, ActiveRule, Check, Filter, RuleSet};
use crate::semantic;
use sha2::Digest as _;
use std::cell::Cell;
use std::collections::HashMap;
use std::ops::ControlFlow;
use std::time::Instant;
use tree_sitter::{Node, ParseOptions, Parser, QueryCursor, QueryCursorOptions, StreamingIterator};

/// A source token for duplication detection: hash of its text and its 1-based line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) hash: u64,
    pub(crate) line: usize,
}

#[cfg_attr(test, derive(Debug, PartialEq))]
pub(crate) struct FileAnalysis {
    pub(crate) path: String,
    pub(crate) lang: Lang,
    pub(crate) issues: Vec<Issue>,
    pub(crate) metrics: FileMetrics,
    /// 1-based numbers of lines holding code (not just comments or blanks), ascending.
    pub(crate) code_lines: Vec<usize>,
    pub(crate) tokens: Vec<Token>,
    pub(crate) has_syntax_errors: bool,
    /// Small (kind, value) facts for rules that look across files, such as
    /// the package a Java file declares. Empty for other languages.
    pub(crate) facts: Vec<(String, String)>,
    /// The semantic layer ran out of time: semantic rules found nothing.
    pub(crate) semantic_incomplete: bool,
    /// Of the exact bytes analyzed, so a later upload can prove it sends the same source.
    pub(crate) sha256: Sha256,
}

/// Why a file could not be analyzed. The scanner reports it as a warning.
#[derive(Debug, thiserror::Error)]
pub(crate) enum FileError {
    #[error("parsing did not finish before the per-file timeout")]
    ParseTimeout,
    #[error("rule matching did not finish before the per-file timeout")]
    QueryTimeout,
    #[error("grammar is incompatible with the tree-sitter runtime: {0}")]
    Grammar(#[from] tree_sitter::LanguageError),
    #[error("{0}")]
    Rules(String),
}

/// Analyzes one file. Parsing and query matching stop with an error once
/// `deadline` passes, so a pathological file cannot stall the scan; the
/// remaining passes are linear in the size of the tree.
pub(crate) fn analyze(
    path: &str,
    lang: Lang,
    src: &str,
    rules: &RuleSet,
    cfg: &Config,
    deadline: Instant,
) -> Result<FileAnalysis, FileError> {
    let mut parser = Parser::new();
    parser.set_language(&lang.grammar())?;
    // Newer Python syntax, rewritten in place for the grammar; rules read
    // `src` itself, at the same positions.
    let parsed = match lang {
        Lang::Python => crate::py_syntax::for_parser(src),
        _ => std::borrow::Cow::Borrowed(src),
    };
    let bytes = parsed.as_bytes();
    let mut check_deadline = |_: &_| expired(deadline);
    let options = ParseOptions::new().progress_callback(&mut check_deadline);
    let Some(tree) = parser.parse_with_options(
        &mut |offset, _| &bytes[offset.min(bytes.len())..],
        None,
        Some(options),
    ) else {
        return Err(FileError::ParseTimeout);
    };
    let root = tree.root_node();
    let ctx = Ctx {
        path,
        src,
        lines: LineIndex::new(src),
        java_version: cfg.java.version,
    };
    let syn = lang.syntax();

    let mut issues = run_queries(&ctx, lang, root, rules, deadline)?;
    if lang == Lang::Rust {
        issues.extend(macro_argument_issues(
            &mut parser,
            src,
            root,
            path,
            rules,
            deadline,
        ));
    }
    let mut taint_facts = Vec::new();
    let semantic_incomplete = run_semantic(
        &ctx,
        lang,
        root,
        rules,
        deadline,
        &mut issues,
        &mut taint_facts,
    );
    let mut metrics = FileMetrics::default();
    measure_functions(&ctx, syn, root, rules, cfg, &mut issues, &mut metrics);
    let scan = scan_tokens(&ctx, syn, root, rules, &mut issues);
    scan_lines(&ctx, rules, scan.code_lines.len(), &mut issues);
    scan_java_files(&ctx, lang, root, rules, &mut issues);
    scan_js_files(&ctx, lang, root, rules, &mut issues);
    scan_py_files(&ctx, lang, root, rules, &mut issues);

    metrics.lines = ctx.lines.count();
    metrics.ncloc = scan.code_lines.len();
    metrics.comment_lines = scan.comment_lines;

    // Each line's suppression is read once: a file of one very long line can
    // have thousands of issues on it.
    let mut suppressions: HashMap<usize, Suppression> = HashMap::new();
    // C#'s `#pragma warning disable S1234` regions and `[SuppressMessage]`
    // attributes silence SonarQube keys.
    let pragmas = match lang {
        Lang::CSharp => suppressed_regions(src, root),
        // Rust's `#[allow(clippy::...)]`, which silences SonarQube's Clippy-based rules.
        Lang::Rust => crate::rust_suppress::regions(src, root),
        // `@SuppressWarnings("java:S1234")` and `("all")`.
        Lang::Java => java_suppressed_regions(src, root),
        _ => Vec::new(),
    };
    if lang == Lang::Rust {
        let test_file = crate::rust_suppress::is_test_file(path);
        issues.retain(|i| {
            !rules::NOT_ON_RUST.contains(&i.rule)
                && !(test_file && crate::rust_suppress::TEST_EXEMPT.contains(&i.rule))
        });
    }
    issues.retain(|i| {
        // A malformed suppression comment cannot suppress the report about itself.
        i.rule == rules::NOSONAR_COMMENT
            || i.rule == "py/suppression-comment-format"
            || !(suppressions
                .entry(i.line)
                .or_insert_with(|| Suppression::of(ctx.lines.text(i.line - 1)))
                .covers(i.rule)
                || silenced_in(&pragmas, i.line, i.rule))
    });
    // A total order, so output never depends on the order rules ran in.
    issues.sort_by(|a, b| {
        (
            a.line,
            a.column,
            a.rule,
            a.end_line,
            a.end_column,
            &a.message,
        )
            .cmp(&(
                b.line,
                b.column,
                b.rule,
                b.end_line,
                b.end_column,
                &b.message,
            ))
    });
    issues.dedup_by(|a, b| a.rule == b.rule && a.line == b.line && a.column == b.column);
    fingerprints(&ctx, &mut issues);

    Ok(FileAnalysis {
        path: path.to_string(),
        lang,
        issues,
        metrics,
        code_lines: scan.code_lines,
        tokens: scan.tokens,
        has_syntax_errors: root.has_error(),
        facts: match lang {
            Lang::CSharp => cs_facts(&ctx, root, deadline),
            Lang::Cpp => cpp_facts(&ctx, root, deadline),
            _ => java_facts(&ctx, lang, root, deadline)
                .into_iter()
                .chain(js_facts(&ctx, lang, root, rules))
                .collect(),
        }
        .into_iter()
        .chain(taint_facts)
        .collect(),
        semantic_incomplete,
        sha256: Digest(sha2::Sha256::digest(bytes).into()),
    })
}

/// Gives each issue an identity that survives re-scans: a hash of the rule,
/// the path, the flagged line's text with all whitespace removed, and how
/// many earlier issues in the file share those three. So edits elsewhere in
/// the file, moving the line and re-indenting it keep the fingerprint;
/// changing the flagged line itself does not. `issues` must be sorted.
fn fingerprints(ctx: &Ctx, issues: &mut [Issue]) {
    use sha2::Digest as _;
    // Many issues can share one very long line (minified code, a generated
    // file): the line is normalized and hashed once per rule, not per issue.
    let mut text_ids: HashMap<String, usize> = HashMap::new();
    let mut line_text: HashMap<usize, usize> = HashMap::new();
    let mut seen: HashMap<(&str, usize), (sha2::Sha256, u64)> = HashMap::new();
    for issue in issues {
        let row = issue.line - 1;
        let id = *line_text.entry(row).or_insert_with(|| {
            let line: String = ctx
                .lines
                .text(row)
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let next = text_ids.len();
            *text_ids.entry(line).or_insert(next)
        });
        let entry = seen.entry((issue.rule, id)).or_insert_with(|| {
            let line = ctx
                .lines
                .text(row)
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>();
            let mut hasher = sha2::Sha256::new();
            // Length-prefixed fields, so no two different inputs hash the same
            // bytes; the tag lets the algorithm change without silent collisions.
            for field in ["sonda-fingerprint-v1", issue.rule, ctx.path, &line] {
                hasher.update((field.len() as u64).to_le_bytes());
                hasher.update(field.as_bytes());
            }
            (hasher, 0)
        });
        let mut hasher = entry.0.clone();
        hasher.update(entry.1.to_le_bytes());
        entry.1 += 1;
        let hash = hasher.finalize();
        let mut short = [0; 16];
        short.copy_from_slice(&hash[..16]);
        issue.fingerprint = Digest(short);
    }
}

struct Ctx<'a> {
    path: &'a str,
    src: &'a str,
    lines: LineIndex<'a>,
    /// The Java version the project targets, when known.
    java_version: Option<u32>,
}

impl<'a> Ctx<'a> {
    fn issue(&self, active: &ActiveRule, node: Node, message: String, effort: u32) -> Issue {
        let start = node.start_position();
        let end = node.end_position();
        Issue {
            rule: active.rule.id,
            severity: active.severity,
            category: active.rule.category,
            message,
            path: self.path.to_string(),
            line: start.row + 1,
            column: self.lines.char_column(start.row, start.column),
            end_line: end.row + 1,
            end_column: self.lines.char_column(end.row, end.column),
            effort_minutes: effort,
            is_new: true,
            // Set once the file's issues are final; see `fingerprints`.
            fingerprint: Fingerprint::default(),
            flow: Vec::new(),
        }
    }

    /// A step of a taint finding's path, at a node.
    fn flow_step(&self, node: Node, message: &str) -> crate::model::FlowStep {
        let (start, end) = (node.start_position(), node.end_position());
        crate::model::FlowStep {
            path: None,
            message: message.to_string(),
            line: start.row + 1,
            column: self.lines.char_column(start.row, start.column),
            end_line: end.row + 1,
            end_column: self.lines.char_column(end.row, end.column),
        }
    }

    /// An issue on a span of one line, in 0-based character columns.
    fn issue_on_line(
        &self,
        active: &ActiveRule,
        row: usize,
        columns: (usize, usize),
        message: String,
    ) -> Issue {
        Issue {
            rule: active.rule.id,
            severity: active.severity,
            category: active.rule.category,
            message,
            path: self.path.to_string(),
            line: row + 1,
            column: columns.0 + 1,
            end_line: row + 1,
            end_column: columns.1 + 1,
            effort_minutes: active.rule.effort_minutes,
            is_new: true,
            fingerprint: Fingerprint::default(),
            flow: Vec::new(),
        }
    }

    fn text(&self, node: Node) -> &'a str {
        &self.src[node.byte_range()]
    }
}

/// The facts the project-level Java rules need from this file: its package,
/// the base packages its Spring scan annotations cover, and the lines of
/// the components it declares.
fn java_facts(ctx: &Ctx, lang: Lang, root: Node, deadline: Instant) -> Vec<(String, String)> {
    if lang != Lang::Java {
        return Vec::new();
    }
    let mut facts = Vec::new();
    // The types this file declares, for rules that compare declarations
    // across files (ADR-0020).
    let index = crate::semantic::java_index::extract(root, ctx.src.as_bytes(), deadline);
    if (!index.types.is_empty() || !index.sites.is_empty())
        && let Ok(json) = serde_json::to_string(&index)
    {
        facts.push((crate::semantic::java_index::FACT.to_string(), json));
    }
    // Lines whose comment suppresses issues, for the issues the project
    // pass adds.
    facts.extend(suppressed_lines(ctx.src, JAVA_SUPPRESSED_LINES));
    let regions = java_suppressed_regions(ctx.src, root);
    if !regions.is_empty()
        && let Ok(json) = serde_json::to_string(&regions)
    {
        facts.push((SUPPRESSION_FACT.to_string(), json));
    }
    let mut cursor = root.walk();
    let children: Vec<Node> = root.named_children(&mut cursor).collect();
    let package = java_package(ctx, &children);
    if let Some(p) = &package {
        facts.push(("package".to_string(), p.clone()));
    }
    for class in children.iter().filter(|n| n.kind() == "class_declaration") {
        let Some(mods) = class
            .children(&mut class.walk())
            .find(|c| c.kind() == "modifiers")
        else {
            continue;
        };
        let t = ctx.text(mods);
        if t.contains("@SpringBootApplication") || t.contains("@ComponentScan") {
            for b in spring_scan_bases(ctx, mods, package.as_deref()) {
                facts.push(("scan".to_string(), b));
            }
        }
        if COMPONENT_ANNOTATIONS.iter().any(|a| t.contains(a)) {
            facts.push((
                "component".to_string(),
                (class.start_position().row + 1).to_string(),
            ));
        }
    }
    facts
}

/// The annotations that make a class a Spring component.
const COMPONENT_ANNOTATIONS: &[&str] = &[
    "@Component",
    "@Service",
    "@Repository",
    "@Controller",
    "@RestController",
    "@Configuration",
];

/// The file's package, from its `package` declaration.
fn java_package(ctx: &Ctx, children: &[Node]) -> Option<String> {
    children
        .iter()
        .find(|n| n.kind() == "package_declaration")
        .and_then(|d| {
            d.named_children(&mut d.walk())
                .find(|n| matches!(n.kind(), "scoped_identifier" | "identifier"))
        })
        .map(|n| ctx.text(n).to_string())
}

/// The packages a Spring scan annotation in `mods` covers: the strings in
/// it, or the class's own package when it names none.
fn spring_scan_bases(ctx: &Ctx, mods: Node, package: Option<&str>) -> Vec<String> {
    let mut bases: Vec<String> = Vec::new();
    let mut stack = vec![mods];
    while let Some(n) = stack.pop() {
        if n.kind() == "string_literal" {
            bases.push(ctx.text(n).trim_matches('"').to_string());
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    if bases.is_empty() {
        bases.extend(package.map(str::to_string));
    }
    bases
}

/// AssemblyInfo attributes of a classic project, which sets them by hand
/// (SDK-style projects generate them from the project file).
const CS_ASSEMBLY_INFO: &[&str] = &[
    "AssemblyTitle",
    "AssemblyDescription",
    "AssemblyProduct",
    "AssemblyCompany",
    "AssemblyCopyright",
];

/// The `[assembly: ...]` attributes of a C# file, by name without the
/// `Attribute` suffix, and the first one's line.
pub(crate) fn cs_assembly_attributes<'a>(
    src: &'a str,
    root: Node,
) -> (Vec<&'a str>, Option<usize>) {
    let mut cursor = root.walk();
    let globals: Vec<Node> = root
        .named_children(&mut cursor)
        .filter(|n| {
            n.kind() == "global_attribute"
                && src[n.byte_range()]
                    .trim_start_matches('[')
                    .trim_start()
                    .starts_with("assembly")
        })
        .collect();
    let names = globals
        .iter()
        .filter_map(|g| g.named_child(0))
        .filter_map(|a| a.child_by_field_name("name"))
        .map(|n| {
            let full = &src[n.byte_range()];
            let last = full.rsplit('.').next().unwrap_or(full);
            last.strip_suffix("Attribute").unwrap_or(last)
        })
        .collect();
    (names, globals.first().map(|g| g.start_position().row + 1))
}

/// Whether a file's assembly attributes are a classic, hand-written
/// AssemblyInfo.
pub(crate) fn is_classic_assembly_info(names: &[&str]) -> bool {
    names.iter().any(|n| CS_ASSEMBLY_INFO.contains(n))
}

/// The facts the project-level C# rules need from this file: its partial
/// methods (declared only, or implemented), whether it uses resources, and
/// where its classic AssemblyInfo attributes are when they lack
/// NeutralResourcesLanguage.
fn cs_facts(ctx: &Ctx, root: Node, deadline: Instant) -> Vec<(String, String)> {
    let mut facts = Vec::new();
    suppression_facts(ctx, root, &mut facts);
    // The types this file declares, for rules that compare declarations
    // across files (ADR-0020).
    let index = crate::semantic::cs_index::extract(root, ctx.src.as_bytes(), deadline);
    if !index.types.is_empty()
        && let Ok(json) = serde_json::to_string(&index)
    {
        facts.push((crate::semantic::cs_index::FACT.to_string(), json));
    }
    if ctx.src.contains("ResourceManager") {
        facts.push(("cs-resources".to_string(), String::new()));
    }
    if ctx.src.contains("assembly") {
        let (names, line) = cs_assembly_attributes(ctx.src, root);
        if is_classic_assembly_info(&names)
            && !names.contains(&"NeutralResourcesLanguage")
            && let Some(line) = line
        {
            facts.push(("cs-assembly-info".to_string(), line.to_string()));
        }
    }
    if ctx.src.contains("partial") {
        partial_method_facts(ctx, root, &mut facts);
    }
    facts
}

/// The file's pragma regions and `[SuppressMessage]`s, and its
/// assembly-level ones.
fn suppression_facts(ctx: &Ctx, root: Node, facts: &mut Vec<(String, String)>) {
    let pragmas = suppressed_regions(ctx.src, root);
    if !pragmas.is_empty()
        && let Ok(json) = serde_json::to_string(&pragmas)
    {
        facts.push((SUPPRESSION_FACT.to_string(), json));
    }
    if ctx.src.contains("SuppressMessage") {
        let globals = global_suppressions(ctx.src, root);
        if !globals.is_empty()
            && let Ok(json) = serde_json::to_string(&globals)
        {
            facts.push((GLOBAL_SUPPRESSION_FACT.to_string(), json));
        }
    }
}

/// A designer or source-generated file.
fn is_generated_file(ctx: &Ctx) -> bool {
    let lower = ctx.path.to_ascii_lowercase();
    [".designer.cs", ".g.cs", ".g.i.cs", ".generated.cs"]
        .iter()
        .any(|ext| lower.ends_with(ext))
        || ctx
            .src
            .lines()
            .take(20)
            .any(|l| l.contains("<auto-generated"))
}

/// The partial methods the file implements, and those it declares without
/// implementing, keyed by namespace, type path, name and arity. Generated
/// code declares optional partial hooks for its users to implement if they
/// want: only its implementations count.
fn partial_method_facts(ctx: &Ctx, root: Node, facts: &mut Vec<(String, String)>) {
    let generated = is_generated_file(ctx);
    let mut file_namespace = String::new();
    let mut path: Vec<(usize, String)> = Vec::new();
    let mut cursor = root.walk();
    let mut depth = 0;
    loop {
        let node = cursor.node();
        if node.kind() == "method_declaration" {
            facts.extend(partial_method_fact(
                ctx,
                node,
                &file_namespace,
                &path,
                generated,
            ));
        } else {
            enter_scope(ctx, node, depth, &mut file_namespace, &mut path);
        }
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        if !step_out(&mut cursor, &mut path, &mut depth) {
            return;
        }
    }
}

/// A namespace or type declaration: the name the walk is now in.
fn enter_scope(
    ctx: &Ctx,
    node: Node,
    depth: usize,
    file_namespace: &mut String,
    path: &mut Vec<(usize, String)>,
) {
    let name = || {
        node.child_by_field_name("name")
            .map(|n| ctx.text(n).to_string())
    };
    match node.kind() {
        "file_scoped_namespace_declaration" => *file_namespace = name().unwrap_or_default(),
        "namespace_declaration"
        | "class_declaration"
        | "struct_declaration"
        | "record_declaration"
        | "interface_declaration" => path.extend(name().map(|n| (depth, n))),
        _ => {}
    }
}

/// Moves the cursor to the next node that isn't below it, leaving the
/// scopes it passes; false at the end of the tree.
fn step_out(
    cursor: &mut tree_sitter::TreeCursor,
    path: &mut Vec<(usize, String)>,
    depth: &mut usize,
) -> bool {
    loop {
        while path.last().is_some_and(|(d, _)| *d >= *depth) {
            path.pop();
        }
        if cursor.goto_next_sibling() {
            return true;
        }
        if !cursor.goto_parent() {
            return false;
        }
        *depth -= 1;
    }
}

/// A partial method's fact: its implementation, or a declaration that may
/// lack one. Only void partial methods without an access modifier may lack
/// an implementation; the compiler requires the others.
fn partial_method_fact(
    ctx: &Ctx,
    node: Node,
    file_namespace: &str,
    path: &[(usize, String)],
    generated: bool,
) -> Option<(String, String)> {
    let modifiers: Vec<&str> = node
        .named_children(&mut node.walk())
        .filter(|m| m.kind() == "modifier")
        .map(|m| ctx.text(m))
        .collect();
    if !modifiers.contains(&"partial") {
        return None;
    }
    let params = node.child_by_field_name("parameters");
    let arity = params.map_or(0, |p| {
        let mut c = p.walk();
        let plain = p
            .named_children(&mut c)
            .filter(|x| x.kind() == "parameter")
            .count();
        plain + usize::from(p.child_by_field_name("name").is_some())
    });
    let mut key: Vec<&str> = Vec::new();
    if !file_namespace.is_empty() {
        key.push(file_namespace);
    }
    key.extend(path.iter().map(|(_, n)| n.as_str()));
    let method = node
        .child_by_field_name("name")
        .map(|n| ctx.text(n).to_string())
        .unwrap_or_default();
    let key = format!("{}.{method}/{arity}", key.join("."));
    if node.child_by_field_name("body").is_some() {
        return Some(("cs-partial-impl".to_string(), key));
    }
    let returns_void = node
        .child_by_field_name("returns")
        .is_some_and(|r| ctx.text(r) == "void");
    let optional = returns_void
        && !modifiers
            .iter()
            .any(|m| ["public", "private", "protected", "internal"].contains(m));
    let line = node.start_position().row + 1;
    (optional && !generated).then(|| ("cs-partial-decl".to_string(), format!("{key}@{line}")))
}

/// Rules about C# code that only the whole project can answer: partial
/// methods implemented in no file, and AssemblyInfo without
/// NeutralResourcesLanguage in a project that uses resources.
pub(crate) fn cs_project_rules(files: &mut [FileAnalysis], rules: &RuleSet) {
    // Declarations compared across files (ADR-0020).
    let active: Vec<&str> = rules::cs_project::RULES
        .iter()
        .copied()
        .filter(|r| rules.get(r).is_some())
        .collect();
    let found = rules::cs_project::run(files.iter().map(|f| f.facts.as_slice()), &active);
    for (rule, file, span) in found {
        if let Some(r) = rules.get(rule) {
            let issue = project_issue_at(r, &files[file].path, span, r.rule.message.to_string());
            files[file].issues.push(issue);
        }
    }
    if let Some(rule) = rules.get(rules::CS_PARTIAL_METHOD_NOT_IMPLEMENTED) {
        unimplemented_partials(files, rule);
    }
    if let Some(rule) = rules.get(rules::CS_NEUTRAL_RESOURCES_LANGUAGE) {
        missing_neutral_language(files, rule);
    }
    apply_suppressions(files);
}

/// The declarations `@SuppressWarnings` silences, as SonarQube honors it:
/// `"all"` every rule, `"java:S1234"` (or `"squid:S1234"`) the rules with that
/// key; the compiler's own names (`"unchecked"`) silence nothing here.
fn java_suppressed_regions(src: &str, root: Node) -> Vec<SuppressedRegion> {
    let mut regions = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.kind() == "annotation"
            && n.child_by_field_name("name").is_some_and(|a| {
                matches!(
                    &src[a.byte_range()],
                    "SuppressWarnings" | "java.lang.SuppressWarnings"
                )
            })
            && let Some(declaration) = n
                .parent()
                .filter(|m| m.kind() == "modifiers")
                .and_then(|m| m.parent())
        {
            let start = declaration.start_position().row + 1;
            let end = declaration.end_position().row + 1;
            let mut values = Vec::new();
            let mut inner = vec![n];
            while let Some(x) = inner.pop() {
                if x.kind() == "string_literal" {
                    values.push(src[x.byte_range()].trim_matches('"'));
                    continue;
                }
                let mut c = x.walk();
                inner.extend(x.named_children(&mut c));
            }
            for v in values {
                // `"unused"` silences the rules about unused code (measured on
                // SonarQube 26.7): locals, private fields and methods,
                // parameters.
                if v == "unused" {
                    for key in ["S1481", "S1068", "S1144", "S1172"] {
                        regions.push(SuppressedRegion::new(Some(key.to_string()), start, end));
                    }
                    continue;
                }
                let key = match v.split_once(':') {
                    Some(("java" | "squid", key)) => Some(Some(key.to_string())),
                    None if v == "all" => Some(None),
                    _ => None,
                };
                if let Some(key) = key {
                    regions.push(SuppressedRegion::new(key, start, end));
                }
            }
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    regions
}

/// The fact listing a Java file's lines with a suppression comment.
const JAVA_SUPPRESSED_LINES: &str = "java-suppressed-lines";

/// The fact listing a C++ file's lines with a suppression comment.
const CPP_SUPPRESSED_LINES: &str = "cpp-suppressed-lines";

/// The facts the project-level C++ rules need from this file: the classes
/// it defines (ADR-0020), and its lines with a suppression comment.
fn cpp_facts(ctx: &Ctx, root: Node, deadline: Instant) -> Vec<(String, String)> {
    let mut facts = Vec::new();
    let index = crate::semantic::cpp_index::extract(root, ctx.src.as_bytes(), deadline);
    if !index.classes.is_empty()
        && let Ok(json) = serde_json::to_string(&index)
    {
        facts.push((crate::semantic::cpp_index::FACT.to_string(), json));
    }
    facts.extend(suppressed_lines(ctx.src, CPP_SUPPRESSED_LINES));
    facts
}

/// The fact `key` listing a file's lines with a suppression comment
/// (`NOSONAR`, `sonda-ignore`), for the issues a project pass adds; none
/// when it has no such line.
fn suppressed_lines(src: &str, key: &str) -> Option<(String, String)> {
    let lines: Vec<(usize, &str)> = src
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains("NOSONAR") || l.contains("sonda-ignore"))
        .map(|(i, l)| (i + 1, l))
        .collect();
    if lines.is_empty() {
        return None;
    }
    serde_json::to_string(&lines)
        .ok()
        .map(|json| (key.to_string(), json))
}

/// C++ rules that need other files' classes (ADR-0020): functions hiding a
/// base's.
pub(crate) fn cpp_project_rules(files: &mut [FileAnalysis], rules: &RuleSet) {
    let active: Vec<&str> = rules::cpp_project::RULES
        .iter()
        .copied()
        .filter(|r| rules.get(r).is_some())
        .collect();
    if active.is_empty() {
        return;
    }
    let found = rules::cpp_project::run(files.iter().map(|f| f.facts.as_slice()), &active);
    push_project_findings(files, rules, found, CPP_SUPPRESSED_LINES);
}

/// Java rules that need other files' declarations (ADR-0020): overrides,
/// serializable fields, `equals` in subclasses, arrays passed as varargs.
pub(crate) fn java_project_rules(files: &mut [FileAnalysis], rules: &RuleSet) {
    let active: Vec<&str> = rules::java_project::RULES
        .iter()
        .copied()
        .filter(|r| rules.get(r).is_some())
        .collect();
    if active.is_empty() {
        return;
    }
    let found = rules::java_project::run(files.iter().map(|f| f.facts.as_slice()), &active);
    push_project_findings(files, rules, found, JAVA_SUPPRESSED_LINES);
}

/// Adds a project pass's findings to their files as issues, unless a
/// suppression comment on the line (listed in the `lines_fact` fact) or a
/// suppressed region covers them.
fn push_project_findings(
    files: &mut [FileAnalysis],
    rules: &RuleSet,
    found: Vec<(&'static str, usize, crate::semantic::cs_index::Span)>,
    lines_fact: &str,
) {
    for (rule, file, span) in found {
        let Some(r) = rules.get(rule) else { continue };
        let f = &mut files[file];
        let suppressed = f
            .facts
            .iter()
            .find(|(k, _)| k == lines_fact)
            .and_then(|(_, json)| serde_json::from_str::<Vec<(usize, String)>>(json).ok())
            .is_some_and(|lines| {
                lines
                    .iter()
                    .any(|(line, text)| *line == span.line && Suppression::of(text).covers(rule))
            });
        let regions: Vec<SuppressedRegion> = f
            .facts
            .iter()
            .find(|(k, _)| k == SUPPRESSION_FACT)
            .and_then(|(_, json)| serde_json::from_str(json).ok())
            .unwrap_or_default();
        if !suppressed && !silenced_in(&regions, span.line, rule) {
            let issue = project_issue_at(r, &f.path, span, r.rule.message.to_string());
            f.issues.push(issue);
        }
    }
    for f in files.iter_mut() {
        f.issues
            .sort_by(|a, b| (a.line, a.column, a.rule).cmp(&(b.line, b.column, b.rule)));
    }
}

/// Partial methods declared, and implemented in no file.
fn unimplemented_partials(files: &mut [FileAnalysis], rule: &ActiveRule) {
    let implemented: std::collections::HashSet<String> = files
        .iter()
        .flat_map(|f| facts_of(f, "cs-partial-impl"))
        .collect();
    for f in files.iter_mut() {
        for declared in facts_of(f, "cs-partial-decl") {
            let Some((key, line)) = declared.rsplit_once('@') else {
                continue;
            };
            if !implemented.contains(key) {
                let issue = project_issue(
                    rule,
                    &f.path,
                    line.parse().unwrap_or(1),
                    "Implement this partial method, or remove it and the calls to it.".into(),
                );
                f.issues.push(issue);
            }
        }
    }
}

/// AssemblyInfo without NeutralResourcesLanguage, in a project that uses
/// resources.
fn missing_neutral_language(files: &mut [FileAnalysis], rule: &ActiveRule) {
    let resources: Vec<String> = files
        .iter()
        .filter(|f| !facts_of(f, "cs-resources").is_empty())
        .map(|f| f.path.replace('\\', "/"))
        .collect();
    for f in files.iter_mut() {
        for line in facts_of(f, "cs-assembly-info") {
            let path = f.path.replace('\\', "/");
            let project = assembly_project(&path);
            let uses = resources
                .iter()
                .any(|r| project.is_empty() || r.starts_with(&format!("{project}/")));
            if uses {
                let issue = project_issue(
                    rule,
                    &f.path,
                    line.parse().unwrap_or(1),
                    "Add [assembly: NeutralResourcesLanguage(...)] for this project's resources."
                        .into(),
                );
                f.issues.push(issue);
            }
        }
    }
}

/// The project directory of an AssemblyInfo file, which usually sits in
/// its Properties folder.
fn assembly_project(path: &str) -> &str {
    let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
    match dir.rsplit_once('/') {
        Some((parent, "Properties")) => parent,
        None if dir == "Properties" => "",
        _ => dir,
    }
}

/// Pragma regions and attributes silence what the project pass found too,
/// and assembly-level suppressions silence the declarations they target,
/// in whichever file those are.
fn apply_suppressions(files: &mut [FileAnalysis]) {
    let globals: Vec<GlobalSuppression> = files
        .iter()
        .filter_map(|f| f.facts.iter().find(|(k, _)| k == GLOBAL_SUPPRESSION_FACT))
        .flat_map(|(_, json)| {
            serde_json::from_str::<Vec<GlobalSuppression>>(json).unwrap_or_default()
        })
        .collect();
    let targets: Vec<(&str, &str)> = globals
        .iter()
        .map(|g| (g.scope.as_str(), g.target.as_str()))
        .collect();
    let targeted: Vec<(usize, String, usize, usize)> =
        rules::cs_project::targeted_regions(files.iter().map(|f| f.facts.as_slice()), &targets)
            .into_iter()
            .map(|(g, file, start, end)| (file, globals[g].key.clone(), start, end))
            .collect();
    for (i, f) in files.iter_mut().enumerate() {
        let mut regions: Vec<SuppressedRegion> = f
            .facts
            .iter()
            .find(|(k, _)| k == SUPPRESSION_FACT)
            .and_then(|(_, json)| serde_json::from_str(json).ok())
            .unwrap_or_default();
        regions.extend(targeted.iter().filter(|(file, _, _, _)| *file == i).map(
            |(_, key, start, end)| SuppressedRegion {
                key: Some(key.clone()),
                start: *start,
                end: *end,
            },
        ));
        if !regions.is_empty() {
            f.issues
                .retain(|issue| !silenced_in(&regions, issue.line, issue.rule));
        }
    }
}

/// An issue found by looking at the project, at a span a fact recorded.
fn project_issue_at(
    rule: &ActiveRule,
    path: &str,
    span: crate::semantic::cs_index::Span,
    message: String,
) -> Issue {
    let mut issue = project_issue(rule, path, span.line, message);
    issue.column = span.column;
    issue.end_line = span.end_line;
    issue.end_column = span.end_column;
    issue
}

/// An issue that belongs to a file as a whole, found by looking at the project.
/// The packages a JavaScript or TypeScript file imports, one fact each:
/// `import` = `<package>\t<line>`. Only read when the dependency rule is on.
fn js_facts(ctx: &Ctx, lang: Lang, root: Node, rules: &RuleSet) -> Vec<(String, String)> {
    if !matches!(lang, Lang::JavaScript | Lang::TypeScript | Lang::Tsx)
        || rules.get(rules::JS_DEPENDENCY_NOT_DECLARED).is_none()
    {
        return Vec::new();
    }
    let mut facts = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        let source = match n.kind() {
            "import_statement" | "export_statement" => n.child_by_field_name("source"),
            "call_expression"
                if n.child_by_field_name("function")
                    .is_some_and(|f| matches!(ctx.text(f), "require" | "import")) =>
            {
                n.child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0))
                    .filter(|a| a.kind() == "string")
            }
            _ => None,
        };
        if let Some(source) = source {
            let t = ctx.text(source);
            let spec = t.get(1..t.len().saturating_sub(1)).unwrap_or("");
            if let Some(package) = package_of(spec) {
                facts.push((
                    "import".to_string(),
                    format!("{package}\t{}", source.start_position().row + 1),
                ));
            }
        }
        let mut c = n.walk();
        let kids: Vec<Node> = n.named_children(&mut c).collect();
        stack.extend(kids);
    }
    facts
}

/// The npm package a module specifier names, or None for relative paths,
/// Node's own modules and aliases.
fn package_of(spec: &str) -> Option<String> {
    const BUILTINS: &[&str] = &[
        "assert",
        "async_hooks",
        "buffer",
        "child_process",
        "cluster",
        "console",
        "constants",
        "crypto",
        "dgram",
        "diagnostics_channel",
        "dns",
        "domain",
        "events",
        "fs",
        "http",
        "http2",
        "https",
        "inspector",
        "module",
        "net",
        "os",
        "path",
        "perf_hooks",
        "process",
        "punycode",
        "querystring",
        "readline",
        "repl",
        "stream",
        "string_decoder",
        "sys",
        "timers",
        "tls",
        "trace_events",
        "tty",
        "url",
        "util",
        "v8",
        "vm",
        "wasi",
        "worker_threads",
        "zlib",
        "test",
    ];
    if spec.is_empty()
        || spec.starts_with(['.', '/', '#', '~', '$'])
        || spec.starts_with("node:")
        || spec.starts_with("@/")
        || spec.contains(':')
    {
        return None;
    }
    let mut parts = spec.split('/');
    let first = parts.next()?;
    let name = if first.starts_with('@') {
        format!("{first}/{}", parts.next()?)
    } else {
        first.to_string()
    };
    let root = name.split('/').next().unwrap_or("");
    if BUILTINS.contains(&root) {
        return None;
    }
    Some(name)
}

/// Imports of packages that the nearest `package.json` (or one above it)
/// does not declare. `manifests` holds each package.json's directory and
/// every name it declares or is called.
pub(crate) fn js_dependency_rules(
    files: &mut [FileAnalysis],
    rules: &RuleSet,
    manifests: &[(String, Vec<String>)],
) {
    let Some(rule) = rules.get(rules::JS_DEPENDENCY_NOT_DECLARED) else {
        return;
    };
    if manifests.is_empty() {
        return;
    }
    // Workspace packages import each other by their names.
    let workspace: std::collections::HashSet<&str> = manifests
        .iter()
        .flat_map(|(_, names)| names.iter().map(String::as_str))
        .collect();
    for f in files.iter_mut() {
        let dir = f.path.rsplit_once('/').map_or("", |(d, _)| d);
        let applicable: Vec<&(String, Vec<String>)> = manifests
            .iter()
            .filter(|(m, _)| m.is_empty() || dir == m || dir.starts_with(&format!("{m}/")))
            .collect();
        if applicable.is_empty() {
            continue;
        }
        let declared: std::collections::HashSet<&str> = applicable
            .iter()
            .flat_map(|(_, names)| names.iter().map(String::as_str))
            .collect();
        let mut reported: std::collections::HashSet<String> = std::collections::HashSet::new();
        let imports: Vec<(String, usize)> = f
            .facts
            .iter()
            .filter(|(k, _)| k == "import")
            .filter_map(|(_, v)| {
                let (name, line) = v.split_once('\t')?;
                Some((name.to_string(), line.parse().ok()?))
            })
            .collect();
        for (name, line) in imports {
            if declared.contains(name.as_str())
                || workspace.contains(name.as_str())
                || !reported.insert(name.clone())
            {
                continue;
            }
            let msg = format!("Add {name} to the dependencies in package.json.");
            let issue = project_issue(rule, &f.path, line, msg);
            f.issues.push(issue);
        }
    }
}

fn project_issue(rule: &ActiveRule, path: &str, line: usize, message: String) -> Issue {
    let mut hasher = sha2::Sha256::new();
    for field in [
        "sonda-fingerprint-v1",
        rule.rule.id,
        path,
        &line.to_string(),
    ] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    let hash = hasher.finalize();
    let mut short = [0; 16];
    short.copy_from_slice(&hash[..16]);
    Issue {
        rule: rule.rule.id,
        severity: rule.severity,
        category: rule.rule.category,
        message,
        path: path.to_string(),
        line,
        column: 1,
        end_line: line,
        end_column: 1,
        effort_minutes: rule.rule.effort_minutes,
        is_new: true,
        fingerprint: Digest(short),
        flow: Vec::new(),
    }
}

/// Rules about Java packages, which only the whole project can answer: a
/// directory of Java files has a package-info.java, or has nothing else.
pub(crate) fn java_package_rules(files: &mut [FileAnalysis], rules: &RuleSet) {
    if let Some(rule) = rules.get(rules::JAVA_COMPONENT_NOT_SCANNED) {
        unscanned_components(files, rule);
    }
    let missing = rules.get(rules::JAVA_PACKAGE_INFO_MISSING);
    let only = rules.get(rules::JAVA_PACKAGE_INFO_ONLY);
    if missing.is_some() || only.is_some() {
        package_info_rules(files, missing, only);
    }
}

/// A file's facts of one kind (`java_facts`).
fn facts_of(f: &FileAnalysis, kind: &str) -> Vec<String> {
    f.facts
        .iter()
        .filter(|(k, _)| k == kind)
        .map(|(_, v)| v.clone())
        .collect()
}

/// Spring components in a package no `@ComponentScan` base covers, when
/// the project has a scan at all.
fn unscanned_components(files: &mut [FileAnalysis], rule: &ActiveRule) {
    let bases: Vec<String> = files.iter().flat_map(|f| facts_of(f, "scan")).collect();
    if bases.is_empty() {
        return;
    }
    for f in files.iter_mut() {
        let Some(package) = facts_of(f, "package").into_iter().next() else {
            continue;
        };
        let covered = bases
            .iter()
            .any(|b| package == *b || package.starts_with(&format!("{b}.")));
        if covered {
            continue;
        }
        for line in facts_of(f, "component") {
            let line = line.parse().unwrap_or(1);
            let msg = format!(
                "Package {package} is outside every @ComponentScan base package, so this bean is not registered."
            );
            let issue = project_issue(rule, &f.path, line, msg);
            f.issues.push(issue);
        }
    }
}

/// A directory of Java files without a package-info.java, or with nothing
/// else.
fn package_info_rules(
    files: &mut [FileAnalysis],
    missing: Option<&ActiveRule>,
    only: Option<&ActiveRule>,
) {
    let mut dirs: std::collections::BTreeMap<String, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (i, f) in files.iter().enumerate() {
        if f.lang == Lang::Java {
            let dir = f.path.rsplit_once('/').map_or("", |(d, _)| d);
            dirs.entry(dir.to_string()).or_default().push(i);
        }
    }
    for members in dirs.values() {
        let is_info = |i: &usize| files[*i].path.ends_with("package-info.java");
        let infos: Vec<usize> = members.iter().copied().filter(is_info).collect();
        let others = members.len() - infos.len();
        if infos.is_empty()
            && others > 0
            && let Some(rule) = missing
        {
            let first = members[0];
            let issue = project_issue(
                rule,
                &files[first].path,
                1,
                "Add a package-info.java to document this package.".into(),
            );
            files[first].issues.push(issue);
        } else if others == 0
            && let (Some(rule), Some(&info)) = (only, infos.first())
        {
            let issue = project_issue(
                rule,
                &files[info].path,
                1,
                "Remove this package: it holds only its package-info.java.".into(),
            );
            files[info].issues.push(issue);
        }
    }
}

/// Rules about a Java file's place in the project, which need its path.
fn scan_java_files(ctx: &Ctx, lang: Lang, root: Node, rules: &RuleSet, issues: &mut Vec<Issue>) {
    if lang != Lang::Java {
        return;
    }
    let path = ctx.path.replace('\\', "/");
    let mut cursor = root.walk();
    let children: Vec<Node> = root.named_children(&mut cursor).collect();
    if let Some(rule) = rules.get(rules::JAVA_PACKAGE_DIRECTORY) {
        package_directory(ctx, &path, &children, rule, issues);
    }
    if path.starts_with("src/main/") || path.contains("/src/main/") {
        tests_in_main(ctx, &children, rules, issues);
    }
    if let Some(rule) = rules.get(rules::JAVA_PARSE_FAILURE)
        && root.has_error()
    {
        parse_failure(ctx, root, rule, issues);
    }
}

/// The file's package doesn't match its directory.
fn package_directory(
    ctx: &Ctx,
    path: &str,
    children: &[Node],
    rule: &ActiveRule,
    issues: &mut Vec<Issue>,
) {
    let Some(decl) = children.iter().find(|n| n.kind() == "package_declaration") else {
        return;
    };
    let Some(name) = decl
        .named_children(&mut decl.walk())
        .find(|n| matches!(n.kind(), "scoped_identifier" | "identifier"))
    else {
        return;
    };
    let Some((dir, _)) = path.rsplit_once('/') else {
        return;
    };
    let expected = ctx.text(name).replace('.', "/");
    if !(dir == expected || dir.ends_with(&format!("/{expected}"))) {
        let msg = format!(
            "Move this file to a directory matching package {}.",
            ctx.text(name)
        );
        issues.push(ctx.issue(rule, name, msg, rule.rule.effort_minutes));
    }
}

/// Test classes and test libraries in production code (`src/main`).
fn tests_in_main(ctx: &Ctx, children: &[Node], rules: &RuleSet, issues: &mut Vec<Issue>) {
    if let Some(rule) = rules.get(rules::JAVA_TEST_IN_MAIN) {
        let marker = children
            .iter()
            .filter(|n| n.kind() == "class_declaration")
            .find(|c| ctx.text(**c).contains("@Test"));
        if let Some(class) = marker {
            let msg = "Move this test class to the test source directory.".to_string();
            issues.push(ctx.issue(rule, *class, msg, rule.rule.effort_minutes));
        }
    }
    if let Some(rule) = rules.get(rules::JAVA_ASSERTION_IN_MAIN) {
        // A call to a test library's assertion, not its import: a generator
        // naming `Test.class` uses the library without asserting anything
        // (measured on SonarQube 26.7).
        let mut classes: Vec<&str> = Vec::new();
        let mut functions: Vec<&str> = Vec::new();
        for import in children.iter().filter(|n| n.kind() == "import_declaration") {
            let t = ctx.text(*import);
            if !TEST_LIBRARIES.iter().any(|l| t.contains(l)) {
                continue;
            }
            let path = t
                .trim_start_matches("import")
                .trim()
                .trim_end_matches(';')
                .trim();
            match path.strip_prefix("static") {
                Some(member) => functions.extend(member.trim().rsplit('.').next()),
                None => classes.extend(path.rsplit('.').next()),
            }
        }
        if classes.is_empty() && functions.is_empty() {
            return;
        }
        let asserts = |name: &str| name.starts_with("assert") || name == "fail";
        let mut stack: Vec<Node> = children.to_vec();
        while let Some(n) = stack.pop() {
            if n.kind() == "method_invocation"
                && let Some(name) = n.child_by_field_name("name").map(|x| ctx.text(x))
            {
                let on_class = n
                    .child_by_field_name("object")
                    .is_some_and(|o| classes.contains(&ctx.text(o)));
                // `import static ...Assertions.assertThat;`, or `...Assert.*;`.
                let imported = n.child_by_field_name("object").is_none()
                    && (functions.contains(&name) || functions.contains(&"*"));
                if (on_class || imported) && asserts(name) {
                    let msg = "Remove this assertion from production code.".to_string();
                    issues.push(ctx.issue(rule, n, msg, rule.rule.effort_minutes));
                }
            }
            let mut c = n.walk();
            stack.extend(n.named_children(&mut c));
        }
    }
}

/// Test libraries whose assertions don't belong in production code.
const TEST_LIBRARIES: &[&str] = &["org.junit.", "org.assertj.", "org.testng.", "org.hamcrest."];

/// The first part of the file the parser couldn't read, in source order.
fn parse_failure(ctx: &Ctx, root: Node, rule: &ActiveRule, issues: &mut Vec<Issue>) {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.is_error() || n.is_missing() {
            let msg = "The parser could not understand this part of the file.".to_string();
            issues.push(ctx.issue(rule, n, msg, 0));
            break;
        }
        let mut c = n.walk();
        let kids: Vec<Node> = n.children(&mut c).collect();
        stack.extend(kids.into_iter().rev());
    }
}

/// Rules about a JavaScript or TypeScript file as a whole, which need its name.
fn scan_js_files(ctx: &Ctx, lang: Lang, root: Node, rules: &RuleSet, issues: &mut Vec<Issue>) {
    if !matches!(lang, Lang::JavaScript | Lang::TypeScript | Lang::Tsx) {
        return;
    }
    let path = ctx.path.replace('\\', "/");
    let file = path.rsplit('/').next().unwrap_or(&path);
    let stem = file.rsplit_once('.').map_or(file, |(s, _)| s);
    let mut cursor = root.walk();
    let children: Vec<Node> = root.named_children(&mut cursor).collect();
    if let Some(rule) = rules.get(rules::JS_MODULE_IMPORTS_ITSELF) {
        module_imports_itself(ctx, root, stem, rule, issues);
    }
    if let Some(rule) = rules.get(rules::JS_DEFAULT_EXPORT_NAME)
        && stem != "index"
    {
        default_export_name(ctx, &children, stem, rule, issues);
    }
    let is_test_file = stem.ends_with(".test")
        || stem.ends_with(".spec")
        || path.contains("/__tests__/")
        || path.starts_with("__tests__/");
    if is_test_file
        && let Some(rule) = rules.get(rules::JS_TEST_FILE_WITHOUT_TESTS)
        && !has_test_case(ctx, root)
    {
        let at = children.first().copied().unwrap_or(root);
        let msg = "Add a test case to this file, or delete it.".to_string();
        issues.push(ctx.issue(rule, at, msg, rule.rule.effort_minutes));
    }
    if let Some(rule) = rules.get(rules::JS_LICENSE_HEADER) {
        license_header(ctx, root, &children, rule, issues);
    }
}

/// The nodes under `root`, in no particular order.
fn descendants(root: Node) -> impl Iterator<Item = Node> {
    let mut stack = vec![root];
    std::iter::from_fn(move || {
        let n = stack.pop()?;
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
        Some(n)
    })
}

fn module_imports_itself(
    ctx: &Ctx,
    root: Node,
    stem: &str,
    rule: &ActiveRule,
    issues: &mut Vec<Issue>,
) {
    let strip_ext = |s: &str| {
        [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
            .iter()
            .find_map(|ext| s.strip_suffix(ext))
            .unwrap_or(s)
            .to_string()
    };
    for n in descendants(root) {
        let source = match n.kind() {
            "import_statement" | "export_statement" => n.child_by_field_name("source"),
            "call_expression"
                if n.child_by_field_name("function")
                    .is_some_and(|f| ctx.text(f) == "require") =>
            {
                n.child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0))
                    .filter(|a| a.kind() == "string")
            }
            _ => None,
        };
        let Some(source) = source else { continue };
        let t = ctx.text(source);
        let spec = t.get(1..t.len().saturating_sub(1)).unwrap_or("");
        if spec
            .strip_prefix("./")
            .is_some_and(|rest| strip_ext(rest) == stem)
        {
            let msg = "Remove this import: the module imports itself.".to_string();
            issues.push(ctx.issue(rule, source, msg, rule.rule.effort_minutes));
        }
    }
}

fn default_export_name(
    ctx: &Ctx,
    children: &[Node],
    stem: &str,
    rule: &ActiveRule,
    issues: &mut Vec<Issue>,
) {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| !matches!(c, '-' | '_' | '.'))
            .collect::<String>()
            .to_lowercase()
    };
    for export in children.iter().filter(|n| n.kind() == "export_statement") {
        let mut c = export.walk();
        if !export.children(&mut c).any(|k| k.kind() == "default") {
            continue;
        }
        let named = export
            .child_by_field_name("declaration")
            .and_then(|d| d.child_by_field_name("name"))
            .or_else(|| {
                export
                    .child_by_field_name("value")
                    .filter(|v| v.kind() == "identifier")
            });
        if let Some(name) = named
            && norm(ctx.text(name)) != norm(stem)
        {
            let msg = format!("Rename the file or the default export {}.", ctx.text(name));
            issues.push(ctx.issue(rule, name, msg, rule.rule.effort_minutes));
        }
    }
}

/// Whether the file calls `it`, `test` or `specify`, as `it.each(...)` too.
fn has_test_case(ctx: &Ctx, root: Node) -> bool {
    descendants(root).any(|n| {
        if n.kind() != "call_expression" {
            return false;
        }
        let mut f = n.child_by_field_name("function");
        while let Some(m) = f.filter(|m| m.kind() == "member_expression") {
            f = m.child_by_field_name("object");
        }
        f.is_some_and(|f| matches!(ctx.text(f), "it" | "test" | "specify"))
    })
}

fn license_header(
    ctx: &Ctx,
    root: Node,
    children: &[Node],
    rule: &ActiveRule,
    issues: &mut Vec<Issue>,
) {
    let first = children
        .iter()
        .find(|n| n.kind() != "hash_bang_line" && n.kind() != "hashbang_comment");
    let has_header = first.is_some_and(|n| {
        n.kind() == "comment" && {
            let t = ctx.text(*n).to_lowercase();
            t.contains("copyright") || t.contains("license")
        }
    });
    if !has_header {
        let at = first.copied().unwrap_or(root);
        let msg = "Add a copyright or license header to this file.".to_string();
        issues.push(ctx.issue(rule, at, msg, rule.rule.effort_minutes));
    }
}

/// Rules about a Python file as a whole: its name and what the parser could
/// not read.
fn scan_py_files(ctx: &Ctx, lang: Lang, root: Node, rules: &RuleSet, issues: &mut Vec<Issue>) {
    if lang != Lang::Python {
        return;
    }
    let path = ctx.path.replace('\\', "/");
    let file = path.rsplit('/').next().unwrap_or(&path);
    let stem = file
        .strip_suffix(".pyi")
        .or_else(|| file.strip_suffix(".py"))
        .unwrap_or(file);
    if let Some(rule) = rules.get(rules::PY_MODULE_NAME)
        && !(stem.starts_with("__") && stem.ends_with("__"))
    {
        let test_prefix = stem.strip_prefix("test_").unwrap_or(stem);
        let ok = test_prefix
            .chars()
            .next()
            .is_some_and(|c| c == '_' || c.is_ascii_lowercase())
            && test_prefix
                .chars()
                .all(|c| c == '_' || c.is_ascii_lowercase() || c.is_ascii_digit());
        if !ok {
            let msg = format!("Rename the module {stem} to lower case with underscores.");
            let at = root.named_child(0).unwrap_or(root);
            issues.push(ctx.issue(rule, at, msg, rule.rule.effort_minutes));
        }
    }
    if let Some(rule) = rules.get(rules::PY_PARSE_FAILURE)
        && root.has_error()
    {
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            if n.is_error() || n.is_missing() {
                let msg = "The parser could not understand this part of the file.".to_string();
                issues.push(ctx.issue(rule, n, msg, 0));
                break;
            }
            let mut c = n.walk();
            let kids: Vec<Node> = n.children(&mut c).collect();
            stack.extend(kids.into_iter().rev());
        }
    }
}

const LINE_LENGTH_LIMIT: usize = 120;
const FILE_LENGTH_LIMIT: usize = 1000;
/// Line rules can fire on every line of a generated file: report the first
/// ones, which is enough to see the problem.
const LINE_ISSUE_CAP: usize = 100;

/// Trailing whitespace, tabs and long lines: each rule reports at most
/// `LINE_ISSUE_CAP` lines of a file.
fn line_text_rules(ctx: &Ctx, rules: &RuleSet, issues: &mut Vec<Issue>) {
    let trailing = rules.get(rules::TRAILING_WHITESPACE);
    let long = rules.get(rules::LINE_LENGTH);
    let tabs = rules.get(rules::TAB_CHARACTER);
    if trailing.is_none() && long.is_none() && tabs.is_none() {
        return;
    }
    let checks: [(Option<&ActiveRule>, LineCheck); 3] = [
        (trailing, trailing_whitespace),
        (tabs, tab_character),
        (long, long_line),
    ];
    let mut counts = [0usize; 3];
    for row in 0..ctx.lines.count() {
        let line = ctx.lines.text(row);
        let line = line.strip_suffix('\r').unwrap_or(line);
        for (k, (rule, check)) in checks.iter().enumerate() {
            if let Some(rule) = rule
                && counts[k] < LINE_ISSUE_CAP
                && let Some(issue) = check(ctx, rule, row, line)
            {
                counts[k] += 1;
                issues.push(issue);
            }
        }
    }
}

/// One line rule: its issue on line `row`, whose text is `line`, if any.
type LineCheck = fn(&Ctx, &ActiveRule, usize, &str) -> Option<Issue>;

fn trailing_whitespace(ctx: &Ctx, rule: &ActiveRule, row: usize, line: &str) -> Option<Issue> {
    let kept = line.trim_end_matches([' ', '\t']);
    (kept.len() < line.len()).then(|| {
        let columns = (kept.chars().count(), line.chars().count());
        let msg = "Remove the trailing whitespace from this line.".to_string();
        ctx.issue_on_line(rule, row, columns, msg)
    })
}

fn tab_character(ctx: &Ctx, rule: &ActiveRule, row: usize, line: &str) -> Option<Issue> {
    let at = line.find('\t')?;
    let column = line[..at].chars().count();
    let msg = "Replace this tab with spaces.".to_string();
    Some(ctx.issue_on_line(rule, row, (column, column + 1), msg))
}

fn long_line(ctx: &Ctx, rule: &ActiveRule, row: usize, line: &str) -> Option<Issue> {
    let width = line.chars().count();
    (width > LINE_LENGTH_LIMIT).then(|| {
        let msg = format!("Split this {width}-character line: the limit is {LINE_LENGTH_LIMIT}.");
        ctx.issue_on_line(rule, row, (LINE_LENGTH_LIMIT, width), msg)
    })
}

/// Rules about the text of lines, not about the syntax tree.
fn scan_lines(ctx: &Ctx, rules: &RuleSet, ncloc: usize, issues: &mut Vec<Issue>) {
    line_text_rules(ctx, rules, issues);
    if let Some(rule) = rules.get(rules::FILE_LENGTH)
        && ncloc > FILE_LENGTH_LIMIT
    {
        let msg = format!(
            "This file has {ncloc} lines of code; the limit is {FILE_LENGTH_LIMIT}. Split it."
        );
        issues.push(ctx.issue_on_line(rule, 0, (0, ctx.lines.text(0).chars().count()), msg));
    }
    if let Some(rule) = rules.get(rules::FINAL_NEWLINE)
        && !ctx.src.is_empty()
        && !ctx.src.ends_with('\n')
    {
        let row = ctx.lines.count() - 1;
        let width = ctx.lines.text(row).chars().count();
        let msg = "Add a newline at the end of this file.".to_string();
        issues.push(ctx.issue_on_line(rule, row, (width, width), msg));
    }
}

/// Whether one line of a comment reads as source code rather than prose.
fn looks_like_code(line: &str) -> bool {
    let l = line.trim().trim_start_matches(['/', '#', '*', '-']).trim();
    if l.chars().count() < 4 || l.contains("http") || l.contains("sonda-ignore") {
        return false;
    }
    if reads_as_prose(l) {
        return false;
    }
    let words = l.split_whitespace().count();
    matches!(l, "}" | "{" | "});" | "};")
        || is_statement_line(l, words)
        || (l.ends_with('{') && starts_with_any(l, BLOCK_KEYWORDS))
        || is_assignment_line(l, words)
        || (l.ends_with(':') && starts_with_any(l, PYTHON_BLOCK_KEYWORDS))
        || is_declaration_line(l, words)
}

/// Sentences have several plain lowercase words; code rarely does.
fn reads_as_prose(l: &str) -> bool {
    let prose = l
        .split_whitespace()
        .filter(|w| w.len() >= 3 && w.chars().all(|c| c.is_ascii_lowercase()))
        .count();
    prose >= 4
}

fn starts_with_any(l: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|k| l.starts_with(k))
}

/// What a line ending in `{` starts with when it opens a block.
const BLOCK_KEYWORDS: &[&str] = &[
    "if ",
    "if(",
    "for ",
    "for(",
    "while ",
    "while(",
    "} else",
    "else",
    "function ",
    "switch",
    "try",
    "catch",
    "class ",
    "public ",
    "private ",
    "static ",
    "void ",
];

/// What a line ending in `:` starts with when it's a Python block header.
const PYTHON_BLOCK_KEYWORDS: &[&str] = &[
    "def ", "class ", "if ", "elif ", "else", "for ", "while ", "try", "except", "with ", "finally",
];

/// A short statement ending in `;` with a call, an assignment or a member.
fn is_statement_line(l: &str, words: usize) -> bool {
    l.ends_with(';') && (l.contains('(') || l.contains(" = ") || l.contains('.')) && words <= 12
}

/// `name = call(...)` or `name = [...]`, short.
fn is_assignment_line(l: &str, words: usize) -> bool {
    let assigns_to_a_name = l.split_once(" = ").is_some_and(|(left, _)| {
        !left.is_empty()
            && left
                .chars()
                .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '[' | ']'))
    });
    assigns_to_a_name
        && (l.ends_with(')') || l.ends_with(']'))
        && words <= 8
        && l.starts_with(|c: char| c.is_alphabetic() || c == '_')
}

/// An import, a print or a declaration, short.
fn is_declaration_line(l: &str, words: usize) -> bool {
    starts_with_any(
        l,
        &[
            "import ", "from ", "return ", "print(", "console.", "const ", "let ", "var ",
        ],
    ) && (l.ends_with(')') || l.ends_with(';') || l.contains(" = ") || l.contains(" import "))
        && words <= 12
}

/// Tool directives that belong at the end of a line.
fn is_pragma_comment(comment: &str) -> bool {
    let body = comment
        .trim_start_matches(['/', '#', '*', '-'])
        .trim_start();
    [
        "noqa",
        "NOSONAR",
        "NOPMD",
        "CHECKSTYLE",
        "type:",
        "pylint",
        "pragma",
        "fmt:",
        "isort:",
        "nosec",
        "mypy:",
        "pyright:",
        "eslint",
        "istanbul",
        "prettier",
        "@ts-",
        "sonda-ignore",
        "flake8",
        "ruff:",
        "yapf:",
    ]
    .iter()
    .any(|p| body.starts_with(p))
}

/// Whether a Python comment, read as source, is a statement: it parses
/// without errors and is an assignment, call, assert, jump, import or block
/// header rather than a bare word, string or number.
fn python_comment_is_code(comment: &str, alone: bool) -> bool {
    use std::cell::RefCell;
    thread_local! {
        static PARSER: RefCell<Option<tree_sitter::Parser>> = const { RefCell::new(None) };
    }
    let text = comment.trim_start_matches('#').trim();
    if is_directive_or_too_short(text) {
        return false;
    }
    // `if x:   # note` keeps its colon; a header needs a body to parse.
    let code = text.split(" #").next().unwrap_or(text).trim_end();
    let source = if code.ends_with(':') {
        format!("{code}\n    pass\n")
    } else {
        format!("{code}\n")
    };
    PARSER.with(|p| {
        let mut p = p.borrow_mut();
        let parser = p.get_or_insert_with(|| {
            let mut parser = tree_sitter::Parser::new();
            let _ = parser.set_language(&Lang::Python.grammar());
            parser
        });
        let Some(tree) = parser.parse(&source, None) else {
            return false;
        };
        let root = tree.root_node();
        if root.has_error() {
            return false;
        }
        let mut cursor = root.walk();
        let statements: Vec<Node> = root
            .named_children(&mut cursor)
            .filter(|n| n.kind() != "comment")
            .collect();
        !statements.is_empty()
            && statements
                .iter()
                .all(|s| python_statement_is_code(*s, &source, alone))
    })
}

/// A shebang, a coding line, a tool directive, or too short to be code.
fn is_directive_or_too_short(text: &str) -> bool {
    text.chars().count() < 4
        || text.contains("http")
        || text.starts_with(['!', '-'])
        || text.contains("coding")
        || text.starts_with("noqa")
        || text.starts_with("type:")
        || text.starts_with("pragma")
}

/// Whether one statement of a parsed comment is code: an assignment, call,
/// assert, jump, import or block header.
fn python_statement_is_code(s: Node, source: &str, alone: bool) -> bool {
    match s.kind() {
        "assert_statement"
        | "return_statement"
        | "raise_statement"
        | "delete_statement"
        | "import_statement"
        | "import_from_statement"
        | "print_statement"
        | "if_statement"
        | "for_statement"
        | "while_statement"
        | "try_statement"
        | "with_statement"
        | "function_definition"
        | "class_definition"
        | "augmented_assignment" => true,
        "expression_statement" => s.named_child(0).is_some_and(|e| match e.kind() {
            "augmented_assignment" => true,
            // `Atlantic (used in Canada)` is prose: a call hugs its name.
            "call" => e
                .child_by_field_name("function")
                .is_some_and(|f| source.as_bytes().get(f.end_byte()) == Some(&b'(')),
            // `x is y` reads as prose; `a == b` does not. After code it
            // is usually a remark about it.
            "comparison_operator" => {
                alone
                    && ["==", "!=", ">=", "<="]
                        .iter()
                        .any(|op| source[e.byte_range()].contains(op))
            }
            "assignment" => e
                .child_by_field_name("right")
                .is_some_and(|r| python_value_looks_like_code(r)),
            _ => false,
        }),
        _ => false,
    }
}

/// A right-hand side that is more than a bare name or number: a call,
/// attribute, subscript, string or collection, alone or inside an operator.
fn python_value_looks_like_code(value: Node) -> bool {
    if matches!(
        value.kind(),
        "call"
            | "attribute"
            | "subscript"
            | "string"
            | "concatenated_string"
            | "list"
            | "dictionary"
            | "tuple"
            | "true"
            | "false"
            | "none"
    ) {
        return true;
    }
    if matches!(
        value.kind(),
        "binary_operator" | "boolean_operator" | "not_operator" | "conditional_expression"
    ) {
        let mut cursor = value.walk();
        return value
            .named_children(&mut cursor)
            .any(|c| python_value_looks_like_code(c));
    }
    false
}

fn comment_is_commented_out_code(comment: &str) -> bool {
    // Doc comments are prose with examples in them.
    if comment.starts_with("/**") || comment.starts_with("///") || comment.starts_with("//!") {
        return false;
    }
    comment.lines().any(looks_like_code)
}

fn expired(deadline: Instant) -> ControlFlow<()> {
    if Instant::now() >= deadline {
        ControlFlow::Break(())
    } else {
        ControlFlow::Continue(())
    }
}

fn run_queries(
    ctx: &Ctx,
    lang: Lang,
    root: Node,
    rules: &RuleSet,
    deadline: Instant,
) -> Result<Vec<Issue>, FileError> {
    run_queries_in(ctx, lang, root, rules, deadline, None)
}

/// Credentials, weak settings and the like are fixtures in tests, not
/// vulnerabilities, so vulnerability rules skip test files (as SonarQube
/// does with test code).
fn skipped_in_test_file(active: &ActiveRule, test_file: bool) -> bool {
    (test_file && active.rule.category == Category::Vulnerability)
        || (!test_file && TEST_CODE_RULES.contains(&active.rule.id))
}

/// Rules about tests, which SonarQube runs on test code only.
pub(crate) const TEST_CODE_RULES: &[&str] = &["java/incomplete-assertion"];

/// Rules a file's name says don't apply: a package's `__init__.py` gathers
/// its modules' names with `from .mod import *`, as SonarQube allows.
fn skipped_for_path(active: &ActiveRule, path: &str) -> bool {
    active.rule.id == "py/wildcard-import" && path.rsplit(['/', '\\']).next() == Some("__init__.py")
}

/// The Java version each rule's suggestion needs: on code that targets an
/// older one, the rule is skipped, as SonarQube skips it.
const JAVA_MIN_VERSION: &[(&str, u32)] = &[
    // @Deprecated(since, forRemoval)
    ("java/deprecated-without-reason", 9),
    // `case A, B:`, switch expressions
    ("java/ends-with-else-switch-labels", 14),
    ("java/switch-to-expression", 14),
    // StringBuilder.isEmpty(), from CharSequence
    ("java/string-builder-empty", 15),
    // pattern matching for instanceof, Stream.toList()
    ("java/instanceof-then-cast", 16),
    ("java/collectors-to-list", 16),
    // unnamed variables
    ("java/unused-exception-parameter", 22),
];

/// The Java version SonarQube needs before it runs a rule, by its key: the
/// rules it tags `java9` to `java22` (read from SonarQube 26.7's rule
/// list). `List.reversed()`, `Math.clamp` and a pattern `switch` need 21.
const JAVA_MIN_VERSION_BY_KEY: &[(&str, u32)] = &[
    ("S4738", 9),
    ("S6355", 9),
    ("S5194", 14),
    ("S5663", 14),
    ("S5664", 14),
    ("S5665", 14),
    ("S6205", 14),
    ("S6208", 14),
    ("S6201", 16),
    ("S6204", 16),
    ("S6206", 16),
    ("S6207", 16),
    ("S6209", 16),
    ("S6211", 16),
    ("S6216", 16),
    ("S6218", 16),
    ("S6219", 16),
    ("S6217", 17),
    ("S6876", 21),
    ("S6877", 21),
    ("S6878", 21),
    ("S6880", 21),
    ("S6881", 21),
    ("S6885", 21),
    ("S6901", 21),
    ("S6906", 21),
    ("S6913", 21),
    ("S6915", 21),
    ("S6916", 21),
    ("S7466", 22),
    ("S7467", 22),
    ("S7475", 22),
];

/// Whether the project targets a Java older than the rule's suggestion needs.
fn needs_newer_java(active: &ActiveRule, java_version: Option<u32>) -> bool {
    java_version.is_some_and(|v| {
        JAVA_MIN_VERSION
            .iter()
            .any(|&(id, min)| id == active.rule.id && v < min)
            || active.rule.id.starts_with("java/")
                && active.rule.sonar.iter().any(|r| {
                    r.exact
                        && JAVA_MIN_VERSION_BY_KEY
                            .iter()
                            .any(|&(key, min)| key == r.key && v < min)
                })
    })
}

/// The nodes a query rule reports for a capture: the capture itself, if its
/// filter keeps it, or the nodes its filter finds; with the message its
/// filter gives, if any, in place of the rule's.
fn filtered_nodes<'t>(
    filter: Option<Filter>,
    node: Node<'t>,
    bytes: &[u8],
) -> Vec<(Node<'t>, Option<String>)> {
    match filter {
        None => vec![(node, None)],
        Some(Filter::Keep(keep)) => keep(node, bytes)
            .then_some((node, None))
            .into_iter()
            .collect(),
        Some(Filter::Find(find)) => find(node, bytes).map(|n| (n, None)).into_iter().collect(),
        Some(Filter::FindSaying(find)) => find(node, bytes)
            .map(|(n, m)| (n, Some(m)))
            .into_iter()
            .collect(),
        Some(Filter::FindAll(find)) => find(node, bytes).into_iter().map(|n| (n, None)).collect(),
    }
}

/// A JavaScript method call in a chain over several lines, `s\n.replace()`,
/// is reported on its method's line (measured on SonarQube 26.7); a call on
/// one line keeps its position.
fn js_chain_anchor(node: Node) -> Node {
    if node.kind() != "call_expression" {
        return node;
    }
    match node
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_expression")
        .and_then(|f| f.child_by_field_name("property"))
    {
        Some(p) if p.start_position().row != node.start_position().row => p,
        _ => node,
    }
}

/// Where SonarQube reports an issue about a Java declaration that has
/// annotations: at its name, below them (measured on SonarQube 26.7, for
/// classes, methods, constructors and fields), not at the first annotation.
fn java_anchor(node: Node) -> Node {
    // A call is reported at its method's name: in a chain spanning lines,
    // `a.b()\n.c()`, each call on its own line (measured on 26.7).
    if node.kind() == "method_invocation" {
        return node.child_by_field_name("name").unwrap_or(node);
    }
    const DECLARATIONS: &[&str] = &[
        "class_declaration",
        "interface_declaration",
        "enum_declaration",
        "record_declaration",
        "annotation_type_declaration",
        "method_declaration",
        "constructor_declaration",
        "field_declaration",
    ];
    if !DECLARATIONS.contains(&node.kind()) {
        return node;
    }
    let mut cursor = node.walk();
    let annotated = node
        .children(&mut cursor)
        .find(|c| c.kind() == "modifiers")
        .is_some_and(|m| {
            let mut c = m.walk();
            m.children(&mut c)
                .any(|a| matches!(a.kind(), "marker_annotation" | "annotation"))
        });
    // A field's name is its first declarator's.
    let name = if node.kind() == "field_declaration" {
        node.child_by_field_name("declarator")
            .and_then(|d| d.child_by_field_name("name"))
    } else {
        node.child_by_field_name("name")
    };
    match name {
        Some(name) if annotated => name,
        _ => node,
    }
}

/// `run_queries`, keeping only what it finds inside `within`'s macro
/// arguments when given: the second pass over a Rust file's rewritten macros.
fn run_queries_in(
    ctx: &Ctx,
    lang: Lang,
    root: Node,
    rules: &RuleSet,
    deadline: Instant,
    within: Option<&crate::rust_macros::Shadow>,
) -> Result<Vec<Issue>, FileError> {
    let bytes = ctx.src.as_bytes();
    let mut issues = Vec::new();
    let mut cursor = QueryCursor::new();
    // Cancellation just ends the match stream, so remember that it happened.
    let timed_out = Cell::new(false);
    let mut check_deadline = |_: &_| {
        let flow = expired(deadline);
        timed_out.set(flow.is_break());
        flow
    };
    let Some(cq) = rules.queries(lang).map_err(FileError::Rules)? else {
        return Ok(issues);
    };
    let test_file = is_test_file(ctx.path);
    let path = ctx.path;
    // Declarations by name, for the filters that look one up.
    let _declarations = crate::lang::JS_TS
        .contains(&lang)
        .then(|| crate::rules::js_index::scope(root, bytes));
    let options = QueryCursorOptions::new().progress_callback(&mut check_deadline);
    let mut matches = cursor.matches_with_options(&cq.query, root, bytes, options);
    while let Some(m) = matches.next() {
        for &(idx, filter) in &cq.patterns[m.pattern_index] {
            let active = &rules.active[idx];
            if skipped_in_test_file(active, test_file)
                || skipped_for_path(active, path)
                || needs_newer_java(active, ctx.java_version)
            {
                continue;
            }
            let found = m
                .captures()
                .iter()
                .filter(|c| c.index == cq.match_capture)
                .flat_map(|cap| filtered_nodes(filter, cap.node, bytes))
                .filter(|(node, _)| within.is_none_or(|w| w.covers(node.start_byte())));
            for (node, message) in found {
                let msg = message.unwrap_or_else(|| active.rule.message.to_string());
                let node = match lang {
                    Lang::Java => java_anchor(node),
                    Lang::JavaScript | Lang::TypeScript | Lang::Tsx => js_chain_anchor(node),
                    _ => node,
                };
                issues.push(ctx.issue(active, node, msg, active.rule.effort_minutes));
            }
        }
    }
    if timed_out.get() {
        return Err(FileError::QueryTimeout);
    }
    Ok(issues)
}

/// What the rules find inside the arguments of Rust's expression macros,
/// which the first parse leaves as tokens (`rust_macros.rs`). A copy that
/// can't be parsed in time costs only these findings, not the file.
fn macro_argument_issues(
    parser: &mut Parser,
    src: &str,
    root: Node,
    path: &str,
    rules: &RuleSet,
    deadline: Instant,
) -> Vec<Issue> {
    let Some(shadow) = crate::rust_macros::shadow(src, root) else {
        return Vec::new();
    };
    let bytes = shadow.source.as_bytes();
    let mut check_deadline = |_: &_| expired(deadline);
    let options = ParseOptions::new().progress_callback(&mut check_deadline);
    let Some(tree) = parser.parse_with_options(
        &mut |offset, _| &bytes[offset.min(bytes.len())..],
        None,
        Some(options),
    ) else {
        return Vec::new();
    };
    let ctx = Ctx {
        path,
        src: &shadow.source,
        lines: LineIndex::new(&shadow.source),
        java_version: None,
    };
    run_queries_in(
        &ctx,
        Lang::Rust,
        tree.root_node(),
        rules,
        deadline,
        Some(&shadow),
    )
    .unwrap_or_default()
}

/// Whether `path` (relative, `/`-separated) looks like a test file, by
/// the common conventions: `*.test.*`, `*.spec.*`, `test_*.py`, `*_test.*`,
/// or a `test`, `tests`, `__tests__`, `spec` or `__mocks__` directory.
pub(crate) fn is_test_file(path: &str) -> bool {
    let mut segments = path.split('/').rev();
    let name = segments.next().unwrap_or("");
    let stem = name.split('.').next().unwrap_or("");
    name.contains(".test.")
        || name.contains(".spec.")
        || stem.starts_with("test_")
        || stem.ends_with("_test")
        || segments.any(|d| matches!(d, "test" | "tests" | "__tests__" | "spec" | "__mocks__"))
}

/// Runs the semantic rules for `lang`, building the model only if one is
/// active. Returns whether the model ran out of time; the file then keeps
/// its other findings (ADR-0008).
fn run_semantic(
    ctx: &Ctx,
    lang: Lang,
    root: Node,
    rules: &RuleSet,
    deadline: Instant,
    issues: &mut Vec<Issue>,
    taint_facts: &mut Vec<(String, String)>,
) -> bool {
    // Declaration files describe code that lives elsewhere: nothing in them
    // runs, and their names are all visible to other files.
    if is_declaration_file(ctx.path) {
        return false;
    }
    let test_file = is_test_file(ctx.path);
    enum Find {
        Nodes(rules::SemanticFind),
        Taint(rules::TaintFind),
    }
    let active: Vec<(&ActiveRule, Find)> = rules
        .active
        .iter()
        .filter_map(|a| match a.rule.check {
            Check::Semantic { langs, find } if langs.contains(&lang) => {
                Some((a, Find::Nodes(find)))
            }
            Check::Taint { langs, find } if langs.contains(&lang) => Some((a, Find::Taint(find))),
            _ => None,
        })
        .filter(|(a, _)| !(test_file && a.rule.category == Category::Vulnerability))
        .collect();
    if active.is_empty() {
        return false;
    }
    let bytes = ctx.src.as_bytes();
    let Some(model) = semantic::build(lang, root, bytes, deadline) else {
        return semantic::supports(lang);
    };
    for (a, find) in active {
        match find {
            Find::Nodes(find) => {
                for node in find(&model, bytes) {
                    let msg = a.rule.message.to_string();
                    issues.push(ctx.issue(a, node, msg, a.rule.effort_minutes));
                }
            }
            Find::Taint(find) => {
                let found = find(&model, bytes);
                taint_facts.extend(taint_fact(ctx, a.rule.id, &found.facts));
                for finding in found.findings {
                    let msg = a.rule.message.to_string();
                    let mut issue = ctx.issue(a, finding.sink, msg, a.rule.effort_minutes);
                    issue.flow = finding
                        .steps
                        .iter()
                        .map(|s| ctx.flow_step(s.node, &s.message))
                        .collect();
                    issues.push(issue);
                }
            }
        }
    }
    false
}

/// A taint rule's facts for the project pass (ADR-0027, T4), positions
/// resolved here, where the source is: one JSON fact per rule.
fn taint_fact(ctx: &Ctx, rule: &str, facts: &semantic::taint::Facts) -> Option<(String, String)> {
    use semantic::taint::Step;
    use semantic::taint_project as tp;
    if facts.is_empty() {
        return None;
    }
    let step = |s: &Step| {
        let f = ctx.flow_step(s.node, &s.message);
        tp::StepFact {
            m: f.message,
            l: f.line,
            c: f.column,
            el: f.end_line,
            ec: f.end_column,
        }
    };
    let steps = |ss: &[Step]| ss.iter().map(step).collect::<Vec<_>>();
    let at = |node: Node, message: String| step(&Step { node, message });
    let sink = |node: Node| {
        let row = node.start_position().row;
        tp::SinkFact {
            at: at(node, String::new()),
            fingerprint: project_fingerprint(ctx, rule, row).to_string(),
            suppressed: Suppression::of(ctx.lines.text(row)).covers(rule),
        }
    };
    let file = tp::FileFacts {
        summaries: facts
            .summaries
            .iter()
            .map(|s| tp::Summary {
                key: s.key.clone(),
                returns_sql: s.returns_sql,
                to_sink: s
                    .to_sink
                    .iter()
                    .map(|(p, ss, n)| tp::ParamSink {
                        p: *p,
                        steps: steps(ss),
                        sink: sink(*n),
                    })
                    .collect(),
                to_return: s
                    .to_return
                    .iter()
                    .map(|(p, ss)| tp::ParamPath {
                        p: *p,
                        steps: steps(ss),
                    })
                    .collect(),
                returns_source: s.returns_source.as_deref().map(steps),
                to_call: s
                    .to_call
                    .iter()
                    .map(|(p, ss, callee, arg)| tp::ParamCall {
                        p: *p,
                        steps: steps(ss),
                        callee: callee.clone(),
                        arg: *arg,
                    })
                    .collect(),
            })
            .collect(),
        calls: facts
            .calls
            .iter()
            .map(|c| {
                let mut ss = steps(&c.steps);
                ss.push(at(c.call, format!("passed to `{}`", c.callee.display())));
                tp::Call {
                    steps: ss,
                    callee: c.callee.clone(),
                    arg: c.arg,
                }
            })
            .collect(),
        returns: facts
            .returns
            .iter()
            .map(|r| tp::Return {
                callee: r.callee.clone(),
                passed: at(r.call, format!("passed to `{}`", r.callee.display())),
                returned: at(r.call, format!("returned by `{}`", r.callee.display())),
                args: r
                    .args
                    .iter()
                    .map(|(p, ss)| tp::ParamPath {
                        p: *p,
                        steps: steps(ss),
                    })
                    .collect(),
                after: steps(&r.after),
                sink: sink(r.sink),
                needs_sql: r.needs_sql,
            })
            .collect(),
    };
    let json = serde_json::to_string(&file).ok()?;
    Some((format!("{}{rule}", tp::FACT_PREFIX), json))
}

/// The fingerprint of an issue the project pass reports: the algorithm of
/// `fingerprints`, with an ordinal no file's own issues reach, so the two
/// never collide.
fn project_fingerprint(ctx: &Ctx, rule: &str, row: usize) -> Fingerprint {
    const PROJECT_ORDINAL: u64 = 1 << 32;
    let line: String = ctx
        .lines
        .text(row)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut hasher = sha2::Sha256::new();
    for field in ["sonda-fingerprint-v1", rule, ctx.path, &line] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(PROJECT_ORDINAL.to_le_bytes());
    let hash = hasher.finalize();
    let mut short = [0; 16];
    short.copy_from_slice(&hash[..16]);
    Digest(short)
}

/// Taint findings whose path crosses files (ADR-0027, T4): each taint
/// rule's facts, joined. The issue is at the sink, in its file; each step
/// names its own file when it's another.
pub(crate) fn taint_project_rules(files: &mut [FileAnalysis], rules: &RuleSet) {
    use semantic::taint_project as tp;
    let mut keys: Vec<&str> = files
        .iter()
        .flat_map(|f| f.facts.iter())
        .filter_map(|(k, _)| k.strip_prefix(tp::FACT_PREFIX).map(|_| k.as_str()))
        .collect();
    keys.sort_unstable();
    keys.dedup();
    let keys: Vec<String> = keys.into_iter().map(str::to_string).collect();
    // C#'s indexes, parsed once for every C# rule.
    let mut cs_parsed: Option<Vec<(usize, semantic::cs_index::FileIndex)>> = None;
    for key in keys {
        let Some(active) = rules.get(&key[tp::FACT_PREFIX.len()..]) else {
            continue;
        };
        let facts: Vec<Option<tp::FileFacts>> = files
            .iter()
            .map(|f| {
                f.facts
                    .iter()
                    .find(|(k, _)| *k == key)
                    .and_then(|(_, json)| serde_json::from_str(json).ok())
            })
            .collect();
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        let found = if key[tp::FACT_PREFIX.len()..].starts_with("cs/") {
            let parsed = cs_parsed.get_or_insert_with(|| cs_indexes(files));
            let index = CsTaintIndex::new(parsed);
            tp::compose(
                &paths,
                &facts,
                Some(&|from, callee| index.resolve(from, callee)),
            )
        } else {
            tp::compose(&paths, &facts, None)
        };
        let mut issues = Vec::new();
        for f in found {
            let file = &files[f.file];
            let at = &f.sink.at;
            if file
                .issues
                .iter()
                .any(|i| i.rule == active.rule.id && i.line == at.l && i.column == at.c)
            {
                continue;
            }
            let mut issue =
                project_issue(active, &file.path, at.l, active.rule.message.to_string());
            issue.column = at.c;
            issue.end_line = at.el;
            issue.end_column = at.ec;
            if let Some(fp) = parse_fingerprint(&f.sink.fingerprint) {
                issue.fingerprint = fp;
            }
            issue.flow = f
                .steps
                .iter()
                .map(|(i, s)| crate::model::FlowStep {
                    path: (*i != f.file).then(|| files[*i].path.clone()),
                    message: s.m.clone(),
                    line: s.l,
                    column: s.c,
                    end_line: s.el,
                    end_column: s.ec,
                })
                .collect();
            issues.push((f.file, issue));
        }
        for (i, issue) in issues {
            if !files[i]
                .issues
                .iter()
                .any(|x| x.rule == issue.rule && x.fingerprint == issue.fingerprint)
            {
                files[i].issues.push(issue);
            }
        }
    }
}

/// The files' C# indexes (ADR-0020), by their position in `files`.
fn cs_indexes(files: &[FileAnalysis]) -> Vec<(usize, semantic::cs_index::FileIndex)> {
    files
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let (_, json) = f
                .facts
                .iter()
                .find(|(k, _)| k == semantic::cs_index::FACT)?;
            Some((i, serde_json::from_str(json).ok()?))
        })
        .collect()
}

/// ADR-0020's index, for the project pass's C# calls: a call's type,
/// written in one file, to the summaries of its methods in the project,
/// and of an interface's or a base class's implementations.
struct CsTaintIndex<'a> {
    files: Vec<usize>,
    index: semantic::cs_index::ProjectIndex<'a>,
    /// Each type's implementations and subclasses in the project.
    below: HashMap<usize, Vec<usize>>,
}

impl<'a> CsTaintIndex<'a> {
    fn new(parsed: &'a [(usize, semantic::cs_index::FileIndex)]) -> Self {
        let index = semantic::cs_index::ProjectIndex::new(parsed.iter().map(|(_, x)| x).collect());
        let mut below: HashMap<usize, Vec<usize>> = HashMap::new();
        for t in 0..index.len() {
            let mut above = index.interfaces(t);
            above.extend(index.ancestors(t));
            for a in above {
                below.entry(a).or_default().push(t);
            }
        }
        CsTaintIndex {
            files: parsed.iter().map(|(i, _)| *i).collect(),
            index,
            below,
        }
    }

    fn resolve(
        &self,
        from: usize,
        callee: &semantic::taint::Callee,
    ) -> Vec<(usize, semantic::taint::Key)> {
        let semantic::taint::Callee::Cs {
            ty,
            namespace,
            owner,
            method,
            arity,
        } = callee
        else {
            return Vec::new();
        };
        let Some(at) = self.files.iter().position(|i| *i == from) else {
            return Vec::new();
        };
        let Some(id) = self.index.resolve_at(at, namespace, owner, ty) else {
            return Vec::new();
        };
        let member = format!("{method}/{arity}");
        let mut out = Vec::new();
        let types = std::iter::once(id).chain(self.below.get(&id).into_iter().flatten().copied());
        for t in types {
            let full = self.index.decl(t).1.full_name();
            for (file, _) in self.index.parts(t) {
                out.push((
                    self.files[*file],
                    semantic::taint::Key {
                        export: full.clone(),
                        member: Some(member.clone()),
                    },
                ));
            }
        }
        out.sort_by(|a, b| (a.0, &a.1.export).cmp(&(b.0, &b.1.export)));
        out.dedup();
        out
    }
}

fn parse_fingerprint(hex: &str) -> Option<Fingerprint> {
    let mut out = [0u8; 16];
    if hex.len() != 32 {
        return None;
    }
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(Digest(out))
}

/// TypeScript declaration files: `x.d.ts`, `x.d.mts`, `x.d.cts`.
fn is_declaration_file(path: &str) -> bool {
    [".d.ts", ".d.mts", ".d.cts"]
        .iter()
        .any(|ext| path.ends_with(ext))
}

fn measure_functions(
    ctx: &Ctx,
    syn: &Syntax,
    root: Node,
    rules: &RuleSet,
    cfg: &Config,
    issues: &mut Vec<Issue>,
    metrics: &mut FileMetrics,
) {
    let t = &cfg.thresholds;
    let max_cognitive = t.cognitive_complexity.unwrap_or(syn.max_cognitive);
    let cognitive_rule = rules.get(rules::COGNITIVE_COMPLEXITY);
    let length_rule = rules.get(rules::FUNCTION_LENGTH);
    let params_rule = rules.get(rules::TOO_MANY_PARAMETERS);

    walk(root, |node| {
        // is_named: keyword tokens such as `function` share their text with node kinds.
        let closure = syn.closures.contains(&node.kind());
        if !node.is_named() || !(closure || syn.functions.contains(&node.kind())) {
            return true;
        }
        if closure {
            return true;
        }
        let c = complexity(node, syn, ctx.src.as_bytes());
        metrics.complexity += c.cyclomatic;
        let whole = syn.cognitive_includes_nested_functions;
        if !syn.file_cognitive_nests_functions && !whole {
            metrics.cognitive_complexity += c.cognitive;
        }
        metrics.functions += 1;

        let name = function_name(node, ctx);
        let anchor = name_node(node).unwrap_or(node);
        if let Some(rule) = cognitive_rule
            && !whole
            && c.cognitive > max_cognitive
            && !macro_body_or_old_style(node, ctx.src.as_bytes())
        {
            let msg = format!(
                "Refactor '{name}' to reduce its cognitive complexity from {} to the {} allowed.",
                c.cognitive, max_cognitive
            );
            let effort = rule.rule.effort_minutes + (c.cognitive - max_cognitive);
            issues.push(ctx.issue(rule, anchor, msg, effort));
        }
        let lines = node.end_position().row - node.start_position().row + 1;
        if let Some(rule) = length_rule
            && lines > t.function_lines as usize
        {
            let msg = format!(
                "'{name}' has {lines} lines, which is more than the {} allowed.",
                t.function_lines
            );
            issues.push(ctx.issue(rule, anchor, msg, rule.rule.effort_minutes));
        }
        let max_parameters = t.parameters.unwrap_or(syn.max_parameters);
        if let Some(rule) = params_rule
            && let Some(n) = parameter_count(node, syn, ctx.src.as_bytes())
            && n > max_parameters as usize
            && !calls_base_constructor(node, ctx.src.as_bytes())
            && !overrides(node, ctx.src.as_bytes())
        {
            let msg = format!(
                "'{name}' has {n} parameters, which is more than the {max_parameters} allowed."
            );
            // An arrow function at its `=>`, after the parameters (measured
            // on SonarQube 26.7).
            let mut cursor = node.walk();
            let arrow = (node.kind() == "arrow_function")
                .then(|| node.children(&mut cursor).find(|c| c.kind() == "=>"))
                .flatten();
            issues.push(ctx.issue(rule, arrow.unwrap_or(anchor), msg, rule.rule.effort_minutes));
        }
        // Keep descending: nested functions are measured on their own.
        true
    });
    if syn.file_cognitive_nests_functions {
        walk(root, |node| {
            if !node.is_named() || !syn.functions.contains(&node.kind()) {
                return true;
            }
            metrics.cognitive_complexity += file_cognitive(node, syn, ctx.src.as_bytes());
            false // its nested functions are part of it
        });
    }
    if syn.cognitive_includes_nested_functions {
        // Code outside any function counts for the file, as SonarQube's
        // Python analyzer measures it (`if __name__ == "__main__":`).
        metrics.cognitive_complexity += complexity(root, syn, ctx.src.as_bytes()).cognitive;
        // Each outermost function (a method too), with what's nested in it.
        walk(root, |node| {
            if !node.is_named() || !syn.functions.contains(&node.kind()) {
                return true;
            }
            if !scored_on_its_own(node) {
                return true; // part of the function around it
            }
            let cognitive = complexity_with(node, syn, ctx.src.as_bytes(), true).cognitive;
            metrics.cognitive_complexity += cognitive;
            if let Some(rule) = cognitive_rule
                && cognitive > max_cognitive
            {
                let name = function_name(node, ctx);
                let msg = format!(
                    "Refactor '{name}' to reduce its cognitive complexity from {cognitive} to the {} allowed.",
                    max_cognitive
                );
                let effort = rule.rule.effort_minutes + (cognitive - max_cognitive);
                issues.push(ctx.issue(rule, name_node(node).unwrap_or(node), msg, effort));
            }
            false
        });
    }
}

/// Whether a Python function is scored on its own: it isn't inside another
/// function, not even through a class defined there, as SonarQube scores it.
fn scored_on_its_own(function: Node) -> bool {
    let mut n = function.parent();
    while let Some(p) = n {
        if p.kind() == "function_definition" {
            return false;
        }
        n = p.parent();
    }
    true
}

/// Whether a function is defined directly in a class body.
fn is_method(function: Node) -> bool {
    let mut n = function;
    if n.parent()
        .is_some_and(|p| p.kind() == "decorated_definition")
    {
        n = n.parent().unwrap_or(n);
    }
    n.parent()
        .filter(|b| b.kind() == "block")
        .and_then(|b| b.parent())
        .is_some_and(|c| c.kind() == "class_definition")
}

/// Whether a nested function's enclosing function only wraps it, as a
/// decorator does: its body holds that one function (and a docstring) and
/// returns it by name. A function defining several isn't a wrapper.
fn encloses_only_functions(nested: Node) -> bool {
    let mut n = nested;
    if n.parent()
        .is_some_and(|p| p.kind() == "decorated_definition")
    {
        n = n.parent().unwrap_or(n);
    }
    let Some(body) = n.parent().filter(|b| b.kind() == "block") else {
        return false;
    };
    if !body
        .parent()
        .is_some_and(|f| f.kind() == "function_definition")
    {
        return false;
    }
    let mut functions = 0;
    let mut returns_a_name = false;
    let mut cursor = body.walk();
    for s in body.named_children(&mut cursor) {
        match s.kind() {
            "function_definition" | "decorated_definition" => functions += 1,
            "comment" => {}
            "return_statement" => {
                returns_a_name = s.named_child(0).is_some_and(|v| v.kind() == "identifier");
            }
            "expression_statement" if s.named_child(0).is_some_and(|c| c.kind() == "string") => {}
            _ => return false,
        }
    }
    functions == 1 && returns_a_name
}

/// An outermost function's share of its file's cognitive complexity, with
/// the functions nested in it: each one level deeper, unless the outermost
/// has no structure of its own, as a wrapper around callbacks doesn't.
fn file_cognitive(func: Node, syn: &Syntax, src: &[u8]) -> u32 {
    let own = complexity(func, syn, src);
    let all = complexity_with(func, syn, src, true);
    if own.structures == 0 {
        // One level less for everything in its nested functions.
        all.cognitive - (all.structures - own.structures)
    } else {
        all.cognitive
    }
}

struct TokenScan {
    code_lines: Vec<usize>,
    comment_lines: usize,
    tokens: Vec<Token>,
}

/// The rules about comments `scan_tokens` checks on each one.
struct CommentRules<'r, 't> {
    todo: Option<&'r ActiveRule>,
    code: Option<&'r ActiveRule>,
    trailing: Option<&'r ActiveRule>,
    nosonar: Option<&'r ActiveRule>,
    python: bool,
    /// Java has its own rule for this, java/commented-out-code.
    java: bool,
    /// java/commented-out-code, for Java's `/* */` comments, judged here line
    /// by line.
    java_code: Option<&'r ActiveRule>,
    /// The row of the last commented-out-code issue: a block of commented
    /// lines is one finding, reported at its first line.
    last_code_comment_row: Option<usize>,
    /// Python: the comment lines of the block being read, judged together
    /// when it ends, as SonarQube judges a block.
    python_block: Vec<(Node<'t>, String)>,
    /// C#: judged as SonarQube 26.7 does (measured), not by the generic
    /// heuristics.
    csharp: bool,
    /// C#: the `//` lines of the block being read.
    csharp_block: Vec<(Node<'t>, String)>,
    /// C and C++: a block of `//` lines is one finding, at its first line.
    cfamily: bool,
    /// C and C++: the `//` lines of the block being read.
    cfamily_block: Vec<(Node<'t>, String)>,
    /// Where the file's first token starts: comments before it are its
    /// header (a licence), which C# doesn't judge.
    header_end: usize,
}

impl<'t> CommentRules<'_, 't> {
    /// Judges the Python comment block read so far as code or not.
    fn flush_python_block(&mut self, ctx: &Ctx, issues: &mut Vec<Issue>) {
        let block = std::mem::take(&mut self.python_block);
        let (Some(rule), Some((first, _))) = (self.code, block.first()) else {
            return;
        };
        let lines: Vec<&str> = block.iter().map(|(_, t)| t.as_str()).collect();
        if python_block_is_code(&lines) {
            let msg = "Remove this commented-out code.".to_string();
            issues.push(ctx.issue(rule, *first, msg, rule.rule.effort_minutes));
        }
    }

    /// Judges the C# `//` block read so far: one issue, at its first line
    /// when the lines together parse as C#, else at its first line that
    /// reads as code on its own.
    fn flush_csharp_block(&mut self, ctx: &Ctx, issues: &mut Vec<Issue>) {
        let block = std::mem::take(&mut self.csharp_block);
        let Some(rule) = self.code else {
            return;
        };
        let lines: Vec<&str> = block.iter().map(|(_, t)| t.as_str()).collect();
        let at = if lines.len() > 1 && csharp_parses(&lines.join("\n")) {
            block.first().map(|(n, _)| *n)
        } else {
            block
                .iter()
                .find(|(_, t)| csharp_line_is_code(t))
                .map(|(n, _)| *n)
        };
        if let Some(node) = at {
            let msg = "Remove this commented-out code.".to_string();
            issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
        }
    }

    /// C and C++: a block of `//` lines with code in it is one issue, at its
    /// first line, prose or not (as SonarCloud reports them; C/C++ couldn't
    /// be measured on SonarQube 26.7).
    fn flush_cfamily_block(&mut self, ctx: &Ctx, issues: &mut Vec<Issue>) {
        let block = std::mem::take(&mut self.cfamily_block);
        let (Some(rule), Some((first, _))) = (self.code, block.first()) else {
            return;
        };
        let lines: Vec<&str> = block
            .iter()
            .map(|(_, t)| t.trim_start_matches('/'))
            .collect();
        if block.iter().any(|(_, t)| cfamily_line_is_code(t)) || cpp_parses(&lines.join("\n")) {
            let msg = "Remove this commented-out code.".to_string();
            issues.push(ctx.issue(rule, *first, msg, rule.rule.effort_minutes));
        }
    }

    fn check_cfamily(
        &mut self,
        ctx: &Ctx,
        node: Node<'t>,
        text: &str,
        alone: bool,
        issues: &mut Vec<Issue>,
    ) {
        let line_comment =
            text.starts_with("//") && !text.starts_with("///") && !text.starts_with("//!");
        let row = node.start_position().row;
        let continues = alone
            && line_comment
            && self
                .cfamily_block
                .last()
                .is_some_and(|(last, _)| last.end_position().row + 1 == row);
        if !continues {
            self.flush_cfamily_block(ctx, issues);
        }
        if alone && line_comment {
            self.cfamily_block.push((node, text.to_string()));
            return;
        }
        let doc = text.starts_with("/**") || text.starts_with("///") || text.starts_with("//!");
        if let Some(rule) = self.code
            && !doc
            && text.lines().any(cfamily_line_is_code)
        {
            let msg = "Remove this commented-out code.".to_string();
            issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
        }
    }

    /// C#: a `//` line on its own joins the block being read; a block
    /// comment, or a comment after code, is judged line by line, reported at
    /// its first line of code (measured on SonarQube 26.7).
    fn check_csharp(
        &mut self,
        ctx: &Ctx,
        node: Node<'t>,
        text: &str,
        alone: bool,
        issues: &mut Vec<Issue>,
    ) {
        let line_comment = text.starts_with("//") && !text.starts_with("///");
        let row = node.start_position().row;
        let continues = alone
            && line_comment
            && self
                .csharp_block
                .last()
                .is_some_and(|(last, _)| last.end_position().row + 1 == row);
        if !continues {
            self.flush_csharp_block(ctx, issues);
        }
        let Some(rule) = self.code else {
            return;
        };
        if node.end_byte() <= self.header_end || text.starts_with("///") || text.starts_with("/**")
        {
            return;
        }
        if alone && line_comment {
            self.csharp_block
                .push((node, text.trim_start_matches('/').to_string()));
            return;
        }
        let body = text
            .strip_prefix("//")
            .or_else(|| text.strip_prefix("/*"))
            .unwrap_or(text);
        let body = body.strip_suffix("*/").unwrap_or(body);
        for (i, line) in body.lines().enumerate() {
            let content = line.trim();
            let content = content.strip_prefix('*').unwrap_or(content);
            if csharp_line_is_code(content) {
                let row = row + i;
                let column = if i == 0 {
                    ctx.lines.char_column(row, node.start_position().column)
                } else {
                    0
                };
                let width = ctx.lines.text(row).chars().count().max(column + 1);
                let msg = "Remove this commented-out code.".to_string();
                issues.push(ctx.issue_on_line(rule, row, (column, width), msg));
                break;
            }
        }
    }

    fn check(&mut self, ctx: &Ctx, node: Node<'t>, issues: &mut Vec<Issue>) {
        let text = ctx.text(node);
        let alone = comment_is_alone(ctx, node);
        if self.csharp {
            self.check_csharp(ctx, node, text, alone, issues);
        }
        if self.cfamily {
            self.check_cfamily(ctx, node, text, alone, issues);
        }
        // A Java `/* */` comment (not a Javadoc) with code in it, reported at
        // its first line of code, as SonarQube 26.7 does (measured).
        if let Some(rule) = self.java_code
            && node.kind() == "block_comment"
            && !text.starts_with("/**")
        {
            let body = text.strip_suffix("*/").unwrap_or(text);
            for (i, line) in body.lines().enumerate() {
                let line = if i == 0 {
                    line.strip_prefix("/*").unwrap_or(line)
                } else {
                    line
                };
                let content = line.trim();
                let content = content.strip_prefix('*').unwrap_or(content).trim();
                if !content.is_empty()
                    && crate::rules::java_line_looks_like_code(content.as_bytes())
                {
                    let row = node.start_position().row + i;
                    let column = if i == 0 {
                        ctx.lines.char_column(row, node.start_position().column)
                    } else {
                        0
                    };
                    let width = ctx.lines.text(row).chars().count().max(column + 1);
                    let msg = "Remove this commented-out code.".to_string();
                    issues.push(ctx.issue_on_line(rule, row, (column, width), msg));
                    break;
                }
            }
        }
        if let Some(rule) = self.nosonar
            && text.contains("NOSONAR")
        {
            let msg = "Review this NOSONAR suppression.".to_string();
            issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
        }
        if let Some(rule) = self.trailing
            && !alone
            && !is_pragma_comment(text)
        {
            let msg = "Move this comment to its own line.".to_string();
            issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
        }
        if self.python {
            // A block of comment lines is judged as one; a comment after
            // code on its line, on its own.
            let row = node.start_position().row;
            let continues = alone
                && self
                    .python_block
                    .last()
                    .is_some_and(|(last, _)| last.end_position().row + 1 == row);
            if !continues {
                self.flush_python_block(ctx, issues);
            }
            if alone {
                self.python_block.push((node, text.to_string()));
            } else if let Some(rule) = self.code
                && python_block_is_code(&[text])
            {
                let msg = "Remove this commented-out code.".to_string();
                issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
            }
        } else if let Some(rule) = self.code
            && !self.java
            && !self.csharp
            && !self.cfamily
            && reads_as_code(text, alone, self.python)
        {
            let row = node.start_position().row;
            let continues_block = self.last_code_comment_row.is_some_and(|r| r + 1 == row);
            self.last_code_comment_row = Some(last_row(node));
            if !continues_block {
                let msg = "Remove this commented-out code.".to_string();
                issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
            }
        }
        if let Some(rule) = self.todo
            && self.cfamily
        {
            // C and C++: once per comment, at its start, the tag in any case
            // (`// Fixme:`, `// todo:`), as SonarCloud reports them.
            let upper = text.to_ascii_uppercase();
            if let Some((tag, _)) = todo_tag_at(&upper) {
                let msg = format!("Complete the task associated with this {tag} comment.");
                issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
            }
        } else if let Some(rule) = self.todo {
            // On each tag's line, as SonarQube reports them in a block
            // comment: one per line.
            let mut from = 0;
            while let Some((tag, found)) = todo_tag_at(&text[from..]) {
                let at = from + found;
                let msg = format!("Complete the task associated with this {tag} comment.");
                let before = &text[..at];
                let row = node.start_position().row + before.matches('\n').count();
                let column = match before.rfind('\n') {
                    Some(nl) => before[nl + 1..].chars().count(),
                    None => {
                        ctx.lines.char_column(row, node.start_position().column)
                            + before.chars().count()
                    }
                };
                issues.push(ctx.issue_on_line(rule, row, (column, column + tag.len()), msg));
                match text[at..].find('\n') {
                    Some(nl) => from = at + nl + 1,
                    None => break,
                }
            }
        }
    }
}

/// Whether a comment is alone on its line: nothing but space before it.
fn comment_is_alone(ctx: &Ctx, node: Node) -> bool {
    let start = node.start_position();
    let line = ctx.lines.text(start.row);
    line[..start.column.min(line.len())].trim().is_empty()
}

/// A string that is a module's, class's or function's docstring: the first
/// statement of its body.
fn is_docstring(string: Node) -> bool {
    let Some(statement) = string
        .parent()
        .filter(|p| p.kind() == "expression_statement")
    else {
        return false;
    };
    let Some(body) = statement.parent() else {
        return false;
    };
    let first = body
        .named_child(0)
        .is_some_and(|f| f.id() == statement.id());
    first
        && (body.kind() == "module"
            || body.kind() == "block"
                && body.parent().is_some_and(|d| {
                    matches!(d.kind(), "function_definition" | "class_definition")
                }))
}

/// Whether a Python comment block (its lines, `#` and all) is commented-out
/// code, as SonarQube judges it: the whole block, without its `#`s and
/// dedented, parses as Python and holds a statement (an assignment, a
/// return, an assert, a block header...), not only expressions such as a
/// lone call. A block mixing prose and code doesn't parse.
fn python_block_is_code(lines: &[&str]) -> bool {
    use std::cell::RefCell;
    thread_local! {
        static PARSER: RefCell<Option<tree_sitter::Parser>> = const { RefCell::new(None) };
    }
    let stripped: Vec<&str> = lines
        .iter()
        .map(|l| l.trim_start().trim_start_matches('#').trim_end())
        .collect();
    let indent = stripped
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    let body: Vec<&str> = stripped
        .iter()
        .map(|l| {
            if l.len() >= indent {
                &l[indent..]
            } else {
                l.trim_start()
            }
        })
        .collect();
    let joined = body.join("\n");
    let text = joined.trim();
    // `fmt: off`, `pylint: disable=...`: SonarQube's own exception.
    let directive = text.starts_with("fmt:")
        || text.starts_with("py")
            && text
                .split(':')
                .next()
                .is_some_and(|w| !w.contains(' ') && text.contains(':'));
    if directive || is_directive_or_too_short(text) {
        return false;
    }
    let mut source = format!("{joined}\n");
    if text.ends_with(':') {
        source.push_str("    pass\n");
    }
    PARSER.with(|p| {
        let mut p = p.borrow_mut();
        let parser = p.get_or_insert_with(|| {
            let mut parser = tree_sitter::Parser::new();
            let _ = parser.set_language(&Lang::Python.grammar());
            parser
        });
        let Some(tree) = parser.parse(&source, None) else {
            return false;
        };
        let root = tree.root_node();
        if root.has_error() {
            return false;
        }
        let mut cursor = root.walk();
        let statements: Vec<Node> = root
            .named_children(&mut cursor)
            .filter(|n| n.kind() != "comment")
            .collect();
        statements.iter().any(|s| match s.kind() {
            "expression_statement" => s.named_child(0).is_some_and(|e| {
                e.kind() == "augmented_assignment"
                    || e.kind() == "assignment" && e.child_by_field_name("right").is_some()
            }),
            "future_import_statement" | "pass_statement" | "comment" => false,
            _ => true,
        })
    })
}

/// Whether a comment is commented-out code. In Python, one after code on
/// its line can be too, when it parses as a statement.
/// A C# comment line that reads as code on its own (measured on SonarQube
/// 26.7): it ends with `;`, a sentence too; it's a lone brace; or it ends
/// with a brace and parses, `public string Name { get; set; }` but not a
/// template's `{{ join .Categories "," }}`.
fn csharp_line_is_code(line: &str) -> bool {
    let l = line.trim();
    if l.is_empty() || l.contains("sonda-ignore") || l.contains("NOSONAR") {
        return false;
    }
    l.ends_with(';')
        || l == "{"
        || l == "}"
        || l.ends_with('}') && csharp_parses(l)
        || l.ends_with('{') && csharp_parses(&format!("{l}\n}}"))
}

/// A C or C++ comment line that reads as code: the generic signs, a lone
/// brace, or a preprocessor directive (`// #endif`, `// #include "x.h"`),
/// as SonarCloud reports them.
fn cfamily_line_is_code(line: &str) -> bool {
    let l = line
        .trim()
        .trim_start_matches(['/', '*'])
        .trim_end_matches("*/")
        .trim();
    let directive = l.strip_prefix('#').is_some_and(|d| {
        let d = d.trim_start();
        [
            "include", "if", "ifdef", "ifndef", "endif", "else", "elif", "define", "undef",
            "pragma",
        ]
        .iter()
        .any(|k| d.starts_with(k))
    });
    matches!(l, "{" | "}" | "};") || directive || looks_like_code(line)
}

/// Whether lines parse as C++ statements (in a function body) or
/// declarations (at namespace or class scope), with no error and at least
/// one statement or declaration with a call, an assignment or a body.
fn cpp_parses(code: &str) -> bool {
    thread_local! {
        static CPP_PARSER: std::cell::RefCell<Option<tree_sitter::Parser>> =
            const { std::cell::RefCell::new(None) };
    }
    if !code.contains([';', '{', '}']) {
        return false;
    }
    CPP_PARSER.with(|p| {
        let mut p = p.borrow_mut();
        let parser = p.get_or_insert_with(|| {
            let mut parser = tree_sitter::Parser::new();
            let _ = parser.set_language(&Lang::Cpp.grammar());
            parser
        });
        [
            ("void __f() {\n", "\n}"),
            ("struct __S {\n", "\n};"),
            ("", ""),
        ]
        .into_iter()
        .any(|(open, close)| {
            let source = format!("{open}{code}{close}");
            parser
                .parse(&source, None)
                .is_some_and(|tree| !tree.root_node().has_error())
        })
    })
}

/// Whether lines parse as C# statements or members, with no error.
fn csharp_parses(code: &str) -> bool {
    thread_local! {
        static CS_PARSER: std::cell::RefCell<Option<tree_sitter::Parser>> =
            const { std::cell::RefCell::new(None) };
    }
    CS_PARSER.with(|p| {
        let mut p = p.borrow_mut();
        let parser = p.get_or_insert_with(|| {
            let mut parser = tree_sitter::Parser::new();
            let _ = parser.set_language(&Lang::CSharp.grammar());
            parser
        });
        ["class __S { void __M() {\n", "class __S {\n"]
            .into_iter()
            .any(|open| {
                let source = format!(
                    "{open}{code}\n}}{}",
                    if open.contains("__M") { " }" } else { "" }
                );
                parser.parse(&source, None).is_some_and(|tree| {
                    let root = tree.root_node();
                    // Something to parse: blank lines aren't code.
                    let mut inner = root
                        .named_child(0)
                        .and_then(|c| c.child_by_field_name("body"));
                    if open.contains("__M") {
                        inner = inner
                            .and_then(|b| b.named_child(0))
                            .and_then(|m| m.child_by_field_name("body"));
                    }
                    !root.has_error()
                        && inner.is_some_and(|b| {
                            b.named_children(&mut b.walk())
                                .any(|c| c.kind() != "comment")
                        })
                })
            })
    })
}

fn reads_as_code(text: &str, alone: bool, python: bool) -> bool {
    if python {
        python_comment_is_code(text, alone) || (alone && comment_is_commented_out_code(text))
    } else {
        alone && comment_is_commented_out_code(text)
    }
}

/// One pass over every node: code/comment lines, duplication tokens, TODO comments.
fn scan_tokens(
    ctx: &Ctx,
    syn: &Syntax,
    root: Node,
    rules: &RuleSet,
    issues: &mut Vec<Issue>,
) -> TokenScan {
    let rows = ctx.lines.count().max(root.end_position().row + 1);
    let mut code = vec![false; rows];
    let mut comment = vec![false; rows];
    let mut tokens = Vec::new();
    let mark = |flags: &mut Vec<bool>, node: Node| {
        flags[node.start_position().row..=last_row(node)].fill(true);
    };
    let mut comment_rules = CommentRules {
        todo: rules.get(rules::TODO_COMMENT),
        code: rules.get(rules::COMMENTED_OUT_CODE),
        trailing: rules.get(rules::TRAILING_COMMENT),
        nosonar: rules.get(rules::NOSONAR_COMMENT),
        python: std::ptr::eq(syn, Lang::Python.syntax()),
        java: std::ptr::eq(syn, Lang::Java.syntax()),
        java_code: std::ptr::eq(syn, Lang::Java.syntax())
            .then(|| rules.get("java/commented-out-code"))
            .flatten(),
        last_code_comment_row: None,
        python_block: Vec::new(),
        csharp: std::ptr::eq(syn, Lang::CSharp.syntax()),
        csharp_block: Vec::new(),
        cfamily: std::ptr::eq(syn, Lang::C.syntax()),
        cfamily_block: Vec::new(),
        header_end: {
            let mut cursor = root.walk();
            root.named_children(&mut cursor)
                .find(|c| !syn.comments.contains(&c.kind()))
                .map_or(usize::MAX, |c| c.start_byte())
        },
    };
    let python = comment_rules.python;

    walk(root, |node| {
        let kind = node.kind();
        if syn.comments.contains(&kind) {
            mark(&mut comment, node);
            comment_rules.check(ctx, node, issues);
            return false;
        }
        if syn.dup_ignore.contains(&kind) {
            mark(&mut code, node);
            return false;
        }
        // A docstring that parses as code is commented-out code too, as
        // SonarQube reports it.
        if python
            && kind == "string"
            && let Some(rule) = comment_rules.code
            && is_docstring(node)
        {
            let content = ctx
                .text(node)
                .trim_matches(['"', '\'', 'r', 'R', 'u', 'U', 'b', 'B']);
            let lines: Vec<&str> = content.lines().collect();
            if python_block_is_code(&lines) {
                let msg = "Remove this commented-out code.".to_string();
                issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
            }
        }
        if node.child_count() == 0 && node.start_byte() < node.end_byte() {
            mark(&mut code, node);
            tokens.push(Token {
                hash: fnv1a(ctx.text(node).as_bytes()),
                line: node.start_position().row + 1,
            });
        }
        true
    });
    comment_rules.flush_python_block(ctx, issues);
    comment_rules.flush_csharp_block(ctx, issues);
    comment_rules.flush_cfamily_block(ctx, issues);

    let code_lines = (0..rows).filter(|&r| code[r]).map(|r| r + 1).collect();
    TokenScan {
        code_lines,
        comment_lines: comment.iter().filter(|&&c| c).count(),
        tokens,
    }
}

/// Consistency checks on an analysis result: every reported position lies
/// inside the file. Applied to results from worker processes (which are not
/// trusted), and used by the property tests and fuzz targets.
pub(crate) fn check_invariants(a: &FileAnalysis) -> Result<(), String> {
    let lines = a.metrics.lines.max(1);
    let inside = |l: usize| l >= 1 && l <= lines;
    if let Some(i) = a
        .issues
        .iter()
        .find(|i| !inside(i.line) || i.end_line < i.line || i.column < 1 || i.end_column < 1)
    {
        return Err(format!(
            "{} at {}:{} is outside the file",
            i.rule, i.line, i.column
        ));
    }
    if let Some((i, s)) = a.issues.iter().find_map(|i| {
        i.flow
            .iter()
            .find(|s| {
                !inside(s.line)
                    || !inside(s.end_line)
                    || s.end_line < s.line
                    || s.column < 1
                    || s.end_column < 1
            })
            .map(|s| (i, s))
    }) {
        return Err(format!(
            "{}'s flow step at {}:{} is outside the file",
            i.rule, s.line, s.column
        ));
    }
    if !a.code_lines.windows(2).all(|w| w[0] < w[1]) {
        return Err("code lines are not strictly ascending".into());
    }
    if let Some(l) = a.code_lines.iter().find(|&&l| !inside(l)) {
        return Err(format!("code line {l} is outside the file ({lines} lines)"));
    }
    if let Some(t) = a.tokens.iter().find(|t| !inside(t.line)) {
        return Err(format!("token on line {} is outside the file", t.line));
    }
    Ok(())
}

/// The last row a node occupies. An end at column 0 of a later row is
/// exclusive: the node stops before that row. (An unterminated string at
/// the end of a file ends there, one row past the last line.)
fn last_row(node: Node) -> usize {
    let (start, end) = (node.start_position(), node.end_position());
    if end.column == 0 && end.row > start.row {
        end.row - 1
    } else {
        end.row
    }
}

/// Depth-first pre-order traversal without recursion. `f` returns whether
/// to descend into the node's children.
fn walk<'t>(root: Node<'t>, mut f: impl FnMut(Node<'t>) -> bool) {
    let mut cursor = root.walk();
    loop {
        if f(cursor.node()) && cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Complexity {
    cyclomatic: u32,
    cognitive: u32,
    /// The increments that grow with nesting: branches, loops, switches,
    /// catches, ternaries.
    structures: u32,
}

/// Cyclomatic complexity plus an approximation of SonarSource's cognitive
/// complexity: +1 per branch/loop/catch/ternary (plus the nesting depth),
/// +1 per else/elif (Rust's `if` is an expression), +1 per run of the same boolean operator. Nested
/// functions are skipped; they are measured separately.
///
/// Iterative on purpose: syntax trees from untrusted input can be nested
/// arbitrarily deep, and recursion would overflow the stack and abort the
/// whole scan.
fn complexity(func: Node, syn: &Syntax, src: &[u8]) -> Complexity {
    complexity_with(func, syn, src, false)
}

/// `complexity`, or with `nested`, also the functions nested in `func`, each
/// one level deeper than where it is.
fn complexity_with(func: Node, syn: &Syntax, src: &[u8], nested: bool) -> Complexity {
    let mut w = ComplexityWalker {
        syn,
        src,
        c: Complexity {
            cyclomatic: 1,
            cognitive: 0,
            structures: 0,
        },
        stack: Vec::new(),
        nested,
    };
    w.children(func, 0, None);
    while let Some(step) = w.stack.pop() {
        match step {
            Step::Visit(node, nesting, parent_op) => w.visit(node, nesting, parent_op),
            Step::If(node, nesting, flat) => w.visit_if(node, nesting, flat),
            Step::Else(node, nesting) => w.visit_else(node, nesting),
        }
    }
    w.c
}

/// Pending work for the complexity walker. Visit order does not matter:
/// every step only adds to the totals.
enum Step<'s, 't> {
    /// With the parent's boolean operator, when the parent is one: carried
    /// down rather than asked for, as `parent()` searches from the root and
    /// asking it per node is quadratic in deeply nested code.
    Visit(Node<'t>, u32, Option<&'s str>),
    /// `flat` marks an else-if: it costs +1 without a nesting increment.
    If(Node<'t>, u32, bool),
    /// The alternative branch of an if, at the if's own nesting level.
    Else(Node<'t>, u32),
}

struct ComplexityWalker<'a, 't> {
    syn: &'a Syntax,
    src: &'a [u8],
    c: Complexity,
    stack: Vec<Step<'a, 't>>,
    /// Whether nested functions are walked too, one level deeper.
    nested: bool,
}

impl<'a, 't> ComplexityWalker<'a, 't> {
    /// Queues `node`'s named children; `op` is `node`'s boolean operator.
    fn children(&mut self, node: Node<'t>, nesting: u32, op: Option<&'a str>) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.stack.push(Step::Visit(child, nesting, op));
        }
    }

    fn visit(&mut self, node: Node<'t>, nesting: u32, parent_op: Option<&'a str>) {
        let kind = node.kind();
        // A class in a Python function starts again at no nesting, and its
        // methods add none (measured on SonarQube 26.7).
        if self.nested && self.syn.cognitive_includes_nested_functions && kind == "class_definition"
        {
            return self.children(node, 0, None);
        }
        if self.syn.functions.contains(&kind) {
            if self.nested {
                let deeper = !(self.syn.cognitive_includes_nested_functions
                    && (encloses_only_functions(node) || is_method(node)));
                self.children(node, nesting + u32::from(deeper), None);
            }
            return;
        }
        if self.syn.closures.contains(&kind) {
            // Part of the enclosing function, one level deeper.
            self.c.cyclomatic += 1;
            return self.children(node, nesting + 1, None);
        }
        if matches!(kind, "if_statement" | "if_expression") {
            return self.stack.push(Step::If(node, nesting, false));
        }
        // Python's `try: ... else:` costs 1 and nests its body, as an if's
        // else does (measured on SonarQube 26.7).
        if kind == "else_clause" && node.parent().is_some_and(|p| p.kind() == "try_statement") {
            self.c.cognitive += 1;
            return self.children(node, nesting + 1, None);
        }
        if self.syn.branches.contains(&kind) {
            self.c.cyclomatic += 1;
            self.c.cognitive += 1 + nesting;
            self.c.structures += 1;
            // Python's `for ... else` and `while ... else`: +1, as an if's else.
            if matches!(kind, "for_statement" | "while_statement")
                && node.child_by_field_name("alternative").is_some()
            {
                self.c.cognitive += 1;
            }
            return self.children(node, nesting + 1, None);
        }
        if self.syn.switches.contains(&kind) {
            self.c.cognitive += 1 + nesting;
            self.c.structures += 1;
            return self.children(node, nesting + 1, None);
        }
        if self.syn.cases.contains(&kind)
            && !is_default_case(
                node.utf8_text(self.src).unwrap_or(""),
                self.syn.wildcard_arm_is_default,
            )
        {
            self.c.cyclomatic += 1;
        }
        let op = logical_operator(node, self.src);
        if let Some(op) = op {
            self.c.cyclomatic += 1;
            if parent_op != Some(op) && !(op == "||" && self.syn.cognitive_skips_or) {
                self.c.cognitive += 1;
            }
        }
        self.children(node, nesting, op);
    }

    fn visit_if(&mut self, node: Node<'t>, nesting: u32, flat: bool) {
        self.c.cyclomatic += 1;
        self.c.cognitive += if flat { 1 } else { 1 + nesting };
        self.c.structures += u32::from(!flat);
        let mut cursor = node.walk();
        if !cursor.goto_first_child() {
            return;
        }
        loop {
            let child = cursor.node();
            if child.is_named() {
                let is_else = cursor.field_name() == Some("alternative")
                    || matches!(child.kind(), "else_clause" | "elif_clause");
                self.stack.push(if is_else {
                    Step::Else(child, nesting)
                } else {
                    Step::Visit(child, nesting + 1, None)
                });
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    fn visit_else(&mut self, node: Node<'t>, nesting: u32) {
        match node.kind() {
            // Java: `else if` is an if_statement directly in the alternative field.
            "if_statement" | "if_expression" => self.stack.push(Step::If(node, nesting, true)),
            "elif_clause" => {
                self.c.cyclomatic += 1;
                self.c.cognitive += 1;
                self.children(node, nesting + 1, None);
            }
            "else_clause" => match only_named_child(node) {
                Some(inner) if matches!(inner.kind(), "if_statement" | "if_expression") => {
                    self.stack.push(Step::If(inner, nesting, true))
                }
                // C and C++: `else { if ... }`, the if alone in its block, is
                // an else-if (as SonarCloud counts it).
                Some(block)
                    if block.kind() == "compound_statement"
                        && named_statements(block).len() == 1
                        && named_statements(block)[0].kind() == "if_statement" =>
                {
                    self.stack
                        .push(Step::If(named_statements(block)[0], nesting, true))
                }
                _ => {
                    self.c.cognitive += 1;
                    self.children(node, nesting + 1, None);
                }
            },
            _ => {
                self.c.cognitive += 1;
                self.stack.push(Step::Visit(node, nesting + 1, None));
            }
        }
    }
}

/// `default:`, or, where `wildcard` says so, C#'s discard arm `_ => ...` in a
/// switch expression.
fn is_default_case(text: &str, wildcard: bool) -> bool {
    text.starts_with("default")
        || (wildcard
            && text
                .strip_prefix('_')
                .is_some_and(|rest| rest.trim_start().starts_with("=>")))
}

/// A block's statements, comments left out.
fn named_statements(block: Node) -> Vec<Node> {
    let mut cursor = block.walk();
    block
        .named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect()
}

fn only_named_child(node: Node) -> Option<Node> {
    (node.named_child_count() == 1)
        .then(|| node.named_child(0))
        .flatten()
}

fn logical_operator<'s>(node: Node, src: &'s [u8]) -> Option<&'s str> {
    if !matches!(node.kind(), "binary_expression" | "boolean_operator") {
        return None;
    }
    let op = node.child_by_field_name("operator")?.utf8_text(src).ok()?;
    matches!(op, "&&" | "||" | "and" | "or").then_some(op)
}

/// The node naming a function: its `name` field, or the innermost
/// declarator for C/C++ function definitions.
fn name_node(node: Node) -> Option<Node> {
    if let Some(n) = node.child_by_field_name("name") {
        return Some(n);
    }
    let mut d = node.child_by_field_name("declarator")?;
    while let Some(inner) = d.child_by_field_name("declarator") {
        d = inner;
    }
    Some(d)
}

/// FNV-1a. Unlike `DefaultHasher`, whose algorithm may change between Rust
/// releases, this keeps duplication results identical across toolchains.
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Longest function name quoted in an issue message, in characters.
const MAX_NAME_CHARS: usize = 80;

/// The function's name for messages, truncated: a name comes from untrusted
/// source and could otherwise be arbitrarily long.
fn function_name(node: Node, ctx: &Ctx) -> String {
    let name = raw_function_name(node, ctx);
    match name.char_indices().nth(MAX_NAME_CHARS) {
        Some((cut, _)) => format!("{}…", &name[..cut]),
        None => name.to_string(),
    }
}

fn raw_function_name<'s>(node: Node, ctx: &Ctx<'s>) -> &'s str {
    if let Some(n) = name_node(node) {
        return ctx.text(n);
    }
    // Anonymous functions take the name of what they are assigned to.
    let named_by = node.parent().and_then(|p| match p.kind() {
        "variable_declarator" | "pair" | "public_field_definition" | "field_definition" => p
            .child_by_field_name("name")
            .or_else(|| p.child_by_field_name("key")),
        "assignment_expression" => p.child_by_field_name("left"),
        "let_declaration" => p.child_by_field_name("pattern"),
        _ => None,
    });
    named_by.map_or("<anonymous>", |n| ctx.text(n))
}

/// A C++ member function marked `override` or `final`: its parameters are
/// the base's (as SonarCloud counts them).
fn overrides(node: Node, src: &[u8]) -> bool {
    node.kind() == "function_definition"
        && node.child_by_field_name("declarator").is_some_and(|d| {
            let mut cursor = d.walk();
            d.named_children(&mut cursor).any(|c| {
                c.kind() == "virtual_specifier"
                    && c.utf8_text(src)
                        .is_ok_and(|t| matches!(t, "override" | "final"))
            })
        })
}

/// A C or C++ function SonarCloud doesn't score: a test macro's body
/// (`TEST(Suite, Name) { ... }`, no return type, a capitalized name) or an
/// old-style definition declaring its parameters after the parentheses.
fn macro_body_or_old_style(node: Node, src: &[u8]) -> bool {
    if node.kind() != "function_definition" {
        return false;
    }
    let macro_body = node.child_by_field_name("type").is_none()
        && node
            .child_by_field_name("declarator")
            .and_then(|d| d.child_by_field_name("declarator"))
            .and_then(|n| n.utf8_text(src).ok())
            .is_some_and(|n| {
                !n.is_empty()
                    && n.chars()
                        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
            });
    let mut cursor = node.walk();
    let old_style = node
        .named_children(&mut cursor)
        .any(|c| c.kind() == "declaration");
    macro_body || old_style
}

/// A C# constructor that calls `: base(...)`: its parameters are largely
/// its base class's to take (measured on SonarQube 26.7, which doesn't
/// count them against it).
fn calls_base_constructor(node: Node, src: &[u8]) -> bool {
    node.kind() == "constructor_declaration"
        && node.named_children(&mut node.walk()).any(|c| {
            c.kind() == "constructor_initializer"
                && c.utf8_text(src).is_ok_and(|t| {
                    t.trim_start_matches([':', ' ', '\n', '\r', '\t'])
                        .starts_with("base")
                })
        })
}

fn parameter_count(node: Node, syn: &Syntax, src: &[u8]) -> Option<usize> {
    if node.child_by_field_name("parameter").is_some() {
        return Some(1); // JS `x => ...`
    }
    let params = node.child_by_field_name("parameters").or_else(|| {
        // C/C++: the parameter list hangs off the (possibly nested) function declarator.
        let mut d = node.child_by_field_name("declarator")?;
        loop {
            if let Some(p) = d.child_by_field_name("parameters") {
                return Some(p);
            }
            d = d.child_by_field_name("declarator")?;
        }
    })?;
    if params.named_child_count() == 0 && params.child_count() == 0 {
        return Some(1); // Java lambda with a bare identifier parameter
    }
    let mut cursor = params.walk();
    let n = params
        .named_children(&mut cursor)
        .filter(|c| !syn.comments.contains(&c.kind()))
        .count();
    // A method's `self` or `cls` isn't one the caller passes.
    let receiver = params
        .named_child(0)
        .and_then(|p| p.utf8_text(src).ok())
        .is_some_and(|p| syn.receivers.contains(&p));
    Some(n - usize::from(receiver))
}

#[cfg(test)]
fn todo_tag(comment: &str) -> Option<&'static str> {
    todo_tag_at(comment).map(|(tag, _)| tag)
}

/// The task tag in a comment, and its byte offset in it.
fn todo_tag_at(comment: &str) -> Option<(&'static str, usize)> {
    // SonarQube knows TODO and FIXME only; XXX is a note, not a task.
    // The first one in the comment.
    ["TODO", "FIXME"]
        .into_iter()
        .filter_map(|tag| {
            comment.match_indices(tag).find_map(|(i, _)| {
                let before = comment[..i].chars().next_back();
                let after = comment[i + tag.len()..].chars().next();
                (!before.is_some_and(char::is_alphanumeric)
                    && !after.is_some_and(char::is_alphanumeric))
                .then_some((tag, i))
            })
        })
        .min_by_key(|(_, i)| *i)
}

/// What a line's suppression comment covers: `NOSONAR` or `sonda-ignore`
/// suppresses every issue on it; `sonda-ignore: rule-a, rule-b` only the
/// listed rules.
enum Suppression<'a> {
    Nothing,
    Everything,
    Rules(Vec<&'a str>),
}

impl<'a> Suppression<'a> {
    fn of(line: &'a str) -> Self {
        if line.contains("NOSONAR") {
            return Self::Everything;
        }
        let Some(pos) = line.find("sonda-ignore") else {
            return Self::Nothing;
        };
        let rest = line[pos + "sonda-ignore".len()..].trim_start();
        match rest.strip_prefix(':') {
            None => Self::Everything,
            Some(ids) => Self::Rules(
                ids.split([',', ' ', '\t'])
                    .map(|s| s.trim_end_matches("*/").trim())
                    .collect(),
            ),
        }
    }

    fn covers(&self, rule: &str) -> bool {
        match self {
            Self::Nothing => false,
            Self::Everything => true,
            Self::Rules(ids) => ids.contains(&rule),
        }
    }
}

/// A region of a C# file where `#pragma warning disable` or a
/// `[SuppressMessage]` attribute silences a
/// SonarQube key, or every warning when `key` is None: lines `start` to
/// `end`, both included.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SuppressedRegion {
    key: Option<String>,
    start: usize,
    end: usize,
}

impl SuppressedRegion {
    pub(crate) fn new(key: Option<String>, start: usize, end: usize) -> Self {
        Self { key, start, end }
    }

    #[cfg(test)]
    pub(crate) fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn start(&self) -> usize {
        self.start
    }

    #[cfg(test)]
    pub(crate) fn end(&self) -> usize {
        self.end
    }
}

/// The fact kind a C# file's suppressed regions travel under, for issues the
/// project pass adds.
const SUPPRESSION_FACT: &str = "cs-suppressions";

/// The `#pragma warning disable`/`restore` regions of a C# file, as Roslyn
/// applies them: from the line after `disable` to the line before the
/// matching `restore`, or to the end of the file. Without a list, `disable`
/// silences every warning and `restore` ends every region.
pub(crate) fn pragma_regions(src: &str) -> Vec<SuppressedRegion> {
    let mut open: Vec<(Option<String>, usize)> = Vec::new();
    let mut regions = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let mut words = rest.split_whitespace();
        if words.next() != Some("pragma") || words.next() != Some("warning") {
            continue;
        }
        let action = words.next();
        let rest = rest.split("//").next().unwrap_or_default();
        let codes: Vec<String> = rest
            .split_whitespace()
            .skip(3)
            .collect::<Vec<_>>()
            .join(" ")
            .split(',')
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
            .collect();
        let line_no = i + 1;
        match action {
            Some("disable") if codes.is_empty() => open.push((None, line_no + 1)),
            Some("disable") => {
                for code in codes {
                    if !open
                        .iter()
                        .any(|(k, _)| k.as_deref() == Some(code.as_str()))
                    {
                        open.push((Some(code), line_no + 1));
                    }
                }
            }
            Some("restore") => {
                let (closed, still): (Vec<_>, Vec<_>) = open.into_iter().partition(|(k, _)| {
                    codes.is_empty() || k.as_ref().is_some_and(|k| codes.contains(k))
                });
                open = still;
                regions.extend(closed.into_iter().map(|(key, start)| SuppressedRegion {
                    key,
                    start,
                    end: line_no - 1,
                }));
            }
            _ => {}
        }
    }
    regions.extend(open.into_iter().map(|(key, start)| SuppressedRegion {
        key,
        start,
        end: usize::MAX,
    }));
    regions
}

/// An attribute's arguments: (name, value) for each, the name of `checkId:`
/// or `Target =`, none for a positional one. Values lose their quotes.
fn attribute_arguments<'s>(attribute: Node, src: &'s str) -> Vec<(Option<&'s str>, &'s str)> {
    let Some(args) = attribute
        .named_children(&mut attribute.walk())
        .find(|c| c.kind() == "attribute_argument_list")
    else {
        return Vec::new();
    };
    args.named_children(&mut args.walk())
        .filter(|a| a.kind() == "attribute_argument" && a.named_child_count() > 0)
        .filter_map(|a| {
            let value = a.named_child(a.named_child_count() as u32 - 1)?;
            let value = src[value.byte_range()].trim_matches(|c| c == '"' || c == '@');
            let name = (a.named_child_count() > 1)
                .then(|| src[a.byte_range()].split([':', '=']).next())
                .flatten()
                .map(str::trim)
                .filter(|n| n.chars().all(|c| c.is_alphanumeric() || c == '_'));
            Some((name, value))
        })
        .collect()
}

/// The SonarQube key a `[SuppressMessage(category, checkId)]` names: its
/// check id up to the colon (`"S2190:Recursion should..."`).
fn suppressed_key(attribute: Node, src: &str) -> Option<String> {
    let args = attribute_arguments(attribute, src);
    let id = args
        .iter()
        .find(|(name, _)| *name == Some("checkId"))
        .or_else(|| args.iter().filter(|(name, _)| name.is_none()).nth(1))?
        .1;
    let key = id.split(':').next()?.trim();
    (!key.is_empty()).then(|| key.to_string())
}

/// A named argument of an attribute: the value of `Target = "~M:..."`.
fn named_argument(attribute: Node, name: &str, src: &str) -> Option<String> {
    attribute_arguments(attribute, src)
        .into_iter()
        .find(|(n, _)| *n == Some(name))
        .map(|(_, value)| value.to_string())
}

fn is_suppress_message(attribute: Node, src: &str) -> bool {
    attribute.child_by_field_name("name").is_some_and(|n| {
        let name = src[n.byte_range()].rsplit('.').next().unwrap_or_default();
        let name = name.strip_suffix("Attribute").unwrap_or(name);
        matches!(name, "SuppressMessage" | "UnconditionalSuppressMessage")
    })
}

/// Pragma regions, and the declarations a `[SuppressMessage]` attribute on
/// them silences, over their whole extent.
pub(crate) fn suppressed_regions(src: &str, root: Node) -> Vec<SuppressedRegion> {
    let mut regions = pragma_regions(src);
    if !src.contains("SuppressMessage") {
        return regions;
    }
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.kind() == "attribute_list" {
            // On a declaration; `[assembly: ...]` ones are global attributes.
            if let Some(target) = n.parent().filter(|p| p.kind() != "global_attribute") {
                push_suppressions(n, target, src, &mut regions);
            }
            continue;
        }
        // Attributes sit on declarations, not in method bodies.
        if matches!(n.kind(), "block" | "arrow_expression_clause") {
            continue;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    regions
}

/// The regions the `[SuppressMessage]`s of `list` silence: all of `target`.
fn push_suppressions(list: Node, target: Node, src: &str, regions: &mut Vec<SuppressedRegion>) {
    let mut c = list.walk();
    for a in list
        .named_children(&mut c)
        .filter(|a| a.kind() == "attribute" && is_suppress_message(*a, src))
    {
        if let Some(key) = suppressed_key(a, src) {
            regions.push(SuppressedRegion {
                key: Some(key),
                start: target.start_position().row + 1,
                end: target.end_position().row + 1,
            });
        }
    }
}

/// An assembly-level `[SuppressMessage]`: its key, and the scope and target
/// the project pass resolves against the project's declarations.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct GlobalSuppression {
    pub(crate) key: String,
    pub(crate) scope: String,
    pub(crate) target: String,
}

/// The fact kind a file's assembly-level suppressions travel under.
const GLOBAL_SUPPRESSION_FACT: &str = "cs-global-suppressions";

fn global_suppressions(src: &str, root: Node) -> Vec<GlobalSuppression> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    for global in root
        .named_children(&mut cursor)
        .filter(|g| g.kind() == "global_attribute")
    {
        let mut c = global.walk();
        for a in global
            .named_children(&mut c)
            .filter(|a| a.kind() == "attribute" && is_suppress_message(*a, src))
        {
            if let Some(key) = suppressed_key(a, src) {
                out.push(GlobalSuppression {
                    key,
                    scope: named_argument(a, "Scope", src)
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                    target: named_argument(a, "Target", src).unwrap_or_default(),
                });
            }
        }
    }
    out
}

/// Whether a suppressed region silences `rule` on `line`: every rule, or the
/// rules that reference the SonarQube key it names, exactly or not.
fn silenced_in(regions: &[SuppressedRegion], line: usize, rule: &str) -> bool {
    if regions.is_empty() {
        return false;
    }
    let keys: Vec<&str> = rules::find(rule)
        .map(|r| r.sonar.iter().map(|s| s.key).collect())
        .unwrap_or_default();
    regions.iter().any(|r| {
        line >= r.start && line <= r.end && r.key.as_deref().is_none_or(|k| keys.contains(&k))
    })
}

#[cfg(test)]
fn is_suppressed(line: &str, rule: &str) -> bool {
    Suppression::of(line).covers(rule)
}

struct LineIndex<'a> {
    src: &'a str,
    starts: Vec<usize>,
    /// An ASCII file has one byte per character: columns need no counting,
    /// which keeps a file of one very long line from costing a scan per issue.
    ascii: bool,
}

impl<'a> LineIndex<'a> {
    fn new(src: &'a str) -> Self {
        let starts = std::iter::once(0)
            .chain(src.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        LineIndex {
            src,
            starts,
            ascii: src.is_ascii(),
        }
    }

    fn count(&self) -> usize {
        // A trailing newline does not start another line.
        if self.src.ends_with('\n') {
            self.starts.len() - 1
        } else {
            self.starts.len()
        }
    }

    fn text(&self, row: usize) -> &'a str {
        let Some(&start) = self.starts.get(row) else {
            return "";
        };
        let end = self.starts.get(row + 1).map_or(self.src.len(), |&e| e - 1);
        &self.src[start..end.max(start)]
    }

    /// Converts a tree-sitter byte column to a 1-based character column.
    fn char_column(&self, row: usize, byte_col: usize) -> usize {
        if self.ascii {
            return byte_col + 1;
        }
        let line = self.text(row);
        let cut = byte_col.min(line.len());
        line.get(..cut).map_or(cut, |s| s.chars().count()) + 1
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::LazyLock;

    fn run(lang: Lang, src: &str) -> FileAnalysis {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        analyze("t", lang, src, &rules, &cfg, far_deadline()).unwrap()
    }

    pub(crate) fn far_deadline() -> Instant {
        Instant::now() + std::time::Duration::from_secs(60)
    }

    /// `rule`'s findings over files given as (path, source), analyzed as
    /// `lang` and then by the project `pass`, as (path, line), sorted.
    pub(crate) fn project_flagged(
        rule: &str,
        lang: Lang,
        files: &[(&str, &str)],
        pass: fn(&mut [FileAnalysis], &RuleSet),
    ) -> Vec<(String, usize)> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<FileAnalysis> = files
            .iter()
            .map(|(path, src)| analyze(path, lang, src, &rules, &cfg, far_deadline()).unwrap())
            .collect();
        pass(&mut analyzed, &rules);
        let mut found: Vec<(String, usize)> = analyzed
            .iter()
            .flat_map(|f| {
                f.issues
                    .iter()
                    .filter(|i| i.rule == rule)
                    .map(|i| (f.path.clone(), i.line))
            })
            .collect();
        found.sort();
        found
    }

    /// A finding's (path, line), as `project_flagged` lists them.
    pub(crate) fn at(path: &str, line: usize) -> (String, usize) {
        (path.to_string(), line)
    }

    fn rules_hit(a: &FileAnalysis) -> Vec<&str> {
        a.issues.iter().map(|i| i.rule).collect()
    }

    /// Regression: the recursive complexity walker overflowed the stack on
    /// deeply nested input, aborting the whole process (test threads have
    /// small stacks, so this fails loudly if recursion comes back).
    #[test]
    fn deeply_nested_code_does_not_overflow_the_stack() {
        let n = 100_000;
        let parens = format!(
            "function f() {{ return {}x{}; }}\n",
            "(".repeat(n),
            ")".repeat(n)
        );
        assert_eq!(run(Lang::JavaScript, &parens).metrics.functions, 1);

        let depth = 20_000;
        let ifs = format!(
            "function g() {{ {}{} }}\n",
            "if (a) { ".repeat(depth),
            "}".repeat(depth)
        );
        let a = run(Lang::JavaScript, &ifs);
        assert_eq!(a.metrics.complexity, depth as u32 + 1);
    }

    /// Regression: js/unused-assignment asked every reference for its
    /// ancestors, and `parent()` searches down from the root, so a local
    /// used at every level of deep nesting cost the cube of the depth.
    #[test]
    fn locals_used_in_deeply_nested_code_stay_cheap() {
        let depth = 5_000;
        // `a` is read at the end, so no assignment to it is dead.
        let src = format!(
            "function g(items) {{\nlet a = f();\nconst hit = items.find(f);\n{}{}return a;\n}}\n",
            "if (a && hit) {\na = 2;\n".repeat(depth),
            "}\n".repeat(depth)
        );
        let a = run(Lang::JavaScript, &src);
        assert_eq!(a.metrics.functions, 1);
        assert!(!rules_hit(&a).contains(&"js/unused-assignment"));
    }

    /// Regression: resolving a name climbed the scope chain once per
    /// reference, and complexity asked each `&&` for its parent, so both grew
    /// with the square of the depth. At 20,000 levels the file ran past 15
    /// seconds and was skipped; it now takes about one in a debug build.
    #[test]
    fn deep_nesting_resolves_names_and_measures_complexity_in_time() {
        let depth = 20_000;
        let src = format!(
            "function g(items) {{\nlet a = f();\nconst hit = items.find(f);\n{}{}}}\n",
            "if (a && hit) {\na = 2;\n".repeat(depth),
            "}\n".repeat(depth)
        );
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(20);
        let a = analyze("t", Lang::JavaScript, &src, &rules, &cfg, deadline).unwrap();
        assert!(!a.semantic_incomplete);
        // An `if` and an `&&` per level.
        assert_eq!(a.metrics.complexity, 2 * depth as u32 + 1);
    }

    #[test]
    fn analysis_stops_at_the_deadline() {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let src = "let x = 1;\n".repeat(50_000);
        let err = analyze("t", Lang::JavaScript, &src, &rules, &cfg, Instant::now()).err();
        assert!(err.is_some_and(|e| e.to_string().contains("timeout")));
    }

    #[test]
    fn fnv1a_matches_reference_vectors() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn test_files_are_recognized() {
        for path in [
            "src/a.test.ts",
            "src/a.spec.js",
            "test/helpers.js",
            "pkg/__tests__/x.tsx",
            "tests/test_api.py",
            "app/test_api.py",
            "src/test/java/AppTest.java",
            "x/handler_test.go",
        ] {
            assert!(is_test_file(path), "{path}");
        }
        for path in [
            "src/latest.js",
            "src/contest/a.ts",
            "testing.py",
            "src/attest.js",
        ] {
            assert!(!is_test_file(path), "{path}");
        }
        // Vulnerability rules skip them; others don't.
        let src = "const db = connect({ password: 'hunter2' });\nvar x = 1;";
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let rules_in = |path| {
            analyze(path, Lang::JavaScript, src, &rules, &cfg, far_deadline())
                .unwrap()
                .issues
                .iter()
                .map(|i| i.rule)
                .collect::<Vec<_>>()
        };
        assert!(rules_in("src/db.js").contains(&"js/hardcoded-password"));
        assert_eq!(
            rules_in("src/db.test.js"),
            ["js/test-file-without-tests", "js/no-var"]
        );
    }

    #[test]
    fn long_function_names_are_truncated_in_messages() {
        let name = "x".repeat(500);
        let params = (0..8)
            .map(|i| format!("p{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let a = run(
            Lang::JavaScript,
            &format!("function {name}({params}) {{}}\n"),
        );
        let issue = a
            .issues
            .iter()
            .find(|i| i.rule == rules::TOO_MANY_PARAMETERS);
        let msg = &issue.expect("too many parameters").message;
        assert!(
            msg.contains(&format!("'{}…'", "x".repeat(MAX_NAME_CHARS))),
            "{msg}"
        );
    }

    /// Regression (found by the fuzz property): an unterminated string at the
    /// end of a file counted a code line past the last line.
    #[test]
    fn tokens_ending_in_a_newline_do_not_add_a_line() {
        let a = run(Lang::Java, "class A { String s = \"abc\n");
        assert_eq!(a.metrics.lines, 1);
        assert_eq!(a.code_lines, vec![1]);
    }

    #[test]
    fn counts_code_and_comment_lines() {
        let a = run(
            Lang::JavaScript,
            "// header\n\nconst a = 1; // trailing\nconst b = `x\ny`;\n",
        );
        assert_eq!(a.metrics.lines, 5);
        assert_eq!(a.metrics.ncloc, 3);
        assert_eq!(a.code_lines, vec![3, 4, 5]);
        assert_eq!(a.metrics.comment_lines, 2);
    }

    /// SonarQube 26.7's JavaScript and TypeScript analyzer counts `&&` and
    /// not `||`, measured file by file (docs/sonar-parity/differences.md);
    /// Python's `or` and Java's `||` count as the specification says.
    #[test]
    fn javascript_cognitive_complexity_leaves_or_out() {
        let cognitive = |lang, src| run(lang, src).metrics.cognitive_complexity;
        let js = Lang::JavaScript;
        assert_eq!(
            cognitive(js, "function f(a, b) { if (a || b) { g(); } }"),
            1
        );
        assert_eq!(
            cognitive(js, "function f(a, b) { if (a && b) { g(); } }"),
            2
        );
        assert_eq!(
            cognitive(js, "function f(a, b, d) { return (a && b) || (!a && d); }"),
            2
        );
        assert_eq!(
            cognitive(js, "function f(a, b, c) { if (a || b && c) { g(); } }"),
            2
        );
        assert_eq!(
            cognitive(
                Lang::TypeScript,
                "function f(a: any, b: any) { return a || b; }"
            ),
            0
        );
        assert_eq!(
            cognitive(Lang::Python, "def f(a, b):\n    if a or b:\n        g()\n"),
            2
        );
        let java = "class J { void f(boolean a, boolean b) { if (a || b) { g(); } } void g() {} }";
        assert_eq!(cognitive(Lang::Java, java), 2);
    }

    /// The file's measure counts a callback one level deeper, unless the
    /// function around it has no structure of its own; each function's own
    /// score, which the rule checks, stays flat. Each case is SonarQube
    /// 26.7's measure of the same code.
    #[test]
    fn javascript_file_cognitive_complexity_nests_callbacks() {
        let cognitive = |src| run(Lang::JavaScript, src).metrics.cognitive_complexity;
        // A wrapper: the callback counts as if on its own.
        assert_eq!(
            cognitive("function f(xs) { return xs.map((x) => (x ? 1 : 2)); }"),
            1
        );
        assert_eq!(
            cognitive(
                "function f(a, b, xs) { const z = a && b; return xs.map((x) => (x ? z : 2)); }"
            ),
            2
        );
        // Not a wrapper: one level deeper, and another per callback inside.
        assert_eq!(
            cognitive("function f(a, xs) { if (a) { g(); } return xs.map((x) => (x ? 1 : 2)); }"),
            3
        );
        assert_eq!(
            cognitive(
                "function f(a, xs) { if (a) { g(); } return xs.map((x) => x.ys.map((y) => (y ? 1 : 2))); }"
            ),
            4
        );
        assert_eq!(
            cognitive("function f(xs) { for (const x of xs) { x.ys.map((y) => (y ? 1 : 2)); } }"),
            4
        );
        // Only the outermost wrapper is left out.
        assert_eq!(
            cognitive("function f(xs) { return xs.map((x) => xs.filter((y) => (y ? 1 : 2))); }"),
            2
        );
        assert_eq!(
            cognitive(
                "class A { m(a, xs) { if (a) { g(); } return xs.map((x) => (x ? 1 : 2)); } }"
            ),
            3
        );

        // The rule scores each function flat: 1 + 8 here, not 17.
        let mut src =
            String::from("function outer(a, xs) {\n  if (a) { g(); }\n  return xs.map((x) => {\n");
        for i in 0..8 {
            src += &format!("    if (x.k{i}) {{ g(); }}\n");
        }
        src += "    return x;\n  });\n}\n";
        let a = run(Lang::JavaScript, &src);
        assert_eq!(a.metrics.cognitive_complexity, 17);
        assert!(
            !a.issues
                .iter()
                .any(|i| i.rule == crate::rules::COGNITIVE_COMPLEXITY)
        );
    }

    /// SonarQube 26.7's Python analyzer, measured file by file: a nested
    /// function is part of the one around it, one level deeper unless that
    /// one only wraps it; a loop's else costs 1; match costs nothing.
    #[test]
    fn python_cognitive_complexity_includes_nested_functions() {
        let cognitive = |src| run(Lang::Python, src).metrics.cognitive_complexity;
        let nested = "def outer(a, xs):\n    if a:\n        return 0\n    def inner(x):\n        if x:\n            return 1\n        return 0\n    return [inner(x) for x in xs]\n";
        assert_eq!(cognitive(nested), 3);
        let wrapper = "def outer(g):\n    def inner(x):\n        if x:\n            return 1\n        return 0\n    return inner\n";
        assert_eq!(cognitive(wrapper), 1);
        let in_loop = "def outer(xs):\n    for x in xs:\n        def inner(y):\n            if y:\n                return 1\n            return 0\n        inner(x)\n";
        assert_eq!(cognitive(in_loop), 4);
        let two = "def outer(a):\n    if a:\n        return 0\n    def mid():\n        def inner(x):\n            if x:\n                return 1\n            return 0\n        return inner\n    return mid\n";
        assert_eq!(cognitive(two), 3);
        assert_eq!(
            cognitive(
                "def f(a):\n    while a:\n        a -= 1\n    else:\n        return 1\n    return 0\n"
            ),
            2
        );
        assert_eq!(
            cognitive(
                "def f(a):\n    match a:\n        case 1:\n            return 1\n        case _:\n            return 0\n"
            ),
            0
        );

        // The rule reports the outermost function, with its nested ones: 1 +
        // 8 * 2 here, and not the nested function on its own.
        let mut src = String::from("def outer(g, a):\n    if a:\n        g()\n    def inner(x):\n");
        for i in 0..8 {
            src += &format!("        if x.k{i}:\n            g()\n");
        }
        src += "    return inner\n";
        let a = run(Lang::Python, &src);
        let lines: Vec<usize> = a
            .issues
            .iter()
            .filter(|i| i.rule == crate::rules::COGNITIVE_COMPLEXITY)
            .map(|i| i.line)
            .collect();
        assert_eq!(lines, [1]);
        assert_eq!(a.metrics.cognitive_complexity, 17);
    }

    /// More of SonarQube 26.7's Python cognitive complexity: a try's else
    /// costs 1 and nests; code outside functions counts for the file; a
    /// class in a function restarts at no nesting and stays part of the
    /// function; only a function defining one function and returning it is
    /// a wrapper.
    #[test]
    fn python_cognitive_complexity_round_two() {
        let cognitive = |src| run(Lang::Python, src).metrics.cognitive_complexity;
        assert_eq!(
            cognitive(
                "def f(g, a):\n    try:\n        g()\n    except OSError:\n        return 1\n    else:\n        if a:\n            return 2\n    return 0\n"
            ),
            4
        );
        assert_eq!(
            cognitive(
                "if __name__ == '__main__':\n    try:\n        main()\n    except OSError:\n        pass\n"
            ),
            3
        );
        assert_eq!(
            cognitive(
                "def outer(a):\n    if a:\n        return 0\n    class C:\n        def m(self, x):\n            if x:\n                return 1\n            return 0\n    return C\n"
            ),
            2
        );
        let two = "def outer():\n    def a(x):\n        if x:\n            return 1\n    def b(x):\n        if x:\n            return 1\n    return a\n";
        assert_eq!(cognitive(two), 4);
    }

    /// Python allows 13 parameters, as SonarQube does, not counting `self`;
    /// JavaScript 7. An explicit threshold applies to every language.
    #[test]
    fn parameter_limits_per_language() {
        let params = |n: usize| {
            (0..n)
                .map(|i| format!("a{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let count = |lang, src: &str| {
            run(lang, src)
                .issues
                .iter()
                .filter(|i| i.rule == crate::rules::TOO_MANY_PARAMETERS)
                .count()
        };
        assert_eq!(
            count(Lang::Python, &format!("def f({}):\n    pass\n", params(13))),
            0
        );
        assert_eq!(
            count(Lang::Python, &format!("def f({}):\n    pass\n", params(14))),
            1
        );
        let method = format!("class C:\n    def f(self, {}):\n        pass\n", params(13));
        assert_eq!(count(Lang::Python, &method), 0);
        assert_eq!(
            count(Lang::JavaScript, &format!("function f({}) {{}}", params(8))),
            1
        );
    }

    /// A package's `__init__.py` gathers names with `from .mod import *`.
    #[test]
    fn wildcard_imports_are_fine_in_a_package_init() {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let wildcard = |path| {
            analyze(
                path,
                Lang::Python,
                "from .mod import *\n",
                &rules,
                &cfg,
                far_deadline(),
            )
            .unwrap()
            .issues
            .iter()
            .filter(|i| i.rule == "py/wildcard-import")
            .count()
        };
        assert_eq!(wildcard("pkg/__init__.py"), 0);
        assert_eq!(wildcard("pkg/mod.py"), 1);
    }

    /// A rule whose suggestion needs a newer Java is skipped on older code;
    /// with the version unknown, it runs.
    #[test]
    fn java_rules_follow_the_target_version() {
        let src = "class A {\n    /** @deprecated use B. */\n    @Deprecated\n    void f() {}\n}\n";
        let count = |version: Option<u32>| {
            let mut cfg = Config::default();
            cfg.java.version = version;
            let rules = RuleSet::new(&cfg.rules).unwrap();
            analyze("A.java", Lang::Java, src, &rules, &cfg, far_deadline())
                .unwrap()
                .issues
                .iter()
                .filter(|i| i.rule == "java/deprecated-without-reason")
                .count()
        };
        assert_eq!(count(Some(8)), 0);
        assert_eq!(count(Some(17)), 1);
        assert_eq!(count(None), 1);
    }

    /// Rules SonarQube runs only from a Java version, by key: `Math.clamp`
    /// needs 21 (S6885, tagged `java21` on SonarQube 26.7).
    #[test]
    fn java_rules_follow_their_keys_version() {
        let src = "class A {\n    int f(int v) {\n        return Math.min(Math.max(v, 0), 10);\n    }\n}\n";
        let count = |version: Option<u32>| {
            let mut cfg = Config::default();
            cfg.java.version = version;
            let rules = RuleSet::new(&cfg.rules).unwrap();
            analyze("A.java", Lang::Java, src, &rules, &cfg, far_deadline())
                .unwrap()
                .issues
                .iter()
                .filter(|i| i.rule == "java/clamp")
                .count()
        };
        assert_eq!(count(Some(17)), 0);
        assert_eq!(count(Some(21)), 1);
    }

    /// `@SuppressWarnings("unused")` silences unused locals, as SonarQube
    /// 26.7 does; a method's covers its body.
    #[test]
    fn suppress_unused_covers_unused_code() {
        let src = "class A {\n    @SuppressWarnings({\"rawtypes\", \"unused\"})\n    void f() {\n        int a = 1;\n    }\n\n    void g() {\n        int b = 1;\n    }\n}\n";
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let a = analyze("A.java", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        let lines: Vec<usize> = a
            .issues
            .iter()
            .filter(|i| i.rule == "java/unused-local-variable")
            .map(|i| i.line)
            .collect();
        assert_eq!(lines, [8]);
    }

    /// A TODO in a block comment is reported on its own line.
    #[test]
    fn todo_on_its_line() {
        let a = run(
            Lang::Java,
            "class A {\n    /**\n     * Gets it.\n     * TODO Make private in 4.0.\n     */\n    void f() {}\n}\n",
        );
        let lines: Vec<usize> = a
            .issues
            .iter()
            .filter(|i| i.rule == rules::TODO_COMMENT)
            .map(|i| i.line)
            .collect();
        assert_eq!(lines, [4]);
    }

    #[test]
    fn todo_comments_are_todo_and_fixme() {
        assert_eq!(todo_tag("# TODO: later"), Some("TODO"));
        assert_eq!(todo_tag("// FIXME"), Some("FIXME"));
        assert_eq!(todo_tag("# XXX handle this later"), None);
    }

    #[test]
    fn cognitive_complexity_follows_nesting() {
        let src = "function f(a, b) {\n\
                   if (a) {\n\
                     for (const x of b) {\n\
                       if (x && a && b) { g(); }\n\
                     }\n\
                   } else if (b) {\n\
                     g();\n\
                   } else {\n\
                     h();\n\
                   }\n\
                 }\n";
        let a = run(Lang::JavaScript, src);
        // if +1, for +2 (nesting 1), inner if +3 (nesting 2), && run +1,
        // else-if +1, else +1  => 9
        assert_eq!(a.metrics.cognitive_complexity, 9);
        // 1 + if + for + if + && + && + else-if = 7
        assert_eq!(a.metrics.complexity, 7);
    }

    #[test]
    fn python_elif_and_boolean_operators() {
        let src = "def f(a, b):\n    if a and b or a:\n        pass\n    elif b:\n        pass\n    else:\n        pass\n";
        let a = run(Lang::Python, src);
        // if +1, `and` +1, `or` +1, elif +1, else +1
        assert_eq!(a.metrics.cognitive_complexity, 5);
    }

    #[test]
    fn java_else_if_is_flat() {
        let src = "class A { int f(int a) { if (a > 1) { return 1; } else if (a > 0) { return 2; } else { return 3; } } }";
        let a = run(Lang::Java, src);
        assert_eq!(a.metrics.cognitive_complexity, 3);
        assert_eq!(a.metrics.functions, 1);
    }

    #[test]
    fn csharp_functions_and_complexity() {
        let src = "class A {\n  int F(int a, bool b) {\n    if (a > 1 && b) { return 1; } else if (a > 0) { return 2; }\n    foreach (var x in xs) { }\n    return a switch { 1 => 1, 2 => 2, _ => 0 };\n  }\n  int P { get { return 1; } }\n}\n";
        let a = run(Lang::CSharp, src);
        assert_eq!(a.metrics.functions, 2);
        // F: 1 + if + && + else-if + foreach + two non-discard arms; the getter: 1
        assert_eq!(a.metrics.complexity, 7 + 1);
        // if +1, && +1, else-if +1, foreach +1, switch expression +1
        assert_eq!(a.metrics.cognitive_complexity, 5);
    }

    #[test]
    fn csharp_parameters() {
        let src =
            "class A { void F(int a, int b, int c, int d, int e, int f, int g, int h) { } }\n";
        let a = run(Lang::CSharp, src);
        let hit = rules_hit(&a);
        assert!(hit.contains(&rules::TOO_MANY_PARAMETERS), "{hit:?}");
    }

    #[test]
    fn rust_functions_and_complexity() {
        let src = "fn f(a: i32, b: bool) -> i32 {\n    if a > 1 && b { return 1; } else if a > 0 { return 2; }\n    for x in xs { }\n    loop { break; }\n    match a { 1 => 1, 2 => 2, _ => 0 }\n}\nimpl A { fn g(&self) { } }\n";
        let a = run(Lang::Rust, src);
        assert_eq!(a.metrics.functions, 2);
        // f: 1 + if + && + else-if + for + three arms (the wildcard counts, as SonarQube counts it); g: 1
        assert_eq!(a.metrics.complexity, 8 + 1);
        // if +1, && +1, else-if +1, for +1, loop +1, match +1; a `loop` has no
        // condition, so it adds nothing to the cyclomatic count
        assert_eq!(a.metrics.cognitive_complexity, 6);
    }

    #[test]
    fn rust_closures_belong_to_their_function_one_level_deeper() {
        let src = "fn main() {\n    let h = |x: bool| { if x { 1 } else { 2 } };\n}\n";
        let a = run(Lang::Rust, src);
        assert_eq!(a.metrics.functions, 1);
        // main 1 + the closure + the if
        assert_eq!(a.metrics.complexity, 3);
        // the if is nested once by the closure (+2), and its else +1
        assert_eq!(a.metrics.cognitive_complexity, 3);
    }

    #[test]
    fn rust_skips_the_common_rules_sonarqube_has_no_rust_key_for() {
        let long = "    g();\n".repeat(85);
        let src = format!(
            "// TODO: split this\nfn f(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) {{\n{long}}}\n"
        );
        let a = run(Lang::Rust, &src);
        let hit = rules_hit(&a);
        assert!(hit.contains(&rules::TOO_MANY_PARAMETERS), "{hit:?}");
        assert!(!hit.contains(&rules::FUNCTION_LENGTH), "{hit:?}");
        assert!(!hit.contains(&rules::TODO_COMMENT), "{hit:?}");
        // Another language still gets them.
        let js = format!("// TODO: split this\nfunction f() {{\n{long}}}\n");
        let a = run(Lang::JavaScript, &js);
        let hit = rules_hit(&a);
        assert!(hit.contains(&rules::FUNCTION_LENGTH), "{hit:?}");
        assert!(hit.contains(&rules::TODO_COMMENT), "{hit:?}");
    }

    #[test]
    fn rust_parameters_and_closure_names() {
        let src = "fn f(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) { }\nfn main() { let add = |x, y| x + y; }\n";
        let a = run(Lang::Rust, src);
        let hit = rules_hit(&a);
        assert!(hit.contains(&rules::TOO_MANY_PARAMETERS), "{hit:?}");
        // A closure adds to complexity but isn't a function: f 1, main 1, the closure 1.
        assert_eq!(a.metrics.functions, 2);
        assert_eq!(a.metrics.complexity, 3);
    }

    #[test]
    fn flags_complex_long_and_wide_functions() {
        let nested = "if (a) { ".repeat(6) + &"}".repeat(6);
        let body = "  g();\n".repeat(85);
        let src = format!("function busy(a, b, c, d, e, f, g, h) {{\n{nested}\n{body}}}\n");
        let a = run(Lang::JavaScript, &src);
        let hit = rules_hit(&a);
        assert!(hit.contains(&rules::COGNITIVE_COMPLEXITY), "{hit:?}");
        assert!(hit.contains(&rules::FUNCTION_LENGTH));
        assert!(hit.contains(&rules::TOO_MANY_PARAMETERS));
        assert!(a.issues[0].message.contains("'busy'"));
    }

    #[test]
    fn counts_c_parameters_through_declarators() {
        let src =
            "static int *f(int a, int b, int c, int d, int e, int f, int g, int h) { return 0; }\n";
        let a = run(Lang::C, src);
        let issue = a
            .issues
            .iter()
            .find(|i| i.rule == rules::TOO_MANY_PARAMETERS)
            .unwrap();
        assert!(
            issue.message.starts_with("'f' has 8 parameters"),
            "{}",
            issue.message
        );
    }

    #[test]
    fn line_rules() {
        let mut cfg = Config::default();
        cfg.rules.enabled = [
            rules::TRAILING_WHITESPACE,
            rules::LINE_LENGTH,
            rules::FILE_LENGTH,
            rules::FINAL_NEWLINE,
        ]
        .map(String::from)
        .to_vec();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let long = "x".repeat(130);
        let src = format!("a = 1  \nb = 2\n{long}\nc = 3");
        let a = analyze("t", Lang::Python, &src, &rules, &cfg, far_deadline()).unwrap();
        let hit = |rule: &str| -> Vec<usize> {
            a.issues
                .iter()
                .filter(|i| i.rule == rule)
                .map(|i| i.line)
                .collect()
        };
        assert_eq!(hit(rules::TRAILING_WHITESPACE), [1]);
        assert_eq!(hit(rules::LINE_LENGTH), [3]);
        assert_eq!(hit(rules::FINAL_NEWLINE), [4]);
    }

    #[test]
    fn python_rules_that_need_the_path_or_a_parse_error() {
        let ids = [rules::PY_MODULE_NAME, rules::PY_PARSE_FAILURE];
        let mut cfg = Config::default();
        cfg.rules.enabled = ids.map(String::from).to_vec();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let hits = |path: &str, src: &str| -> Vec<&'static str> {
            analyze(path, Lang::Python, src, &rules, &cfg, far_deadline())
                .unwrap()
                .issues
                .iter()
                .map(|i| i.rule)
                .filter(|r| ids.contains(r))
                .collect()
        };
        assert!(hits("pkg/good_name.py", "x = 1\n").is_empty());
        assert!(hits("pkg/__init__.py", "x = 1\n").is_empty());
        assert!(hits("pkg/test_thing.py", "x = 1\n").is_empty());
        assert_eq!(hits("pkg/BadName.py", "x = 1\n"), [rules::PY_MODULE_NAME]);
        assert_eq!(hits("a.py", "x = (\n"), [rules::PY_PARSE_FAILURE]);
    }

    #[test]
    fn python_3_13_and_3_15_syntax_parses() {
        // A lazy import (3.15) and a type parameter default (3.13), which the
        // grammar doesn't know yet: no syntax error, `lazy` isn't a name, and
        // the lazily imported sink is still resolved.
        let src = "lazy from subprocess import run\n\
            from flask import request\n\
            def ident[T = int](x: T) -> T:\n    return x\n\
            def view():\n    run(\"ls \" + request.args[\"d\"], shell=True)\n";
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let a = analyze("app.py", Lang::Python, src, &rules, &cfg, far_deadline()).unwrap();
        assert!(!a.has_syntax_errors);
        let found: Vec<_> = a.issues.iter().map(|i| (i.rule, i.line)).collect();
        assert!(
            !found.iter().any(|(r, _)| *r == "py/undefined-name"),
            "{found:?}"
        );
        assert!(found.contains(&("py/command-injection", 6)), "{found:?}");
    }

    #[test]
    fn js_rules_that_need_the_path() {
        let ids = [
            rules::JS_MODULE_IMPORTS_ITSELF,
            rules::JS_DEFAULT_EXPORT_NAME,
            rules::JS_TEST_FILE_WITHOUT_TESTS,
            rules::JS_LICENSE_HEADER,
        ];
        let mut cfg = Config::default();
        cfg.rules.enabled = ids.map(String::from).to_vec();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let hits = |path: &str, src: &str| -> Vec<&'static str> {
            analyze(path, Lang::TypeScript, src, &rules, &cfg, far_deadline())
                .unwrap()
                .issues
                .iter()
                .map(|i| i.rule)
                .filter(|r| ids.contains(r))
                .collect()
        };
        let header = "// Copyright Acme\n";
        assert_eq!(
            hits("src/a.ts", &format!("{header}import x from './a';\n")),
            [rules::JS_MODULE_IMPORTS_ITSELF]
        );
        assert!(hits("src/a.ts", &format!("{header}import x from './b';\n")).is_empty());
        assert_eq!(
            hits(
                "src/user-service.ts",
                &format!("{header}export default class Other {{}}\n")
            ),
            [rules::JS_DEFAULT_EXPORT_NAME]
        );
        assert!(
            hits(
                "src/user-service.ts",
                &format!("{header}export default class UserService {{}}\n")
            )
            .is_empty()
        );
        assert_eq!(
            hits("src/a.test.ts", &format!("{header}const x = 1;\n")),
            [rules::JS_TEST_FILE_WITHOUT_TESTS]
        );
        assert!(
            hits(
                "src/a.test.ts",
                &format!("{header}describe('a', () => {{ it('b', () => {{}}); }});\n")
            )
            .is_empty()
        );
        assert_eq!(
            hits("src/a.ts", "const x = 1;\n"),
            [rules::JS_LICENSE_HEADER]
        );
        assert!(
            hits(
                "src/a.ts",
                "#!/usr/bin/env node\n/* MIT License */\nconst x = 1;\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn java_rules_that_need_the_path() {
        let mut cfg = Config::default();
        cfg.rules.enabled = [
            rules::JAVA_PACKAGE_DIRECTORY,
            rules::JAVA_TEST_IN_MAIN,
            rules::JAVA_PARSE_FAILURE,
            rules::NOSONAR_COMMENT,
        ]
        .map(String::from)
        .to_vec();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let hits = |path: &str, src: &str| -> Vec<&'static str> {
            analyze(path, Lang::Java, src, &rules, &cfg, far_deadline())
                .unwrap()
                .issues
                .iter()
                .map(|i| i.rule)
                .filter(|r| {
                    [
                        rules::JAVA_PACKAGE_DIRECTORY,
                        rules::JAVA_TEST_IN_MAIN,
                        rules::JAVA_PARSE_FAILURE,
                        rules::NOSONAR_COMMENT,
                    ]
                    .contains(r)
                })
                .collect()
        };
        let ok = "package com.acme;\nclass A {}\n";
        assert!(hits("src/main/java/com/acme/A.java", ok).is_empty());
        assert_eq!(
            hits("src/main/java/com/other/A.java", ok),
            [rules::JAVA_PACKAGE_DIRECTORY]
        );
        let test = "package com.acme;\nclass A { @Test void t() {} }\n";
        assert_eq!(
            hits("src/main/java/com/acme/A.java", test),
            [rules::JAVA_TEST_IN_MAIN]
        );
        assert!(hits("src/test/java/com/acme/A.java", test).is_empty());
        assert_eq!(
            hits("a/A.java", "class A { int x = ; }\n"),
            [rules::JAVA_PARSE_FAILURE]
        );
        let nosonar = "class A { int x; // NOSONAR\n}\n";
        assert_eq!(hits("a/A.java", nosonar), [rules::NOSONAR_COMMENT]);
    }

    /// Measured on SonarQube 26.7: an assertion called in production code,
    /// not a test library imported or named (`Test.class` in a generator).
    #[test]
    fn assertions_in_production_code() {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rules::JAVA_ASSERTION_IN_MAIN.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let lines = |path: &str, src: &str| -> Vec<usize> {
            analyze(path, Lang::Java, src, &rules, &cfg, far_deadline())
                .unwrap()
                .issues
                .iter()
                .filter(|i| i.rule == rules::JAVA_ASSERTION_IN_MAIN)
                .map(|i| i.line)
                .collect()
        };
        let src = "package a;\nimport org.junit.jupiter.api.Test;\nimport org.junit.jupiter.api.Assertions;\nimport static org.assertj.core.api.Assertions.assertThat;\nclass A {\nObject t() { return Test.class; }\nvoid f(Object x) { Assertions.assertEquals(1, x); }\nvoid g(Object x) { assertThat(x); }\n}\n";
        assert_eq!(lines("src/main/java/a/A.java", src), [7, 8]);
        assert!(lines("src/test/java/a/A.java", src).is_empty());
    }

    /// `@SuppressWarnings` silences what its declaration covers, as SonarQube
    /// honors it: "all", or the rule's key.
    #[test]
    fn java_suppress_warnings() {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec!["java/empty-method".to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let src = "class A {\n@SuppressWarnings(\"java:S1186\")\nvoid a() {}\n@SuppressWarnings({\"unchecked\", \"all\"})\nvoid b() {}\n@SuppressWarnings(\"unchecked\")\nvoid c() {}\nvoid d() {}\n}\n";
        let lines: Vec<usize> = analyze("a/A.java", Lang::Java, src, &rules, &cfg, far_deadline())
            .unwrap()
            .issues
            .iter()
            .filter(|i| i.rule == "java/empty-method")
            .map(|i| i.line)
            .collect();
        assert_eq!(lines, [7, 8]);
    }

    #[test]
    fn commented_out_code() {
        // Python, as SonarQube 26.7 judges it: a block of comment lines as
        // a whole. Prose with code isn't code; a lone call isn't either.
        let lines = |src: &str| -> Vec<usize> {
            run(Lang::Python, src)
                .issues
                .iter()
                .filter(|i| i.rule == rules::COMMENTED_OUT_CODE)
                .map(|i| i.line)
                .collect()
        };
        let mixed = "# this explains the next step\n# x = compute(a, b)\n# if ready:\ny = 1\n";
        assert!(lines(mixed).is_empty());
        let code = "y = 1\n\n# x = compute(a, b)\n# if x:\n#     y = x\n\n# print(y)\n";
        assert_eq!(lines(code), [3]); // one finding per block
        let trailing = "def f(url):\n    return url  # return (domain, rest)\n";
        assert_eq!(lines(trailing), [2]);
        let docstring =
            "def f():\n    \"\"\" mailbox = name_addr / addr_spec\n    \"\"\"\n    return 1\n";
        assert_eq!(lines(docstring), [2]);
        assert!(lines("# fmt: off\n# pylint: disable=x\ny = 1\n").is_empty());
        let js = run(
            Lang::JavaScript,
            "// Returns the sum;\n// foo(1);\n/** @return {x}; */\n",
        );
        assert_eq!(
            js.issues
                .iter()
                .filter(|i| i.rule == rules::COMMENTED_OUT_CODE)
                .count(),
            1
        );
    }

    #[test]
    fn finds_todo_tags_as_whole_words() {
        assert_eq!(todo_tag("// TODO: fix"), Some("TODO"));
        assert_eq!(todo_tag("# FIXME"), Some("FIXME"));
        assert_eq!(todo_tag("// todos and TODOS"), None);
        let a = run(Lang::Python, "# TODO remove\nx = 1\n");
        assert_eq!(rules_hit(&a), vec![rules::TODO_COMMENT]);
    }

    #[test]
    fn suppression_comments() {
        assert!(is_suppressed("eval(x) // NOSONAR", "js/no-eval"));
        assert!(is_suppressed("eval(x) // sonda-ignore", "js/no-eval"));
        assert!(is_suppressed(
            "eval(x) /* sonda-ignore: js/no-var, js/no-eval */",
            "js/no-eval"
        ));
        assert!(!is_suppressed(
            "eval(x) // sonda-ignore: js/no-var",
            "js/no-eval"
        ));
        let a = run(Lang::JavaScript, "eval(x); // sonda-ignore\nvar y = 1;\n");
        assert_eq!(rules_hit(&a), vec!["js/no-var"]);
    }

    #[test]
    fn csharp_pragma_regions() {
        let src = "class A {\nbool F(double x) {\n#pragma warning disable S1244 // compared on purpose\nvar a = x == 0.1;\n#pragma warning restore S1244\nvar b = x == 0.2;\n#pragma warning disable CA1822, S1244\nvar c = x == 0.3;\n#pragma warning restore\nvar d = x == 0.4;\n#pragma warning disable\nvar e = x == 0.5;\nreturn a;\n}\n}\n";
        assert_eq!(
            pragma_regions(src),
            [
                SuppressedRegion {
                    key: Some("S1244".into()),
                    start: 4,
                    end: 4
                },
                SuppressedRegion {
                    key: Some("CA1822".into()),
                    start: 8,
                    end: 8
                },
                SuppressedRegion {
                    key: Some("S1244".into()),
                    start: 8,
                    end: 8
                },
                SuppressedRegion {
                    key: None,
                    start: 12,
                    end: usize::MAX
                },
            ]
        );
        let a = run(Lang::CSharp, src);
        let floats: Vec<usize> = a
            .issues
            .iter()
            .filter(|i| i.rule == "cs/float-equality")
            .map(|i| i.line)
            .collect();
        assert_eq!(floats, [6, 10]);
    }

    #[test]
    fn csharp_suppress_message_attributes() {
        let src = "using System.Diagnostics.CodeAnalysis;\nclass A {\n[SuppressMessage(\"Major Code Smell\", \"S1244:Floating point numbers should not be tested for equality\", Justification = \"exact\")]\nbool F(double x) {\nreturn x == 0.1;\n}\n[SuppressMessage(\"Style\", \"S9999\")]\nbool G(double x) {\nreturn x == 0.2;\n}\n}\n[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute(\"Bug\", checkId: \"S1244\")]\nclass B {\nbool H(double x) => x == 0.3;\n}\n";
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::CSharp.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let regions = suppressed_regions(src, tree.root_node());
        assert_eq!(
            regions,
            [
                SuppressedRegion {
                    key: Some("S1244".into()),
                    start: 12,
                    end: 15
                },
                SuppressedRegion {
                    key: Some("S9999".into()),
                    start: 7,
                    end: 10
                },
                SuppressedRegion {
                    key: Some("S1244".into()),
                    start: 3,
                    end: 6
                },
            ]
        );
        let a = run(Lang::CSharp, src);
        let floats: Vec<usize> = a
            .issues
            .iter()
            .filter(|i| i.rule == "cs/float-equality")
            .map(|i| i.line)
            .collect();
        assert_eq!(floats, [9]);
    }

    #[test]
    fn columns_are_character_based() {
        let a = run(Lang::JavaScript, "const é = 1; eval(x);\n");
        let issue = a.issues.iter().find(|i| i.rule == "js/no-eval").unwrap();
        assert_eq!((issue.line, issue.column), (1, 14));
    }

    #[test]
    fn imports_are_not_duplication_tokens() {
        let a = run(Lang::Python, "import os\nfrom a import b\nx = 1\n");
        assert_eq!(a.tokens.len(), 3); // x = 1
        assert_eq!(a.metrics.ncloc, 3);
    }

    static CONFIG: LazyLock<Config> = LazyLock::new(Config::default);
    static RULES: LazyLock<RuleSet> = LazyLock::new(|| RuleSet::new(&CONFIG.rules).unwrap());

    /// Code-shaped noise: real keywords and brackets in random order,
    /// including unbalanced nesting, odd line endings and non-ASCII text.
    fn code_like() -> impl Strategy<Value = String> {
        let vocab = vec![
            "if", "else", "elif", "for", "while", "do", "switch", "case", "default", "try",
            "catch", "except", "def", "function", "class", "return", "goto", "eval", "var", "=>",
            "->", "(", ")", "{", "}", "[", "]", ";", ",", ":", "=", "==", "&&", "||", "and", "x",
            "y", "\"s\"", "'c'", "`t`", "#", "//", "/*", "*/", "TODO", "NOSONAR", "é", "\u{202e}",
            " ", "\t", "\n", "\r\n", "\r", "\\",
        ];
        prop::collection::vec(prop::sample::select(vocab), 0..400).prop_map(|t| t.concat())
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(64))]

        /// A small fuzzer: analysis of arbitrary code-shaped input must succeed
        /// in every grammar and report positions inside the file.
        #[test]
        fn analysis_never_fails_on_malformed_code(src in code_like()) {
            for &lang in crate::lang::ALL {
                let a = analyze("f", lang, &src, &RULES, &CONFIG, far_deadline());
                let a = a.map_err(|e| TestCaseError::fail(format!("{lang:?}: {e}")))?;
                check_invariants(&a).map_err(|e| TestCaseError::fail(format!("{lang:?}: {e}")))?;
            }
        }
    }

    fn fingerprints_of(path: &str, src: &str) -> Vec<String> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let a = analyze(path, Lang::JavaScript, src, &rules, &cfg, far_deadline()).unwrap();
        a.issues.iter().map(|i| i.fingerprint.to_string()).collect()
    }

    /// The algorithm is a contract with every server that stored issues:
    /// changing it makes all of them look fixed and re-opened. The expected
    /// values were computed independently (Python's hashlib) from the spec
    /// in `fingerprints`.
    #[test]
    fn fingerprint_and_file_hash_are_pinned() {
        assert_eq!(
            fingerprints_of("t", "var x = 1;\n"),
            ["04d724dbbd800b9d4c64c4649cd55415"]
        );
        let a = run(Lang::JavaScript, "var x = 1;\n");
        assert_eq!(
            a.sha256.to_string(),
            "b9a604979c9b2929d86fca2e07b2af1d125ab5e9de226bda1ed91caa417724d3"
        );
    }

    #[test]
    fn fingerprint_survives_moves_and_reindentation() {
        let before = fingerprints_of("t", "var x = 1;\n");
        let after = fingerprints_of(
            "t",
            "// a new comment\n\nfunction f() { g(); }\n    var  x=1;\n",
        );
        assert_eq!(before, after);
    }

    #[test]
    fn fingerprint_changes_with_the_flagged_line_or_the_path() {
        let base = fingerprints_of("t", "var x = 1;\n");
        assert_ne!(base, fingerprints_of("t", "var x = 2;\n"));
        assert_ne!(base, fingerprints_of("u", "var x = 1;\n"));
    }

    #[test]
    fn identical_lines_get_distinct_stable_fingerprints() {
        // Not `var x` twice: that is also a redeclaration.
        let two = fingerprints_of("t", "eval(x);\neval(x);\n");
        assert_eq!(two.len(), 2);
        assert_ne!(two[0], two[1]);
        // Inserting code between them changes neither.
        assert_eq!(
            two,
            fingerprints_of("t", "eval(x);\nconst y = 2;\neval(x);\n")
        );
    }
}
