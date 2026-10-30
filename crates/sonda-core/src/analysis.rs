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
    let bytes = src.as_bytes();
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
    };
    let syn = lang.syntax();

    let mut issues = run_queries(&ctx, lang, root, rules, deadline)?;
    let semantic_incomplete = run_semantic(&ctx, lang, root, rules, deadline, &mut issues);
    let mut metrics = FileMetrics::default();
    measure_functions(&ctx, syn, root, rules, cfg, &mut issues, &mut metrics);
    let scan = scan_tokens(&ctx, syn, root, rules, &mut issues);

    metrics.lines = ctx.lines.count();
    metrics.ncloc = scan.code_lines.len();
    metrics.comment_lines = scan.comment_lines;

    issues.retain(|i| !is_suppressed(ctx.lines.text(i.line - 1), i.rule));
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
    let mut seen: HashMap<(&str, String), u64> = HashMap::new();
    for issue in issues {
        let line: String = ctx
            .lines
            .text(issue.line - 1)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut hasher = sha2::Sha256::new();
        // Length-prefixed fields, so no two different inputs hash the same
        // bytes; the tag lets the algorithm change without silent collisions.
        for field in ["sonda-fingerprint-v1", issue.rule, ctx.path, &line] {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field.as_bytes());
        }
        let occurrence = seen.entry((issue.rule, line)).or_insert(0);
        hasher.update(occurrence.to_le_bytes());
        *occurrence += 1;
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
        }
    }

    fn text(&self, node: Node) -> &'a str {
        &self.src[node.byte_range()]
    }
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
    // Credentials, weak settings and the like are fixtures in tests, not
    // vulnerabilities, so vulnerability rules skip test files (as SonarQube
    // does with test code).
    let test_file = is_test_file(ctx.path);
    let options = QueryCursorOptions::new().progress_callback(&mut check_deadline);
    let mut matches = cursor.matches_with_options(&cq.query, root, bytes, options);
    while let Some(m) = matches.next() {
        for &(idx, filter) in &cq.patterns[m.pattern_index] {
            let active = &rules.active[idx];
            if test_file && active.rule.category == Category::Vulnerability {
                continue;
            }
            for cap in m.captures().iter().filter(|c| c.index == cq.match_capture) {
                let node = match filter {
                    None => Some(cap.node),
                    Some(Filter::Keep(keep)) => keep(cap.node, bytes).then_some(cap.node),
                    Some(Filter::Find(find)) => find(cap.node, bytes),
                };
                if let Some(node) = node {
                    let msg = active.rule.message.to_string();
                    issues.push(ctx.issue(active, node, msg, active.rule.effort_minutes));
                }
            }
        }
    }
    if timed_out.get() {
        return Err(FileError::QueryTimeout);
    }
    Ok(issues)
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
) -> bool {
    // Declaration files describe code that lives elsewhere: nothing in them
    // runs, and their names are all visible to other files.
    if is_declaration_file(ctx.path) {
        return false;
    }
    let test_file = is_test_file(ctx.path);
    let active: Vec<(&ActiveRule, rules::SemanticFind)> = rules
        .active
        .iter()
        .filter_map(|a| match a.rule.check {
            Check::Semantic { langs, find } if langs.contains(&lang) => Some((a, find)),
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
        for node in find(&model, bytes) {
            let msg = a.rule.message.to_string();
            issues.push(ctx.issue(a, node, msg, a.rule.effort_minutes));
        }
    }
    false
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
    let cognitive_rule = rules.get(rules::COGNITIVE_COMPLEXITY);
    let length_rule = rules.get(rules::FUNCTION_LENGTH);
    let params_rule = rules.get(rules::TOO_MANY_PARAMETERS);

    walk(root, |node| {
        // is_named: keyword tokens such as `function` share their text with node kinds.
        if !node.is_named() || !syn.functions.contains(&node.kind()) {
            return true;
        }
        metrics.functions += 1;
        let c = complexity(node, syn, ctx.src.as_bytes());
        metrics.complexity += c.cyclomatic;
        metrics.cognitive_complexity += c.cognitive;

        let name = function_name(node, ctx);
        let anchor = name_node(node).unwrap_or(node);
        if let Some(rule) = cognitive_rule
            && c.cognitive > t.cognitive_complexity
        {
            let msg = format!(
                "Refactor '{name}' to reduce its cognitive complexity from {} to the {} allowed.",
                c.cognitive, t.cognitive_complexity
            );
            let effort = rule.rule.effort_minutes + (c.cognitive - t.cognitive_complexity);
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
        if let Some(rule) = params_rule
            && let Some(n) = parameter_count(node, syn)
            && n > t.parameters as usize
        {
            let msg = format!(
                "'{name}' has {n} parameters, which is more than the {} allowed.",
                t.parameters
            );
            issues.push(ctx.issue(rule, anchor, msg, rule.rule.effort_minutes));
        }
        // Keep descending: nested functions are measured on their own.
        true
    });
}

struct TokenScan {
    code_lines: Vec<usize>,
    comment_lines: usize,
    tokens: Vec<Token>,
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
    let todo_rule = rules.get(rules::TODO_COMMENT);
    let mark = |flags: &mut Vec<bool>, node: Node| {
        flags[node.start_position().row..=last_row(node)].fill(true);
    };

    walk(root, |node| {
        let kind = node.kind();
        if syn.comments.contains(&kind) {
            mark(&mut comment, node);
            if let Some(rule) = todo_rule
                && let Some(tag) = todo_tag(ctx.text(node))
            {
                let msg = format!("Complete the task associated with this {tag} comment.");
                issues.push(ctx.issue(rule, node, msg, rule.rule.effort_minutes));
            }
            return false;
        }
        if syn.dup_ignore.contains(&kind) {
            mark(&mut code, node);
            return false;
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
}

/// Cyclomatic complexity plus an approximation of SonarSource's cognitive
/// complexity: +1 per branch/loop/catch/ternary (plus the nesting depth),
/// +1 per else/elif, +1 per run of the same boolean operator. Nested
/// functions are skipped; they are measured separately.
///
/// Iterative on purpose: syntax trees from untrusted input can be nested
/// arbitrarily deep, and recursion would overflow the stack and abort the
/// whole scan.
fn complexity(func: Node, syn: &Syntax, src: &[u8]) -> Complexity {
    let mut w = ComplexityWalker {
        syn,
        src,
        c: Complexity {
            cyclomatic: 1,
            cognitive: 0,
        },
        stack: Vec::new(),
    };
    w.children(func, 0);
    while let Some(step) = w.stack.pop() {
        match step {
            Step::Visit(node, nesting) => w.visit(node, nesting),
            Step::If(node, nesting, flat) => w.visit_if(node, nesting, flat),
            Step::Else(node, nesting) => w.visit_else(node, nesting),
        }
    }
    w.c
}

/// Pending work for the complexity walker. Visit order does not matter:
/// every step only adds to the totals.
enum Step<'t> {
    Visit(Node<'t>, u32),
    /// `flat` marks an else-if: it costs +1 without a nesting increment.
    If(Node<'t>, u32, bool),
    /// The alternative branch of an if, at the if's own nesting level.
    Else(Node<'t>, u32),
}

struct ComplexityWalker<'a, 't> {
    syn: &'a Syntax,
    src: &'a [u8],
    c: Complexity,
    stack: Vec<Step<'t>>,
}

impl<'t> ComplexityWalker<'_, 't> {
    fn children(&mut self, node: Node<'t>, nesting: u32) {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.stack.push(Step::Visit(child, nesting));
        }
    }

    fn visit(&mut self, node: Node<'t>, nesting: u32) {
        let kind = node.kind();
        if self.syn.functions.contains(&kind) {
            return;
        }
        if kind == "if_statement" {
            return self.stack.push(Step::If(node, nesting, false));
        }
        if self.syn.branches.contains(&kind) {
            self.c.cyclomatic += 1;
            self.c.cognitive += 1 + nesting;
            return self.children(node, nesting + 1);
        }
        if self.syn.switches.contains(&kind) {
            self.c.cognitive += 1 + nesting;
            return self.children(node, nesting + 1);
        }
        if self.syn.cases.contains(&kind)
            && !node
                .utf8_text(self.src)
                .unwrap_or("")
                .starts_with("default")
        {
            self.c.cyclomatic += 1;
        }
        if let Some(op) = logical_operator(node, self.src) {
            self.c.cyclomatic += 1;
            let continues_run = node
                .parent()
                .and_then(|p| logical_operator(p, self.src))
                .is_some_and(|parent_op| parent_op == op);
            if !continues_run {
                self.c.cognitive += 1;
            }
        }
        self.children(node, nesting);
    }

    fn visit_if(&mut self, node: Node<'t>, nesting: u32, flat: bool) {
        self.c.cyclomatic += 1;
        self.c.cognitive += if flat { 1 } else { 1 + nesting };
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
                    Step::Visit(child, nesting + 1)
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
            "if_statement" => self.stack.push(Step::If(node, nesting, true)),
            "elif_clause" => {
                self.c.cyclomatic += 1;
                self.c.cognitive += 1;
                self.children(node, nesting + 1);
            }
            "else_clause" => match only_named_child(node) {
                Some(inner) if inner.kind() == "if_statement" => {
                    self.stack.push(Step::If(inner, nesting, true))
                }
                _ => {
                    self.c.cognitive += 1;
                    self.children(node, nesting + 1);
                }
            },
            _ => {
                self.c.cognitive += 1;
                self.stack.push(Step::Visit(node, nesting + 1));
            }
        }
    }
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
        _ => None,
    });
    named_by.map_or("<anonymous>", |n| ctx.text(n))
}

fn parameter_count(node: Node, syn: &Syntax) -> Option<usize> {
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
    Some(n)
}

fn todo_tag(comment: &str) -> Option<&'static str> {
    ["TODO", "FIXME", "XXX"].into_iter().find(|tag| {
        comment.match_indices(tag).any(|(i, _)| {
            let before = comment[..i].chars().next_back();
            let after = comment[i + tag.len()..].chars().next();
            !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
        })
    })
}

/// `NOSONAR` or `sonda-ignore` on a line suppresses every issue on it;
/// `sonda-ignore: rule-a, rule-b` suppresses only the listed rules.
fn is_suppressed(line: &str, rule: &str) -> bool {
    if line.contains("NOSONAR") {
        return true;
    }
    let Some(pos) = line.find("sonda-ignore") else {
        return false;
    };
    let rest = line[pos + "sonda-ignore".len()..].trim_start();
    match rest.strip_prefix(':') {
        None => true,
        Some(ids) => ids
            .split([',', ' ', '\t'])
            .map(|s| s.trim_end_matches("*/").trim())
            .any(|id| id == rule),
    }
}

struct LineIndex<'a> {
    src: &'a str,
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(src: &'a str) -> Self {
        let starts = std::iter::once(0)
            .chain(src.match_indices('\n').map(|(i, _)| i + 1))
            .collect();
        LineIndex { src, starts }
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
        assert_eq!(rules_in("src/db.test.js"), ["js/no-var"]);
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
    fn finds_todo_tags_as_whole_words() {
        assert_eq!(todo_tag("// TODO: fix"), Some("TODO"));
        assert_eq!(todo_tag("# FIXME"), Some("FIXME"));
        assert_eq!(todo_tag("// todos and TODOS"), None);
        let a = run(Lang::Python, "x = 1  # TODO remove\n");
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
