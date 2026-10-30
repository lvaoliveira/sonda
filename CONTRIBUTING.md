# Contributing

Thanks for helping! Start with [ARCHITECTURE.md](ARCHITECTURE.md) for the
layout and [docs/engineering-standards.md](docs/engineering-standards.md) for
the bar every change must meet. Report security issues privately: see
[SECURITY.md](SECURITY.md).

## Setup

Install Rust with [rustup](https://rustup.rs). The minimum supported version
is 1.90 (see `rust-version` in the root `Cargo.toml`).

```sh
cargo build
cargo run -p sonda -- scan path/to/project
cargo install cargo-deny cargo-audit cargo-llvm-cov   # optional, CI runs them too
```

## Before you open a pull request

All of these must pass. CI runs them too, with the tests on Linux, macOS and
Windows:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc
cargo doc --workspace --lib --no-deps
cargo run -q -p sonda -- rules --format markdown | diff - docs/rules.md
cargo deny check && cargo audit
```

Please make sure your change also follows these:

- **Tests for every change.**
  - A bug fix includes a test that fails without the fix.
  - Changes that touch untrusted input (file contents, names, git) include a
    test with hostile input.
- **Property tests** (`proptest`) use a fixed seed, so CI is deterministic.
  When changing a parser or the analysis, also run a few other seeds, for
  example `PROPTEST_RNG_SEED=7 cargo test`. A failure prints a minimal input;
  turn it into a named regression test.
- **The domain stays pure.** Don't add I/O outside `scanner.rs`, `git.rs`,
  `lib.rs` and the interface layer; the `architecture` tests will fail.
- **Output stays deterministic.** Never let `HashMap` order or thread timing
  reach a report.
- **No `unwrap`/`expect`/`panic!` on production paths** unless a comment
  states why it can't fail.
- **Dependencies are rare.** Say in the PR why the standard library or an
  existing dependency isn't enough, and check its license against
  `deny.toml`.
- **Docs move with the code.** Update README, ARCHITECTURE, the ADRs and
  `CHANGELOG.md` (under `Unreleased`) when behavior changes.

## Adding a rule

Most rules are a tree-sitter query that captures the offending node as
`@match`, plus an optional filter function. Add the rule to its language's
file in `crates/sonda-core/src/rules/catalog/` (`js.rs`, `py.rs`, `java.rs`,
`c.rs`; `common.rs` holds structural rules):

```rust
Rule {
    id: "js/no-eval",
    name: "eval() should not be used",
    description: "eval() executes arbitrary strings as code and is a common injection vector.",
    message: "Remove this use of eval().",
    category: Vulnerability,
    severity: Critical,
    effort_minutes: 30,
    sonar: &[related("S1523")],
    check: Check::Query {
        langs: JS_TS,
        query: r#"(call_expression function: (identifier) @f (#eq? @f "eval")) @match"#,
        filter: None,
    },
    example: Some(Example {
        lang: Lang::JavaScript,
        bad: "eval(userInput);",
        good: "JSON.parse(userInput);",
    }),
},
```

- The `example` is mandatory. Tests check that the rule flags `bad`, ignores
  `good`, and compiles for every language in `langs`. Make `good` cover the
  false positive you most expect, as `js/eqeqeq` does with `x == null`.
- Node kinds differ between grammars and grammar versions. To see the tree
  for a snippet, parse it in a test and print `root_node().to_sexp()`.
- Match named nodes, not keyword tokens: the keyword `function` shares its
  text with a node kind.
- Regenerate the docs with
  `cargo run -q -p sonda -- rules --format markdown > docs/rules.md`.

Rules run on every file, including generated and minified ones, so keep
them linear in the file's size:

- **Look down, not up.** `Node::parent()` and sibling lookups walk from the
  root, so calling them for a common node (every `if`, every object member)
  is quadratic on deep or wide code. Capture the container instead (the
  object, the switch body, the `finally` block) and walk its children.
- **Prefer patterns without later child steps on deep nodes.** A pattern
  like `(binary_expression right: ...)` or `operator: ...` stays in progress
  while the left operand's subtree is matched, which is quadratic on long
  `a + b + ...` chains. Match `(binary_expression) @match` and check the
  operator in the filter.
- **Watch for unanchored child steps.** `(statement_block (statement_block))`
  stays open over the whole outer block, so it's quadratic on deep
  nesting. Capture the outer node and find the child with a `Find` filter,
  which can report a node other than the captured one.
- **Compare text in the filter, lengths first**, rather than `#eq?` on
  captures that can be large.
- `large_and_deep_code_stays_fast` in `catalog/js.rs` guards these shapes.

### Rules equivalent to SonarQube's

sonda is working towards an equivalent for each SonarQube rule key
([ADR-0007](docs/adr/0007-sonarqube-rule-parity.md)). What's covered and
what's left is in [docs/sonar-parity/](docs/sonar-parity/), one CSV per
language.

- **Write your own.** Name, description, message, examples and check are
  all sonda's own. **Never copy SonarSource's text, code or test cases.**
- **Record the key** in `sonar`:
  - `exact("S3504")` when the rule has the same intent and scope.
  - `related("S1523")` when it overlaps but differs, for example a
    syntactic check for what SonarQube does with taint analysis.

  A JavaScript rule also covers the TypeScript key with the same number.
- **Record its standards** in `rules/catalog/standards.rs`: the CWE ids
  and OWASP Top 10 2021 categories the rule relates to. Every
  vulnerability rule needs at least one CWE id (a test checks), and for an
  exact key they should match SonarQube's, which the refresh below reports.
- **Check it on real code.** Scan the reference projects and review every
  finding. A rule that misfires doesn't ship.
- **Refresh the compatibility table:**
  `python3 scripts/sonar_parity.py --server URL --token-file FILE`.

## Fuzzing

`fuzz/` has [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets:
- `analyze` runs arbitrary input through every grammar. The first byte
  picks the language.
- `config` parses arbitrary `sonda.toml` contents.

They need nightly Rust:

```sh
rustup toolchain install nightly && cargo install cargo-fuzz
CFLAGS="-fsanitize-coverage=inline-8bit-counters,pc-table" \
  cargo +nightly fuzz run analyze fuzz/corpus/analyze fuzz/seeds/analyze -- -max_total_time=300
```

`CFLAGS` instruments the C grammars as well, so the fuzzer can explore them.
On Linux, add `-fsanitize=address` to it, and set `CC=clang`, to also catch
memory errors in the C code. That flag doesn't work with Apple clang.

The `Fuzz` workflow runs both targets weekly with AddressSanitizer, and for
60 seconds on pull requests that touch `crates/sonda-core/` or `fuzz/`. A crash is saved
as a workflow artifact. Reproduce it with `cargo +nightly fuzz run <target>
<file>`, then turn it into a regression test.

## The worker sandbox

The warning "killed by the sandbox" means a worker made a system call
outside the Linux allow-list (`crates/sonda-core/src/sandbox/linux.rs`). This usually follows
a dependency or std update. To find the call:
1. Reproduce with `--jobs 1`.
2. Compare against `--sandbox off`.
3. Trace the worker with
   `strace -f -o trace sonda scan <dir> --sandbox off`, looking at what the
   `__worker` process does after it writes its ready frame.

Add a call to the allow-list only if it cannot reach files, the network or
other processes, and say why in a comment.

## Commits and pull requests

- Keep each change small and focused, with a message that explains *why*.
- Mention breaking changes (CLI flags, config keys, report formats, the
  public library API) in the PR and in `CHANGELOG.md`.
- Contributions are licensed under MIT OR Apache-2.0, the project's license.

## AI-assisted contributions

These are welcome, under the same bar. [CLAUDE.md](CLAUDE.md) summarizes the
non-negotiables for coding agents. You are responsible for reviewing and
testing everything you submit.
