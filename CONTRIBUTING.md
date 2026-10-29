# Contributing

Thanks for helping! Start with [ARCHITECTURE.md](ARCHITECTURE.md) for the
layout and [docs/engineering-standards.md](docs/engineering-standards.md) for
the bar every change must meet. Report security issues privately: see
[SECURITY.md](SECURITY.md).

## Setup

Install Rust with [rustup](https://rustup.rs). The minimum supported version
is 1.90 (see `rust-version` in `Cargo.toml`).

```sh
cargo build
cargo run -- scan path/to/project
cargo install cargo-deny cargo-audit cargo-llvm-cov   # optional, CI runs them too
```

## Before you open a pull request

All of these must pass. CI runs them too, with the tests on Linux, macOS and
Windows:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo doc --no-deps
cargo run -q -- rules --format markdown | diff - docs/rules.md
cargo deny check && cargo audit
```

Please make sure your change also follows these:

- **Tests for every change.**
  - A bug fix includes a test that fails without the fix.
  - Changes that touch untrusted input (file contents, names, git) include a
    test with hostile input.
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
`@match`, plus an optional filter function. Add the rule to
`src/rules/catalog.rs`:

```rust
Rule {
    id: "js/no-eval",
    name: "eval() should not be used",
    description: "eval() executes arbitrary strings as code and is a common injection vector.",
    message: "Remove this use of eval().",
    category: Vulnerability,
    severity: Critical,
    effort_minutes: 30,
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
  `cargo run -q -- rules --format markdown > docs/rules.md`.

## Commits and pull requests

- Keep each change small and focused, with a message that explains *why*.
- Mention breaking changes (CLI flags, config keys, report formats, the
  public library API) in the PR and in `CHANGELOG.md`.
- Contributions are licensed under MIT OR Apache-2.0, the project's license.

## AI-assisted contributions

These are welcome, under the same bar. [CLAUDE.md](CLAUDE.md) summarizes the
non-negotiables for coding agents. You are responsible for reviewing and
testing everything you submit.
