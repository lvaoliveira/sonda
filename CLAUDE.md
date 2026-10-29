# sonda

Open-source static analysis and quality gates (SonarQube-like), written in Rust.
Full policy: [`docs/engineering-standards.md`](docs/engineering-standards.md).
Overview and usage: [`README.md`](README.md).

## Non-negotiables

- **The analyzed repository is untrusted input.** That covers source files, names, symlinks,
  `.git/` and its config, and its own `sonda.toml`. Never execute anything from it. Every git
  call disables repo-controlled hooks (`core.fsmonitor`, `core.hooksPath`, ext-diff, textconv)
  and puts `--end-of-options` before user values.
- **One hostile file must never abort or stall a scan.** Bound size, parse time and stack depth.
  No unbounded recursion over syntax trees: walk iteratively or cap the depth. A per-file failure
  becomes a warning.
- **Deterministic output**: same input and config give a byte-identical report. Sort everything
  that reaches output, and never let `HashMap` order or thread scheduling leak into it.
- Domain modules (model, lang, rules, analysis, duplication, measures, gate) do no I/O.
  Dependencies point toward the domain; nothing in the domain imports `scanner`, `report` or `main`.
- No `unsafe`. No `unwrap`/`expect` on production paths without a comment stating the invariant.
  No `panic!` for recoverable errors.
- Every query rule ships `bad`/`good` examples (they are tests). Every bug fix ships a regression test.
- Fail loudly on bad config: unknown keys, rule ids and metrics are errors, never ignored.
- Never weaken a quality gate, remove a test, or `#[allow]` a lint without a justifying comment.
  Never claim a check passed unless it was run in this session.
- Add a dependency only after weighing maintenance, security, license, footprint and stdlib
  alternatives. Commit `Cargo.lock`.
- Work in small increments. Propose a design (with trade-offs and an ADR in `docs/adr/` for
  significant decisions) before large changes.

## Quality gates (all must pass)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo doc --no-deps
cargo run -q -- rules --format markdown | diff - docs/rules.md
```

`cargo deny check`, `cargo audit` and `cargo llvm-cov` run in CI. Install them locally with
`cargo install cargo-deny cargo-audit cargo-llvm-cov`.

## Project facts

- Rust is installed via rustup in `~/.cargo`. If `cargo` is not on `PATH`, prefix commands with
  `export PATH="$HOME/.cargo/bin:$PATH";`.
- Parsing is tree-sitter (0.27; grammars are C code via FFI, which makes them the main
  memory-safety surface). Grammar node kinds differ between languages and versions: the
  `lang.rs` test checks every listed kind exists, and a keyword token can share its text with
  a node kind (`function`), so match on named nodes only.
- Without `--new-code`, the whole project counts as new code.
