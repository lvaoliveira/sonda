# sonda

Open-source static analysis and quality gates (SonarQube-like), written in Rust.
Full policy: [`docs/engineering-standards.md`](docs/engineering-standards.md).
Overview and usage: [`README.md`](README.md).

## Non-negotiables

- **The analyzed repository is untrusted input.** That covers source files, names, symlinks,
  `.git/` and its config, and its own `sonda.toml`. Never execute anything from it. Only ask git
  to read objects (`rev-parse`, `merge-base`, `ls-tree`, `cat-file`); never `diff`/`status`/
  `ls-files`, which run repo-configured programs ([ADR-0002](docs/adr/0002-new-code-from-git-objects.md)).
  Pass `--end-of-options` before user values.
- **One hostile file must never abort or stall a scan.** Bound size, parse time and stack depth.
  No unbounded recursion over syntax trees: walk iteratively or cap the depth. A per-file failure
  becomes a warning.
- **Deterministic output**: same input and config give a byte-identical report. Sort everything
  that reaches output, and never let `HashMap` order or thread scheduling leak into it.
- Crates: `crates/sonda-core` (the library: everything below) and `crates/sonda` (the CLI,
  `main.rs` only). The core never depends on clap, anyhow or the CLI.
- Layering ([ADR-0001](docs/adr/0001-architecture.md)): interface (`main`, `report`) →
  application (`lib.rs`: `run`, `load_config`) → infrastructure (`scanner`, `git`, `worker`) → domain
  (`project`, `measures`, `gate`, `analysis`, `duplication`, `rules`, `newcode`, `coverage`,
  `config`) → shared types (`model`, `lang`). Domain does no I/O. The `architecture` tests in
  `lib.rs` enforce this; fix the code, not the test.
- Library errors are the typed `sonda_core::Error`; per-file problems become warnings, never errors.
  `anyhow` only in `main.rs`. Keep tree-sitter and clap types out of the public API.
- No `unsafe`, except `crates/sonda-core/src/sandbox/macos.rs` (ADR-0004: `sandbox_init` FFI, with a safety argument).
  No `unwrap`/`expect` on production paths without a comment stating the invariant.
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
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo test --workspace --doc
# Server database tests need PostgreSQL; without it they skip (docs/server.md):
SONDA_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:55432/postgres cargo test -p sonda-server
cargo doc --workspace --lib --no-deps
cargo run -q -p sonda -- rules --format markdown | diff - docs/rules.md
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
