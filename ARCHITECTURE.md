# Architecture

This is the map for people changing sonda. Decisions and their reasons are
in the ADRs in [`docs/adr/`](docs/adr/).

## Pipeline

```
sonda::run
  ├─ RuleSet::new           compile each enabled rule's tree-sitter query (once)
  └─ scanner::scan
       ├─ collect_files     walk the root (.gitignore + scan.exclude, no symlinks), sort by path
       ├─ load_coverage     read the LCOV files the user named
       ├─ git::new_code     merge base + blob reads → changed lines   (only with --new-code)
       ├─ analysis::analyze per file, in parallel (rayon):
       │     parse (time budget) → query rules (time budget) → complexity,
       │     length, parameters → lines, comments, tokens, TODOs → suppressions
       └─ duplication::detect   rolling hash over every file's token stream
  measures::compute        → project metrics, overall and on new code
  gate::evaluate           → pass/fail per condition
report::build / render     → text, JSON, SARIF
```

## Layers

Dependencies only point down ([ADR-0001](docs/adr/0001-architecture.md)).
The `architecture` tests in `src/lib.rs` enforce this.

| Layer | Modules | Responsibility |
|---|---|---|
| Interface | `main.rs`, `report/` | CLI arguments, logging setup, exit codes; text/JSON/SARIF rendering and terminal escaping |
| Application | `lib.rs` | `run`, `load_config`, `Outcome`: the public entry points |
| Infrastructure | `scanner.rs`, `git.rs` | Filesystem walk and capped reads, coverage files, git object reads |
| Domain | `analysis.rs` | One file: parse, rules, complexity, metrics, tokens, suppressions |
| | `rules/` | Rule catalog (`catalog.rs`) and compiled queries (`RuleSet`) |
| | `duplication.rs` | Cross-file copy-paste detection |
| | `newcode.rs`, `coverage.rs` | Changed-line diff, LCOV parsing |
| | `project.rs`, `measures.rs`, `gate.rs` | Analysis result, metrics, quality gate |
| | `config.rs` | Configuration types, parsing and validation |
| Shared | `model.rs`, `lang.rs` | Plain data (`Issue`, `Metric`, `Condition`, ...), language table |

## Cross-cutting concerns

**Untrusted input.** Everything in the analyzed repository is hostile until
proven otherwise ([SECURITY.md](SECURITY.md)):

- Files are read with a size cap.
- Parsing and rule matching run against a per-file deadline.
- Syntax trees are walked iteratively (`analysis::walk` and the complexity
  walker's explicit stack), never recursively.
- git is limited to object reads ([ADR-0002](docs/adr/0002-new-code-from-git-objects.md)).
- Anything printed to a terminal (report lines, errors, logs) goes through
  `report::terminal_safe`.

**Determinism.** The same input gives a byte-identical report:

- Discovered files are sorted before analysis, and rayon's `collect` keeps
  that order.
- Issues are sorted on all their fields, and warnings are sorted.
- Token hashes use FNV-1a, which is stable across Rust releases.
- `HashMap`s are only used for lookups, never iterated into output.
- `scanner::tests::reports_are_deterministic` feeds the pipeline in two
  orders, with one and four threads.
- The one exception: a file that hits its time budget can depend on machine
  speed. It is always reported as a warning.

**Errors.**
- A failure that stops the run is a typed `sonda::Error`: config, invalid
  argument, I/O on a file the user named, git, or internal.
- A problem with one analyzed file is a `FileError` or a skip reason, and
  becomes a report warning.
- The binary converts errors to exit code 2. Exit code 1 is reserved for a
  failed quality gate.

**Logging.**
- `tracing` events are emitted only from the application and infrastructure
  layers: phase timings and counts at `info`, skipped files and git commands
  at `debug`.
- The binary sends them to stderr through an escaping writer. Stdout holds
  only the report.
- Turn logging on with `-v`/`-vv`/`-vvv` or `RUST_LOG`.

## Extension points

- **A new rule** is a `Rule` entry in `src/rules/catalog.rs`
  ([CONTRIBUTING.md](CONTRIBUTING.md#adding-a-rule)).
- **A new language** needs:
  - its grammar crate
  - a `Lang` variant with its extension mapping and grammar
  - a `Syntax` table in `lang.rs`: function, branch, comment and import node kinds
  - rules for it
- **A new output format** is a renderer in `report/` that consumes `Report`.
- **A new metric** is a `Metric` variant in `model.rs` plus its computation
  in `measures.rs`. A debug assertion checks that every metric is computed.
