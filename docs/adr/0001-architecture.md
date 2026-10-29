# ADR-0001: Layered modular monolith in a single crate

- Status: accepted
- Date: 2026-10-28

## Context

sonda is a CLI today, with a server and dashboard on the roadmap. It parses
untrusted repositories, so the code that touches the filesystem and runs
processes must be small and easy to audit. Analysis logic must be testable
without any I/O, and its output must be deterministic.

## Decision

Build sonda as one crate (library plus thin binary), with layers enforced by
module visibility and fitness tests. Dependencies only point down:

| Layer | Modules | May do I/O |
|---|---|---|
| Interface | `main.rs` (CLI), `report/` | stdout/stderr, output file |
| Application | `lib.rs`: `run`, `load_config`, `Outcome` | reads the config file |
| Infrastructure | `scanner` (walk and read files, load coverage), `git`, `worker` (analysis processes, ADR-0003) | yes |
| Domain | `project`, `measures`, `gate`, `analysis`, `duplication`, `rules`, `newcode`, `coverage`, `config` | **no** |
| Shared types | `model`, `lang` | no, and they import nothing from the crate |

- **Public API**: `run`, `load_config`, `ScanOptions`, `Outcome`, `Error`,
  and the data types they expose (`config`, `model`, `lang`, `rules`
  catalog, `report`). Everything else is crate-private. tree-sitter and clap
  types do not appear in the public API.
- **Errors**: run-level failures are a public `#[non_exhaustive]` `sonda::Error`
  (`Config`, `InvalidArgument`, `Io`, `Git`, `Internal`). Per-file problems
  (too large, not UTF-8, timeout) never fail a run: they become sorted
  warnings in the report. `anyhow` is only used in the binary.
- **Determinism**: discovered files are sorted before analysis, issues have a
  total order, warnings are sorted, token hashes use FNV-1a (not
  `DefaultHasher`, whose algorithm can change), and `HashMap`s are only used
  for lookups, never iterated into output.
- **Untrusted input**: syntax trees are walked iteratively, never
  recursively. Every file has a size cap and a time budget. Git is restricted
  to object reads (ADR-0002).

`src/lib.rs` has `architecture` tests that fail if a domain file uses
filesystem, process, network or printing APIs, or imports `scanner`, `git`,
`report` or the application layer.

## Alternatives considered

- **A Cargo workspace** (`sonda-core`, `sonda-cli`, later `sonda-server`).
  Crate boundaries enforce layering through the compiler, but they add
  build and release overhead before there is a second consumer. We will
  revisit this when the server starts, because the layering above maps
  directly onto crates.
- **A plugin system for rules** (dynamic loading, WASM). Not needed yet.
  Rules are data plus a tree-sitter query, which already makes adding one
  cheap and reviewable.

## Consequences

- Adding I/O to the domain fails a test. It has to go through the scanner or
  git layer instead.
- The textual fitness tests can be fooled, for example by a fully qualified
  path built in a macro. Code review is still the main guard; the tests catch
  ordinary mistakes.
