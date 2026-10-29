# Engineering Standards

The full engineering policy for sonda. [`CLAUDE.md`](../CLAUDE.md) holds the
non-negotiable subset; this document is the reference behind it.

Goal: build software that another experienced engineering team can confidently
understand, maintain, secure and extend for years. Treat sonda as production
software from day one, and optimize for long-term maintainability over
short-term implementation speed.

## 1. Core principles

- **KISS**: prefer simple, understandable solutions.
- **DRY**: no duplicated business logic, but no premature abstractions either.
- **SOLID**: apply it where it helps module boundaries, interfaces and responsibilities.
- **YAGNI**: no speculative functionality.
- **Separation of concerns**: keep analysis logic independent of the filesystem, git, the CLI and output formats.
- **Explicit over implicit**: make dependencies, errors and behavior visible.
- **Composition over inheritance**: use traits and composition, and use traits only at meaningful boundaries.
- **Secure by default**, and **fail safely**: an error must never leave results inconsistent or the host exposed.
- **Observability by design**: the tool should be diagnosable without leaking sensitive data.

## 2. Rust practices

- Write modern, stable, idiomatic Rust that follows the Rust API Guidelines.
- Prefer compile-time guarantees, and use strong types and enums to make invalid states unrepresentable.
- Avoid unnecessary clones and allocations.
- Don't use `unwrap()` or `expect()` in production paths unless a comment states the invariant that makes them safe. Never `panic!` for a recoverable error.
- Library code uses structured errors (`thiserror`) where callers need to tell errors apart. Binaries and top-level glue use `anyhow` with context.
- Prefer immutable data and avoid global mutable state.
- **No `unsafe`** in sonda's own code. If it ever becomes necessary: explain why safe Rust is insufficient, document the safety invariants, isolate the code in one module, add targeted tests, and keep the surface minimal.
- Use async only where it brings a measurable benefit. The CLI is CPU-bound and stays synchronous.

## 3. Architecture

- Build a modular monolith with dependencies flowing toward the domain and no cycles.
- Layers:
  - **Domain**: model, languages, rules, per-file analysis, duplication, measures, gate. Pure: no filesystem, process, network or stdout access.
  - **Infrastructure**: file discovery, git, coverage-file reading, config-file loading.
  - **Interface**: the CLI and report renderers.
- Keep the public API minimal and intentional. `pub` is a decision, not a default.
- Inject dependencies through constructors and parameters, and add a trait only when there are two real implementations or a test genuinely needs one.
- Add extension points only for concrete requirements. No plugin framework until one is needed.
- Before implementing a significant change, propose the design and its trade-offs, and record decisions as ADRs in `docs/adr/`.

## 4. Security

**Trust model**: everything inside the analyzed repository is untrusted. That
includes source files, file names, directory structure, symlinks, `.git/`
contents and git config, `.gitignore`/`.gitattributes`, and the repository's
own `sonda.toml`. The person running sonda, their CLI arguments, and the files
they explicitly pass (such as `--config` and `--coverage`) are trusted, but
CLI arguments are still validated.

Mandatory:

- Never execute analyzed code. Any external process sonda runs (today only git) must run with repository-controlled execution hooks disabled (`core.fsmonitor`, `core.hooksPath`, external diff, textconv) and with `--end-of-options` before user-supplied values.
- Validate untrusted input at trust boundaries. Malformed input produces a warning for that file, never a crash of the whole run.
- **Denial of service**: every per-file stage must be bounded in time, memory and stack depth. That means file-size limits, parse timeouts, iterative tree walks or depth limits instead of unbounded recursion, and bounded concurrency. One hostile file must not abort or stall the scan.
- **Filesystem**: don't follow symlinks out of the scan root. Read only within the scan root. Write only to paths the user named.
- **Output**: strip terminal control characters from anything derived from the repository (paths, identifiers, messages) before printing it to a terminal. JSON and SARIF go through a proper serializer.
- Never log secrets, tokens or source contents beyond what an issue needs.
- Use established libraries for cryptography and never write custom crypto.
- Error messages must not leak internals beyond what the user needs to act.
- Document the security assumptions in `SECURITY.md` and keep them current.

## 5. Reliability and error handling

- Handle errors explicitly, never fail silently, and keep useful context.
- A per-file failure becomes a reported warning, and the run continues and stays consistent.
- Retry only transient failures, with bounded backoff (not currently relevant to the CLI).
- Bound concurrency and queues, release resources deterministically, and handle cancellation and interruption safely.
- Don't sacrifice correctness for performance.

## 6. Testing

- Take a test-first approach for domain rules, algorithms, input validation and security-sensitive code.
- **Unit tests**: rules (every rule has bad/good examples that are executed), algorithms, validation, error and boundary conditions.
- **Integration tests** (`tests/`): the CLI end to end, exit codes, config loading, git integration, report formats.
- **Property tests**: parsers (LCOV, unified diff, suppression comments) and algorithms with invariants (rolling hash, duplication symmetry, determinism).
- **Security tests**: deep nesting, huge files, binary and invalid-UTF-8 files, symlink escapes, hostile git config, control characters in names.
- **Regression tests**: every significant bug fix gets a test that would have caught it.
- Tests are deterministic, isolated and meaningful. Avoid excessive mocking, and don't test implementation details.

## 7. Quality gates

All of these must pass locally and in CI:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo doc --no-deps
cargo deny check            # advisories, licenses, bans, sources
cargo audit
cargo llvm-cov              # coverage: use it to find gaps, not as a vanity number
```

Never weaken a gate just to make the pipeline pass, never remove tests to get
a green build, and never suppress a warning without a justifying comment.

## 8. Dependencies

- Minimize dependencies. Before adding one, evaluate its maintenance activity, security history, adoption, license compatibility, transitive footprint and sustainability, and record the reasoning in the PR or an ADR.
- Prefer the standard library when the code stays clear.
- Commit `Cargo.lock`.
- The tree-sitter runtime and grammars are C code that parses untrusted input. They are the largest supply-chain and memory-safety surface. Keep them current, and treat updates to them as security-relevant.

## 9. Performance

- Correctness comes first. Establish baselines before optimizing, and profile before adding complexity.
- Design for repositories with millions of lines: memory and time must scale predictably and roughly linearly.
- Don't hold more than one file's source in memory per worker. Keep only compact per-file results.
- Use bounded concurrency, and benchmark critical algorithms such as duplication detection and query execution.

## 10. Observability

- Use structured logging through `tracing` on stderr, with levels controlled by `-v`/`RUST_LOG`. Never write it to stdout, which belongs to the report.
- Log useful context: phase timings, files skipped and why, parse timeouts.
- Never log file contents or secrets.
- Report per-phase timings and counts at debug level. Don't add OpenTelemetry until a real deployment needs it.

## 11. Documentation

Maintain `README.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`LICENSE-*`, `CHANGELOG.md` and ADRs in `docs/adr/`. Docs change in the same
change as the code they describe. `docs/rules.md` is generated, and CI checks
it is current.

## 12. CI/CD and supply chain

- Give workflows least-privilege permissions (`permissions: contents: read` by default).
- Pin third-party actions to full commit SHAs.
- Never expose secrets to untrusted pull requests, and never run PR code with privileged credentials (no `pull_request_target` checkout of PR code).
- Keep build and release permissions separate.
- Builds should be reproducible. Release artifacts ship with checksums, and an SBOM and provenance attestation where practical.
- CI runs fmt, clippy, tests, docs, `cargo deny`, `cargo audit`, coverage, and the rules-doc check.

## 13. Project-specific requirements

1. **Untrusted input isolation**: analyzing a malicious repository must not compromise or crash the host (see §4).
2. **Deterministic analysis**: the same code and configuration produce byte-identical reports regardless of thread scheduling, filesystem iteration order or machine. Sort everything that reaches output, and never let `HashMap` iteration order reach a report.
3. **Extensible analysis engine**: keep clear boundaries between parsing, rule execution, measurement, issue reporting and integrations, without building a plugin framework prematurely.

## 14. Working method (including AI-assisted work)

Before implementing a significant feature:

1. Understand the requirements.
2. List assumptions and ambiguities.
3. Evaluate the security implications.
4. Propose a simple design and its trade-offs.
5. Define acceptance criteria.

Then implement in small increments, add meaningful tests, run the quality
gates, and review the result critically. After each increment, state what
changed, what was run and its real result, the remaining risks, and the next
step.

Don't invent requirements, over-engineer, add unnecessary frameworks, make
undisclosed breaking changes, or ignore security findings. Don't claim checks
passed unless they were actually executed, and don't leave placeholders that
look like finished functionality.

## 15. Definition of done

A change is done when:

- the functional requirements are met
- relevant tests exist and pass
- the security implications have been evaluated
- error handling is complete
- the code follows these conventions
- docs and ADRs are updated
- no unnecessary complexity was added
- all CI quality gates pass
