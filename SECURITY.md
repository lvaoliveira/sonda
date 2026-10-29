# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's **"Report a vulnerability"**
button on this repository's Security tab. Don't open a public issue. Please
include a reproduction, such as a minimal repository or file that triggers
the problem.

Only the latest release receives fixes while sonda is at 0.x.

## Threat model

sonda is built to analyze code you don't trust, such as a pull request from
a stranger or a downloaded archive.

**Untrusted**: everything inside the analyzed directory:
- file contents, file names, directory structure and symlinks
- `.gitignore` and `.gitattributes`
- `.git/` and its config
- the repository's own `sonda.toml`

**Trusted**: the person running sonda, the command-line arguments (which are
still validated), and the files they explicitly name (`--config`,
`--coverage`, `-o`).

### What sonda guarantees

- **No code execution.** sonda never runs, imports or evaluates analyzed code.
  It only asks git to read objects (`rev-parse`, `merge-base`, `ls-tree`,
  `cat-file`). It never runs commands that can start programs configured in
  the repository, such as fsmonitor, clean/smudge filters, textconv or
  external diff ([ADR-0002](docs/adr/0002-new-code-from-git-objects.md)).
  Tests configure each of these in a hostile repository and fail if any runs.
- **No argument injection.** A `--new-code` reference that starts with `-`
  or contains whitespace or control characters is rejected, and references
  are passed to git after `--end-of-options`.
- **A single file cannot crash or stall a scan:**
  - Reads are capped at `scan.max_file_size_kb`.
  - Parsing and rule matching stop at `scan.file_timeout_secs`.
  - Syntax trees are walked without recursion, which is tested with 100,000
    levels of nesting.
  - Duplication detection runs in linear time, even on input crafted to be
    repetitive.
- **git cannot hang a scan.** Every git process is killed after
  `scan.git_timeout_secs` (default 120), and the run fails with a clear
  error instead of waiting forever.
  - Malformed files become warnings.
- **No reads outside the scan root.** Symlinks are not followed.
- **No terminal injection.** Control characters and Unicode bidi overrides
  ("Trojan Source") from the repository are shown as visible `\u{..}`
  escapes in text reports, error messages and logs. JSON and SARIF escape
  them through the serializer.
- **Deterministic output**, so results can be audited and reproduced.

### Known limitations

- **Parsers are C code.** tree-sitter's runtime and grammars are C, called
  through FFI. A memory-safety bug in them, triggered by a crafted file,
  could affect the sonda process. They are fuzzed weekly in CI with
  AddressSanitizer (see CONTRIBUTING.md) and kept up to date, but they still
  run in the same process as the rest of sonda.
- **File-swap race.** If an attacker can modify the directory *while* it is
  being scanned, a file could be swapped for a symlink between the walk and
  the read. A static checkout is not affected.
- **The repository's own `sonda.toml` is trusted by default.** A pull request
  can edit it to disable rules or weaken the quality gate. In CI, load the
  config from a trusted place instead, such as the base branch:

  ```sh
  git show origin/main:sonda.toml > /tmp/sonda.toml
  sonda scan . --config /tmp/sonda.toml --new-code origin/main
  ```

## Supply chain

CI runs `cargo deny` (advisories, licenses, sources) and `cargo audit` on
every change. Actions are pinned to commit SHAs, and workflows get a
read-only token. `Cargo.lock` is committed. See
[docs/engineering-standards.md](docs/engineering-standards.md#12-cicd-and-supply-chain).
