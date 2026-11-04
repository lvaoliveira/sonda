# Clippy as the oracle for Rust rules

SonarQube's Rust rules are Clippy lints under its keys
([ADR-0026](../../docs/adr/0026-rust.md)), so Clippy run on the same code says
what a rule should report. This compares them, rule by rule.

**Running Clippy on a crate executes its build script and its dependencies'
procedural macros: code from whoever published it.** So it runs in a container
with the sources mounted read-only, one output directory, no capabilities and
limits, never on your machine, and only on code you'd run in that box.

```sh
docker build -t sonda-clippy-oracle tools/clippy-oracle

# Crates to check, each a directory under in/ (for example copied from
# ~/.cargo/registry/src), listed in in/_crates.json, with run.py as in/_run.py.
mkdir -p in out && chmod 777 out
printf '["crate-1.0.0"]' > in/_crates.json
cp tools/clippy-oracle/run.py in/_run.py

docker run --rm --user 1000:1000 --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 2048 --memory 6g --cpus 6 \
  -v "$PWD/in:/in:ro" -v "$PWD/out:/out" sonda-clippy-oracle python3 /in/_run.py
```

It forces each lint on (`--force-warn`), so a crate's own `#[allow]` doesn't
hide a finding. To make sonda ignore suppressions the same way, scan a copy
of the sources in which `clippy::` inside `allow(...)`/`expect(...)` is
renamed (`clippyX::`):

```sh
sonda scan in --config oracle.toml --format json --no-gate -o sonda.json
python3 tools/clippy-oracle/compare.py sonda.json out/results.json in
```

`oracle.toml` lists the off-by-default rules under test in `rules.enabled`.
Findings in files Clippy didn't compile (other platforms, features that
aren't on, test fixtures) can't be judged and are counted apart. A rule with
no finding on either side proves nothing: use a corpus that has the pattern.

First batch, on 66 crates (default features, all targets): `else-if-without-else`
98% precision / 95% recall, `match-on-bool` 94% / 96%, `redundant-field-name`
92% / 88%, `let-and-return` 74% / 89%, `null-pointer-from-zero` 100% / 100%.
