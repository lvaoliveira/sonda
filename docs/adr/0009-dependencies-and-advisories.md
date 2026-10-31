# ADR-0009: Dependencies (SBOM) and known vulnerabilities

- Status: **accepted.** Phases 1 to 3 are done, with one change to
  decision 4 (below). Phase 4 (more lockfile formats) remains.
- Date: 2026-10-30

## Context

sonda analyzes a project's own code. Most of the code a project ships is
its dependencies, and a known vulnerability in one of them is the risk the
OWASP Top 10 2025 ranks third (A03, Software Supply Chain Failures; A06
in 2021). Two things are needed:

1. **An SBOM:** which packages, at which exact versions, a project uses.
   Lockfiles already record this.
2. **Advisories:** which of those versions have published vulnerabilities.
   CVE.org assigns CVE ids but has no package or version index, so it
   can't be matched against a lockfile. [OSV](https://osv.dev) can.
   - It aggregates the GitHub Advisory Database, RustSec, the PyPA and Go
     vulnerability databases, and more.
   - Each advisory names the ecosystem, the package and the affected
     version ranges, and keeps CVE ids as aliases.
   - It publishes bulk exports per ecosystem, plus a `modified_id.csv` for
     incremental updates.

Constraints from earlier decisions:

- **Scans are offline and deterministic** (ADR-0005). A scan of the same
  commit must give the same report, whenever it runs.
- **Analyzed input is untrusted** (ADR-0003, ADR-0004). Lockfiles come
  from the repository like source files do.
- **The server makes no outbound connections today.** Syncing advisories
  would be its first.

## Decision

### 1. The CLI builds the SBOM; it never looks up vulnerabilities

`sonda scan` reads lockfiles and adds a `dependencies` section to the
report. It's a new field, so `report_version` stays (the report's contract:
adding fields keeps the version), and servers that don't know it ignore
it. Each dependency records:

- its ecosystem, name and exact version, and its package URL (purl), the
  identifier CycloneDX, SPDX and OSV all use;
- whether it's direct or transitive, where the lockfile says;
- the lockfile it came from;
- its license, where the lockfile records one.

The first lockfiles are those parsable with dependencies sonda already
has (JSON and TOML):

- `package-lock.json` v2/v3;
- `Cargo.lock`;
- `poetry.lock` and `uv.lock`;
- pinned `requirements.txt` (`name==version` only).

Later, each needing a parser review first:

- `pnpm-lock.yaml` and Yarn Berry's `yarn.lock` (YAML);
- Yarn v1's `yarn.lock` (its own format);
- `go.mod` with `go.sum`;
- Gradle lockfiles.

Maven's `pom.xml` has no resolved versions without running Maven, which
sonda never does, so it isn't supported.

Lockfiles are parsed in-process, not in the sandboxed workers. The
workers exist to contain the C parsers (ADR-0003, ADR-0004), and these
parsers are memory-safe Rust. As with source files, they get the same
size limit, `serde_json`'s nesting limit, and a warning, not an abort,
for a file that doesn't parse.

`sonda sbom` (and `--format cyclonedx|spdx`) exports CycloneDX 1.6 or
SPDX 2.3 JSON from the same data. This needs no server.

### 2. The server matches dependencies against a local advisory mirror

- **Storage.** The server stores each analysis's dependencies, and keeps
  advisories in its own tables.
- **Matching.** It matches each project's latest main-branch SBOM against
  them. A newly published advisory flags an already-analyzed project with
  no rescan, and no dependency list leaves the installation.
- **Sync is opt-in** (`SONDA_ADVISORY_SYNC=true`), since it's the server's
  first outbound connection.
  - It downloads OSV's per-ecosystem exports, then follows
    `modified_id.csv` daily.
  - Air-gapped installs use `sonda-server advisories import FILE.zip` with
    the same exports, carried over by hand.
- **Sources are allow-listed by license.** Only sources whose terms allow
  any use with attribution are imported:
  - the GitHub Advisory Database (CC-BY 4.0);
  - RustSec (CC0);
  - the PyPA database (CC-BY 4.0);
  - the Go vulnerability database (CC-BY 4.0).

  Each advisory keeps its source, and the web app attributes it. Sources
  with non-commercial terms are skipped.
- **Matching is exact or not at all.**
  - An advisory's explicit `versions` list is used when present.
  - Otherwise its ranges are compared with each ecosystem's own version
    order: SemVer for npm, crates.io and Go, and PEP 440 for PyPI.
  - A version or range that doesn't parse is reported as **unchecked**,
    never guessed as safe or vulnerable.

### 3. A vulnerable dependency is its own kind of finding

It isn't an `Issue`:

- an issue is a rule's verdict on a line of code;
- this is a pair of a package version and an advisory, located at a
  lockfile;
- it appears with no code change, and is fixed by an upgrade.

It records:

- the advisory id and its aliases (CVE, GHSA);
- a summary and the source;
- its CWE ids, which plug into ADR-0007's standards and the OWASP
  grouping;
- the fixed versions, if any.

It gets the same review states as issues (open, confirmed, accepted with
a reason), keyed by package and advisory, so accepting one survives
rescans.

**Severity** comes from the advisory's CVSS base score, mapped to sonda's
scale:

| CVSS | sonda severity |
|---|---|
| ≥ 9.0 | blocker |
| ≥ 7.0 | critical |
| ≥ 4.0 | major |
| > 0 | minor |
| none | major, marked "no score" |

### 4. Gate conditions on dependencies are evaluated by the server

`vulnerable_dependencies` and `new_vulnerable_dependencies` (introduced
by the analysis's SBOM change), both by severity, are gate metrics the
server evaluates and shows.

The CLI's gate and exit code stay about code only, because the CLI has no
advisories. `sonda scan --advisories DIR` can evaluate them against a
pinned local export instead. It's deterministic for that snapshot, for CI
that wants a failing build.

**As built:**
- **The metrics.** They're `vulnerable_dependencies` and
  `severe_vulnerable_dependencies` (packages with a blocker or critical
  finding), counted in packages. Their `new_` variants came later
  (2026-10-31): a package's finding is new when that advisory didn't
  affect that package at the base, at any version. The CLI's base is the
  lockfiles at the new-code reference (read from git's objects, as
  ADR-0002 allows); the server's, on the main branch, is the dependencies
  of the new code period's start (ADR-0011). Other branches keep the CLI's
  values, since the server doesn't know their base.
- **Where the gate lives.** The server keeps the stored gate current
  instead of overlaying it when read. It re-evaluates these conditions,
  reviews included, when an analysis is uploaded, when advisories are
  imported or synced, and when a finding is reviewed. Every page then shows
  the same gate, and older analyses keep the gate they had.

## Phases

1. **SBOM in the CLI:** the JSON/TOML lockfiles above, the report's
   `dependencies`, and `sonda sbom` exporting CycloneDX and SPDX.
2. **SBOM on the server:** upload and storage, and a Dependencies tab per
   project.
3. **Advisories:** the mirror, sync and import, matching, findings and
   review, gate metrics, the Security screen, and `--advisories`.
4. **More lockfiles:** YAML, Yarn v1, Go and Gradle, each with its parser
   review.

## Consequences

- The report gains a field, and later the upload carries it; older
  servers ignore it. Storing it (phase 2) is a server migration.
- Dependency results can change without a new analysis, unlike every
  other server number. The web app shows when advisories were last synced.
- Two version-ordering implementations, SemVer and PEP 440, become part
  of sonda's attack surface and its correctness. They need property
  tests against each ecosystem's documented examples. New crates go
  through the dependency review (maintenance, licenses, the 14-day
  minimum age).
- Reachability (roadmap) can later rank a vulnerable dependency by
  whether the vulnerable function is called.
