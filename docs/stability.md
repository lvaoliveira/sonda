# What sonda promises

From 1.0, a minor or patch release doesn't break what is listed under
"Promised". Only a major release does. Before 1.0, a minor release may
change any of it, and says so in the [changelog](../CHANGELOG.md).

## Promised

- **The CLI.** The commands, options and environment variables
  (`SONDA_SERVER`, `SONDA_TOKEN`, `SONDA_TOKEN_FILE`) documented in
  `sonda --help` and these docs, and the exit codes:

  | Code | Meaning |
  |---|---|
  | `0` | The quality gate passed, or `--no-gate`. |
  | `1` | The quality gate failed. With an upload, the server's gate decides ([server.md](server.md#uploading-analyses)). |
  | `2` | An error: bad arguments, an unreadable config, a failed upload. |

  Options may be added. The text report is for people and may change; use
  the JSON or SARIF report in scripts.
- **`sonda.toml`.** Its keys and what they mean. Keys may be added; an
  unknown key is still an error, so a typo doesn't pass silently.
- **The JSON and SARIF reports.** Fields are added without a new
  `report_version`; removing or changing one bumps it. The JSON report is
  version 1 until then. The SARIF report follows SARIF 2.1.0.
- **The upload protocol.** What `sonda upload` and `sonda scan --upload`
  send to `POST /api/analyses` and what the server answers (status codes
  and `analysis_id`, `issues`, `gate`). The window is below.
- **The `sonda-core` library.** The items exported from `sonda_core` that
  the crate's documentation shows, such as `load_config`, `run`, `report`
  and `ScanOptions`. Items marked `#[doc(hidden)]` (the fuzzing hooks)
  aren't covered.

## Not promised

- **The server's HTTP API**, other than `POST /api/analyses`. The web app is
  its one client and moves with it. Scripts that read other endpoints may
  break in any release.
- **The web app**: layout, pages, URLs.
- **Rule results.** Rules get better: a new release can report a finding
  that an older one missed, or stop reporting a false positive, and a new
  finding can fail a gate. The changelog says so under "Changed rule
  results" in every release that does it, naming the rules, so a gate that
  starts failing can be traced to its cause. To hold results still, pin the
  CLI's version.
- **Metrics, logs and the database schema.** The server upgrades its
  database on start (back up first; there's no downgrade).

## Compatibility window

CI pipelines pin a CLI while servers upgrade, so **a server accepts uploads
from the CLI of the previous minor version and the current one.** The
`compat` job runs on every pull request: the last published release's CLI
uploads to the server built from the change, and it must be accepted and
served. A change that would break that fails the job; it needs a deprecation
(below), or waits for a major release.

A new CLI against an older server isn't promised: upgrade the server first.

## Deprecation

A promised thing is deprecated for **at least one minor release** before it
goes: the release that deprecates it keeps it working, warns when it's used
(on stderr for the CLI, in the logs for the server) and lists it in the
changelog under "Deprecated". It goes in a later major release. A security
fix may be the exception, and the changelog says why.
