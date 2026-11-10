# Performance and limits

How fast sonda scans and how its server holds up as analyses pile up,
measured on real repositories, and the limits that bound both.

Measured on 2026-11-10 on an Apple M4 Pro (12 cores, 24 GB), with the
server's PostgreSQL 17 in Docker on the same machine at its default
settings, as [compose.yaml](../compose.yaml) runs it. Other hardware gives
other numbers; how they grow carries over.

## Scanning

| Repository | Files analyzed | Lines of code | 12 workers | 4 workers | 1 worker | Peak memory |
|---|---|---|---|---|---|---|
| [VS Code](https://github.com/microsoft/vscode) (TypeScript) | 14,609 | 4.0 million | 30 s | 66 s | 244 s | 1.7 GB |
| [CPython](https://github.com/python/cpython) (Python, C) | 3,514 | 1.7 million | 6 s | 12 s | 46 s | 550 MB |

The time is a whole `sonda scan`: finding files, analyzing them, detecting
duplication and writing the JSON report. Generated, minified and very large
files are skipped: 979 of VS Code's.

- **Time** grows with lines of code and drops with workers: 4 are almost 4
  times as fast as one, and 12 about 8 times. `--jobs N` sets the number of
  workers; the default is one per CPU.
- **Memory** is mostly the main process, which keeps every file's tokens
  and results until the report is written: about 0.3 to 0.45 GB per
  million lines of code. Each worker adds 40 to 70 MB while files are
  analyzed. Fewer workers barely lower the peak: it's reached as much after
  the workers finish, while duplication is detected across the whole
  repository, as while they run.
- **Per file**, as [configured](../README.md#configuration):
  - files larger than `scan.max_file_size_kb` (1024 KB by default) are
    skipped with a warning;
  - each file gets `scan.file_timeout_secs` (10 s by default) to be parsed
    and matched by every rule; one that runs out is skipped, with a
    warning. Neither scan above has one;
  - each git command, for new code, gets `scan.git_timeout_secs` (120 s).
    Raise it for very large histories.

## Server

A server loaded with 3,149 analyses of three JavaScript and TypeScript
projects of different sizes, 1.26 million tracked issues and a 3.0 GB
database:

| Project | Files | Lines of code | Issues per analysis | Analyses |
|---|---|---|---|---|
| [Ghost](https://github.com/TryGhost/Ghost) | 7,333 | 1.0 million | 19,892 | 359 |
| [Juice Shop](https://github.com/juice-shop/juice-shop) | 651 | 55,000 | 2,258 | 1,114 |
| [NodeGoat](https://github.com/OWASP/NodeGoat) | 44 | 2,200 | 213 | 1,676 |

All but 300 are on `main`; those 300 are on branches and pull requests.

### Pages

The API calls behind the web app's pages, median of five, for the largest
project where a page is per project:

| Page | Time |
|---|---|
| Overview (30 days) | 0.19 s |
| Projects | 0.11 s |
| Project overview | 0.14 s |
| Project activity | 0.01 s |
| An analysis | 0.01 to 0.19 s |
| Issues, all projects | 0.29 s |
| Issues, one project (and its page 100) | 0.25 s (0.32 s) |
| Issues, filtered by severity and type | 0.10 s |
| An issue | 0.01 s |
| Security | 0.03 s |
| Quality gates | 0.02 s |
| Dependencies | 0.02 s |
| Components | 0.13 s |
| Rules | 0.12 s |

The issue lists are the slowest pages, and grow with the issues a project
has open: with each page, they count the matching issues for every filter.

### Uploads

| Project | One at a time | Four at once, same branch |
|---|---|---|
| Ghost | 2.2 s | 5.0 s |
| Juice Shop | 0.18 s | 0.49 s |
| NodeGoat | 0.06 s | 0.12 s |

An upload stores the analysis, matches its issues with the branch's and
recomputes its new code and counts. **Uploads to one branch run one at a
time**: each waits for the one before it, so concurrent CI jobs on the
same branch queue rather than conflict. Uploads to different branches and
projects run in parallel; the database pool has 10 connections.

An upload is refused (`413`, or `422` past a count) beyond:

| Limit | Value |
|---|---|
| Request body, as sent (gzipped) | 128 MB |
| Report, after decompression | 800 MB |
| Files | 200,000 |
| Issues | 2,000,000 |
| Dependencies | 200,000 |

Ghost's report is 12 MB before gzip, so these leave room for repositories
far larger than the ones measured here.

### Storage

The database grows with analyses, mostly their per-file data
(`analysis_files`, 1.5 GB of the 3.0 GB here), then issues and
dependencies. [Retention and storage](server.md#retention-and-storage)
says what's kept, how branch analyses are thinned after 90 days, and how
much each analysis costs.
