"""Compares a sonda scan with what Clippy reported on the same sources: per rule,
how many findings agree, and what each side has alone. Only files Clippy
compiled count, and a struct field definition it flags (a derive macro's
span) is set aside. See tools/clippy-oracle/README.md.

usage: compare.py SONDA_REPORT.json RESULTS.json SOURCES_DIR [DUMP_DIR]
SONDA_REPORT is `sonda scan SOURCES_DIR --format json`; RESULTS.json is run.py's.
"""
import collections
import json
import os
import re
import sys

# `pub(crate) x: u32, // note`: the visibility, then a name, a colon and
# anything up to the comma.
VISIBILITY = re.compile(r"\s*(?:pub(?:\([a-z]+\))?\s+)?")
FIELD = re.compile(r"([a-z_][a-z0-9_]*)\s*:\s*([^=]+?),?\s*(?://.*)?$")


def is_definition(line):
    # `x: u32,` defines a field; `x: x,` initializes one, which is what the lint is about.
    m = FIELD.match(line, VISIBILITY.match(line).end())
    return bool(m) and m.group(1) != m.group(2).strip()


def source_line(root, crate, path, line):
    try:
        with open(f"{root}{crate}/{path}", errors="replace") as f:
            return f.read().split("\n")[line - 1]
    except Exception:
        return ""


def near(finding, others):
    crate, path, line = finding
    return any((crate, path, line + d) in others for d in (-1, 0, 1))


def sonda_findings(report, oracle, compiled):
    """sonda's findings in the files Clippy compiled, and per rule how many
    fall in files it didn't (unjudged)."""
    mine = collections.defaultdict(set)
    unjudged = collections.Counter()
    for issue in report["issues"]:
        if not issue["rule"].startswith("rs/"):
            continue
        crate, _, path = issue["path"].partition("/")
        if crate not in oracle:
            continue
        if path in compiled[crate]:
            mine[issue["rule"]].add((crate, path, issue["line"]))
        else:
            unjudged[issue["rule"]] += 1
    return mine, unjudged


def clippy_findings(oracle, root):
    """Clippy's findings, and per rule how many were field definitions."""
    clip = collections.defaultdict(set)
    derive = collections.Counter()
    for crate, result in oracle.items():
        for rule, path, line in result["findings"]:
            if rule == "rs/redundant-field-name" and is_definition(source_line(root, crate, path, line)):
                derive[rule] += 1
                continue
            clip[rule].add((crate, path, line))
    return clip, derive


def percent(part, whole):
    return f"{100 * part / len(whole):.0f}%" if whole else "-"


def print_table(mine, clip, unjudged, derive):
    print(f"{'rule':28} {'sonda':>5} {'clippy':>6} {'agree':>5} {'sonda-only':>10} {'clippy-only':>11} {'precision':>9} {'recall':>6} {'(unjudged,derive)':>18}")
    for rule in sorted(set(mine) | set(clip) | set(unjudged)):
        a, b = mine[rule], clip[rule]
        agree_a = sum(1 for x in a if near(x, b))
        agree_b = sum(1 for y in b if near(y, a))
        print(f"{rule:28} {len(a):5} {len(b):6} {agree_a:5} {len(a) - agree_a:10} {len(b) - agree_b:11} {percent(agree_a, a):>9} {percent(agree_b, b):>6} {unjudged[rule]:>9},{derive[rule]:>3}")


def dump(directory, mine, clip):
    """Writes each side's findings to `directory`, to read the differences."""
    os.makedirs(directory, exist_ok=True)
    for name, findings in (("sonda", mine), ("clippy", clip)):
        with open(f"{directory}/{name}.json", "w") as f:
            json.dump({r: sorted(v) for r, v in findings.items()}, f)


def main():
    with open(sys.argv[1]) as f:
        report = json.load(f)
    with open(sys.argv[2]) as f:
        oracle = json.load(f)
    root = sys.argv[3].rstrip("/") + "/"
    # A file Clippy reported on was compiled, whatever the dependency info listed (example targets).
    compiled = {c: set(v["compiled"]) | {f for _, f, _ in v["findings"]} for c, v in oracle.items()}
    mine, unjudged = sonda_findings(report, oracle, compiled)
    clip, derive = clippy_findings(oracle, root)
    print_table(mine, clip, unjudged, derive)
    if len(sys.argv) > 4:
        dump(sys.argv[4], mine, clip)
    print("failed crates:", {c: v["err"][:50] for c, v in oracle.items() if v["rc"] not in (0, 101)})


if __name__ == "__main__":
    main()
