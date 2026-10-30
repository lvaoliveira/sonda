#!/usr/bin/env python3
"""Refresh docs/sonar-parity/: sonda's compatibility with SonarQube rule keys (ADR-0007).

Compares sonda's rules (`sonda rules --format json`) with the rule keys of a
SonarQube server you have access to, using its standard rules API, and writes
one CSV per language plus a summary. Only rule keys and a few facts (type,
default severity, whether enabled by default, and the CWE ids and OWASP Top
10 2021 categories a rule relates to) are written. It also reports where
sonda's catalog records different CWE or OWASP references than SonarQube for
the rules it covers.

    python3 scripts/sonar_parity.py --server http://sonarqube:9000 \\
        --token-file ~/.sonar_token

Standard library only. The token is sent as a bearer header and never
printed.
"""

import argparse
import concurrent.futures
import csv
import datetime
import json
import os
import subprocess
import urllib.parse
import urllib.request

# SonarQube language key -> sonda language ids it corresponds to.
LANGUAGES = {
    "js": ("JavaScript", {"javascript"}),
    "ts": ("TypeScript", {"typescript", "tsx"}),
    "py": ("Python", {"python"}),
    "java": ("Java", {"java"}),
    "c": ("C", {"c"}),
    "cpp": ("C++", {"cpp"}),
}
TIERS = ("syntactic", "types", "dataflow")


def fetch(server, token, path, **query):
    url = f"{server.rstrip('/')}{path}?{urllib.parse.urlencode(query)}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def all_rules(server, token, **query):
    rules, page = [], 1
    while True:
        result = fetch(server, token, "/api/rules/search", ps=500, p=page, **query)
        rules += result["rules"]
        if page * 500 >= result["total"]:
            return rules
        page += 1


def standards(server, token, key):
    """The CWE ids and OWASP Top 10 2021 categories of one rule, from the
    search facets (rules don't list them as fields)."""
    result = fetch(server, token, "/api/rules/search", rule_key=key, ps=1,
                   facets="cwe,owaspTop10-2021")
    values = {f["property"]: sorted((v["val"] for v in f["values"] if v["count"]),
                                    key=lambda v: (len(v), v))
              for f in result["facets"]}
    cwe = [v for v in values.get("cwe", []) if v.isdigit()]
    owasp = [f"A{int(v[1:]):02d}" for v in values.get("owaspTop10-2021", [])]
    return cwe, owasp


def tier(rule):
    """A first guess at what analysis a rule needs, from SonarQube's tags.
    Confirmed (and corrected in sonda) when the rule is implemented."""
    tags = set(rule.get("sysTags", []))
    if "symbolic-execution" in tags:
        return "dataflow"
    if "type-dependent" in tags:
        return "types"
    return "syntactic"


def number(key):
    digits = "".join(c for c in key.split(":")[1] if c.isdigit())
    return (int(digits) if digits else 10**9, key)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--server", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--out", default="docs/sonar-parity")
    parser.add_argument("--sonda", default="cargo run -q --locked -p sonda --",
                        help="how to run sonda")
    args = parser.parse_args()
    with open(os.path.expanduser(args.token_file)) as f:
        token = f.read().strip()

    sonda = json.loads(subprocess.run(args.sonda.split() + ["rules", "--format", "json"],
                                      check=True, capture_output=True, text=True).stdout)
    version = urllib.request.urlopen(urllib.request.Request(
        f"{args.server.rstrip('/')}/api/server/version",
        headers={"Authorization": f"Bearer {token}"}), timeout=30).read().decode().strip()
    available = {l["key"] for l in fetch(args.server, token, "/api/languages/list")["languages"]}
    profiles = {p["language"]: p["key"]
                for p in fetch(args.server, token, "/api/qualityprofiles/search", defaults="true")["profiles"]}

    os.makedirs(args.out, exist_ok=True)
    summary = []
    # sonda rule id -> (CWE ids, OWASP categories) SonarQube gives its exact keys.
    expected = {}
    for lang, (label, sonda_langs) in LANGUAGES.items():
        if lang not in available:
            summary.append((label, None))
            continue
        rules = all_rules(args.server, token, languages=lang,
                          f="severity,sysTags,status,isTemplate,scope")
        active = {r["key"] for r in all_rules(args.server, token, languages=lang, f="name",
                                              qprofile=profiles[lang], activation="true")} \
            if lang in profiles else set()
        live = [r["key"] for r in rules if r["status"] != "DEPRECATED"]
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            found = dict(zip(live, pool.map(lambda k: standards(args.server, token, k), live)))
        rows = []
        for r in sorted(rules, key=lambda r: number(r["key"])):
            short = r["key"].split(":")[1]
            exact = [s["id"] for s in sonda if sonda_langs & set(s["languages"])
                     and any(x["key"] == short and x["exact"] for x in s["sonar"])]
            related = [s["id"] for s in sonda if sonda_langs & set(s["languages"])
                       and any(x["key"] == short and not x["exact"] for x in s["sonar"])]
            if r["status"] == "DEPRECATED":
                status = "deprecated"
            elif r["isTemplate"]:
                status = "template"
            elif exact:
                status = "done"
            elif related:
                status = "partial"
            else:
                status = "todo"
            cwe, owasp = found.get(r["key"], ([], []))
            for rule in exact:
                seen = expected.setdefault(rule, (set(), set()))
                seen[0].update(cwe)
                seen[1].update(owasp)
            rows.append({
                "key": r["key"],
                "type": r["type"].lower(),
                "severity": r["severity"].lower(),
                "default_profile": "yes" if r["key"] in active else "no",
                "scope": r.get("scope", "").lower(),
                "tier": tier(r),
                "status": status,
                "sonda_rule": " ".join(exact or related),
                "cwe": " ".join(cwe),
                "owasp_2021": " ".join(owasp),
            })
        with open(os.path.join(args.out, f"{lang}.csv"), "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        summary.append((label, rows))

    lines = [
        "# Compatibility with SonarQube rules",
        "",
        "Which SonarQube rule keys have an equivalent in sonda"
        " ([ADR-0007](../adr/0007-sonarqube-rule-parity.md)).",
        f"Refreshed by `scripts/sonar_parity.py` on {datetime.date.today().isoformat()},"
        f" against SonarQube {version}.",
        "",
        "- **done**: a sonda rule covers it (`exact` in sonda's catalog);",
        "  **partial**: a sonda rule is related but differs, for example syntactic where",
        "  SonarQube uses taint analysis; **todo**: not covered yet.",
        "- **tier** is a first guess at the analysis needed: `syntactic` (tree-sitter queries),",
        "  `types` (a type checker, tagged type-dependent), `dataflow` (symbolic execution).",
        "  It's confirmed when a rule is implemented.",
        "",
        "| Language | Rules (not deprecated) | Done | Partial | Todo: syntactic | Todo: types | Todo: dataflow |",
        "|---|---|---|---|---|---|---|",
    ]
    for label, rows in summary:
        if rows is None:
            lines.append(f"| {label} | not available on this SonarQube edition | | | | | |")
            continue
        live = [r for r in rows if r["status"] not in ("deprecated", "template")]
        count = lambda pred: sum(1 for r in live if pred(r))
        todo = lambda t: count(lambda r: r["status"] == "todo" and r["tier"] == t)
        lines.append(f"| {label} | {len(live)} | {count(lambda r: r['status'] == 'done')} | "
                     f"{count(lambda r: r['status'] == 'partial')} | {todo('syntactic')} | "
                     f"{todo('types')} | {todo('dataflow')} |")
    # Standards drift: what sonda records against what SonarQube says.
    drift = []
    for s in sonda:
        # Rules with no exact key record standards of their own choosing.
        if s["id"] not in expected:
            continue
        want = expected[s["id"]]
        have = ({str(c) for c in s.get("cwe", [])}, set(s.get("owasp_2021", [])))
        if have != want:
            drift.append(f"| `{s['id']}` | {fmt(have)} | {fmt(want)} |")
    lines += [
        "",
        "## Security standards",
        "",
        "CWE ids and OWASP Top 10 2021 categories in sonda's catalog, compared with",
        "SonarQube's for the keys each rule covers exactly. Rules without an exact key",
        "aren't compared.",
        "",
    ]
    if drift:
        lines += [f"{len(drift)} rules differ:", "",
                  "| Rule | sonda | SonarQube |", "|---|---|---|", *drift]
    else:
        lines.append("All match.")
    lines += ["", "Per-language details: the `.csv` files in this directory."]
    with open(os.path.join(args.out, "README.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines[14:]))


def fmt(standards):
    cwe, owasp = standards
    parts = [f"CWE-{c}" for c in sorted(cwe, key=int)] + sorted(owasp)
    return ", ".join(parts) or "none"


if __name__ == "__main__":
    main()
