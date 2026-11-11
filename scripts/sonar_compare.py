#!/usr/bin/env python3
"""Compare sonda's findings with SonarQube's on the same commit (ADR-0007).

Reads a sonda JSON report and a SonarQube project's issues (from a server you
have access to, or SonarCloud for a public project), and pairs them: same
file, the same SonarQube rule key (a sonda rule's `sonar` references), and a
line within `--tolerance`. Prints a summary and, per rule key, what only one
side found; `--details` writes every difference, for review.

Only files SonarQube analyzed as main code are compared: it applies few rules
to test files, so those would only add noise. A sonda finding counts as a
difference only when SonarQube's quality profile has its key active.

    sonda scan . -f json -o sonda.json --no-gate --new-code none
    python3 scripts/sonar_compare.py --server http://sonarqube:9000 \\
        --token-file ~/.sonar_token --project my-project --report sonda.json

    # A public project on SonarCloud: no token.
    python3 scripts/sonar_compare.py --server https://sonarcloud.io \\
        --project org_repo --report sonda.json --path-prefix src/

Standard library only. The token is sent as a bearer header and never
printed. SonarQube's messages go to `--details` only, for local review: the
compatibility docs describe differences in sonda's own words.
"""

import argparse
import collections
import json
import subprocess
import sys
import urllib.parse
import urllib.request

# Statuses of issues SonarQube raised, whatever was decided about them since.
RAISED = "OPEN,CONFIRMED,ACCEPTED,FALSE_POSITIVE"
PAGE = 500
# SonarQube's issue search returns at most this many results per query.
SEARCH_LIMIT = 10_000
ISSUES = "/api/issues/search"


class Sonar:
    def __init__(self, server, token):
        self.server = server.rstrip("/")
        self.token = token

    def get(self, path, **query):
        url = f"{self.server}{path}?{urllib.parse.urlencode(query)}"
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as r:
            return json.load(r)

    def pages(self, path, key, **query):
        page = 1
        while True:
            data = self.get(path, p=page, ps=PAGE, **query)
            yield from data[key]
            total = data.get("paging", data).get("total", 0)
            if page * PAGE >= min(total, SEARCH_LIMIT):
                return
            page += 1

    def files(self, project, branch):
        """Path -> (qualifier, language) of every file SonarQube indexed. A main
        file it couldn't parse has no lines of code; its qualifier is "UNPARSED".
        (Test files never have lines of code.)"""
        extra = {"branch": branch} if branch else {}

        def qualifier(c):
            parsed = any(m["metric"] == "ncloc" for m in c["measures"])
            return c["qualifier"] if parsed or c["qualifier"] != "FIL" else "UNPARSED"

        return {
            c["path"]: (qualifier(c), c.get("language"))
            for c in self.pages("/api/measures/component_tree", "components",
                                component=project, qualifiers="FIL,UTS", metricKeys="ncloc",
                                **extra)
        }

    def issues(self, project, branch):
        extra = {"branch": branch} if branch else {}
        query = dict(componentKeys=project, issueStatuses=RAISED, **extra)
        head = self.get(ISSUES, ps=1, facets="rules", **query)
        if head["paging"]["total"] <= SEARCH_LIMIT:
            return list(self.pages(ISSUES, "issues", **query))
        # Past the search limit: one query per rule.
        out = []
        for value in head["facets"][0]["values"]:
            if value["count"] > SEARCH_LIMIT:
                print(f"warning: {value['val']} has {value['count']} issues; "
                      f"only {SEARCH_LIMIT} are compared", file=sys.stderr)
            out += self.pages(ISSUES, "issues", rules=value["val"], **query)
        return out

    def active_keys(self, project):
        """Language -> the rule keys (`S1234`) its quality profile has active."""
        out = {}
        for profile in self.get("/api/qualityprofiles/search", project=project)["profiles"]:
            out[profile["language"]] = {
                r["key"].split(":", 1)[1]
                for r in self.pages("/api/rules/search", "rules", qprofile=profile["key"],
                                    activation="true", f="internalKey")
            }
        return out

    def revision(self, project, branch):
        extra = {"branch": branch} if branch else {}
        analyses = self.get("/api/project_analyses/search", project=project, ps=1,
                            **extra)["analyses"]
        return analyses[0].get("revision") if analyses else None


def sonda_rules(sonda):
    """Rule id -> (keys it covers exactly, keys it's related to), and the ids on by default."""
    rules = json.loads(subprocess.run([sonda, "rules", "--format", "json"], check=True,
                                      capture_output=True, text=True).stdout)
    refs = {r["id"]: ({s["key"] for s in r["sonar"] if s["exact"]},
                      {s["key"] for s in r["sonar"] if not s["exact"]}) for r in rules}
    return refs, {r["id"] for r in rules if r["on_by_default"]}


def match(sonar_lines, sonda_lines, tolerance):
    """Pairs each SonarQube line with a sonda line: the same line first, then
    the nearest within the tolerance. Returns (pairs, unmatched sonar lines,
    unmatched sonda lines); lines are (line, payload)."""
    left, right = list(sonar_lines), list(sonda_lines)
    pairs = []
    for distance in range(tolerance + 1):
        rest = []
        for a in left:
            # A SonarQube issue without a line is on the file: any line will do.
            j = next((j for j, b in enumerate(right)
                      if abs(a[0] - b[0]) == distance or a[0] == 0 and distance == 0), None)
            if j is None:
                rest.append(a)
            else:
                pairs.append((a, right.pop(j)))
        left = rest
    return pairs, left, right


def sonar_by_key(issues, main_files, tests, analyzed, prefix):
    """SonarQube's issues on the compared files, by (path, key), and a count
    of those on other files, by why they aren't compared."""
    by_key, elsewhere = collections.defaultdict(list), collections.Counter()
    for i in issues:
        path = prefix + i["component"].split(":", 1)[1]
        if path not in main_files:
            elsewhere["test files" if path in tests else "other files"] += 1
        elif path not in analyzed:
            elsewhere["files sonda doesn't analyze"] += 1
        else:
            by_key[(path, i["rule"].split(":", 1)[1])].append((i.get("line", 0), i))
    return by_key, elsewhere


def sonda_by_key(report, main_files, active, refs, unparsed):
    """sonda's issues that SonarQube's profile could have raised, by (path,
    key) for each key their rule covers, and a count of the others."""
    by_key, elsewhere = collections.defaultdict(list), collections.Counter()
    for i in report["issues"]:
        exact, related = refs.get(i["rule"], (set(), set()))
        keys = exact | related
        if i["path"] in unparsed:
            elsewhere["files SonarQube couldn't parse"] += 1
        elif i["path"] not in main_files:
            elsewhere["files SonarQube doesn't analyze as main code"] += 1
        elif not keys:
            elsewhere["rules with no SonarQube key"] += 1
        elif not keys & active.get(main_files[i["path"]], set()):
            elsewhere["rules whose key SonarQube's profile has off"] += 1
        else:
            for key in keys:
                by_key[(i["path"], key)].append((i["line"], i))
    return by_key, elsewhere


def pair_up(sonar, sonda, tolerance):
    """Per key: how many issues both raised, and what only one side did."""
    matched = collections.Counter()
    only_sonar, only_sonda = collections.defaultdict(list), collections.defaultdict(list)
    # The sonda issues that matched under one of their keys.
    paired = set()
    for path, key in sorted(set(sonar) | set(sonda)):
        pairs, left, right = match(sonar.get((path, key), []), sonda.get((path, key), []),
                                   tolerance)
        matched[key] += len(pairs)
        paired |= {id(b[1]) for _, b in pairs}
        only_sonar[key] += [(path, line, i) for line, i in left]
        only_sonda[key] += [(path, line, i) for line, i in right]
    # A sonda issue matched under another of its keys isn't a difference.
    for key, items in only_sonda.items():
        only_sonda[key] = [d for d in items if id(d[2]) not in paired]
    return matched, only_sonar, only_sonda


def compare(report, sonar_data, refs, on_by_default, prefix, tolerance):
    """sonar_data: SonarQube's (issues, files, active keys per language)."""
    issues, files, active = sonar_data
    main_files = {prefix + p: lang for p, (q, lang) in files.items() if q == "FIL"}
    tests = {prefix + p for p, (q, _) in files.items() if q == "UTS"}
    unparsed = {prefix + p for p, (q, _) in files.items() if q == "UNPARSED"}
    analyzed = {f["path"] for f in report["files"]}
    report_rules = set(report.get("active_rules") or on_by_default)
    # SonarQube key -> the sonda rules that cover it.
    covering = collections.defaultdict(set)
    for rule, (exact, related) in refs.items():
        for key in exact | related:
            covering[key].add(rule)
    sonar, sonar_elsewhere = sonar_by_key(issues, main_files, tests, analyzed, prefix)
    sonda, sonda_elsewhere = sonda_by_key(report, main_files, active, refs, unparsed)
    matched, only_sonar, only_sonda = pair_up(sonar, sonda, tolerance)

    def why_missing(key):
        rules = covering.get(key)
        if not rules:
            return "no sonda rule"
        if not rules & report_rules:
            return "sonda rule off"
        return "sonda rule on"

    return {"matched": matched, "only_sonar": only_sonar, "only_sonda": only_sonda,
            "sonar_elsewhere": sonar_elsewhere, "sonda_elsewhere": sonda_elsewhere,
            "why_missing": why_missing, "covering": covering, "main_files": main_files}


def totals(result, only_sonar, only_sonda):
    """The summary's first table: what both raised, and what wasn't compared."""
    matched = sum(result["matched"].values())
    by_reason = collections.Counter()
    for key, items in only_sonar.items():
        by_reason[result["why_missing"](key)] += len(items)
    sonar_total = matched + sum(len(v) for v in only_sonar.values())
    sonda_total = len({id(d[2]) for v in only_sonda.values() for d in v})
    out = ["| | Issues |", "|---|---|"]
    out += [f"| SonarQube's, also raised by sonda | {matched} of {sonar_total} |"]
    out += [f"| SonarQube's, not raised: {reason} | {by_reason[reason]} |"
            for reason in ("sonda rule on", "sonda rule off", "no sonda rule")]
    out += [f"| sonda's, not raised by SonarQube (key active there) | {sonda_total} |"]
    out += [f"| Not compared: SonarQube's on {what} | {n} |"
            for what, n in sorted(result["sonar_elsewhere"].items())]
    out += [f"| Not compared: sonda's on {what} | {n} |"
            for what, n in sorted(result["sonda_elsewhere"].items())]
    return out


def per_key(result, only_sonar, only_sonda):
    """The summary's second table: each key with a difference, most first."""
    def size(k):
        return len(only_sonar.get(k, [])) + len(only_sonda.get(k, []))

    out = ["| Key | Both | SonarQube only | sonda only | sonda rules |", "|---|---|---|---|---|"]
    for key in sorted(set(only_sonar) | set(only_sonda), key=lambda k: (-size(k), k)):
        rules = ", ".join(sorted(result["covering"].get(key, []))) or "none"
        out += [f"| {key} | {result['matched'][key]} | {len(only_sonar.get(key, []))} "
                f"({result['why_missing'](key)}) | {len(only_sonda.get(key, []))} | {rules} |"]
    return out


def summary(result, project, revision):
    only_sonar = {k: v for k, v in result["only_sonar"].items() if v}
    only_sonda = {k: v for k, v in result["only_sonda"].items() if v}
    out = [f"# {project} at {revision or 'an unknown revision'}", ""]
    out += [f"{len(result['main_files'])} files SonarQube analyzed as main code.", ""]
    out += totals(result, only_sonar, only_sonda)
    out += [""] + per_key(result, only_sonar, only_sonda)
    return "\n".join(out)


def details(result):
    return {
        "sonarqube_only": [
            {"key": key, "path": p, "line": line, "why": result["why_missing"](key),
             "sonarqube_message": i.get("message")}
            for key, items in sorted(result["only_sonar"].items()) for p, line, i in items],
        "sonda_only": [
            {"key": key, "path": p, "line": line, "rule": i["rule"], "message": i["message"]}
            for key, items in sorted(result["only_sonda"].items()) for p, line, i in items],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--server", required=True)
    ap.add_argument("--token-file", help="omit for a public SonarCloud project")
    ap.add_argument("--project", required=True, help="SonarQube project key")
    ap.add_argument("--branch", help="SonarQube branch, if not the main one")
    ap.add_argument("--report", required=True, help="sonda's JSON report")
    ap.add_argument("--sonda", default="sonda", help="the sonda binary, for its rules")
    ap.add_argument("--commit", help="warn if SonarQube's last analysis isn't of this commit")
    ap.add_argument("--path-prefix", default="",
                    help="what to put before SonarQube's paths to get sonda's")
    ap.add_argument("--tolerance", type=int, default=1, help="lines apart that still match")
    ap.add_argument("--details", help="write every difference to this JSON file")
    args = ap.parse_args()

    token = open(args.token_file).read().strip() if args.token_file else None
    sonar = Sonar(args.server, token)
    report = json.load(open(args.report))
    refs, on_by_default = sonda_rules(args.sonda)
    revision = sonar.revision(args.project, args.branch)
    if args.commit and revision and not revision.startswith(args.commit) \
            and not args.commit.startswith(revision):
        print(f"warning: SonarQube's last analysis is of {revision}, not {args.commit}",
              file=sys.stderr)
    sonar_data = (sonar.issues(args.project, args.branch), sonar.files(args.project, args.branch),
                  sonar.active_keys(args.project))
    result = compare(report, sonar_data, refs, on_by_default, args.path_prefix, args.tolerance)
    print(summary(result, args.project, revision))
    if args.details:
        with open(args.details, "w") as f:
            json.dump(details(result), f, indent=1)
            f.write("\n")


if __name__ == "__main__":
    main()
