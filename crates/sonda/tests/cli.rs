//! End-to-end tests of the `sonda` binary: exit codes, output formats and
//! commands, as a user or CI pipeline sees them.

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn sonda() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sonda"));
    cmd.env_remove("RUST_LOG");
    cmd
}

fn run(args: &[&str], dir: &Path) -> Output {
    sonda().args(args).arg(dir).output().unwrap()
}

fn code(out: &Output) -> i32 {
    out.status.code().expect("exited normally")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn project(files: &[(&str, &str)]) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (path, content) in files {
        let full = dir.path().join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    dir
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?} failed");
}

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("valid JSON on stdout")
}

#[test]
fn exit_code_reflects_the_quality_gate() {
    let clean = project(&[("app.py", "x = 1\n")]);
    let out = run(&["scan"], clean.path());
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stdout(&out).contains("Quality gate: PASSED"));

    let vulnerable = project(&[("app.js", "eval(x);\n")]);
    let out = run(&["scan"], vulnerable.path());
    assert_eq!(code(&out), 1);
    assert!(stdout(&out).contains("Quality gate: FAILED"));

    assert_eq!(code(&run(&["scan", "--no-gate"], vulnerable.path())), 0);
}

#[test]
fn errors_exit_with_2_and_a_message() {
    let dir = project(&[("app.py", "x = 1\n")]);
    let missing = dir.path().join("nope");
    let cases: Vec<(Vec<&str>, &Path, &str)> = vec![
        (vec!["scan"], &missing, "is not a directory"),
        // `--new-code -x` is already refused by clap; the `=` form reaches
        // sonda's own validation.
        (
            vec!["scan", "--new-code=-x"],
            dir.path(),
            "invalid --new-code reference",
        ),
        (
            vec!["scan", "--new-code", "-x"],
            dir.path(),
            "unexpected argument",
        ),
        (vec!["scan", "--new-code", "main"], dir.path(), "git"),
        (
            vec!["scan", "--coverage", "/no/such/lcov.info"],
            dir.path(),
            "cannot read",
        ),
    ];
    for (args, path, expected) in cases {
        let out = run(&args, path);
        assert_eq!(code(&out), 2, "{args:?}");
        assert!(
            stderr(&out).contains(expected),
            "{args:?}: {}",
            stderr(&out)
        );
        assert!(out.stdout.is_empty(), "{args:?}: no report on error");
    }
}

#[test]
fn bad_repository_config_is_an_error_not_ignored() {
    for (toml, expected) in [
        (
            "[rules]\ndisabled = [\"js/nope\"]\n",
            "unknown rule 'js/nope'",
        ),
        (
            "[[gate.conditions]]\nmetric = \"bugz\"\nop = \"gt\"\nthreshold = 0\n",
            "unknown variant `bugz`",
        ),
        ("[thresholds]\nparams = 3\n", "unknown field `params`"),
        ("[scan]\nfile_timeout_secs = 0\n", "scan.file_timeout_secs"),
    ] {
        let dir = project(&[("app.py", "x = 1\n"), ("sonda.toml", toml)]);
        let out = run(&["scan"], dir.path());
        assert_eq!(code(&out), 2, "{toml}");
        assert!(stderr(&out).contains(expected), "{toml}: {}", stderr(&out));
    }
}

#[test]
fn json_report_has_measures_gate_and_issues() {
    let dir = project(&[("src/app.js", "var x = 1;\neval(x);\n")]);
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], dir.path()));
    assert_eq!(report["tool"], "sonda");
    assert_eq!(report["measures"]["files"], 1.0);
    assert_eq!(report["measures"]["vulnerabilities"], 1.0);
    assert_eq!(report["gate"]["passed"], false);
    let rules: Vec<&str> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["rule"].as_str().unwrap())
        .collect();
    assert_eq!(rules, ["js/no-var", "js/no-eval"]);
    assert_eq!(report["issues"][1]["path"], "src/app.js");
    assert_eq!(report["issues"][1]["line"], 2);
    // The fields `sonda upload` and the server rely on (ADR-0005).
    assert_eq!(report["report_version"], 1);
    assert!(is_hex(&report["issues"][1]["fingerprint"], 32));
    assert_ne!(
        report["issues"][0]["fingerprint"],
        report["issues"][1]["fingerprint"]
    );
    assert!(is_hex(&report["files"][0]["sha256"], 64));
}

fn is_hex(v: &Value, len: usize) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[test]
fn sarif_report_is_valid_2_1_0() {
    let dir = project(&[("app.js", "eval(x);\n")]);
    let sarif = json(&run(&["scan", "--no-gate", "-f", "sarif"], dir.path()));
    assert_eq!(sarif["version"], "2.1.0");
    let run0 = &sarif["runs"][0];
    let rule_count = stdout(&sonda().arg("rules").output().unwrap())
        .lines()
        .count();
    assert_eq!(
        run0["tool"]["driver"]["rules"].as_array().unwrap().len(),
        rule_count
    );
    let result = &run0["results"][0];
    assert_eq!(result["ruleId"], "js/no-eval");
    assert_eq!(result["level"], "error");
    // ruleIndex must point at the rule it names.
    let index = result["ruleIndex"].as_u64().unwrap() as usize;
    let rule = &run0["tool"]["driver"]["rules"][index];
    assert_eq!(rule["id"], "js/no-eval");
    // CWE-95, A05:2025 and A03:2021, as GitHub's tag and as taxa the run declares.
    assert!(
        rule["properties"]["tags"]
            .as_array()
            .unwrap()
            .contains(&"external/cwe/cwe-095".into())
    );
    let targets: Vec<String> = rule["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rel| {
            let target = &rel["target"];
            let taxonomy =
                &run0["taxonomies"][target["toolComponent"]["index"].as_u64().unwrap() as usize];
            assert!(
                taxonomy["taxa"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t["id"] == target["id"]),
                "{target}"
            );
            format!(
                "{} {}",
                taxonomy["name"].as_str().unwrap(),
                taxonomy["version"].as_str().unwrap_or_default()
            )
            .trim()
            .to_string()
                + " "
                + target["id"].as_str().unwrap()
        })
        .collect();
    assert_eq!(
        targets,
        ["CWE 95", "OWASP Top 10 2025 A05", "OWASP Top 10 2021 A03"]
    );
    let location = &result["locations"][0]["physicalLocation"];
    assert_eq!(location["artifactLocation"]["uri"], "app.js");
    assert_eq!(location["region"]["startLine"], 1);
    // Same identity as the JSON report's, so tools can correlate the two.
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], dir.path()));
    assert_eq!(
        result["partialFingerprints"]["sonda/v1"],
        report["issues"][0]["fingerprint"]
    );
}

#[test]
fn sbom_lists_lockfile_dependencies_in_both_formats() {
    let dir = project(&[
        (
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4"}},
               "node_modules/lodash": {"version": "4.17.20", "license": "MIT"}}}"#,
        ),
        ("requirements.txt", "flask==3.0.0\nrequests>=2\n"),
    ]);
    let sbom = |format: &str| {
        let out = sonda()
            .env("SOURCE_DATE_EPOCH", "1793361600")
            .args(["sbom", "--format", format])
            .arg(dir.path())
            .output()
            .unwrap();
        assert_eq!(code(&out), 0, "{}", stderr(&out));
        (stdout(&out), stderr(&out))
    };
    let (cdx, warnings) = sbom("cyclonedx");
    assert!(
        warnings
            .contains("requirements.txt: requirements without an exact `==` version: 1 not listed")
    );
    let cdx: Value = serde_json::from_str(&cdx).unwrap();
    assert_eq!(cdx["specVersion"], "1.6");
    assert_eq!(cdx["metadata"]["timestamp"], "2026-10-30T12:00:00Z");
    let purls: Vec<&str> = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["purl"].as_str().unwrap())
        .collect();
    assert_eq!(purls, ["pkg:npm/lodash@4.17.20", "pkg:pypi/flask@3.0.0"]);
    assert_eq!(
        cdx["dependencies"][0]["dependsOn"],
        serde_json::json!(["pkg:npm/lodash@4.17.20"])
    );

    let (spdx, _) = sbom("spdx");
    let spdx: Value = serde_json::from_str(&spdx).unwrap();
    assert_eq!(spdx["spdxVersion"], "SPDX-2.3");
    assert_eq!(spdx["creationInfo"]["created"], "2026-10-30T12:00:00Z");
    assert_eq!(spdx["packages"].as_array().unwrap().len(), 3);
    // Reproducible with SOURCE_DATE_EPOCH.
    assert_eq!(sbom("spdx").0, sbom("spdx").0);

    // And in the scan report.
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], dir.path()));
    assert_eq!(report["dependencies"][0]["purl"], "pkg:npm/lodash@4.17.20");
    assert_eq!(report["dependencies"][0]["direct"], true);
}

#[test]
fn advisories_fill_the_dependency_gate_metrics() {
    let dir = project(&[
        (
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4"}},
               "node_modules/lodash": {"version": "4.17.20"}}}"#,
        ),
        (
            "sonda.toml",
            "[[gate.conditions]]\nmetric = \"severe_vulnerable_dependencies\"\nop = \"gt\"\nthreshold = 0\n",
        ),
    ]);
    let osv = project(&[(
        "npm/GHSA-35jh-r3h4-6jhm.json",
        r#"{"id": "GHSA-35jh-r3h4-6jhm", "modified": "2024-01-01T00:00:00Z",
            "summary": "Command Injection in lodash", "aliases": ["CVE-2021-23337"],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}"#,
    )]);

    // Without advisories: no data, so the gate passes.
    let out = run(&["scan", "-f", "json"], dir.path());
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let report = json(&out);
    assert_eq!(report["gate"]["conditions"][0]["status"], "no_data");
    assert!(report.get("vulnerabilities").is_none());

    let out = sonda()
        .args(["scan", "-f", "json", "--advisories"])
        .arg(osv.path())
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(
        code(&out),
        1,
        "the severe vulnerability fails the gate: {}",
        stderr(&out)
    );
    let report = json(&out);
    assert_eq!(report["measures"]["severe_vulnerable_dependencies"], 1.0);
    assert_eq!(
        report["vulnerabilities"][0]["advisory"],
        "GHSA-35jh-r3h4-6jhm"
    );
    assert_eq!(report["vulnerabilities"][0]["fixed_in"], "4.17.21");

    let text = stdout(
        &sonda()
            .args(["scan", "--no-gate", "--advisories"])
            .arg(osv.path())
            .arg(dir.path())
            .output()
            .unwrap(),
    );
    assert!(
        text.contains("CRITICAL  lodash 4.17.20  GHSA-35jh-r3h4-6jhm"),
        "{text}"
    );

    let missing = sonda()
        .args(["scan", "--advisories", "/nonexistent/osv"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(code(&missing), 2, "{}", stderr(&missing));
}

#[test]
fn output_file_receives_the_report_and_stdout_stays_empty() {
    let dir = project(&[("app.js", "eval(x);\n")]);
    let target = dir.path().join("out.sarif");
    let out = sonda()
        .args(["scan", "--no-gate", "-f", "sarif", "-o"])
        .arg(&target)
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(code(&out), 0);
    assert!(out.stdout.is_empty());
    assert!(stderr(&out).contains("quality gate FAILED"));
    let written: Value = serde_json::from_str(&std::fs::read_to_string(target).unwrap()).unwrap();
    assert_eq!(written["runs"][0]["results"][0]["ruleId"], "js/no-eval");
}

#[test]
fn new_code_defaults_to_the_latest_tag_or_the_default_branch() {
    let dir = project(&[("old.js", "eval(a);\n")]);
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@example.com"]);
    git(root, &["config", "user.name", "t"]);
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "old"]);
    git(root, &["tag", "v1.0"]);
    std::fs::write(root.join("new.js"), "eval(b);\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "after the release"]);

    // On main: changes since the latest tag.
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], root));
    assert_eq!(report["new_code_basis"], "latest_tag");
    assert_eq!(report["new_code_reference"], "v1.0");
    assert_eq!(report["new_code_description"], "changes since tag v1.0");
    let new_paths: Vec<&str> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["is_new"] == true)
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert_eq!(new_paths, ["new.js"]);
    let text = stdout(&run(&["scan", "--no-gate"], root));
    assert!(
        text.contains("new code = changes since tag v1.0, marked *"),
        "{text}"
    );

    // On a branch: its merge base with main.
    git(root, &["checkout", "-qb", "feature"]);
    std::fs::write(root.join("feature.js"), "eval(c);\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "feature"]);
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], root));
    assert_eq!(
        (
            report["new_code_basis"].as_str(),
            report["new_code_reference"].as_str()
        ),
        (Some("default_branch"), Some("main"))
    );

    // `none`, and a sonda.toml setting, win over auto.
    let report = json(&run(
        &["scan", "--no-gate", "-f", "json", "--new-code", "none"],
        root,
    ));
    assert_eq!(report["new_code_basis"], "whole_project");
    assert_eq!(report["new_code_reference"], serde_json::Value::Null);
    std::fs::write(root.join("sonda.toml"), "[scan]\nnew_code = \"v1.0\"\n").unwrap();
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], root));
    assert_eq!(
        (
            report["new_code_basis"].as_str(),
            report["new_code_reference"].as_str()
        ),
        (Some("given"), Some("v1.0"))
    );
}

#[test]
fn a_baseline_starts_new_code_where_it_is_set() {
    let dir = project(&[("old.js", "eval(a);\n")]);
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@example.com"]);
    git(root, &["config", "user.name", "t"]);
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "old"]);

    // No tag: the whole project, and how to fix that.
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], root));
    assert_eq!(report["new_code_basis"], "whole_project");
    assert!(
        report["new_code_description"]
            .as_str()
            .unwrap()
            .contains("sonda baseline"),
        "{}",
        report["new_code_description"]
    );

    let out = run(&["baseline"], root);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("git push origin sonda-baseline"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        code(&run(&["baseline"], root)),
        2,
        "an existing baseline isn't moved by accident"
    );

    std::fs::write(root.join("new.js"), "eval(b);\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "new"]);
    let report = json(&run(&["scan", "--no-gate", "-f", "json"], root));
    assert_eq!(report["new_code_reference"], "sonda-baseline");
    let new_paths: Vec<&str> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["is_new"] == true)
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert_eq!(new_paths, ["new.js"]);
}

#[test]
fn only_new_lists_new_issues_but_gate_sees_everything() {
    let dir = project(&[("old.js", "eval(a);\n")]);
    let root = dir.path();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "user.email", "t@example.com"]);
    git(root, &["config", "user.name", "t"]);
    git(root, &["add", "."]);
    git(root, &["commit", "-qm", "old"]);
    git(root, &["checkout", "-qb", "feature"]);
    std::fs::write(root.join("new.js"), "eval(b);\n").unwrap();

    let out = run(
        &["scan", "--new-code", "main", "--only-new", "-f", "json"],
        root,
    );
    assert_eq!(
        code(&out),
        1,
        "the new vulnerability fails the default gate"
    );
    let report = json(&out);
    assert_eq!(report["new_code_reference"], "main");
    let paths: Vec<&str> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["new.js"]);
    assert_eq!(report["measures"]["vulnerabilities"], 2.0);
    assert_eq!(report["measures"]["new_vulnerabilities"], 1.0);
}

#[test]
fn coverage_report_feeds_the_coverage_measures() {
    let dir = project(&[
        ("app.js", "const a = 1;\nconst b = 2;\n"),
        ("lcov.info", "SF:app.js\nDA:1,3\nDA:2,0\nend_of_record\n"),
    ]);
    let lcov = dir.path().join("lcov.info");
    let out = sonda()
        .args(["scan", "-f", "json", "--coverage"])
        .arg(&lcov)
        .arg(dir.path())
        .output()
        .unwrap();
    let report = json(&out);
    assert_eq!(report["measures"]["coverage"], 50.0);
    assert_eq!(report["measures"]["new_coverage"], 50.0);
    assert_eq!(
        code(&out),
        1,
        "50% < 80% on new code fails the default gate"
    );
}

#[test]
fn init_writes_a_working_config_once() {
    let dir = project(&[("app.py", "x = 1\n")]);
    let config = dir.path().join("sonda.toml");
    let out = run(&["init"], dir.path());
    assert_eq!(code(&out), 0);
    let written = std::fs::read_to_string(&config).unwrap();
    assert!(written.contains("[[gate.conditions]]"));
    assert_eq!(
        code(&run(&["scan"], dir.path())),
        0,
        "the written config loads"
    );

    std::fs::write(&config, "# mine\n").unwrap();
    let again = run(&["init"], dir.path());
    assert_eq!(code(&again), 2);
    assert!(stderr(&again).contains("already exists"));
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "# mine\n",
        "not overwritten"
    );

    assert_eq!(code(&run(&["init", "--force"], dir.path())), 0);
    assert_eq!(std::fs::read_to_string(&config).unwrap(), written);
}

/// The library's events have the target `sonda_core`, not `sonda`; `-v` must
/// still show them.
#[test]
fn verbose_shows_the_librarys_log_events() {
    let dir = project(&[("a.py", "x = 1\n")]);
    let out = run(&["-v", "scan"], dir.path());
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("compiled rules"), "{}", stderr(&out));
}

#[test]
fn rules_command_lists_every_rule() {
    let text = stdout(&sonda().arg("rules").output().unwrap());
    assert!(text.lines().count() >= 30);
    assert!(text.lines().any(|l| l.starts_with("js/no-eval ")));
    let md = stdout(
        &sonda()
            .args(["rules", "--format", "markdown"])
            .output()
            .unwrap(),
    );
    assert!(md.starts_with("# Rules"));
    assert!(md.contains("Noncompliant:"));
}

#[test]
fn worker_isolation_does_not_change_the_report() {
    let shared = "function shared(a, b) {\n  if (a == b) { return a + b; }\n  for (let i = 0; i < a; i++) { b += i * 2; }\n  return b - a;\n}\n";
    let dir = project(&[
        ("src/a.js", &format!("var x = 1;\n{shared}")),
        ("src/b.js", &format!("{shared}eval(y);\n")),
        ("tool.py", "def f(a=[]):\n    return a  # TODO\n"),
        ("broken.py", "def (:\n"),
        ("Main.java", "class Main { void f() { System.exit(1); } }\n"),
        (
            "sonda.toml",
            "[duplication]\nmin_tokens = 20\nmin_lines = 3\n",
        ),
    ]);
    std::fs::write(dir.path().join("latin1.py"), b"x = '\xff'\n").unwrap();
    let isolated = run(&["scan", "--no-gate", "-f", "json"], dir.path());
    let in_process = run(
        &["scan", "--no-gate", "-f", "json", "--no-isolation"],
        dir.path(),
    );
    assert_eq!(code(&isolated), 0, "{}", stderr(&isolated));
    let report = json(&isolated);
    assert!(!report["duplications"].as_array().unwrap().is_empty());
    assert!(report["warnings"].as_array().unwrap().len() >= 2);
    assert_eq!(stdout(&isolated), stdout(&in_process));
}

/// ADR-0003: a parser crash loses only the file being parsed. Debug builds
/// abort a worker on a file containing `SONDA_TEST_WORKER_ABORT`.
#[cfg(debug_assertions)]
#[test]
fn a_parser_crash_loses_only_that_file() {
    let marker = "SONDA_ABORT_MARKER_42";
    // The crashing file comes first; with one worker, every later file
    // needs the restarted worker.
    let dir = project(&[
        ("a-crash.py", &format!("x = '{marker}'\n")),
        ("b.js", "eval(x);\n"),
        ("c.js", "var y = 1;\n"),
    ]);
    let out = sonda()
        .args(["scan", "--no-gate", "-f", "json", "--jobs", "1"])
        .arg(dir.path())
        .env("SONDA_TEST_WORKER_ABORT", marker)
        .output()
        .unwrap();
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let report = json(&out);
    let rules: Vec<&str> = report["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["rule"].as_str().unwrap())
        .collect();
    assert_eq!(
        rules,
        ["js/no-eval", "js/no-var"],
        "the other files are analyzed"
    );
    let warnings = report["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .starts_with("a-crash.py: skipped, the parser crashed"),
        "{warnings:?}"
    );
}

/// ADR-0004: inside the sandbox a worker cannot read files, connect to the
/// network or run programs. Debug builds make a worker try all three on a
/// file containing `SONDA_TEST_WORKER_ESCAPE`.
#[cfg(all(debug_assertions, any(target_os = "linux", target_os = "macos")))]
#[test]
fn sandboxed_workers_cannot_escape() {
    let marker = "SONDA_ESCAPE_MARKER_7";
    // Connecting succeeds as soon as the listener exists; no accept needed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let dir = project(&[("escape.py", &format!("x = '{marker}'\n"))]);
    let scan = |sandbox: &str| {
        sonda()
            .args([
                "scan",
                "--no-gate",
                "-f",
                "json",
                "--jobs",
                "1",
                "--sandbox",
                sandbox,
            ])
            .arg(dir.path())
            .env("SONDA_TEST_WORKER_ESCAPE", marker)
            .env("SONDA_TEST_WORKER_ESCAPE_PORT", &port)
            .output()
            .unwrap()
    };
    let warning = |out: &Output| {
        assert_eq!(code(out), 0, "{}", stderr(out));
        json(out)["warnings"][0].as_str().unwrap().to_string()
    };

    // The seam works: without a sandbox every attempt succeeds.
    assert_eq!(
        warning(&scan("off")),
        "escape.py: skipped, escape attempt: read=true connect=true exec=true"
    );
    // `require` fails the run unless the worker is fully sandboxed.
    let locked = warning(&scan("require"));
    assert!(
        locked == "escape.py: skipped, escape attempt: read=false connect=false exec=false"
            || locked.contains("killed by the sandbox"),
        "{locked}"
    );
}

/// Regression: verbose logs printed a file name's raw escape sequence to
/// the terminal (tracing-subscriber does not escape `%`-formatted values).
#[cfg(unix)]
#[test]
fn logs_escape_control_characters_from_the_repository() {
    let dir = tempfile::tempdir().unwrap();
    // Invalid UTF-8 content makes the file name appear in a debug log.
    std::fs::write(dir.path().join("evil\x1b[2J.py"), b"x = '\xff'\n").unwrap();

    let out = run(&["scan", "--no-gate", "-vv"], dir.path());
    assert_eq!(code(&out), 0);
    let stderr = stderr(&out);
    assert!(stderr.contains("evil\\u{1b}[2J.py"), "{stderr}");
    assert!(!stderr.contains('\x1b'), "raw escape in logs");
    assert!(!out.stdout.contains(&0x1b), "raw escape in report");
}

// ------------------------------------------------------------------ upload

/// What the fake server received.
struct Request {
    head: String,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// An HTTP server on localhost that answers one request with `status` and
/// `reply`, then hands back what it received.
fn fake_server(
    status: &'static str,
    reply: &'static str,
) -> (String, std::thread::JoinHandle<Request>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            head.push_str(&line);
        }
        let request = Request {
            head,
            body: Vec::new(),
        };
        let len: usize = request.header("content-length").unwrap().parse().unwrap();
        let mut body = vec![0; len];
        reader.read_exact(&mut body).unwrap();
        let mut stream = stream;
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        )
        .unwrap();
        Request { body, ..request }
    });
    (url, handle)
}

/// A scanned project and its JSON report, kept outside the project.
fn scanned(files: &[(&str, &str)]) -> (TempDir, TempDir) {
    let dir = project(files);
    let out = tempfile::tempdir().unwrap();
    let report = out.path().join("report.json");
    let status = sonda()
        .args(["scan", "--no-gate", "-f", "json", "-o"])
        .arg(&report)
        .arg(dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    (dir, out)
}

fn upload(dir: &Path, out: &Path, server: &str) -> Command {
    let mut cmd = sonda();
    cmd.args([
        "upload",
        "--project",
        "payments",
        "--branch",
        "main",
        "--commit",
        "0123abc",
    ])
    .arg("--server")
    .arg(server)
    .arg("--root")
    .arg(dir)
    .arg(out.join("report.json"))
    .env("SONDA_TOKEN", "s3cret")
    .env_remove("SONDA_TOKEN_FILE")
    .env_remove("SONDA_SERVER");
    // The fake server is on localhost; never route through a proxy.
    for var in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

#[test]
fn upload_sends_the_report_and_sources() {
    let (dir, out) = scanned(&[("src/app.js", "var x = 1;\n")]);
    let (url, server) = fake_server(
        "201 Created",
        r#"{"analysis_id":7,"issues":{"open":1,"new":1,"reopened":0,"fixed":2}}"#,
    );
    let result = upload(dir.path(), out.path(), &url).output().unwrap();
    assert_eq!(code(&result), 0, "{}", stderr(&result));
    assert!(
        stderr(&result).contains("uploaded 1 files for payments/main to http://127.0.0.1:"),
        "{}",
        stderr(&result)
    );
    assert!(
        stderr(&result).contains(": 1 open issues (1 new, 2 fixed)"),
        "{}",
        stderr(&result)
    );

    let request = server.join().unwrap();
    assert!(
        request.head.starts_with("POST /api/analyses HTTP/1.1"),
        "{}",
        request.head
    );
    assert_eq!(request.header("authorization"), Some("Bearer s3cret"));
    assert_eq!(request.header("content-encoding"), Some("gzip"));
    let mut json = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::read::GzDecoder::new(&request.body[..]),
        &mut json,
    )
    .unwrap();
    let body: Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(body["project"], "payments");
    assert_eq!(body["branch"], "main");
    assert_eq!(body["commit"], "0123abc");
    let report: Value =
        serde_json::from_slice(&std::fs::read(out.path().join("report.json")).unwrap()).unwrap();
    assert_eq!(body["report"], report);
    assert_eq!(body["sources"][0]["path"], "src/app.js");
    assert_eq!(body["sources"][0]["content"], "var x = 1;\n");
}

#[test]
fn upload_reports_the_servers_refusal() {
    let (dir, out) = scanned(&[("a.js", "var x;\n")]);
    let (url, server) = fake_server("401 Unauthorized", r#"{"error":"bad token"}"#);
    let result = upload(dir.path(), out.path(), &url).output().unwrap();
    server.join().unwrap();
    assert_eq!(code(&result), 2);
    assert!(stderr(&result).contains("401"), "{}", stderr(&result));
    assert!(stderr(&result).contains("bad token"), "{}", stderr(&result));
}

/// These fail before connecting: nothing listens on the URL they get.
#[test]
fn upload_refuses_before_sending_anything() {
    let nowhere = "http://127.0.0.1:9";
    let (dir, out) = scanned(&[("a.js", "var x;\n")]);

    std::fs::write(dir.path().join("a.js"), "var y;\n").unwrap();
    let changed = stderr(&upload(dir.path(), out.path(), nowhere).output().unwrap());
    assert!(changed.contains("changed since the scan"), "{changed}");

    let insecure = stderr(
        &upload(dir.path(), out.path(), "http://example.com")
            .output()
            .unwrap(),
    );
    assert!(insecure.contains("plain http"), "{insecure}");

    let no_token = upload(dir.path(), out.path(), nowhere)
        .env_remove("SONDA_TOKEN")
        .output()
        .unwrap();
    assert_eq!(code(&no_token), 2);
    assert!(
        stderr(&no_token).contains("SONDA_TOKEN"),
        "{}",
        stderr(&no_token)
    );

    // SONDA_TOKEN_FILE works like --token-file, and never alongside SONDA_TOKEN.
    let token_file = out.path().join("token");
    std::fs::write(&token_file, "s3cret\n").unwrap();
    let both = stderr(
        &upload(dir.path(), out.path(), nowhere)
            .env("SONDA_TOKEN_FILE", &token_file)
            .output()
            .unwrap(),
    );
    assert!(both.contains("not both"), "{both}");
    let from_file = stderr(
        &upload(dir.path(), out.path(), nowhere)
            .env_remove("SONDA_TOKEN")
            .env("SONDA_TOKEN_FILE", &token_file)
            .output()
            .unwrap(),
    );
    assert!(
        !from_file.contains("token"),
        "the token was read: {from_file}"
    );

    let report = out.path().join("report.json");
    let text = std::fs::read_to_string(&report).unwrap();
    std::fs::write(&report, text.replace("\"a.js\"", "\"../a.js\"")).unwrap();
    let unsafe_path = stderr(&upload(dir.path(), out.path(), nowhere).output().unwrap());
    assert!(unsafe_path.contains("unsafe path"), "{unsafe_path}");
}
