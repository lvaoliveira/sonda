//! Taint across files (ADR-0027, T4): each file's facts, as the worker
//! serializes them, and the project pass that joins them into paths.
//!
//! A worker analyzes one file. For each taint rule it reports, as one fact:
//! - the summaries of the functions other files can call: which
//!   parameters reach a sink, the return value, or another file's function;
//! - the request's values it passes to other files' functions;
//! - the results of other files' functions it passes to a sink.
//!
//! The scanner joins them, as it joins declarations for ADR-0020's rules:
//! a value passed to a function whose parameter reaches a sink is a
//! finding at that sink, with a path through both files. No syntax tree
//! leaves the sandbox; a malformed fact is dropped, and its file's part of
//! any path with it.

use super::taint::{Callee, Key};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// The fact's kind, followed by the rule's id: `taint:js/sql-injection`.
pub(crate) const FACT_PREFIX: &str = "taint:";

/// How many files a path crosses through functions that pass a value on.
const MAX_HOPS: usize = 4;
/// The most steps a cross-file path keeps: its first and its last half.
const MAX_STEPS: usize = 12;

/// A step's message and span, 1-based, as an issue's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StepFact {
    pub(crate) m: String,
    pub(crate) l: usize,
    pub(crate) c: usize,
    pub(crate) el: usize,
    pub(crate) ec: usize,
}

/// A sink: its span, the issue's fingerprint (computed where the line's
/// text is), and whether a comment on its line suppresses the rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SinkFact {
    pub(crate) at: StepFact,
    pub(crate) fingerprint: String,
    #[serde(default)]
    pub(crate) suppressed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ParamPath {
    pub(crate) p: usize,
    pub(crate) steps: Vec<StepFact>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ParamSink {
    pub(crate) p: usize,
    pub(crate) steps: Vec<StepFact>,
    pub(crate) sink: SinkFact,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ParamCall {
    pub(crate) p: usize,
    pub(crate) steps: Vec<StepFact>,
    pub(crate) callee: Callee,
    pub(crate) arg: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Summary {
    pub(crate) key: Key,
    #[serde(default)]
    pub(crate) returns_sql: bool,
    #[serde(default)]
    pub(crate) to_sink: Vec<ParamSink>,
    #[serde(default)]
    pub(crate) to_return: Vec<ParamPath>,
    #[serde(default)]
    pub(crate) returns_source: Option<Vec<StepFact>>,
    #[serde(default)]
    pub(crate) to_call: Vec<ParamCall>,
}

/// A request's value passed to another file's function; `steps` end with
/// "passed to `f`" at the call.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Call {
    pub(crate) steps: Vec<StepFact>,
    pub(crate) callee: Callee,
    pub(crate) arg: usize,
}

/// Another file's function's result reaching a sink here.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Return {
    pub(crate) callee: Callee,
    /// "passed to `f`" and "returned by `f`", at the call.
    pub(crate) passed: StepFact,
    pub(crate) returned: StepFact,
    #[serde(default)]
    pub(crate) args: Vec<ParamPath>,
    /// From the call's result to the sink, ending with the sink's step.
    pub(crate) after: Vec<StepFact>,
    pub(crate) sink: SinkFact,
    #[serde(default)]
    pub(crate) needs_sql: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct FileFacts {
    #[serde(default)]
    pub(crate) summaries: Vec<Summary>,
    #[serde(default)]
    pub(crate) calls: Vec<Call>,
    #[serde(default)]
    pub(crate) returns: Vec<Return>,
}

/// A finding the project pass made: the sink's file, the sink, and the
/// path, each step with its file.
#[derive(Debug)]
pub(crate) struct Found {
    pub(crate) file: usize,
    pub(crate) sink: SinkFact,
    pub(crate) steps: Vec<(usize, StepFact)>,
}

/// The C# summaries a call can reach: (file, key) pairs, from ADR-0020's
/// index. The project pass passes one in; tests can pass none.
pub(crate) type CsResolver<'r> = &'r dyn Fn(usize, &Callee) -> Vec<(usize, Key)>;

/// Joins one rule's facts, `facts[i]` being file `i`'s (with `paths[i]`
/// its path from the project root), into the findings that cross files.
pub(crate) fn compose(
    paths: &[&str],
    facts: &[Option<FileFacts>],
    cs: Option<CsResolver>,
) -> Vec<Found> {
    let by_path: HashMap<String, usize> = paths
        .iter()
        .enumerate()
        .map(|(i, p)| (normalize(p), i))
        .collect();
    let mut summaries: HashMap<(usize, &Key), &Summary> = HashMap::new();
    for (i, f) in facts.iter().enumerate() {
        for s in f.iter().flat_map(|f| &f.summaries) {
            summaries.entry((i, &s.key)).or_insert(s);
        }
    }
    let py_index = std::cell::OnceCell::new();
    let resolve = |from: usize, callee: &Callee| -> Vec<(usize, &Summary)> {
        match callee {
            Callee::Js { spec, name, member } => {
                let Some(file) = resolve_module(paths[from], spec, &by_path) else {
                    return Vec::new();
                };
                candidate_keys(name.as_deref(), member.as_deref())
                    .into_iter()
                    .find_map(|k| summaries.get(&(file, &k)).map(|s| vec![(file, *s)]))
                    .unwrap_or_default()
            }
            Callee::Py {
                module,
                name,
                member,
            } => py_candidates(
                paths[from],
                module,
                name.as_deref(),
                member.as_deref(),
                &by_path,
                py_index.get_or_init(|| PyModules::new(&by_path)),
            )
            .into_iter()
            .find_map(|(file, k)| summaries.get(&(file, &k)).map(|s| vec![(file, *s)]))
            .unwrap_or_default(),
            Callee::Cs { .. } => cs
                .map(|r| r(from, callee))
                .unwrap_or_default()
                .into_iter()
                .filter_map(|(file, key)| summaries.get(&(file, &key)).map(|s| (file, *s)))
                .collect(),
        }
    };

    let mut found = Vec::new();
    // A request's value passed to another file's function, and on through
    // the functions that pass it on.
    struct Work {
        steps: Vec<(usize, StepFact)>,
        from: usize,
        callee: Callee,
        arg: usize,
        hops: usize,
    }
    let mut work: Vec<Work> = facts
        .iter()
        .enumerate()
        .flat_map(|(i, f)| {
            f.iter().flat_map(move |f| {
                f.calls.iter().map(move |c| Work {
                    steps: c.steps.iter().map(|s| (i, s.clone())).collect(),
                    from: i,
                    callee: c.callee.clone(),
                    arg: c.arg,
                    hops: 0,
                })
            })
        })
        .collect();
    let mut seen: HashSet<(usize, String, usize)> = HashSet::new();
    while let Some(w) = work.pop() {
        for (file, s) in resolve(w.from, &w.callee) {
            // The same call reached twice: once is enough.
            if !seen.insert((file, format!("{:?}", s.key), w.arg)) && w.hops > 0 {
                continue;
            }
            for t in s.to_sink.iter().filter(|t| t.p == w.arg) {
                let mut steps = w.steps.clone();
                steps.extend(t.steps.iter().map(|x| (file, x.clone())));
                found.push(Found {
                    file,
                    sink: t.sink.clone(),
                    steps,
                });
            }
            if w.hops + 1 >= MAX_HOPS {
                continue;
            }
            for c in s.to_call.iter().filter(|c| c.p == w.arg) {
                let mut steps = w.steps.clone();
                steps.extend(c.steps.iter().map(|x| (file, x.clone())));
                work.push(Work {
                    steps,
                    from: file,
                    callee: c.callee.clone(),
                    arg: c.arg,
                    hops: w.hops + 1,
                });
            }
        }
    }
    // Another file's function's result reaching a sink.
    for (i, f) in facts.iter().enumerate() {
        for r in f.iter().flat_map(|f| &f.returns) {
            for (file, s) in resolve(i, &r.callee) {
                if r.needs_sql && !s.returns_sql {
                    continue;
                }
                let after = |mut steps: Vec<(usize, StepFact)>| {
                    steps.push((i, r.returned.clone()));
                    steps.extend(r.after.iter().map(|x| (i, x.clone())));
                    steps
                };
                if let Some(source) = &s.returns_source {
                    found.push(Found {
                        file: i,
                        sink: r.sink.clone(),
                        steps: after(source.iter().map(|x| (file, x.clone())).collect()),
                    });
                }
                for t in &s.to_return {
                    let Some(arg) = r.args.iter().find(|a| a.p == t.p) else {
                        continue;
                    };
                    let mut steps: Vec<(usize, StepFact)> =
                        arg.steps.iter().map(|x| (i, x.clone())).collect();
                    steps.push((i, r.passed.clone()));
                    steps.extend(t.steps.iter().map(|x| (file, x.clone())));
                    found.push(Found {
                        file: i,
                        sink: r.sink.clone(),
                        steps: after(steps),
                    });
                }
            }
        }
    }
    // Each sink once, by its shortest path; capped like a file's paths.
    found.sort_by_key(|f| (f.file, f.sink.at.l, f.sink.at.c, f.steps.len()));
    found.dedup_by(|a, b| a.file == b.file && a.sink.at == b.sink.at);
    for f in &mut found {
        if f.steps.len() > MAX_STEPS {
            let half = MAX_STEPS / 2;
            let tail = f.steps.split_off(f.steps.len() - half);
            f.steps.truncate(half);
            f.steps.extend(tail);
        }
    }
    found.retain(|f| !f.sink.suppressed);
    found
}

/// The keys a call can mean, most specific first: `users.find` is
/// `./users`'s export `find`, or its default export's member `find`.
fn candidate_keys(name: Option<&str>, member: Option<&str>) -> Vec<Key> {
    let key = |export: &str, member: Option<&str>| Key {
        export: export.to_string(),
        member: member.map(str::to_string),
    };
    match (name, member) {
        (Some(n), m) => vec![key(n, m)],
        (None, Some(m)) => vec![key(m, None), key("default", Some(m))],
        (None, None) => vec![key("default", None)],
    }
}

/// The project file a relative import names: `./users` from `src/a.ts` is
/// `src/users.ts`, `src/users.js`, `src/users/index.ts`…; TypeScript's
/// `./users.js` is `users.ts` too. Package imports aren't the project's.
fn resolve_module(from: &str, spec: &str, by_path: &HashMap<String, usize>) -> Option<usize> {
    if !spec.starts_with("./") && !spec.starts_with("../") {
        return None;
    }
    let from = normalize(from);
    let dir = from.rsplit_once('/').map_or("", |(d, _)| d);
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for seg in spec.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    let base = parts.join("/");
    const EXTS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];
    let stem = [".js", ".jsx", ".mjs", ".cjs"]
        .iter()
        .find_map(|e| base.strip_suffix(e))
        .unwrap_or(&base);
    std::iter::once(base.clone())
        .chain(EXTS.iter().map(|e| format!("{stem}.{e}")))
        .chain(EXTS.iter().map(|e| format!("{base}/index.{e}")))
        .find_map(|p| by_path.get(&p).copied())
}

/// The files and keys a Python call can mean, most specific first:
/// `from app import db; db.query(x)` is `app/__init__.py`'s `db.query`, or
/// `app/db.py`'s `query`.
fn py_candidates(
    from: &str,
    module: &str,
    name: Option<&str>,
    member: Option<&str>,
    by_path: &HashMap<String, usize>,
    modules: &PyModules,
) -> Vec<(usize, Key)> {
    let key = |export: &str, member: Option<&str>| Key {
        export: export.to_string(),
        member: member.map(str::to_string),
    };
    let mut out = Vec::new();
    match (name, member) {
        (Some(n), m) => {
            if let Some(f) = resolve_py_module(from, module, by_path, modules) {
                out.push((f, key(n, m)));
            }
            // `n` a submodule: `from app import db`.
            if let Some(m) = m {
                let sub = if module.ends_with('.') {
                    format!("{module}{n}")
                } else {
                    format!("{module}.{n}")
                };
                if let Some(f) = resolve_py_module(from, &sub, by_path, modules) {
                    out.push((f, key(m, None)));
                }
            }
        }
        (None, Some(m)) => {
            if let Some(f) = resolve_py_module(from, module, by_path, modules) {
                out.push((f, key(m, None)));
            }
        }
        (None, None) => {}
    }
    out
}

/// The project file a Python module names: `.db` from `app/views.py` is
/// `app/db.py` or `app/db/__init__.py`; `..db` one package up; `app.db`
/// whichever file of the project ends with `app/db.py` (or its package's
/// `__init__.py`), when only one does.
fn resolve_py_module(
    from: &str,
    module: &str,
    by_path: &HashMap<String, usize>,
    modules: &PyModules,
) -> Option<usize> {
    let dots = module.chars().take_while(|c| *c == '.').count();
    let rest = module[dots..].replace('.', "/");
    if dots > 0 {
        let from = normalize(from);
        let mut parts: Vec<&str> = from.split('/').collect();
        parts.pop();
        for _ in 1..dots {
            parts.pop()?;
        }
        let base = parts.join("/");
        let join = |tail: &str| {
            if base.is_empty() {
                tail.to_string()
            } else if tail.is_empty() {
                base.clone()
            } else {
                format!("{base}/{tail}")
            }
        };
        let stem = join(&rest);
        return [format!("{stem}.py"), format!("{}/__init__.py", stem)]
            .iter()
            .find_map(|p| by_path.get(p.trim_start_matches('/')).copied());
    }
    match modules.by_suffix.get(&rest).map(Vec::as_slice) {
        Some([one]) => Some(*one),
        _ => None,
    }
}

/// The project's Python files by every module path they can be imported
/// by: `src/app/db.py` is `db`, `app/db` and `src/app/db`; a package's
/// `__init__.py` is its directory's. Built once per project pass, so an
/// absolute import's resolution doesn't scan every file.
pub(crate) struct PyModules {
    by_suffix: HashMap<String, Vec<usize>>,
}

impl PyModules {
    fn new(by_path: &HashMap<String, usize>) -> Self {
        let mut by_suffix: HashMap<String, Vec<usize>> = HashMap::new();
        for (path, &i) in by_path {
            let Some(stem) = path.strip_suffix(".py") else {
                continue;
            };
            let stem = stem.strip_suffix("/__init__").unwrap_or(stem);
            let parts: Vec<&str> = stem.split('/').collect();
            for k in 0..parts.len() {
                by_suffix.entry(parts[k..].join("/")).or_default().push(i);
            }
        }
        PyModules { by_suffix }
    }
}

fn normalize(p: &str) -> String {
    p.replace('\\', "/").trim_start_matches("./").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> HashMap<String, usize> {
        ["src/a.ts", "src/users.ts", "src/lib/index.js", "src/db.ts"]
            .iter()
            .enumerate()
            .map(|(i, p)| (p.to_string(), i))
            .collect()
    }

    #[test]
    fn python_modules_resolve_to_project_files() {
        let p: HashMap<String, usize> = [
            "app/views.py",
            "app/db.py",
            "app/services/__init__.py",
            "app/services/users.py",
            "lib/util.py",
            "other/util.py",
        ]
        .iter()
        .enumerate()
        .map(|(i, p)| (p.to_string(), i))
        .collect();
        let m = PyModules::new(&p);
        assert_eq!(resolve_py_module("app/views.py", ".db", &p, &m), Some(1));
        assert_eq!(
            resolve_py_module("app/views.py", ".services", &p, &m),
            Some(2)
        );
        assert_eq!(
            resolve_py_module("app/services/users.py", "..db", &p, &m),
            Some(1)
        );
        assert_eq!(resolve_py_module("app/views.py", "app.db", &p, &m), Some(1));
        assert_eq!(
            resolve_py_module("app/views.py", "app.services.users", &p, &m),
            Some(3)
        );
        // Two `util` modules: ambiguous; and a package's module isn't ours.
        assert_eq!(resolve_py_module("app/views.py", "util", &p, &m), None);
        assert_eq!(resolve_py_module("app/views.py", "requests", &p, &m), None);
        // `from . import db; db.query(x)`.
        let c = py_candidates("app/views.py", ".", Some("db"), Some("query"), &p, &m);
        assert!(c.iter().any(|(f, k)| *f == 1 && k.export == "query"));
    }

    #[test]
    fn relative_imports_resolve_to_project_files() {
        let p = paths();
        assert_eq!(resolve_module("src/a.ts", "./users", &p), Some(1));
        assert_eq!(resolve_module("src/a.ts", "./users.js", &p), Some(1));
        assert_eq!(resolve_module("src/a.ts", "./lib", &p), Some(2));
        assert_eq!(resolve_module("src/lib/index.js", "../db", &p), Some(3));
        assert_eq!(resolve_module("src/a.ts", "users", &p), None);
        assert_eq!(resolve_module("src/a.ts", "../../../x", &p), None);
    }
}
