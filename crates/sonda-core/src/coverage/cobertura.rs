//! Cobertura's XML report (`coverage.xml`, from coverage.py's `coverage xml`,
//! the Maven and Gradle plugins, istanbul's `cobertura` reporter and
//! coverlet). A class's `filename` is relative to one of the report's
//! `<source>` directories, so each is tried in turn, then the path's end
//! (a CI's checkout path is rarely the local one). A line's branches come
//! from its `condition-coverage="50% (1/2)"`, and a method's calls from the
//! hits of its first line.

use super::xml::{Event, Tag, scan};
use super::{Candidates, FileData, relative_path};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Default)]
struct Reader {
    sources: Vec<String>,
    in_source: bool,
    /// The `filename` of the class being read.
    class: Option<String>,
    /// Elements open, to tell a class's own lines from its methods'.
    in_method: bool,
    /// The method being read: its name, and its first line's number and hits.
    method: Option<(String, Option<(usize, u64)>)>,
    files: BTreeMap<String, FileData>,
}

pub(super) fn parse(text: &str, roots: &[&Path]) -> Vec<(Candidates, FileData)> {
    let mut reader = Reader::default();
    scan(text, |event| {
        match event {
            Event::Start(tag) => reader.start(&tag),
            Event::End(name) => reader.end(name),
            Event::Text(text) if reader.in_source => reader.sources.push(text.into_owned()),
            Event::Text(_) => {}
        }
        true
    });
    let sources = std::mem::take(&mut reader.sources);
    reader
        .files
        .into_iter()
        .map(|(filename, data)| {
            let mut paths: Vec<String> = sources
                .iter()
                .map(|s| relative_path(&Path::new(s).join(&filename), roots))
                .collect();
            paths.push(relative_path(Path::new(&filename), roots));
            paths.dedup();
            (
                Candidates {
                    paths,
                    suffix: true,
                },
                data,
            )
        })
        .collect()
}

impl Reader {
    fn start(&mut self, tag: &Tag) {
        match tag.name {
            "source" => self.in_source = true,
            "class" => self.class = tag.attr("filename").map(str::to_string),
            "method" => {
                self.in_method = true;
                self.method = Some((tag.attr("name").unwrap_or_default().to_string(), None));
            }
            "line" => self.line(tag),
            _ => {}
        }
    }

    fn end(&mut self, name: &str) {
        match name {
            "source" => self.in_source = false,
            "class" => self.class = None,
            "method" => self.finish_method(),
            _ => {}
        }
    }

    fn finish_method(&mut self) {
        self.in_method = false;
        if let (Some((name, Some((line, hits)))), Some(path)) = (self.method.take(), &self.class) {
            self.files
                .entry(path.clone())
                .or_default()
                .add_function(line, &name, hits);
        }
    }

    fn line(&mut self, tag: &Tag) {
        let (Some(number), Some(hits)) = (tag.number("number"), tag.number("hits")) else {
            return;
        };
        let number = number as usize;
        if self.in_method {
            if let Some((_, first)) = self.method.as_mut() {
                first.get_or_insert((number, hits));
            }
            return;
        }
        let Some(path) = self.class.clone() else {
            return;
        };
        let data = self.files.entry(path).or_default();
        data.add_line(number, hits);
        if tag.attr("branch") == Some("true")
            && let Some((covered, total)) = tag.attr("condition-coverage").and_then(conditions)
        {
            for i in 0..total.min(256) {
                data.add_branch(number, "0", &i.to_string(), u64::from(i < covered));
            }
        }
    }
}

/// `(covered, total)` of `"50% (1/2)"`.
fn conditions(text: &str) -> Option<(u64, u64)> {
    let inner = text.split_once('(')?.1.split_once(')')?.0;
    let (covered, total) = inner.split_once('/')?;
    Some((covered.trim().parse().ok()?, total.trim().parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"<?xml version="1.0" ?>
<!DOCTYPE coverage SYSTEM "http://cobertura.sourceforge.net/xml/coverage-04.dtd">
<coverage version="7.4" line-rate="0.5">
  <sources><source>/repo/src</source><source>other</source></sources>
  <packages><package name="pkg"><classes>
    <class name="mod.py" filename="pkg/mod.py" line-rate="0.5">
      <methods>
        <method name="f" signature="()"><lines><line number="3" hits="2"/><line number="4" hits="2"/></lines></method>
        <method name="g" signature="()"><lines><line number="8" hits="0"/></lines></method>
      </methods>
      <lines>
        <line number="3" hits="2"/>
        <line number="4" hits="2" branch="true" condition-coverage="50% (1/2)"><conditions><condition number="0" type="jump" coverage="50%"/></conditions></line>
        <line number="8" hits="0"/>
      </lines>
    </class>
  </classes></package></packages>
</coverage>"#;

    #[test]
    fn reads_lines_branches_functions_and_source_candidates() {
        let files = parse(REPORT, &[Path::new("/repo")]);
        assert_eq!(files.len(), 1);
        let (candidates, data) = &files[0];
        assert!(candidates.suffix);
        assert_eq!(
            candidates.paths,
            ["src/pkg/mod.py", "other/pkg/mod.py", "pkg/mod.py"]
        );
        // The method's own `line` elements are not counted twice.
        assert_eq!(data.lines, BTreeMap::from([(3, 2), (4, 2), (8, 0)]));
        let key = |i: &str| (4, "0".to_string(), i.to_string());
        assert_eq!(
            data.branches,
            BTreeMap::from([(key("0"), 1), (key("1"), 0)])
        );
        assert_eq!(
            data.functions,
            BTreeMap::from([((3, "f".to_string()), 2), ((8, "g".to_string()), 0)])
        );
    }

    #[test]
    fn conditions_are_read_from_the_parenthesis() {
        assert_eq!(conditions("100% (2/2)"), Some((2, 2)));
        assert_eq!(conditions("50%"), None);
        assert_eq!(conditions("x (a/b)"), None);
    }
}
