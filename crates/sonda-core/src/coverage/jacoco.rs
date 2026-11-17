//! JaCoCo's XML report (`jacoco.xml`, from the Maven and Gradle plugins).
//! A file is its package plus the `sourcefile` name, relative to the source
//! root, so it is matched to a scanned file by that path's end. JaCoCo counts
//! instructions and branches per line, not individual branches, so a line's
//! `cb` covered and `mb` missed branches become that many numbered ones, and
//! it says only whether a method ran, not how often.

use super::xml::{Event, Tag, scan};
use super::{Candidates, FileData};
use std::collections::BTreeMap;

#[derive(Default)]
struct Reader {
    package: String,
    /// The `sourcefilename` of the class being read, which its methods belong to.
    class_file: Option<String>,
    /// The method being read: its name and first line.
    method: Option<(String, usize)>,
    /// The `sourcefile` being read.
    file: Option<String>,
    files: BTreeMap<String, FileData>,
}

pub(super) fn parse(text: &str) -> Vec<(Candidates, FileData)> {
    let mut reader = Reader::default();
    scan(text, |event| {
        match event {
            Event::Start(tag) => reader.start(&tag),
            Event::End(name) => reader.end(name),
            Event::Text(_) => {}
        }
        true
    });
    reader
        .files
        .into_iter()
        .map(|(path, data)| {
            let candidates = Candidates {
                paths: vec![path],
                suffix: true,
            };
            (candidates, data)
        })
        .collect()
}

impl Reader {
    fn path(&self, name: &str) -> String {
        if self.package.is_empty() {
            name.to_string()
        } else {
            format!("{}/{name}", self.package)
        }
    }

    fn start(&mut self, tag: &Tag) {
        match tag.name {
            "package" => self.package = tag.attr("name").unwrap_or_default().to_string(),
            "class" => self.class_file = tag.attr("sourcefilename").map(|n| self.path(n)),
            "method" => {
                self.method = tag
                    .attr("name")
                    .zip(tag.number("line"))
                    .map(|(name, line)| (name.to_string(), line as usize));
            }
            "sourcefile" => {
                self.file = tag.attr("name").map(|n| self.path(n));
            }
            "line" => self.line(tag),
            "counter" => self.method_counter(tag),
            _ => {}
        }
    }

    fn end(&mut self, name: &str) {
        match name {
            "package" => self.package.clear(),
            "class" => self.class_file = None,
            "method" => self.method = None,
            "sourcefile" => self.file = None,
            _ => {}
        }
    }

    /// `<line nr mi ci mb cb>`: missed and covered instructions and branches.
    fn line(&mut self, tag: &Tag) {
        let (Some(path), Some(nr)) = (self.file.clone(), tag.number("nr")) else {
            return;
        };
        let nr = nr as usize;
        let (mi, ci) = (tag.number("mi").unwrap_or(0), tag.number("ci").unwrap_or(0));
        let (mb, cb) = (tag.number("mb").unwrap_or(0), tag.number("cb").unwrap_or(0));
        let data = self.files.entry(path).or_default();
        if mi.saturating_add(ci) > 0 {
            data.add_line(nr, ci);
        }
        // Branch counts are bounded so a hostile report can't make a huge map.
        for i in 0..cb.saturating_add(mb).min(256) {
            data.add_branch(nr, "0", &i.to_string(), u64::from(i < cb));
        }
    }

    /// `<counter type="METHOD" covered="1">` inside a method: it ran.
    fn method_counter(&mut self, tag: &Tag) {
        let (Some((name, line)), Some(path)) = (&self.method, &self.class_file) else {
            return;
        };
        if tag.attr("type") == Some("METHOD") {
            let calls = tag.number("covered").unwrap_or(0);
            let data = self.files.entry(path.clone()).or_default();
            data.add_function(*line, name, calls);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" "report.dtd">
<report name="app">
  <package name="com/acme">
    <class name="com/acme/Util" sourcefilename="Util.java">
      <method name="add" desc="(II)I" line="4"><counter type="METHOD" missed="0" covered="1"/></method>
      <method name="&lt;init&gt;" desc="()V" line="2"><counter type="METHOD" missed="1" covered="0"/></method>
      <counter type="CLASS" missed="0" covered="1"/>
    </class>
    <sourcefile name="Util.java">
      <line nr="2" mi="3" ci="0" mb="0" cb="0"/>
      <line nr="4" mi="0" ci="5" mb="1" cb="1"/>
      <line nr="5" mi="1" ci="2" mb="2" cb="0"/>
      <counter type="LINE" missed="1" covered="2"/>
    </sourcefile>
  </package>
  <package name=""><sourcefile name="Main.kt"><line nr="1" mi="0" ci="2"/></sourcefile></package>
</report>"#;

    #[test]
    fn reads_lines_branches_and_methods_by_package_path() {
        let files = parse(REPORT);
        let paths: Vec<_> = files.iter().map(|(c, _)| c.paths[0].as_str()).collect();
        assert_eq!(paths, ["Main.kt", "com/acme/Util.java"]);
        assert!(files.iter().all(|(c, _)| c.suffix));
        let util = &files[1].1;
        // A line with missed instructions only is uncovered, not absent.
        assert_eq!(util.lines, BTreeMap::from([(2, 0), (4, 5), (5, 2)]));
        let key = |l: usize, i: &str| (l, "0".to_string(), i.to_string());
        assert_eq!(
            util.branches,
            BTreeMap::from([
                (key(4, "0"), 1),
                (key(4, "1"), 0),
                (key(5, "0"), 0),
                (key(5, "1"), 0)
            ])
        );
        assert_eq!(
            util.functions,
            BTreeMap::from([((4, "add".to_string()), 1), ((2, "<init>".to_string()), 0)])
        );
        assert_eq!(files[0].1.lines, BTreeMap::from([(1, 2)]));
    }
}
