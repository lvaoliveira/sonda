//! Regular expressions as patterns (ADR-0013): a parser for Python's `re`
//! dialect, a small character-set algebra, and the analyses the regex rules
//! use. Pure functions over text: no I/O.
//!
//! The parser is recursive descent with a hard depth cap, so hostile input
//! costs a skipped pattern, never a stack overflow.

const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 4000;
const MAX_CHAR: u32 = 0x10_FFFF;

// ---------------------------------------------------- character sets

/// A set of code points, as sorted, non-touching inclusive ranges.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct Set(Vec<(u32, u32)>);

impl Set {
    pub(crate) fn empty() -> Set {
        Set(Vec::new())
    }

    pub(crate) fn of(c: char) -> Set {
        Set(vec![(c as u32, c as u32)])
    }

    pub(crate) fn range(lo: u32, hi: u32) -> Set {
        if lo > hi {
            Set::empty()
        } else {
            Set(vec![(lo, hi)])
        }
    }

    fn normalize(mut v: Vec<(u32, u32)>) -> Set {
        v.sort_unstable();
        let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
        for (lo, hi) in v {
            match out.last_mut() {
                Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
                _ => out.push((lo, hi)),
            }
        }
        Set(out)
    }

    pub(crate) fn union(&self, other: &Set) -> Set {
        let mut v = self.0.clone();
        v.extend_from_slice(&other.0);
        Set::normalize(v)
    }

    pub(crate) fn negate(&self) -> Set {
        let mut out = Vec::new();
        let mut next = 0u32;
        for &(lo, hi) in &self.0 {
            if lo > next {
                out.push((next, lo - 1));
            }
            next = hi.saturating_add(1);
        }
        if next <= MAX_CHAR {
            out.push((next, MAX_CHAR));
        }
        Set(out)
    }

    pub(crate) fn intersect(&self, other: &Set) -> Set {
        let mut out = Vec::new();
        let (mut i, mut j) = (0, 0);
        while i < self.0.len() && j < other.0.len() {
            let (a, b) = (self.0[i], other.0[j]);
            let (lo, hi) = (a.0.max(b.0), a.1.min(b.1));
            if lo <= hi {
                out.push((lo, hi));
            }
            if a.1 < b.1 {
                i += 1;
            } else {
                j += 1;
            }
        }
        Set(out)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn overlaps(&self, other: &Set) -> bool {
        !self.intersect(other).is_empty()
    }

    pub(crate) fn contains(&self, c: u32) -> bool {
        self.0.iter().any(|&(lo, hi)| lo <= c && c <= hi)
    }

    pub(crate) fn is_subset_of(&self, other: &Set) -> bool {
        self.intersect(&other.negate()).is_empty()
    }

    /// Adds the other-case ASCII letters.
    fn fold_case(&self) -> Set {
        let mut extra = Vec::new();
        for &(lo, hi) in &self.0 {
            let (l, h) = (lo.max(b'a' as u32), hi.min(b'z' as u32));
            if l <= h {
                extra.push((l - 32, h - 32));
            }
            let (l, h) = (lo.max(b'A' as u32), hi.min(b'Z' as u32));
            if l <= h {
                extra.push((l + 32, h + 32));
            }
        }
        self.union(&Set::normalize(extra))
    }
}

fn digit_set() -> Set {
    Set::range(b'0' as u32, b'9' as u32)
}

fn word_set(ascii: bool) -> Set {
    let mut s = digit_set()
        .union(&Set::range(b'a' as u32, b'z' as u32))
        .union(&Set::range(b'A' as u32, b'Z' as u32))
        .union(&Set::of('_'));
    if !ascii {
        s = s.union(&Set::range(0xAA, MAX_CHAR).intersect(&Set::range(0xC0, MAX_CHAR)));
    }
    s
}

fn space_set(ascii: bool) -> Set {
    let mut s = Set::range(9, 13).union(&Set::of(' '));
    if !ascii {
        s = s
            .union(&Set::range(0x1c, 0x1f))
            .union(&Set::of('\u{85}'))
            .union(&Set::of('\u{a0}'))
            .union(&Set::range(0x2000, 0x200a))
            .union(&Set::range(0x2028, 0x2029))
            .union(&Set::of('\u{202f}'))
            .union(&Set::of('\u{205f}'))
            .union(&Set::of('\u{3000}'));
    }
    s
}

// ---------------------------------------------------- syntax tree

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Flags {
    pub ignore_case: bool,
    pub multiline: bool,
    pub dot_all: bool,
    pub verbose: bool,
    pub ascii: bool,
    /// Java: CANON_EQ, UNICODE_CASE and UNICODE_CHARACTER_CLASS.
    pub canon_eq: bool,
    pub unicode_case: bool,
    pub unicode_class: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Greedy,
    Lazy,
    Possessive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Assertion {
    Start,
    End,
    StartAbs,
    EndAbs,
    /// Java `\G`: where the previous match ended.
    MatchStart,
    WordBoundary,
    NotWordBoundary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ClassItem {
    Char(char),
    Range(char, char),
    Shorthand(char),
    /// Java: a nested class such as the `[b-d]` in `[a[b-d]]`.
    Nested {
        negated: bool,
        items: Vec<ClassItem>,
    },
    /// Java: `[a-z&&[^aeiou]]`, the parts joined by `&&`.
    Intersect(Vec<Vec<ClassItem>>),
    /// Java: `\p{L}`, whose members this layer doesn't enumerate.
    Property {
        name: String,
        negated: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum GroupKind {
    Capture,
    Named(String),
    NonCapture,
    /// `(?i:...)`: scopes flags, so it is never redundant.
    Scoped,
    Atomic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Node {
    Empty,
    Char(char),
    Any,
    Shorthand(char),
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
    Assertion(Assertion),
    Group {
        kind: GroupKind,
        index: usize,
        inner: Box<Node>,
    },
    Look {
        ahead: bool,
        negative: bool,
        inner: Box<Node>,
    },
    BackrefIndex(usize),
    BackrefName(String),
    Conditional {
        yes: Box<Node>,
        no: Option<Box<Node>>,
    },
    Alt(Vec<Node>),
    Concat(Vec<Node>),
    Repeat {
        inner: Box<Node>,
        min: u32,
        max: Option<u32>,
        mode: Mode,
        braces: bool,
    },
    /// An octal escape such as `\012`.
    Octal(char),
    /// Java `\p{L}`, `\R`, `\X`: matched characters aren't enumerated.
    Property {
        name: String,
        negated: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParseError {
    pub message: String,
}

#[derive(Debug)]
pub(crate) struct Regex {
    pub root: Node,
    pub flags: Flags,
    pub groups: usize,
    pub names: Vec<String>,
    /// Java `\cX` escapes whose X is outside `@` to `_`.
    pub bad_controls: usize,
}

// ---------------------------------------------------- parser

struct Parser {
    chars: Vec<char>,
    pos: usize,
    flags: Flags,
    groups: usize,
    names: Vec<String>,
    nodes: usize,
    depth: usize,
    java: bool,
    bad_controls: usize,
}

fn err<T>(message: &str) -> Result<T, ParseError> {
    Err(ParseError {
        message: message.to_string(),
    })
}

/// Parses `pattern` as a Python `re` pattern.
pub(crate) fn parse(pattern: &str, flags: Flags) -> Result<Regex, ParseError> {
    parse_dialect(pattern, flags, false)
}

/// Parses `pattern` as a `java.util.regex` pattern.
pub(crate) fn parse_java(pattern: &str, flags: Flags) -> Result<Regex, ParseError> {
    parse_dialect(pattern, flags, true)
}

fn parse_dialect(pattern: &str, flags: Flags, java: bool) -> Result<Regex, ParseError> {
    let mut p = Parser {
        chars: pattern.chars().collect(),
        pos: 0,
        flags,
        groups: 0,
        names: Vec::new(),
        nodes: 0,
        depth: 0,
        java,
        bad_controls: 0,
    };
    let root = p.alternation()?;
    if p.pos < p.chars.len() {
        return err("unbalanced parenthesis");
    }
    Ok(Regex {
        root,
        flags: p.flags,
        groups: p.groups,
        names: p.names,
        bad_controls: p.bad_controls,
    })
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn looking_at(&self, s: &str) -> bool {
        s.chars()
            .enumerate()
            .all(|(i, c)| self.chars.get(self.pos + i) == Some(&c))
    }

    fn count(&mut self) -> Result<(), ParseError> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return err("pattern too large to analyze");
        }
        Ok(())
    }

    fn alternation(&mut self) -> Result<Node, ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return err("pattern nested too deeply to analyze");
        }
        let mut alts = vec![self.concatenation()?];
        while self.eat('|') {
            alts.push(self.concatenation()?);
        }
        self.depth -= 1;
        Ok(if alts.len() == 1 {
            alts.pop().unwrap_or(Node::Empty)
        } else {
            Node::Alt(alts)
        })
    }

    fn concatenation(&mut self) -> Result<Node, ParseError> {
        let mut items = Vec::new();
        loop {
            if self.flags.verbose {
                self.skip_verbose();
            }
            match self.peek() {
                None | Some('|') | Some(')') => break,
                _ => {}
            }
            let atom = self.atom()?;
            let Some(atom) = atom else { continue };
            let item = self.quantified(atom)?;
            items.push(item);
        }
        Ok(match items.len() {
            0 => Node::Empty,
            1 => items.pop().unwrap_or(Node::Empty),
            _ => Node::Concat(items),
        })
    }

    fn skip_verbose(&mut self) {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => self.pos += 1,
                Some('#') => {
                    while let Some(c) = self.peek() {
                        self.pos += 1;
                        if c == '\n' {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
    }

    fn quantified(&mut self, atom: Node) -> Result<Node, ParseError> {
        let mut node = atom;
        {
            if self.flags.verbose {
                self.skip_verbose();
            }
            let (min, max, braces) = match self.peek() {
                Some('*') => {
                    self.pos += 1;
                    (0, None, false)
                }
                Some('+') => {
                    self.pos += 1;
                    (1, None, false)
                }
                Some('?') => {
                    self.pos += 1;
                    (0, Some(1), false)
                }
                Some('{') => match self.braces()? {
                    Some((min, max)) => (min, max, true),
                    None if self.java => return err("Illegal repetition"),
                    None => return Ok(node),
                },
                _ => return Ok(node),
            };
            if matches!(node, Node::Assertion(_) | Node::Look { .. } | Node::Empty)
                && !matches!(node, Node::Look { .. })
            {
                return err("nothing to repeat");
            }
            if matches!(node, Node::Repeat { .. }) && !matches!(self.peek(), Some('?' | '+')) {
                // `a**` and `a+*` are "multiple repeat" in Python.
                if let Node::Repeat { mode, .. } = &node
                    && *mode == Mode::Greedy
                {
                    return err("multiple repeat");
                }
            }
            let mode = if self.eat('?') {
                Mode::Lazy
            } else if self.eat('+') {
                Mode::Possessive
            } else {
                Mode::Greedy
            };
            self.count()?;
            node = Node::Repeat {
                inner: Box::new(node),
                min,
                max,
                mode,
                braces,
            };
            // a quantifier applied to a repeat is only valid after lazy
            // or possessive marks, which were just consumed: a further
            // quantifier is a "multiple repeat"
            if matches!(self.peek(), Some('*' | '+' | '?')) {
                return err("multiple repeat");
            }
            if self.peek() == Some('{') {
                let save = self.pos;
                if self.braces()?.is_some() {
                    return err("multiple repeat");
                }
                self.pos = save;
            }
            Ok(node)
        }
    }

    /// Reads `{m}`, `{m,}`, `{,n}`, `{m,n}`; None (and no input consumed)
    /// when the brace is a literal.
    fn braces(&mut self) -> Result<Option<(u32, Option<u32>)>, ParseError> {
        let save = self.pos;
        self.pos += 1;
        let read = |p: &mut Parser| -> Option<u32> {
            let start = p.pos;
            while p.peek().is_some_and(|c| c.is_ascii_digit()) {
                p.pos += 1;
            }
            if p.pos == start {
                return None;
            }
            p.chars[start..p.pos]
                .iter()
                .collect::<String>()
                .parse::<u32>()
                .ok()
        };
        let lo = read(self);
        let result = if self.eat(',') {
            let hi = read(self);
            if self.eat('}') && (lo.is_some() || hi.is_some()) {
                Some((lo.unwrap_or(0), hi))
            } else {
                None
            }
        } else if self.eat('}') {
            lo.map(|n| (n, Some(n)))
        } else {
            None
        };
        if self.java && lo.is_none() {
            return err("Illegal repetition");
        }
        match result {
            Some((min, Some(max))) if min > max => err("min repeat greater than max repeat"),
            Some(r) => Ok(Some(r)),
            None => {
                self.pos = save;
                Ok(None)
            }
        }
    }

    fn atom(&mut self) -> Result<Option<Node>, ParseError> {
        self.count()?;
        let Some(c) = self.peek() else {
            return Ok(None);
        };
        self.pos += 1;
        Ok(Some(match c {
            '.' => Node::Any,
            '^' => Node::Assertion(Assertion::Start),
            '$' => Node::Assertion(Assertion::End),
            '*' | '+' | '?' => return err("nothing to repeat"),
            '{' if self.java => return err("Illegal repetition"),
            '{' => {
                self.pos -= 1;
                if self.braces()?.is_some() {
                    return err("nothing to repeat");
                }
                self.pos += 1;
                Node::Char('{')
            }
            '[' if self.java => self.java_class()?,
            '[' => self.class()?,
            '(' => return self.group(),
            '\\' if self.java => self.java_escape()?,
            '\\' => self.escape()?,
            c => Node::Char(c),
        }))
    }

    fn group(&mut self) -> Result<Option<Node>, ParseError> {
        if self.eat('?') {
            if self.java {
                return self.java_group();
            }
            if self.eat(':') {
                return self.group_body(GroupKind::NonCapture, 0).map(Some);
            }
            if self.eat('>') {
                return self.group_body(GroupKind::Atomic, 0).map(Some);
            }
            if self.eat('#') {
                while let Some(c) = self.peek() {
                    self.pos += 1;
                    if c == ')' {
                        return Ok(None);
                    }
                }
                return err("missing ), unterminated comment");
            }
            if self.eat('=') || self.eat('!') {
                let negative = self.chars[self.pos - 1] == '!';
                return self.look(true, negative).map(Some);
            }
            if self.looking_at("<=") || self.looking_at("<!") {
                self.pos += 1;
                let negative = self.eat('!');
                if !negative {
                    self.pos += 1;
                }
                return self.look(false, negative).map(Some);
            }
            if self.eat('P') {
                if self.eat('<') {
                    let name = self.name('>')?;
                    if self.names.contains(&name) {
                        return err("redefinition of group name");
                    }
                    self.names.push(name.clone());
                    self.groups += 1;
                    let index = self.groups;
                    return self.group_body(GroupKind::Named(name), index).map(Some);
                }
                if self.eat('=') {
                    let name = self.name(')')?;
                    if !self.names.contains(&name) {
                        return err("unknown group name");
                    }
                    return Ok(Some(Node::BackrefName(name)));
                }
                return err("unknown extension ?P");
            }
            if self.eat('(') {
                let start = self.pos;
                while self.peek().is_some_and(|c| c != ')') {
                    self.pos += 1;
                }
                if !self.eat(')') {
                    return err("missing ), unterminated name");
                }
                let reference: String = self.chars[start..self.pos - 1].iter().collect();
                if reference.chars().all(|c| c.is_ascii_digit()) && !reference.is_empty() {
                    let n: usize = reference.parse().unwrap_or(0);
                    if n == 0 {
                        return err("bad group number");
                    }
                } else if !self.names.contains(&reference) {
                    return err("unknown group name");
                }
                let yes = self.concatenation()?;
                let no = if self.eat('|') {
                    Some(Box::new(self.concatenation()?))
                } else {
                    None
                };
                if !self.eat(')') {
                    return err("missing ), unterminated subpattern");
                }
                return Ok(Some(Node::Conditional {
                    yes: Box::new(yes),
                    no,
                }));
            }
            return self.inline_flags();
        }
        self.groups += 1;
        let index = self.groups;
        self.group_body(GroupKind::Capture, index).map(Some)
    }

    fn name(&mut self, close: char) -> Result<String, ParseError> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c != close) {
            self.pos += 1;
        }
        if !self.eat(close) {
            return err("missing group name terminator");
        }
        let name: String = self.chars[start..self.pos - 1].iter().collect();
        let mut chars = name.chars();
        let valid = chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
            && chars.all(|c| c.is_alphanumeric() || c == '_');
        if valid {
            Ok(name)
        } else {
            err("bad character in group name")
        }
    }

    fn inline_flags(&mut self) -> Result<Option<Node>, ParseError> {
        let mut on = true;
        let mut changed = self.flags;
        let mut any = false;
        loop {
            match self.peek() {
                Some('-') if on => {
                    on = false;
                    self.pos += 1;
                }
                Some(c @ ('a' | 'i' | 'L' | 'm' | 's' | 'u' | 'x' | 'd' | 'U'))
                    if (if self.java {
                        !matches!(c, 'a' | 'L')
                    } else {
                        !matches!(c, 'd' | 'U')
                    }) =>
                {
                    self.pos += 1;
                    any = true;
                    match c {
                        'i' => changed.ignore_case = on,
                        'm' => changed.multiline = on,
                        's' => changed.dot_all = on,
                        'x' => changed.verbose = on,
                        'a' => changed.ascii = on,
                        'u' if self.java => changed.unicode_case = on,
                        'U' if self.java => changed.unicode_class = on,
                        _ => {}
                    }
                }
                Some(')') if on => {
                    self.pos += 1;
                    if !any {
                        return err("unknown extension");
                    }
                    self.flags = changed;
                    return Ok(None);
                }
                Some(':') => {
                    self.pos += 1;
                    if !any {
                        return err("missing flag");
                    }
                    let saved = self.flags;
                    self.flags = changed;
                    let result = self.group_body_open(GroupKind::Scoped, 0);
                    self.flags = saved;
                    return result.map(Some);
                }
                _ => return err("unknown extension"),
            }
        }
    }

    fn look(&mut self, ahead: bool, negative: bool) -> Result<Node, ParseError> {
        let inner = self.alternation()?;
        if !self.eat(')') {
            return err("missing ), unterminated subpattern");
        }
        Ok(Node::Look {
            ahead,
            negative,
            inner: Box::new(inner),
        })
    }

    fn group_body(&mut self, kind: GroupKind, index: usize) -> Result<Node, ParseError> {
        self.group_body_open(kind, index)
    }

    fn group_body_open(&mut self, kind: GroupKind, index: usize) -> Result<Node, ParseError> {
        let saved = self.flags;
        let inner = self.alternation()?;
        if !self.eat(')') {
            return err("missing ), unterminated subpattern");
        }
        // inline flags inside a group end with it
        if !matches!(kind, GroupKind::NonCapture) || true {
            self.flags = saved;
        }
        Ok(Node::Group {
            kind,
            index,
            inner: Box::new(inner),
        })
    }

    fn class(&mut self) -> Result<Node, ParseError> {
        let negated = self.eat('^');
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let Some(c) = self.peek() else {
                return err("unterminated character set");
            };
            self.pos += 1;
            if c == ']' && !first {
                break;
            }
            first = false;
            let lo = if c == '\\' {
                match self.class_escape()? {
                    ClassItem::Char(ch) => ch,
                    shorthand => {
                        if self.peek() == Some('-') && self.chars.get(self.pos + 1) != Some(&']') {
                            return err("bad character range");
                        }
                        items.push(shorthand);
                        continue;
                    }
                }
            } else {
                c
            };
            if self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|n| *n != ']') {
                self.pos += 1;
                let Some(h) = self.peek() else {
                    return err("unterminated character set");
                };
                self.pos += 1;
                let hi = if h == '\\' {
                    match self.class_escape()? {
                        ClassItem::Char(ch) => ch,
                        _ => return err("bad character range"),
                    }
                } else {
                    h
                };
                if hi < lo {
                    return err("bad character range");
                }
                items.push(ClassItem::Range(lo, hi));
            } else {
                items.push(ClassItem::Char(lo));
            }
        }
        Ok(Node::Class { negated, items })
    }

    fn class_escape(&mut self) -> Result<ClassItem, ParseError> {
        let Some(c) = self.peek() else {
            return err("bad escape (end of pattern)");
        };
        self.pos += 1;
        Ok(match c {
            'd' | 'D' | 's' | 'S' | 'w' | 'W' => ClassItem::Shorthand(c),
            'b' => ClassItem::Char('\u{8}'),
            c => ClassItem::Char(self.simple_escape(c, true)?),
        })
    }

    fn simple_escape(&mut self, c: char, in_class: bool) -> Result<char, ParseError> {
        Ok(match c {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'f' => '\u{c}',
            'v' => '\u{b}',
            'a' => '\u{7}',
            'x' => self.hex(2)?,
            'u' => self.hex(4)?,
            'U' => self.hex(8)?,
            'N' => {
                if !self.eat('{') {
                    return err("missing {");
                }
                while self.peek().is_some_and(|ch| ch != '}') {
                    self.pos += 1;
                }
                if !self.eat('}') {
                    return err("missing }, unterminated name");
                }
                '\u{fffd}'
            }
            '0'..='7' if in_class => {
                let mut v = c.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match self.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) => {
                            v = v * 8 + d;
                            self.pos += 1;
                        }
                        None => break,
                    }
                }
                char::from_u32(v).unwrap_or('\0')
            }
            c if c.is_ascii_alphabetic() => return err("bad escape"),
            c if c.is_ascii_digit() => return err("bad escape"),
            c => c,
        })
    }

    fn hex(&mut self, n: usize) -> Result<char, ParseError> {
        let mut v = 0u32;
        for _ in 0..n {
            let Some(d) = self.peek().and_then(|c| c.to_digit(16)) else {
                return err("incomplete escape");
            };
            self.pos += 1;
            v = v.saturating_mul(16).saturating_add(d);
        }
        match char::from_u32(v) {
            Some(c) => Ok(c),
            None => err("bad escape (value out of range)"),
        }
    }

    fn escape(&mut self) -> Result<Node, ParseError> {
        let Some(c) = self.peek() else {
            return err("bad escape (end of pattern)");
        };
        self.pos += 1;
        Ok(match c {
            'd' | 'D' | 's' | 'S' | 'w' | 'W' => Node::Shorthand(c),
            'A' => Node::Assertion(Assertion::StartAbs),
            'Z' => Node::Assertion(Assertion::EndAbs),
            'b' => Node::Assertion(Assertion::WordBoundary),
            'B' => Node::Assertion(Assertion::NotWordBoundary),
            '0' => {
                let mut v = 0;
                let mut digits = 1;
                while digits < 3 {
                    match self.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) => {
                            v = v * 8 + d;
                            self.pos += 1;
                            digits += 1;
                        }
                        None => break,
                    }
                }
                if digits > 1 {
                    Node::Octal(char::from_u32(v).unwrap_or('\0'))
                } else {
                    Node::Char('\0')
                }
            }
            '1'..='9' => {
                let mut n = c.to_digit(10).unwrap_or(0) as usize;
                // three octal digits starting 0-3 are an octal escape
                let rest: Vec<char> = self.chars[self.pos..].iter().take(2).copied().collect();
                if c <= '3' && rest.len() == 2 && rest.iter().all(|d| ('0'..='7').contains(d)) {
                    let v = c.to_digit(8).unwrap_or(0) * 64
                        + rest[0].to_digit(8).unwrap_or(0) * 8
                        + rest[1].to_digit(8).unwrap_or(0);
                    self.pos += 2;
                    return Ok(Node::Octal(char::from_u32(v).unwrap_or('\0')));
                }
                if self.peek().is_some_and(|d| d.is_ascii_digit()) {
                    n = n * 10 + self.peek().and_then(|d| d.to_digit(10)).unwrap_or(0) as usize;
                    self.pos += 1;
                }
                if n > self.groups {
                    return err("invalid group reference");
                }
                Node::BackrefIndex(n)
            }
            c => Node::Char(self.simple_escape(c, false)?),
        })
    }
}

// ---------------------------------------------------- Java dialect

impl Parser {
    fn java_group(&mut self) -> Result<Option<Node>, ParseError> {
        if self.eat(':') {
            return self.group_body(GroupKind::NonCapture, 0).map(Some);
        }
        if self.eat('>') {
            return self.group_body(GroupKind::Atomic, 0).map(Some);
        }
        if self.eat('=') || self.eat('!') {
            let negative = self.chars[self.pos - 1] == '!';
            return self.look(true, negative).map(Some);
        }
        if self.looking_at("<=") || self.looking_at("<!") {
            self.pos += 1;
            let negative = self.eat('!');
            if !negative {
                self.pos += 1;
            }
            return self.look(false, negative).map(Some);
        }
        if self.eat('<') {
            let name = self.java_group_name()?;
            if self.names.contains(&name) {
                return err("Named capturing group is already defined");
            }
            self.names.push(name.clone());
            self.groups += 1;
            let index = self.groups;
            return self.group_body(GroupKind::Named(name), index).map(Some);
        }
        self.inline_flags()
    }

    fn java_group_name(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c != '>') {
            self.pos += 1;
        }
        if !self.eat('>') {
            return err("named capturing group is missing trailing '>'");
        }
        let name: String = self.chars[start..self.pos - 1].iter().collect();
        let mut chars = name.chars();
        let valid = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric());
        if valid {
            Ok(name)
        } else {
            err("capturing group name does not start with a Latin letter")
        }
    }

    fn java_escape(&mut self) -> Result<Node, ParseError> {
        let Some(c) = self.peek() else {
            return err("Unexpected internal error: trailing backslash");
        };
        self.pos += 1;
        Ok(match c {
            'd' | 'D' | 's' | 'S' | 'w' | 'W' | 'h' | 'H' | 'v' | 'V' => Node::Shorthand(c),
            'A' => Node::Assertion(Assertion::StartAbs),
            'z' => Node::Assertion(Assertion::EndAbs),
            'Z' => Node::Assertion(Assertion::End),
            'G' => Node::Assertion(Assertion::MatchStart),
            'b' => Node::Assertion(Assertion::WordBoundary),
            'B' => Node::Assertion(Assertion::NotWordBoundary),
            'R' | 'X' => Node::Property {
                name: c.to_string(),
                negated: false,
            },
            'p' | 'P' => {
                let name = self.java_property_name()?;
                Node::Property {
                    name,
                    negated: c == 'P',
                }
            }
            'Q' => {
                let mut items = Vec::new();
                while self.pos < self.chars.len() && !self.looking_at("\\E") {
                    items.push(Node::Char(self.chars[self.pos]));
                    self.pos += 1;
                }
                if self.looking_at("\\E") {
                    self.pos += 2;
                }
                match items.len() {
                    0 => Node::Empty,
                    1 => items.pop().unwrap_or(Node::Empty),
                    _ => Node::Concat(items),
                }
            }
            'E' => Node::Empty,
            'k' => {
                if !self.eat('<') {
                    return err("\\k is not followed by '<' for named capturing group");
                }
                let name = self.java_group_name()?;
                if !self.names.contains(&name) {
                    return err("named capturing group does not exist");
                }
                Node::BackrefName(name)
            }
            '0' => {
                let mut v = 0;
                let mut digits = 0;
                while digits < 3 {
                    match self.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) if digits < 2 || v < 32 => {
                            v = v * 8 + d;
                            self.pos += 1;
                            digits += 1;
                        }
                        _ => break,
                    }
                }
                if digits == 0 {
                    return err("Illegal octal escape sequence");
                }
                Node::Octal(char::from_u32(v).unwrap_or('\0'))
            }
            '1'..='9' => {
                let mut n = c.to_digit(10).unwrap_or(0) as usize;
                while let Some(d) = self.peek().and_then(|d| d.to_digit(10)) {
                    let next = n * 10 + d as usize;
                    if next > self.groups {
                        break;
                    }
                    n = next;
                    self.pos += 1;
                }
                Node::BackrefIndex(n)
            }
            _ => Node::Char(self.java_char_escape(c)?),
        })
    }

    fn java_property_name(&mut self) -> Result<String, ParseError> {
        if self.eat('{') {
            let start = self.pos;
            while self.peek().is_some_and(|c| c != '}') {
                self.pos += 1;
            }
            if !self.eat('}') {
                return err("Unclosed character family");
            }
            Ok(self.chars[start..self.pos - 1].iter().collect())
        } else {
            match self.peek() {
                Some(c) => {
                    self.pos += 1;
                    Ok(c.to_string())
                }
                None => err("Illegal character family"),
            }
        }
    }

    /// The escapes that stand for one character, in or out of a class.
    fn java_char_escape(&mut self, c: char) -> Result<char, ParseError> {
        Ok(match c {
            't' => '\t',
            'n' => '\n',
            'r' => '\r',
            'f' => '\u{c}',
            'a' => '\u{7}',
            'e' => '\u{1b}',
            'x' => {
                if self.eat('{') {
                    let start = self.pos;
                    while self.peek().is_some_and(|d| d.is_ascii_hexdigit()) {
                        self.pos += 1;
                    }
                    let digits: String = self.chars[start..self.pos].iter().collect();
                    if !self.eat('}') || digits.is_empty() {
                        return err("Unclosed hexadecimal escape sequence");
                    }
                    match u32::from_str_radix(&digits, 16)
                        .ok()
                        .and_then(char::from_u32)
                    {
                        Some(ch) => ch,
                        None => return err("Hexadecimal codepoint is too big"),
                    }
                } else {
                    self.hex(2)?
                }
            }
            'u' => self.hex(4)?,
            'c' => {
                let Some(x) = self.peek() else {
                    return err("Illegal control escape sequence");
                };
                self.pos += 1;
                if !('@'..='_').contains(&x) {
                    self.bad_controls += 1;
                }
                char::from_u32((x as u32) ^ 64).unwrap_or('\0')
            }
            'N' => {
                if !self.eat('{') {
                    return err("Illegal/unsupported escape sequence");
                }
                while self.peek().is_some_and(|d| d != '}') {
                    self.pos += 1;
                }
                if !self.eat('}') {
                    return err("Unclosed character name escape sequence");
                }
                '\u{fffd}'
            }
            c if c.is_ascii_alphabetic() => return err("Illegal/unsupported escape sequence"),
            c => c,
        })
    }

    fn java_class(&mut self) -> Result<Node, ParseError> {
        let (negated, items) = self.java_class_body()?;
        Ok(Node::Class { negated, items })
    }

    fn java_class_body(&mut self) -> Result<(bool, Vec<ClassItem>), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return err("pattern nested too deeply to analyze");
        }
        self.count()?;
        let negated = self.eat('^');
        let mut parts: Vec<Vec<ClassItem>> = vec![Vec::new()];
        let mut first = true;
        loop {
            let Some(c) = self.peek() else {
                return err("Unclosed character class");
            };
            self.pos += 1;
            if c == ']' && !first {
                break;
            }
            first = false;
            let current = parts.len() - 1;
            match c {
                '[' => {
                    let (n, it) = self.java_class_body()?;
                    parts[current].push(ClassItem::Nested {
                        negated: n,
                        items: it,
                    });
                }
                '&' if self.peek() == Some('&') => {
                    self.pos += 1;
                    parts.push(Vec::new());
                }
                _ => {
                    let lo = if c == '\\' {
                        match self.java_class_escape()? {
                            Escaped::Char(ch) => ch,
                            Escaped::Items(items) => {
                                parts[current].extend(items);
                                continue;
                            }
                        }
                    } else {
                        c
                    };
                    let range_follows = self.peek() == Some('-')
                        && self
                            .chars
                            .get(self.pos + 1)
                            .is_some_and(|n| *n != ']' && *n != '[');
                    if range_follows {
                        self.pos += 1;
                        let h = self.peek().unwrap_or(']');
                        self.pos += 1;
                        let hi = if h == '\\' {
                            match self.java_class_escape()? {
                                Escaped::Char(ch) => ch,
                                Escaped::Items(_) => return err("Illegal character range"),
                            }
                        } else {
                            h
                        };
                        if hi < lo {
                            return err("Illegal character range");
                        }
                        parts[current].push(ClassItem::Range(lo, hi));
                    } else {
                        parts[current].push(ClassItem::Char(lo));
                    }
                }
            }
        }
        self.depth -= 1;
        let items = if parts.len() == 1 {
            parts.pop().unwrap_or_default()
        } else {
            vec![ClassItem::Intersect(parts)]
        };
        Ok((negated, items))
    }

    fn java_class_escape(&mut self) -> Result<Escaped, ParseError> {
        let Some(c) = self.peek() else {
            return err("Unexpected internal error: trailing backslash");
        };
        self.pos += 1;
        Ok(match c {
            'd' | 'D' | 's' | 'S' | 'w' | 'W' | 'h' | 'H' | 'v' | 'V' => {
                Escaped::Items(vec![ClassItem::Shorthand(c)])
            }
            'p' | 'P' => {
                let name = self.java_property_name()?;
                Escaped::Items(vec![ClassItem::Property {
                    name,
                    negated: c == 'P',
                }])
            }
            'Q' => {
                let mut items = Vec::new();
                while self.pos < self.chars.len() && !self.looking_at("\\E") {
                    items.push(ClassItem::Char(self.chars[self.pos]));
                    self.pos += 1;
                }
                if self.looking_at("\\E") {
                    self.pos += 2;
                }
                Escaped::Items(items)
            }
            '0' => {
                let mut v = 0;
                let mut digits = 0;
                while digits < 3 {
                    match self.peek().and_then(|d| d.to_digit(8)) {
                        Some(d) if digits < 2 || v < 32 => {
                            v = v * 8 + d;
                            self.pos += 1;
                            digits += 1;
                        }
                        _ => break,
                    }
                }
                if digits == 0 {
                    return err("Illegal octal escape sequence");
                }
                Escaped::Char(char::from_u32(v).unwrap_or('\0'))
            }
            'b' | 'B' | 'A' | 'z' | 'Z' | 'G' | 'R' | 'X' | 'k' | '1'..='9' => {
                return err("Illegal/unsupported escape sequence");
            }
            c => Escaped::Char(self.java_char_escape(c)?),
        })
    }
}

enum Escaped {
    Char(char),
    Items(Vec<ClassItem>),
}

// ---------------------------------------------------- analyses

/// The characters a single-character node can match; None for nodes that
/// are not one character wide.
pub(crate) fn set_of(node: &Node, flags: &Flags) -> Option<Set> {
    let s = match node {
        Node::Char(c) | Node::Octal(c) => Set::of(*c),
        Node::Any => {
            if flags.dot_all {
                Set::range(0, MAX_CHAR)
            } else {
                Set::of('\n').negate()
            }
        }
        Node::Shorthand(c) => shorthand_set(*c, flags.ascii),
        Node::Class { negated, items } => {
            let mut s = items_set(items, flags)?;
            if flags.ignore_case {
                s = s.fold_case();
            }
            return Some(if *negated { s.negate() } else { s });
        }
        _ => return None,
    };
    Some(if flags.ignore_case { s.fold_case() } else { s })
}

fn items_set(items: &[ClassItem], flags: &Flags) -> Option<Set> {
    let mut s = Set::empty();
    for item in items {
        s = s.union(&match item {
            ClassItem::Char(c) => Set::of(*c),
            ClassItem::Range(lo, hi) => Set::range(*lo as u32, *hi as u32),
            ClassItem::Shorthand(c) => shorthand_set(*c, flags.ascii),
            ClassItem::Nested { negated, items } => {
                let inner = items_set(items, flags)?;
                if *negated { inner.negate() } else { inner }
            }
            ClassItem::Intersect(parts) => {
                let mut acc: Option<Set> = None;
                for part in parts {
                    let p = items_set(part, flags)?;
                    acc = Some(match acc {
                        Some(a) => a.intersect(&p),
                        None => p,
                    });
                }
                acc.unwrap_or_default()
            }
            ClassItem::Property { .. } => return None,
        });
    }
    Some(s)
}

fn shorthand_set(c: char, ascii: bool) -> Set {
    match c {
        'h' => Set::of(' ')
            .union(&Set::of('\t'))
            .union(&Set::of('\u{a0}'))
            .union(&Set::range(0x2000, 0x200a)),
        'H' => shorthand_set('h', ascii).negate(),
        'v' => Set::range(0x0a, 0x0d)
            .union(&Set::of('\u{85}'))
            .union(&Set::range(0x2028, 0x2029)),
        'V' => shorthand_set('v', ascii).negate(),
        'd' => digit_set(),
        'D' => digit_set().negate(),
        's' => space_set(ascii),
        'S' => space_set(ascii).negate(),
        'w' => word_set(ascii),
        _ => word_set(ascii).negate(),
    }
}

/// Whether the node can match the empty string.
pub(crate) fn nullable(node: &Node) -> bool {
    match node {
        Node::Empty | Node::Assertion(_) | Node::Look { .. } => true,
        Node::Char(_)
        | Node::Octal(_)
        | Node::Any
        | Node::Shorthand(_)
        | Node::Property { .. }
        | Node::Class { .. } => false,
        Node::BackrefIndex(_) | Node::BackrefName(_) => true,
        Node::Group { inner, .. } => nullable(inner),
        Node::Conditional { yes, no } => nullable(yes) || no.as_ref().is_none_or(|n| nullable(n)),
        Node::Alt(alts) => alts.iter().any(nullable),
        Node::Concat(items) => items.iter().all(nullable),
        Node::Repeat { inner, min, .. } => *min == 0 || nullable(inner),
    }
}

/// The characters a non-empty match can start with.
pub(crate) fn first_set(node: &Node, flags: &Flags) -> Set {
    match node {
        Node::Group { inner, .. } => first_set(inner, flags),
        Node::Repeat { inner, .. } => first_set(inner, flags),
        Node::Alt(alts) => alts
            .iter()
            .fold(Set::empty(), |acc, a| acc.union(&first_set(a, flags))),
        Node::Concat(items) => {
            let mut acc = Set::empty();
            for item in items {
                acc = acc.union(&first_set(item, flags));
                if !nullable(item) {
                    break;
                }
            }
            acc
        }
        Node::Conditional { yes, no } => {
            let mut s = first_set(yes, flags);
            if let Some(n) = no {
                s = s.union(&first_set(n, flags));
            }
            s
        }
        Node::BackrefIndex(_) | Node::BackrefName(_) => Set::range(0, MAX_CHAR),
        other => set_of(other, flags).unwrap_or_default(),
    }
}

/// Visits every node, parents first.
pub(crate) fn walk<'a>(node: &'a Node, visit: &mut impl FnMut(&'a Node)) {
    visit(node);
    match node {
        Node::Group { inner, .. } | Node::Look { inner, .. } | Node::Repeat { inner, .. } => {
            walk(inner, visit)
        }
        Node::Conditional { yes, no } => {
            walk(yes, visit);
            if let Some(n) = no {
                walk(n, visit);
            }
        }
        Node::Alt(items) | Node::Concat(items) => {
            for n in items {
                walk(n, visit);
            }
        }
        _ => {}
    }
}

/// The string a node matches when it is a plain run of literal characters.
pub(crate) fn literal_text(node: &Node) -> Option<String> {
    match node {
        Node::Char(c) => Some(c.to_string()),
        Node::Concat(items) => items.iter().map(literal_text).collect(),
        Node::Group {
            kind: GroupKind::NonCapture,
            inner,
            ..
        } => literal_text(inner),
        _ => None,
    }
}

/// Cognitive-style complexity, as SonarQube scores a pattern: each
/// alternation, repetition, look-around and conditional counts 1 plus its
/// nesting depth.
pub(crate) fn complexity(node: &Node) -> usize {
    fn go(node: &Node, depth: usize) -> usize {
        match node {
            Node::Alt(alts) => 1 + depth + alts.iter().map(|a| go(a, depth + 1)).sum::<usize>(),
            Node::Repeat { inner, .. } => 1 + depth + go(inner, depth + 1),
            Node::Group { inner, .. } | Node::Look { inner, .. } => go(inner, depth + 1),
            Node::Concat(items) => items.iter().map(|a| go(a, depth)).sum(),
            Node::Conditional { yes, no } => {
                1 + depth + go(yes, depth + 1) + no.as_ref().map_or(0, |n| go(n, depth + 1))
            }
            _ => 0,
        }
    }
    go(node, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(p: &str) -> Regex {
        parse(p, Flags::default()).unwrap_or_else(|e| panic!("{p}: {}", e.message))
    }

    fn bad(p: &str) -> bool {
        parse(p, Flags::default()).is_err()
    }

    #[test]
    fn accepts_what_python_accepts() {
        for p in [
            r"\d+(\.\d+)?",
            r"^(?P<year>\d{4})-(?P<m>\d\d)$",
            r"(?:a|b)*?c",
            r"[^\]\\]+",
            r"[]a]",
            r"a{,3}",
            r"x{2,}",
            r"a{",
            r"(?i)abc",
            r"(?i:a)b",
            r"(a)\1",
            r"(?P<n>a)(?P=n)",
            r"(?<=a)b",
            r"(?<!a)b",
            r"(?=a)(?!b)",
            r"(a)?(?(1)b|c)",
            r"\x41A\n\t",
            r"a++b",
            r"(?>a)",
            r"[\w-]",
            r"[a-]",
            r"\bword\B",
            r"(?#comment)a",
        ] {
            ok(p);
        }
    }

    #[test]
    fn rejects_what_python_rejects() {
        for p in [
            "(",
            ")",
            "[a",
            "a**",
            "*a",
            "+",
            "a{2,1}",
            "[z-a]",
            r"\q",
            r"(?P<n>a)(?P<n>b)",
            r"\1",
            r"(?P=x)",
            "(?",
            r"(?<n>a)",
            "a|*",
            r"\x4",
            "(?x",
            r"[\d-z]",
        ] {
            assert!(bad(p), "{p} should not parse");
        }
    }

    #[test]
    fn counts_groups_and_names() {
        let r = ok(r"(a)(?P<n>b)(?:c)");
        assert_eq!(r.groups, 2);
        assert_eq!(r.names, ["n"]);
    }

    #[test]
    fn verbose_mode_ignores_space_and_comments() {
        let flags = Flags {
            verbose: true,
            ..Flags::default()
        };
        let r = parse("a b # note\n c", flags).unwrap();
        assert_eq!(literal_text(&r.root).as_deref(), Some("abc"));
    }

    #[test]
    fn nullable_and_sets() {
        assert!(nullable(&ok("a*").root));
        assert!(!nullable(&ok("a+").root));
        assert!(nullable(&ok("(a|)").root));
        let r = ok(r"[a-c]\d");
        let first = first_set(&r.root, &r.flags);
        assert!(first.contains('b' as u32) && !first.contains('1' as u32));
        assert!(Set::of('a').is_subset_of(&Set::range(97, 99)));
    }

    fn java_ok(p: &str) -> Regex {
        parse_java(p, Flags::default()).unwrap_or_else(|e| panic!("{p}: {}", e.message))
    }

    #[test]
    fn java_dialect_accepts_what_java_accepts() {
        for p in [
            r"\d+(\.\d+)?",
            r"(?<year>\d{4})-(?<m>\d\d)",
            r"(?<year>a)\k<year>",
            r"[a-z&&[^aeiou]]",
            r"[a[b-d]]",
            r"\p{L}+\P{Lu}",
            r"\p{IsAlphabetic}\pL",
            r"\Qa.b\E+",
            r"a*+b++c?+",
            r"(?>a)",
            r"(?i)abc(?-i:d)",
            r"\h\v\R\X",
            r"\x{1F600}\u00e9\0101\cA",
            r"\z\Z\G\A",
            r"(?<=a)b(?<!c)d",
            r"a]b}c",
        ] {
            java_ok(p);
        }
    }

    #[test]
    fn java_dialect_rejects_what_java_rejects() {
        for p in [
            "(",
            "a{",
            "a{,3}",
            "{1}",
            "*a",
            "[a",
            r"\q",
            r"\0",
            "a**",
            r"(?<1a>x)",
            r"\k<n>",
            r"(?<n>a)(?<n>b)",
            "[z-a]",
            r"(?P<n>a)",
            "(?#c)",
            r"[\b]",
            r"\x{110000}",
        ] {
            assert!(
                parse_java(p, Flags::default()).is_err(),
                "{p} should not parse"
            );
        }
    }

    #[test]
    fn java_classes_resolve_to_sets() {
        let r = java_ok("[a-z&&[^aeiou]]");
        let set = set_of(&r.root, &r.flags).unwrap();
        assert!(set.contains('b' as u32) && !set.contains('e' as u32));
        assert_eq!(java_ok(r"\cz").bad_controls, 1);
    }

    #[test]
    fn deep_nesting_is_refused() {
        let p = format!("{}a{}", "(".repeat(200), ")".repeat(200));
        assert!(parse(&p, Flags::default()).is_err());
    }
}
