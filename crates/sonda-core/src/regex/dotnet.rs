//! Whether .NET's `Regex` accepts a pattern: the syntax errors its parser
//! raises, read from the .NET regular-expression language reference and
//! behavior. No tree is built; the regex rules that analyze patterns use
//! the parser above, this only answers "would the constructor throw".
//!
//! Like .NET, a first pass numbers the capturing groups, so references
//! may come before the groups they name; the second pass scans the
//! pattern the way `Regex` does, left to right with a stack of open
//! groups.

use std::collections::HashSet;

/// Where a character-class subtraction nests deeper than this, the
/// pattern isn't judged.
const MAX_DEPTH: usize = 64;

/// The options that change how a pattern reads.
#[derive(Clone, Copy, Default)]
pub(crate) struct Options {
    /// `IgnorePatternWhitespace`, `(?x)`.
    pub(crate) x: bool,
    /// `ExplicitCapture`, `(?n)`.
    pub(crate) n: bool,
}

/// What a pattern uses that an option rejects.
#[derive(Default, Debug)]
pub(crate) struct Facts {
    /// `(?!...)` or `(?<!...)`.
    pub(crate) negative_lookaround: bool,
}

#[derive(Debug)]
pub(crate) enum Verdict {
    Valid(Facts),
    /// The constructor throws.
    Invalid,
    /// Too deep to judge.
    Unknown,
}

enum Stop {
    Invalid,
    TooDeep,
}

type Scan<T> = Result<T, Stop>;

/// The constructor throws; `_why` names the error it throws.
fn invalid<T>(_why: &str) -> Scan<T> {
    Err(Stop::Invalid)
}

/// Judges `pattern` as .NET's `Regex` would read it with `options`.
pub(crate) fn check(pattern: &str, options: Options) -> Verdict {
    let chars: Vec<char> = pattern.chars().collect();
    let groups = Groups::count(&chars, options);
    let mut p = Parser {
        c: &chars,
        pos: 0,
        options,
        groups,
        facts: Facts::default(),
    };
    match p.regex() {
        Ok(()) => Verdict::Valid(p.facts),
        Err(Stop::Invalid) => Verdict::Invalid,
        Err(Stop::TooDeep) => Verdict::Unknown,
    }
}

/// A character that may start or continue a group name, and that a
/// backslash can't escape.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '\u{200c}' || c == '\u{200d}'
}

/// Whitespace that `IgnorePatternWhitespace` skips.
fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0c')
}

fn is_special(c: char) -> bool {
    matches!(
        c,
        '\\' | '[' | '(' | ')' | '|' | '*' | '+' | '?' | '{' | '^' | '$' | '.'
    )
}

fn is_quantifier(c: char) -> bool {
    matches!(c, '*' | '+' | '?' | '{')
}

/// The Unicode general categories `\p{...}` names; the named blocks all
/// start with "Is".
const CATEGORIES: &[&str] = &[
    "L", "Lu", "Ll", "Lt", "Lm", "Lo", "M", "Mn", "Mc", "Me", "N", "Nd", "Nl", "No", "Z", "Zs",
    "Zl", "Zp", "C", "Cc", "Cf", "Cs", "Co", "Cn", "P", "Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
    "S", "Sm", "Sc", "Sk", "So",
];

fn known_property(name: &str) -> bool {
    CATEGORIES.iter().any(|c| c.eq_ignore_ascii_case(name))
        || (name.len() > 2 && name[..2].eq_ignore_ascii_case("is"))
}

// ---------------------------------------------------- group numbers

/// The pattern's group numbers and names. Unnamed groups number from 1,
/// then each name takes the next number no group has.
struct Groups {
    slots: HashSet<u64>,
    names: HashSet<String>,
}

impl Groups {
    fn count(c: &[char], options: Options) -> Groups {
        let (mut x, mut n) = (options.x, options.n);
        let mut saved: Vec<(bool, bool)> = Vec::new();
        let mut slots = HashSet::from([0]);
        let mut names: Vec<String> = Vec::new();
        let mut autocap = 1u64;
        let mut ignore_next = false;
        let mut i = 0;
        while i < c.len() {
            let ch = c[i];
            i += 1;
            match ch {
                '\\' => i += 1,
                '#' if x => {
                    while i < c.len() && c[i] != '\n' {
                        i += 1;
                    }
                }
                '[' => {
                    let mut p = Parser::bare(c, i);
                    i = match p.class(0) {
                        Ok(()) => p.pos,
                        Err(_) => c.len(),
                    };
                }
                ')' => {
                    if let Some(s) = saved.pop() {
                        (x, n) = s;
                    }
                }
                '(' if c.get(i) == Some(&'?') && c.get(i + 1) == Some(&'#') => {
                    while i < c.len() && c[i] != ')' {
                        i += 1;
                    }
                    i += 1;
                }
                '(' => {
                    saved.push((x, n));
                    if c.get(i) == Some(&'?') {
                        i += 1;
                        if i + 1 < c.len() && matches!(c[i], '<' | '\'') {
                            i += 1;
                            if c[i] != '0' && is_word(c[i]) {
                                let mut p = Parser::bare(c, i);
                                if c[i].is_ascii_digit() {
                                    slots.insert(p.decimal().unwrap_or(u64::MAX));
                                } else {
                                    names.push(p.capname());
                                }
                                i = p.pos;
                            }
                        } else {
                            let mut p = Parser::bare(c, i);
                            p.options = Options { x, n };
                            p.scan_options();
                            (x, n, i) = (p.options.x, p.options.n, p.pos);
                            match c.get(i) {
                                Some(')') => {
                                    i += 1;
                                    saved.pop();
                                }
                                // The condition of `(?(...)yes|no)` doesn't capture.
                                Some('(') => {
                                    ignore_next = true;
                                    continue;
                                }
                                _ => {}
                            }
                        }
                    } else if !n && !ignore_next {
                        slots.insert(autocap);
                        autocap += 1;
                    }
                    ignore_next = false;
                }
                _ => {}
            }
        }
        let mut named = HashSet::new();
        for name in names {
            if named.contains(&name) {
                continue;
            }
            while slots.contains(&autocap) {
                autocap += 1;
            }
            slots.insert(autocap);
            named.insert(name);
        }
        Groups {
            slots,
            names: named,
        }
    }
}

// ---------------------------------------------------- the scan

/// What the group a `(` opens is.
enum Opened {
    /// `(?imnsx-imnsx)`: changes the options, opens nothing.
    Options,
    Group,
    /// `(?(...)yes|no)`, with how many `|` it takes.
    Conditional {
        bars: usize,
    },
}

struct Frame {
    saved: Options,
    /// A conditional's limit on `|` and how many it has.
    bars: Option<(usize, usize)>,
}

struct Parser<'c> {
    c: &'c [char],
    pos: usize,
    options: Options,
    groups: Groups,
    facts: Facts,
}

impl<'c> Parser<'c> {
    /// A parser that only scans pieces: no group numbers.
    fn bare(c: &'c [char], pos: usize) -> Parser<'c> {
        Parser {
            c,
            pos,
            options: Options::default(),
            groups: Groups {
                slots: HashSet::new(),
                names: HashSet::new(),
            },
            facts: Facts::default(),
        }
    }

    fn peek(&self) -> Option<char> {
        self.c.get(self.pos).copied()
    }

    fn peek_at(&self, k: usize) -> Option<char> {
        self.c.get(self.pos + k).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += 1;
        Some(c)
    }

    fn remaining(&self) -> usize {
        self.c.len().saturating_sub(self.pos)
    }

    fn regex(&mut self) -> Scan<()> {
        let mut stack: Vec<Frame> = Vec::new();
        while self.pos < self.c.len() {
            self.blank()?;
            let start = self.pos;
            while let Some(ch) = self.peek() {
                let stops = is_special(ch) || (self.options.x && (is_space(ch) || ch == '#'));
                if stops && !(ch == '{' && !self.true_quantifier()) {
                    break;
                }
                self.pos += 1;
            }
            let end = self.pos;
            self.blank()?;
            let Some(ch) = self.peek().filter(|c| is_special(*c)) else {
                continue;
            };
            self.pos += 1;
            // A quantifier right after literal text takes its last character.
            let unit = start < end && is_quantifier(ch);
            match ch {
                '[' => self.class(0)?,
                '(' => {
                    let saved = self.options;
                    match self.group_open()? {
                        Opened::Options => {}
                        Opened::Group => stack.push(Frame { saved, bars: None }),
                        Opened::Conditional { bars } => stack.push(Frame {
                            saved,
                            bars: Some((bars, 0)),
                        }),
                    }
                    continue;
                }
                '|' => {
                    if let Some(Frame {
                        bars: Some((limit, bars)),
                        ..
                    }) = stack.last_mut()
                    {
                        *bars += 1;
                        if *bars > *limit {
                            return invalid("too many | in (?()|)");
                        }
                    }
                    continue;
                }
                ')' => {
                    let Some(frame) = stack.pop() else {
                        return invalid("too many )'s");
                    };
                    self.options = frame.saved;
                }
                '\\' => self.backslash()?,
                '^' | '$' | '.' => {}
                _ => {
                    if !unit {
                        return invalid("quantifier following nothing");
                    }
                    self.pos -= 1;
                }
            }
            self.blank()?;
            if !self.true_quantifier() {
                continue;
            }
            if self.next() == Some('{') {
                let min = self.decimal()?;
                let max = if self.peek() == Some(',') {
                    self.pos += 1;
                    if self.peek() == Some('}') {
                        u64::MAX
                    } else {
                        self.decimal()?
                    }
                } else {
                    min
                };
                self.pos += 1;
                if min > max {
                    return invalid("illegal {x,y} with x > y");
                }
            }
            self.blank()?;
            if self.peek() == Some('?') {
                self.pos += 1;
            }
        }
        if stack.is_empty() {
            Ok(())
        } else {
            invalid("not enough )'s")
        }
    }

    /// Skips comments, and whitespace under `IgnorePatternWhitespace`.
    fn blank(&mut self) -> Scan<()> {
        loop {
            if self.options.x {
                while self.peek().is_some_and(is_space) {
                    self.pos += 1;
                }
                if self.peek() == Some('#') {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.pos += 1;
                    }
                    continue;
                }
            }
            if self.peek() == Some('(')
                && self.peek_at(1) == Some('?')
                && self.peek_at(2) == Some('#')
            {
                while self.peek().is_some_and(|c| c != ')') {
                    self.pos += 1;
                }
                if self.next().is_none() {
                    return invalid("unterminated (?#...) comment");
                }
                continue;
            }
            return Ok(());
        }
    }

    /// `*`, `+`, `?`, `{n}`, `{n,}` or `{n,m}`: other braces are literal.
    fn true_quantifier(&self) -> bool {
        match self.peek() {
            Some('*' | '+' | '?') => true,
            Some('{') => {
                let digits = |i: &mut usize| {
                    let start = *i;
                    while self.c.get(*i).is_some_and(char::is_ascii_digit) {
                        *i += 1;
                    }
                    *i > start
                };
                let mut i = self.pos + 1;
                if !digits(&mut i) {
                    return false;
                }
                match self.c.get(i) {
                    Some('}') => true,
                    Some(',') => {
                        i += 1;
                        digits(&mut i);
                        self.c.get(i) == Some(&'}')
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn decimal(&mut self) -> Scan<u64> {
        let mut value = 0u64;
        while let Some(d) = self.peek().and_then(|c| c.to_digit(10)) {
            value = value * 10 + u64::from(d);
            if value > i32::MAX as u64 {
                return invalid("quantifier or capture group number out of range");
            }
            self.pos += 1;
        }
        Ok(value)
    }

    fn capname(&mut self) -> String {
        let start = self.pos;
        while self.peek().is_some_and(is_word) {
            self.pos += 1;
        }
        self.c[start..self.pos].iter().collect()
    }

    /// The inline options `imnsx`, `-` turning the rest off; stops at
    /// anything else.
    fn scan_options(&mut self) {
        let mut on = true;
        while let Some(c) = self.peek() {
            match c.to_ascii_lowercase() {
                '-' => on = false,
                '+' => on = true,
                'x' => self.options.x = on,
                'n' => self.options.n = on,
                'i' | 'm' | 's' => {}
                _ => return,
            }
            self.pos += 1;
        }
    }

    /// After a `(`: what it opens.
    fn group_open(&mut self) -> Scan<Opened> {
        // `(`, and `(?)` whose `?` then quantifies nothing.
        if self.peek() != Some('?') || self.peek_at(1) == Some(')') {
            return Ok(Opened::Group);
        }
        self.pos += 1;
        let unrecognized = || invalid("unrecognized grouping construct");
        let Some(ch) = self.next() else {
            return unrecognized();
        };
        match ch {
            ':' | '>' | '=' => Ok(Opened::Group),
            '!' => {
                self.facts.negative_lookaround = true;
                Ok(Opened::Group)
            }
            '<' | '\'' => {
                let close = if ch == '<' { '>' } else { '\'' };
                let Some(ch) = self.next() else {
                    return unrecognized();
                };
                match ch {
                    '=' if close == '>' => Ok(Opened::Group),
                    '!' if close == '>' => {
                        self.facts.negative_lookaround = true;
                        Ok(Opened::Group)
                    }
                    '=' | '!' => unrecognized(),
                    _ => {
                        self.pos -= 1;
                        self.named_group(ch, close)
                    }
                }
            }
            '(' => self.condition(),
            _ => {
                self.pos -= 1;
                self.scan_options();
                match self.next() {
                    Some(')') => Ok(Opened::Options),
                    Some(':') => Ok(Opened::Group),
                    _ => unrecognized(),
                }
            }
        }
    }

    /// `(?<name>`, `(?<number>`, and the balancing `(?<name-other>` and
    /// `(?<-other>`, from the first character of the name.
    fn named_group(&mut self, ch: char, close: char) -> Scan<Opened> {
        let bogus = |p: &Self, also: char| p.peek().is_some_and(|c| c != close && c != also);
        let mut capture = None;
        let mut proceed = false;
        if ch.is_ascii_digit() {
            let n = self.decimal()?;
            capture = self.groups.slots.contains(&n).then_some(n);
            if bogus(self, '-') {
                return invalid("invalid group name");
            }
            if capture == Some(0) {
                return invalid("capture number cannot be zero");
            }
        } else if is_word(ch) {
            let name = self.capname();
            capture = self.groups.names.contains(&name).then_some(0);
            if bogus(self, '-') {
                return invalid("invalid group name");
            }
        } else if ch == '-' {
            proceed = true;
        } else {
            return invalid("invalid group name");
        }
        let mut balances = false;
        if (capture.is_some() || proceed) && self.remaining() > 1 && self.peek() == Some('-') {
            self.pos += 1;
            let ch = self.peek().unwrap_or(close);
            if ch.is_ascii_digit() {
                let n = self.decimal()?;
                if !self.groups.slots.contains(&n) {
                    return invalid("reference to undefined group number");
                }
            } else if is_word(ch) {
                let name = self.capname();
                if !self.groups.names.contains(&name) {
                    return invalid("reference to undefined group name");
                }
            } else {
                return invalid("invalid group name");
            }
            if bogus(self, close) {
                return invalid("invalid group name");
            }
            balances = true;
        }
        if (capture.is_some() || balances) && self.next() == Some(close) {
            Ok(Opened::Group)
        } else {
            invalid("unrecognized grouping construct")
        }
    }

    /// After `(?(`: a group reference, or an expression the main scan
    /// reads as the next group.
    fn condition(&mut self) -> Scan<Opened> {
        let paren = self.pos;
        match self.peek() {
            Some(c) if c.is_ascii_digit() => {
                let n = self.decimal()?;
                if self.next() != Some(')') {
                    return invalid("malformed (?(number)...) reference");
                }
                if !self.groups.slots.contains(&n) {
                    return invalid("(?(number)...) reference to undefined group");
                }
                return Ok(Opened::Conditional { bars: 1 });
            }
            Some(c) if is_word(c) => {
                let name = self.capname();
                if self.groups.names.contains(&name) && self.next() == Some(')') {
                    return Ok(Opened::Conditional { bars: 1 });
                }
            }
            _ => {}
        }
        self.pos = paren - 1;
        if self.peek_at(1) == Some('?') {
            match (self.peek_at(2), self.peek_at(3)) {
                (Some('#'), _) => return invalid("alternation conditions cannot be comments"),
                (Some('\''), _) => return invalid("alternation conditions do not capture"),
                (Some('<'), Some(c)) if c != '=' && c != '!' => {
                    return invalid("alternation conditions do not capture");
                }
                _ => {}
            }
        }
        // The condition's group isn't counted among the alternatives here,
        // which only lets more through.
        Ok(Opened::Conditional { bars: 2 })
    }

    /// After a `\` outside a class.
    fn backslash(&mut self) -> Scan<()> {
        let Some(ch) = self.peek() else {
            return invalid("illegal \\ at end of pattern");
        };
        match ch {
            'b' | 'B' | 'A' | 'G' | 'Z' | 'z' | 'w' | 'W' | 's' | 'S' | 'd' | 'D' => {
                self.pos += 1;
                Ok(())
            }
            'p' | 'P' => {
                self.pos += 1;
                self.property()
            }
            _ => self.reference(),
        }
    }

    /// A backreference, `\1`, `\k<name>`, `\<name>`, or else a character.
    fn reference(&mut self) -> Scan<()> {
        let back = self.pos;
        let mut ch = self.peek().unwrap_or('\\');
        let mut close = None;
        if ch == 'k' {
            if self.remaining() >= 2 {
                self.pos += 1;
                close = match self.next() {
                    Some('<') => Some('>'),
                    Some('\'') => Some('\''),
                    _ => None,
                };
            }
            if close.is_none() || self.remaining() == 0 {
                return invalid("malformed \\k<...> named back reference");
            }
            ch = self.peek().unwrap_or('\\');
        } else if matches!(ch, '<' | '\'') && self.remaining() > 1 {
            close = Some(if ch == '<' { '>' } else { '\'' });
            self.pos += 1;
            ch = self.peek().unwrap_or('\\');
        }
        match close {
            Some(close) if ch.is_ascii_digit() => {
                let n = self.decimal()?;
                if self.next() == Some(close) {
                    return if self.groups.slots.contains(&n) {
                        Ok(())
                    } else {
                        invalid("reference to undefined group number")
                    };
                }
            }
            None if ('1'..='9').contains(&ch) => {
                let n = self.decimal()?;
                if self.groups.slots.contains(&n) {
                    return Ok(());
                }
                if n <= 9 {
                    return invalid("reference to undefined group number");
                }
            }
            Some(close) if is_word(ch) => {
                let name = self.capname();
                if self.next() == Some(close) {
                    return if self.groups.names.contains(&name) {
                        Ok(())
                    } else {
                        invalid("reference to undefined group name")
                    };
                }
            }
            _ => {}
        }
        // Not a reference: a character, `\10` in octal.
        self.pos = back;
        self.char_escape().map(|_| ())
    }

    /// After `\p` or `\P`: `{name}`.
    fn property(&mut self) -> Scan<()> {
        if self.remaining() < 3 {
            return invalid("incomplete \\p{X} character escape");
        }
        if self.next() != Some('{') {
            return invalid("malformed \\p{X} character escape");
        }
        let start = self.pos;
        while self.peek().is_some_and(|c| is_word(c) || c == '-') {
            self.pos += 1;
        }
        let name: String = self.c[start..self.pos].iter().collect();
        if self.next() != Some('}') {
            return invalid("incomplete \\p{X} character escape");
        }
        if !known_property(&name) {
            return invalid("unknown property");
        }
        Ok(())
    }

    /// After a `\` that escapes one character: which.
    fn char_escape(&mut self) -> Scan<char> {
        let Some(ch) = self.next() else {
            return invalid("illegal \\ at end of pattern");
        };
        match ch {
            '0'..='7' => {
                self.pos -= 1;
                let mut value = 0u32;
                for _ in 0..3 {
                    match self.peek().and_then(|c| c.to_digit(8)) {
                        Some(d) => {
                            value = value * 8 + d;
                            self.pos += 1;
                        }
                        None => break,
                    }
                }
                Ok(char::from_u32(value & 0xFF).unwrap_or('\0'))
            }
            'x' => self.hex(2),
            'u' => self.hex(4),
            'a' => Ok('\x07'),
            'b' => Ok('\x08'),
            'e' => Ok('\x1b'),
            'f' => Ok('\x0c'),
            'n' => Ok('\n'),
            'r' => Ok('\r'),
            't' => Ok('\t'),
            'v' => Ok('\x0b'),
            'c' => match self.next().map(|c| c.to_ascii_uppercase()) {
                Some(c @ '@'..='_') => Ok(char::from(c as u8 - b'@')),
                Some(_) => invalid("unrecognized control character"),
                None => invalid("missing control character"),
            },
            _ if is_word(ch) => invalid("unrecognized escape sequence"),
            _ => Ok(ch),
        }
    }

    fn hex(&mut self, digits: usize) -> Scan<char> {
        let mut value = 0u32;
        for _ in 0..digits {
            match self.next().and_then(|c| c.to_digit(16)) {
                Some(d) => value = value * 16 + d,
                None => return invalid("insufficient or invalid hexadecimal digits"),
            }
        }
        Ok(char::from_u32(value).unwrap_or('\u{fffd}'))
    }

    /// After a `[`: the class, through its `]`.
    fn class(&mut self, depth: usize) -> Scan<()> {
        if depth > MAX_DEPTH {
            return Err(Stop::TooDeep);
        }
        if self.peek() == Some('^') {
            self.pos += 1;
        }
        let (mut first, mut in_range, mut prev) = (true, false, '\0');
        let must_end = |p: &Self| {
            if p.peek().is_some_and(|c| c != ']') {
                invalid("a subtraction must be the last element in a character class")
            } else {
                Ok(())
            }
        };
        while let Some(mut ch) = self.next() {
            let mut translated = false;
            if ch == ']' {
                if !first {
                    return Ok(());
                }
            } else if ch == '\\' && self.remaining() > 0 {
                match self.next() {
                    Some(e @ ('d' | 'D' | 's' | 'S' | 'w' | 'W' | 'p' | 'P')) => {
                        if in_range {
                            return invalid("cannot include a class in a character range");
                        }
                        if matches!(e, 'p' | 'P') {
                            self.property()?;
                        }
                        first = false;
                        continue;
                    }
                    Some('-') => {
                        first = false;
                        continue;
                    }
                    _ => {
                        self.pos -= 1;
                        ch = self.char_escape()?;
                        translated = true;
                    }
                }
            } else if ch == '[' && self.peek() == Some(':') && !in_range {
                // `[:name:]` reads as itself, or else as `[`.
                let save = self.pos;
                self.pos += 1;
                self.capname();
                if !(self.next() == Some(':') && self.next() == Some(']')) {
                    self.pos = save;
                }
            }
            if in_range {
                in_range = false;
                if ch == '[' && !translated && !first {
                    self.class(depth + 1)?;
                    must_end(self)?;
                } else if prev > ch {
                    return invalid("[x-y] range in reverse order");
                }
            } else if self.remaining() >= 2
                && self.peek() == Some('-')
                && self.peek_at(1) != Some(']')
            {
                prev = ch;
                in_range = true;
                self.pos += 1;
            } else if ch == '-' && !translated && !first && self.peek() == Some('[') {
                self.pos += 1;
                self.class(depth + 1)?;
                must_end(self)?;
            }
            first = false;
        }
        invalid("unterminated [] set")
    }
}

#[cfg(test)]
mod tests {
    use super::{Options, Verdict, check};

    fn verdict(pattern: &str) -> Verdict {
        check(pattern, Options::default())
    }

    #[test]
    fn accepts_dotnet_syntax() {
        for ok in [
            "",
            "[A-Z]",
            "a(?!b)",
            "(?<!a)b",
            r"^\d{3}-\d{4}$",
            r"(?<year>\d{4})-(?<month>\d{2})\k<year>\k'month'",
            r"(?'word'\w+)\s\k<word>",
            r"(?<open>\()[^()]*(?<close-open>\))",
            r"(?<-open>x)?(?<open>y)",
            r"(?(open)(?!))",
            r"(?<1>a)\1",
            r"\2(a)(b)",
            r"(a)\10",
            r"[a-z-[aeiou]]",
            r"[\p{L}-[\p{Lu}]]",
            r"\p{IsGreek}\P{Lu}",
            r"(?i)abc(?-i)d(?ims:e)(?n)(f)",
            r"(?x) a b # comment [ unterminated",
            r"a{,3}",
            r"{abc}",
            r"x{2}?y{3,}z{1,4}?",
            r"a(?#comment)*",
            r"[]a]",
            r"[^]a]",
            r"[a-]",
            r"[-a]",
            r"[\b\x41-\x5AA\cA]",
            r"[\d-z]",
            r"[[:alpha:]]",
            r"\$\.\*\+\?\(\)\[\]\{\}\|\\\/\-\#\ \<",
            r"^*",
            r"\b+",
            r"(?(1)a|b)(x)",
            r"(?(?=a)ab|cd)",
            r"(?(x)a|b)",
            r"(?>a+)b",
            r"\Ga\Z\z\A",
            r"(?<café>x)\k<café>",
        ] {
            assert!(
                matches!(verdict(ok), Verdict::Valid(_)),
                "{ok}: {:?}",
                verdict(ok)
            );
        }
    }

    #[test]
    fn rejects_what_dotnet_throws_on() {
        for bad in [
            "[A",
            "(ab",
            "ab)",
            "*a",
            "a|*b",
            "(*a)",
            "a**",
            "a{2}{3}",
            "a*+",
            "(?)",
            "(?i)*",
            "x{2,1}",
            "{2}x",
            r"\1",
            r"(a)\2",
            r"\k<name>",
            r"(?<a>x)\k<b>",
            r"\k",
            r"\kname",
            r"\<undefined>",
            r"\q",
            r"\_",
            r"[\8]",
            r"[\A]",
            r"\x4",
            r"\u12G4",
            r"\c1",
            r"\p{Alpha}",
            r"\pL",
            r"\p{L",
            r"[z-a]",
            r"[a-\d]",
            r"[a-z-[aeiou]x]",
            r"(?P<name>x)",
            r"(?<1a>x)",
            r"(?<0>x)",
            r"(?<a-b>x)",
            r"(?'=x)",
            r"(?u)",
            r"(?(2)a|b)(x)",
            r"(?(1)a|b|c)(x)",
            r"(?(?#c)a)",
            r"(?(?<n>a)b)",
            "a\\",
            "(?#unterminated",
            "a{2147483648}",
        ] {
            assert!(
                matches!(verdict(bad), Verdict::Invalid),
                "{bad}: {:?}",
                verdict(bad)
            );
        }
    }

    #[test]
    fn options_change_the_reading() {
        let x = Options { x: true, n: false };
        assert!(matches!(check("a b # [ x", x), Verdict::Valid(_)));
        assert!(matches!(
            check("a b # [ x", Options::default()),
            Verdict::Invalid
        ));
        let n = Options { x: false, n: true };
        assert!(matches!(check(r"(a)\1", n), Verdict::Invalid));
        assert!(matches!(check(r"(?<a>x)\1", n), Verdict::Valid(_)));
        assert!(matches!(
            check(r"(?n:(a))(b)\1", Options::default()),
            Verdict::Valid(_)
        ));
        assert!(matches!(
            check(r"(?n:(a))(b)\2", Options::default()),
            Verdict::Invalid
        ));
    }

    #[test]
    fn notes_negative_lookarounds() {
        for (pattern, negative) in [
            ("a(?!b)", true),
            ("(?<!a)b", true),
            ("a(?=b)", false),
            ("(?<=a)b", false),
            ("[(?!]", false),
        ] {
            match verdict(pattern) {
                Verdict::Valid(f) => assert_eq!(f.negative_lookaround, negative, "{pattern}"),
                v => panic!("{pattern}: {v:?}"),
            }
        }
    }

    #[test]
    fn deep_subtractions_are_not_judged() {
        let pattern = "[a-".repeat(200);
        assert!(matches!(verdict(&pattern), Verdict::Unknown));
    }
}
