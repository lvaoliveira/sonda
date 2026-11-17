//! A small streaming XML reader for coverage reports. It reports elements
//! and text, decodes the predefined and numeric entities in them and leaves
//! every other entity as written, so nothing expands (no entity bombs) and
//! nothing is fetched (JaCoCo's DOCTYPE names a `report.dtd`; it is skipped).
//! It is not a validating parser: malformed input ends the scan early.

use std::borrow::Cow;

pub(super) struct Tag<'a> {
    pub(super) name: &'a str,
    attrs: Vec<Attr<'a>>,
}

impl Tag<'_> {
    pub(super) fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_ref())
    }

    pub(super) fn number(&self, key: &str) -> Option<u64> {
        self.attr(key)?.trim().parse().ok()
    }
}

pub(super) enum Event<'a> {
    /// An element opens; an empty one (`<a/>`) is followed by its `End`.
    Start(Tag<'a>),
    End(&'a str),
    /// Text between elements, outer whitespace removed, when not empty.
    Text(Cow<'a, str>),
}

/// Calls `visit` for each event, until it returns `false` or the input ends.
pub(super) fn scan<'a>(text: &'a str, mut visit: impl FnMut(Event<'a>) -> bool) {
    let mut at = 0;
    while at < text.len() {
        let lt = text[at..].find('<').map_or(text.len(), |p| at + p);
        let chars = text[at..lt].trim();
        if !chars.is_empty() && !visit(Event::Text(decode(chars))) {
            return;
        }
        if lt >= text.len() {
            return;
        }
        match markup(text, lt, &mut visit) {
            Some(next) => at = next,
            None => return,
        }
    }
}

/// Handles the markup at `lt` (a `<`); where scanning goes on, or `None` to stop.
fn markup<'a>(
    text: &'a str,
    lt: usize,
    visit: &mut impl FnMut(Event<'a>) -> bool,
) -> Option<usize> {
    let rest = &text[lt..];
    if rest.starts_with("<!--") {
        skip_past(text, lt + 4, "-->")
    } else if rest.starts_with("<![CDATA[") {
        let end = text[lt + 9..].find("]]>")? + lt + 9;
        let data = &text[lt + 9..end];
        (data.trim().is_empty() || visit(Event::Text(Cow::Borrowed(data.trim()))))
            .then_some(end + 3)
    } else if rest.starts_with("<?") {
        skip_past(text, lt + 2, "?>")
    } else if rest.starts_with("<!") {
        skip_declaration(text, lt + 2)
    } else if rest.starts_with("</") {
        let end = text[lt..].find('>')? + lt;
        visit(Event::End(text[lt + 2..end].trim())).then_some(end + 1)
    } else {
        start_tag(text, lt + 1, visit)
    }
}

fn skip_past(text: &str, from: usize, end: &str) -> Option<usize> {
    Some(text[from..].find(end)? + from + end.len())
}

/// A `<!DOCTYPE ...>`, which may hold an internal subset in brackets and
/// quoted strings with a `>` in them.
fn skip_declaration(text: &str, from: usize) -> Option<usize> {
    let (mut depth, mut quote) = (0usize, None);
    for (i, b) in text.bytes().enumerate().skip(from) {
        match (quote, b) {
            (Some(q), _) => quote = (b != q).then_some(q),
            (None, b'"' | b'\'') => quote = Some(b),
            (None, b'[') => depth += 1,
            (None, b']') => depth = depth.saturating_sub(1),
            (None, b'>') if depth == 0 => return Some(i + 1),
            _ => {}
        }
    }
    None
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn skip_space(bytes: &[u8], mut at: usize) -> usize {
    while bytes.get(at).copied().is_some_and(is_space) {
        at += 1;
    }
    at
}

/// The offset of the first byte from `at` that is one of `stops` or a space.
fn name_end(bytes: &[u8], at: usize, stops: &[u8]) -> usize {
    bytes[at..]
        .iter()
        .position(|b| is_space(*b) || stops.contains(b))
        .map_or(bytes.len(), |p| at + p)
}

fn start_tag<'a>(
    text: &'a str,
    from: usize,
    visit: &mut impl FnMut(Event<'a>) -> bool,
) -> Option<usize> {
    let bytes = text.as_bytes();
    let end = name_end(bytes, from, b"/>");
    if end == from {
        // A stray `<`: not an element.
        return Some(from);
    }
    let name = &text[from..end];
    let mut attrs = Vec::new();
    let mut at = end;
    let empty = loop {
        at = skip_space(bytes, at);
        match *bytes.get(at)? {
            b'>' => break false,
            b'/' => break true,
            _ => {
                let (attr, next) = attribute(text, at)?;
                attrs.extend(attr);
                at = next;
            }
        }
    };
    let next = text[at..].find('>')? + at + 1;
    let keep_going =
        visit(Event::Start(Tag { name, attrs })) && (!empty || visit(Event::End(name)));
    keep_going.then_some(next)
}

type Attr<'a> = (&'a str, Cow<'a, str>);

/// One `key="value"` at `at`, and where the next begins. Always advances.
fn attribute(text: &str, at: usize) -> Option<(Option<Attr<'_>>, usize)> {
    let bytes = text.as_bytes();
    let key_end = name_end(bytes, at, b"=/>");
    if key_end == at {
        return Some((None, at + 1));
    }
    let key = &text[at..key_end];
    let eq = skip_space(bytes, key_end);
    if bytes.get(eq) != Some(&b'=') {
        return Some((Some((key, Cow::Borrowed(""))), key_end));
    }
    let start = skip_space(bytes, eq + 1);
    let (value, next) = match *bytes.get(start)? {
        q @ (b'"' | b'\'') => {
            let close = text[start + 1..].find(q as char)? + start + 1;
            (&text[start + 1..close], close + 1)
        }
        _ => {
            let stop = name_end(bytes, start, b">");
            (&text[start..stop], stop)
        }
    };
    Some((Some((key, decode(value))), next))
}

/// `&lt;`, `&gt;`, `&amp;`, `&quot;`, `&apos;` and `&#N;`/`&#xH;`; anything
/// else stays as written.
fn decode(raw: &str) -> Cow<'_, str> {
    if !raw.contains('&') {
        return Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        match entity(rest) {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// The character `rest` (which starts with `&`) names, and the entity's length.
fn entity(rest: &str) -> Option<(char, usize)> {
    let semi = rest.find(';').filter(|s| *s <= 10)?;
    let name = &rest[1..semi];
    let c = match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "quot" => '"',
        "apos" => '\'',
        _ => {
            let digits = name.strip_prefix('#')?;
            let code = match digits.strip_prefix(['x', 'X']) {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => digits.parse().ok()?,
            };
            char::from_u32(code)?
        }
    };
    Some((c, semi + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        scan(text, |e| {
            out.push(match e {
                Event::Start(t) => format!(
                    "<{} {}>",
                    t.name,
                    t.attrs
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                Event::End(n) => format!("</{n}>"),
                Event::Text(t) => format!("text:{t}"),
            });
            true
        });
        out
    }

    #[test]
    fn reads_elements_attributes_and_text() {
        let e = events("<?xml version='1.0'?><a x=\"1\" y='2'><b/><c>hi &amp; bye</c></a>");
        assert_eq!(
            e,
            [
                "<a x=1,y=2>",
                "<b >",
                "</b>",
                "<c >",
                "text:hi & bye",
                "</c>",
                "</a>"
            ]
        );
    }

    #[test]
    fn skips_comments_doctypes_and_reads_cdata() {
        let doc = "<!DOCTYPE report PUBLIC \"-//a//b\" \"report.dtd\" [<!ENTITY e \"a>b\">]>\
                   <!-- <not> --><r><![CDATA[1 < 2]]></r>";
        assert_eq!(events(doc), ["<r >", "text:1 < 2", "</r>"]);
    }

    #[test]
    fn decodes_character_references_and_keeps_unknown_entities() {
        let e = events("<a n=\"A&lt;T&gt; &#65;&#x42; &bogus; &\"/>");
        assert_eq!(e[0], "<a n=A<T> AB &bogus; &>");
    }

    #[test]
    fn a_visitor_can_stop_the_scan() {
        let mut seen = 0;
        scan("<a><b/><c/></a>", |_| {
            seen += 1;
            seen < 2
        });
        assert_eq!(seen, 2);
    }

    #[test]
    fn malformed_input_ends_the_scan_without_panicking() {
        for doc in [
            "<",
            "<a",
            "<a x",
            "<a x=",
            "<a x=\"",
            "<a x='1",
            "</",
            "<!--",
            "<![CDATA[",
            "<!DOCTYPE",
            "<a x=1 y=2>",
            "< >",
            "<a =>",
            "é<é é='é'>é</é>",
            "<a/ >",
        ] {
            events(doc);
        }
        assert_eq!(events("<a x=1 y=2>"), ["<a x=1,y=2>"]);
    }

    proptest::proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn any_input_scans_without_panicking(
            text in proptest::prop_oneof![
                proptest::prelude::any::<String>(),
                "[<>/=!?\\[\\]\"'&;#a-z0-9 \\n-]*"
            ]
        ) {
            events(&text);
        }
    }
}
