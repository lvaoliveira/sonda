//! The regex analyses shared by every language (ADR-0013): each takes a
//! parsed pattern and says whether a rule applies. The language modules
//! find the patterns in their source; these decide what is wrong with them.

use crate::regex::{
    Assertion, ClassItem, Flags, GroupKind, Mode, Node as Rx, Regex, Set, complexity, first_set,
    literal_text, nullable, set_of, walk,
};

fn any_node(regex: &Regex, mut pred: impl FnMut(&Rx) -> bool) -> bool {
    let mut found = false;
    walk(&regex.root, &mut |n| {
        if !found && pred(n) {
            found = true;
        }
    });
    found
}

pub(super) fn has_empty_group(r: &Regex) -> bool {
    any_node(
        r,
        |n| matches!(n, Rx::Group { inner, kind, .. } if **inner == Rx::Empty && *kind != GroupKind::Scoped),
    )
}

pub(super) fn has_empty_alternative(r: &Regex) -> bool {
    any_node(
        r,
        |n| matches!(n, Rx::Alt(alts) if alts.contains(&Rx::Empty)),
    )
}

pub(super) fn has_single_character_class(r: &Regex) -> bool {
    any_node(r, |n| {
        matches!(n, Rx::Class { negated: false, items }
                if matches!(items.as_slice(), [ClassItem::Char(c)] if !".*+?()[]{}|^$\\ -#&~".contains(*c) && !c.is_whitespace()))
    })
}

fn group_is_useless(node: &Rx, in_repeat: bool) -> bool {
    match node {
        Rx::Group { kind, inner, .. } => {
            (*kind == GroupKind::NonCapture
                && !in_repeat
                && !matches!(**inner, Rx::Alt(_) | Rx::Empty))
                || group_is_useless(inner, false)
        }
        Rx::Repeat { inner, .. } => group_is_useless(inner, true),
        Rx::Look { inner, .. } => group_is_useless(inner, false),
        Rx::Conditional { yes, no } => {
            group_is_useless(yes, false) || no.as_ref().is_some_and(|n| group_is_useless(n, false))
        }
        Rx::Alt(items) => items.iter().any(|n| group_is_useless(n, false)),
        Rx::Concat(items) => items.iter().any(|n| group_is_useless(n, false)),
        _ => false,
    }
}

pub(super) fn has_useless_group(r: &Regex) -> bool {
    // A group that is the whole pattern still has no job.
    group_is_useless(&r.root, false)
}

pub(super) fn has_superfluous_braces(r: &Regex) -> bool {
    any_node(r, |n| {
        matches!(
            n,
            Rx::Repeat {
                min: 1,
                max: Some(1),
                braces: true,
                ..
            }
        )
    })
}

fn class_is_digits(items: &[ClassItem]) -> bool {
    matches!(items, [ClassItem::Range('0', '9')])
}

fn class_is_word(items: &[ClassItem]) -> bool {
    let (mut lower, mut upper, mut digit, mut underscore) = (false, false, false, false);
    for item in items {
        match item {
            ClassItem::Range('a', 'z') => lower = true,
            ClassItem::Range('A', 'Z') => upper = true,
            ClassItem::Range('0', '9') => digit = true,
            ClassItem::Char('_') => underscore = true,
            _ => return false,
        }
    }
    lower && upper && digit && underscore
}

pub(super) fn could_be_concise(r: &Regex) -> bool {
    any_node(r, |n| match n {
        Rx::Repeat {
            min,
            max,
            braces: true,
            ..
        } => matches!((min, max), (0, None) | (1, None) | (0, Some(1))),
        Rx::Class { items, .. } => class_is_digits(items) || class_is_word(items),
        _ => false,
    })
}

pub(super) fn has_octal_escape(r: &Regex) -> bool {
    any_node(r, |n| matches!(n, Rx::Octal(_)))
}

fn contains_backref_to(node: &Rx, index: usize, name: Option<&str>) -> bool {
    let mut found = false;
    walk(node, &mut |n| match n {
        Rx::BackrefIndex(i) if *i == index => found = true,
        Rx::BackrefName(s) if Some(s.as_str()) == name => found = true,
        _ => {}
    });
    found
}

pub(super) fn backreferences_its_own_group(r: &Regex) -> bool {
    any_node(r, |n| match n {
        Rx::Group { kind, index, inner } if *index > 0 => {
            let name = match kind {
                GroupKind::Named(s) => Some(s.as_str()),
                _ => None,
            };
            contains_backref_to(inner, *index, name)
        }
        _ => false,
    })
}

pub(super) fn has_single_character_alternation(r: &Regex) -> bool {
    any_node(
        r,
        |n| matches!(n, Rx::Alt(alts) if alts.len() >= 2 && alts.iter().all(|a| matches!(a, Rx::Char(_)))),
    )
}

pub(super) fn has_multiple_spaces(r: &Regex) -> bool {
    !r.flags.verbose
        && any_node(r, |n| match n {
            Rx::Concat(items) => items
                .windows(2)
                .any(|w| w[0] == Rx::Char(' ') && w[1] == Rx::Char(' ')),
            _ => false,
        })
}

pub(super) fn class_repeats_a_character(r: &Regex) -> bool {
    any_node(r, |n| {
        let Rx::Class { items, .. } = n else {
            return false;
        };
        let sets: Vec<Set> = items
            .iter()
            .filter_map(|i| {
                set_of(
                    &Rx::Class {
                        negated: false,
                        items: vec![i.clone()],
                    },
                    &r.flags,
                )
            })
            .collect();
        sets.iter()
            .enumerate()
            .any(|(i, a)| sets[i + 1..].iter().any(|b| a.overlaps(b)))
    })
}

pub(super) fn class_splits_a_grapheme(r: &Regex) -> bool {
    any_node(r, |n| {
        let Rx::Class { items, .. } = n else {
            return false;
        };
        items.iter().any(|i| match i {
            ClassItem::Char(c) => {
                ('\u{300}'..='\u{36f}').contains(c)
                    || matches!(*c, '\u{200d}' | '\u{fe0f}' | '\u{20e3}')
                    || ('\u{1f3fb}'..='\u{1f3ff}').contains(c)
            }
            _ => false,
        })
    })
}

pub(super) fn repeats_something_empty(r: &Regex) -> bool {
    any_node(r, |n| {
        matches!(n, Rx::Repeat { inner, max, mode, .. }
                if *mode != Mode::Possessive
                    && max.is_none_or(|m| m > 1)
                    && !matches!(**inner, Rx::Assertion(_) | Rx::Look { .. })
                    && nullable(inner))
    })
}

fn starts_with_anchor(node: &Rx) -> bool {
    match node {
        Rx::Assertion(Assertion::Start | Assertion::StartAbs) => true,
        Rx::Concat(items) => items.first().is_some_and(starts_with_anchor),
        _ => false,
    }
}

fn ends_with_anchor(node: &Rx) -> bool {
    match node {
        Rx::Assertion(Assertion::End | Assertion::EndAbs) => true,
        Rx::Concat(items) => items.last().is_some_and(ends_with_anchor),
        _ => false,
    }
}

pub(super) fn anchors_bind_one_alternative(r: &Regex) -> bool {
    let Rx::Alt(alts) = &r.root else { return false };
    let some_start = alts.iter().any(starts_with_anchor);
    let all_start = alts.iter().all(starts_with_anchor);
    let some_end = alts.iter().any(ends_with_anchor);
    let all_end = alts.iter().all(ends_with_anchor);
    (some_start && !all_start && starts_with_anchor(&alts[0]))
        || (some_end && !all_end && ends_with_anchor(&alts[alts.len() - 1]))
}

pub(super) fn has_redundant_alternative(r: &Regex) -> bool {
    any_node(r, |n| {
        let Rx::Alt(alts) = n else { return false };
        alts.iter().enumerate().any(|(i, a)| {
            alts[..i].iter().any(|b| {
                b == a
                    || (matches!(a, Rx::Char(_))
                        && matches!(b, Rx::Class { negated: false, .. })
                        && set_of(a, &r.flags)
                            .zip(set_of(b, &r.flags))
                            .is_some_and(|(x, y)| x.is_subset_of(&y)))
            })
        })
    })
}

fn single_char_set(node: &Rx, flags: &Flags) -> Option<Set> {
    set_of(node, flags)
}

pub(super) fn possessive_starves_next(r: &Regex) -> bool {
    any_node(r, |n| {
        let Rx::Concat(items) = n else { return false };
        items.windows(2).any(|w| {
            let Rx::Repeat {
                inner,
                max: None,
                mode: Mode::Possessive,
                ..
            } = &w[0]
            else {
                return false;
            };
            let Some(taken) = single_char_set(inner, &r.flags) else {
                return false;
            };
            !nullable(&w[1]) && {
                let next = first_set(&w[1], &r.flags);
                !next.is_empty() && next.is_subset_of(&taken)
            }
        })
    })
}

pub(super) fn boundary_cannot_match(r: &Regex) -> bool {
    any_node(r, |n| {
        let Rx::Concat(items) = n else { return false };
        items.windows(2).any(|w| match &w[0] {
            Rx::Assertion(Assertion::EndAbs) => !nullable(&w[1]),
            Rx::Assertion(Assertion::End) if !r.flags.multiline => {
                !nullable(&w[1]) && !first_set(&w[1], &r.flags).contains('\n' as u32)
            }
            _ => match &w[1] {
                Rx::Assertion(Assertion::StartAbs) => !nullable(&w[0]),
                Rx::Assertion(Assertion::Start) if !r.flags.multiline => !nullable(&w[0]),
                _ => false,
            },
        })
    })
}

pub(super) fn lookahead_contradicts_next(r: &Regex) -> bool {
    any_node(r, |n| {
        let Rx::Concat(items) = n else { return false };
        items.windows(2).any(|w| {
            let Rx::Look {
                ahead: true,
                negative,
                inner,
            } = &w[0]
            else {
                return false;
            };
            if nullable(&w[1]) || nullable(inner) {
                return false;
            }
            let (looked, next) = (first_set(inner, &r.flags), first_set(&w[1], &r.flags));
            if looked.is_empty() || next.is_empty() {
                return false;
            }
            if *negative {
                // (?!a)a: the whole lookahead is one character
                single_char_set(inner, &r.flags).is_some_and(|l| next.is_subset_of(&l))
            } else {
                !looked.overlaps(&next)
            }
        })
    })
}

pub(super) fn ends_with_reluctant(r: &Regex) -> bool {
    let last = match &r.root {
        Rx::Concat(items) => items.last(),
        other => Some(other),
    };
    matches!(
        last,
        Some(Rx::Repeat {
            mode: Mode::Lazy,
            min: 0,
            max: None,
            ..
        })
    )
}

pub(super) fn reluctant_dot_before_literal(r: &Regex) -> bool {
    let dot_lazy = |n: &Rx| matches!(n, Rx::Repeat { inner, max: None, mode: Mode::Lazy, .. } if **inner == Rx::Any);
    any_node(r, |n| match n {
        Rx::Concat(items) => items.windows(2).any(|w| {
            (dot_lazy(&w[0]) || matches!(&w[0], Rx::Group { inner, .. } if dot_lazy(inner)))
                && matches!(w[1], Rx::Char(c) if !c.is_alphanumeric())
        }),
        _ => false,
    })
}

pub(super) fn is_too_complex(r: &Regex) -> bool {
    complexity(&r.root) > 20
}

fn peel(node: &Rx) -> &Rx {
    match node {
        Rx::Group { inner, kind, .. } if *kind != GroupKind::Atomic => peel(inner),
        other => other,
    }
}

fn items_of(node: &Rx) -> Vec<&Rx> {
    match peel(node) {
        Rx::Concat(items) => items.iter().collect(),
        other => vec![other],
    }
}

fn is_unbounded(node: &Rx) -> bool {
    matches!(node, Rx::Repeat { max: None, mode, .. } if *mode != Mode::Possessive)
}

fn repeat_body_ambiguous(body: &Rx, flags: &Flags) -> bool {
    let body = peel(body);
    // (a|a)*, (a|ab)*: alternatives that can match a common prefix
    if let Rx::Alt(alts) = body {
        for (i, a) in alts.iter().enumerate() {
            for b in &alts[i + 1..] {
                if literal_text(a)
                    .zip(literal_text(b))
                    .is_some_and(|(x, y)| x.starts_with(&y) || y.starts_with(&x))
                {
                    return true;
                }
                if single_char_set(a, flags)
                    .zip(single_char_set(b, flags))
                    .is_some_and(|(x, y)| x.overlaps(&y))
                {
                    return true;
                }
            }
        }
        return false;
    }
    let items = items_of(body);
    let begin = first_set(body, flags);
    // an unbounded repeat at the end of the body whose characters can also
    // start the next iteration: (a+)+, (\w+\s?)*
    for (i, item) in items.iter().enumerate().rev() {
        if is_unbounded(item) {
            let Rx::Repeat { inner, .. } = item else {
                break;
            };
            let chars = first_set(inner, flags);
            if chars.overlaps(&begin) {
                return true;
            }
        }
        if !nullable(item) && i + 1 != items.len() {
            break;
        }
        if !nullable(item) {
            break;
        }
    }
    false
}

pub(super) fn backtracks_exponentially(r: &Regex) -> bool {
    any_node(r, |n| match n {
        Rx::Repeat {
            inner,
            max: None,
            mode,
            ..
        } if *mode != Mode::Possessive => repeat_body_ambiguous(inner, &r.flags),
        _ => false,
    })
}

pub(super) fn backtracks_polynomially(r: &Regex) -> bool {
    any_node(r, |n| {
        let Rx::Concat(items) = n else { return false };
        (0..items.len()).any(|i| {
            let Rx::Repeat { inner: a, .. } = &items[i] else {
                return false;
            };
            if !is_unbounded(&items[i]) {
                return false;
            }
            let Some(sa) = single_char_set(a, &r.flags) else {
                return false;
            };
            for later in &items[i + 1..] {
                if let Rx::Repeat { inner: b, .. } = later
                    && is_unbounded(later)
                {
                    return single_char_set(b, &r.flags).is_some_and(|sb| sa.overlaps(&sb));
                }
                if !nullable(later) {
                    return false;
                }
            }
            false
        })
    })
}

// ---- Java-only analyses

pub(super) fn multiline_matches_empty_lines(r: &Regex) -> bool {
    r.flags.multiline
        && any_node(r, |n| {
            matches!(n, Rx::Concat(items) if items.windows(2).any(|w| {
                w[0] == Rx::Assertion(Assertion::Start) && w[1] == Rx::Assertion(Assertion::End)
            }))
        })
}

fn has_composed_character(c: char) -> bool {
    (('\u{c0}'..='\u{17f}').contains(&c) && c != '\u{d7}' && c != '\u{f7}')
        || ('\u{300}'..='\u{36f}').contains(&c)
}

pub(super) fn needs_canonical_equivalence(r: &Regex) -> bool {
    !r.flags.canon_eq
        && any_node(r, |n| match n {
            Rx::Char(c) => has_composed_character(*c),
            Rx::Class { items, .. } => items.iter().any(|i| match i {
                ClassItem::Char(c) => has_composed_character(*c),
                _ => false,
            }),
            _ => false,
        })
}

pub(super) fn needs_unicode_case(r: &Regex) -> bool {
    r.flags.ignore_case
        && !r.flags.unicode_case
        && !r.flags.unicode_class
        && any_node(r, |n| match n {
            Rx::Char(c) => !c.is_ascii() && c.is_alphabetic(),
            Rx::Class { items, .. } => items.iter().any(|i| match i {
                ClassItem::Char(c) => !c.is_ascii() && c.is_alphabetic(),
                ClassItem::Range(lo, hi) => {
                    (!lo.is_ascii() && lo.is_alphabetic()) || (!hi.is_ascii() && hi.is_alphabetic())
                }
                _ => false,
            }),
            _ => false,
        })
}

pub(super) fn repeats_an_alternation(r: &Regex) -> bool {
    any_node(r, |n| {
        matches!(n, Rx::Repeat { inner, max: None, mode, .. }
            if *mode != Mode::Possessive && matches!(peel(inner), Rx::Alt(alts) if alts.len() >= 2))
    })
}

pub(super) fn control_escape_out_of_range(r: &Regex) -> bool {
    r.bad_controls > 0
}

pub(super) fn has_ascii_letter_class(r: &Regex) -> bool {
    any_node(r, |n| {
        matches!(n, Rx::Class { negated: false, items }
            if items.contains(&ClassItem::Range('a', 'z')) && items.contains(&ClassItem::Range('A', 'Z')))
    })
}
