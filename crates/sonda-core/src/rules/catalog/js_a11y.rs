//! JSX accessibility and React rules (ADR-0007, batch 3). See the notes in
//! `js_modern.rs` about keeping queries cheap on deep trees.

use super::js::{
    attribute, has_spread, has_token, on_dom_element, opening_tag, static_value, string_content,
    tag_name, text,
};
use super::js_modern::collect_below;
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/html-lang",
        name: "HTML elements should have a valid language attribute",
        description: "Screen readers pick their pronunciation rules from the page language.",
        message: "Add a 'lang' attribute to this <html> element.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S5254")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#any-of? @n "html"))) @match
(jsx_self_closing_element name: (identifier) @n (#any-of? @n "html")) @match"#,
            filter: Some(Keep(html_lacks_lang)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const p = <html><body /></html>;",
            good: "const p = <html lang=\"en\"><body /></html>;",
        }),
    },
    Rule {
        id: "js/media-captions",
        name: "Media elements should have captions",
        description: "Without a <track>, people who can't hear the audio get nothing.",
        message: "Add a <track kind=\"captions\"> to this media element.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S4084")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#any-of? @n "video" "audio"))) @match
(jsx_self_closing_element name: (identifier) @n (#any-of? @n "video" "audio")) @match"#,
            filter: Some(Keep(media_lacks_track)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <video src={url} />;",
            good: "const v = <video src={url}><track kind=\"captions\" src={vtt} /></video>;",
        }),
    },
    Rule {
        id: "js/object-alternative-content",
        name: "<object> tags should provide an alternative content",
        description: "Browsers and assistive technology fall back to the content inside <object> when it can't be shown.",
        message: "Give this <object> alternative content or a label.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S5264")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#any-of? @n "object"))) @match
(jsx_self_closing_element name: (identifier) @n (#any-of? @n "object")) @match"#,
            filter: Some(Keep(object_lacks_alternative)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const o = <object data={url} />;",
            good: "const o = <object data={url} aria-label=\"Quarterly chart\" />;",
        }),
    },
    Rule {
        id: "js/redundant-role",
        name: "ARIA roles that repeat the element's own role should be removed",
        description: "<button role=\"button\"> adds noise without changing what assistive technology announces.",
        message: "Remove this redundant role.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6822")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(role_repeats_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const b = <button role=\"button\">Go</button>;",
            good: "const b = <button>Go</button>;",
        }),
    },
    Rule {
        id: "js/invalid-role",
        name: "DOM elements with ARIA roles should have a valid, non-abstract role",
        description: "An unknown role is ignored by assistive technology, so the element is announced as nothing in particular.",
        message: "Use a valid WAI-ARIA role.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6821")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(role_is_unknown)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const d = <div role=\"buton\" />;",
            good: "const d = <div role=\"button\" tabIndex={0} />;",
        }),
    },
    Rule {
        id: "js/unknown-dom-property",
        name: "JSX elements should not use unknown properties and attributes",
        description: "React expects className, htmlFor and camelCase event names; the HTML spellings are ignored or warn.",
        message: "Use the React spelling of this attribute.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6747")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#any-of? @a "class" "for" "tabindex" "maxlength" "readonly" "colspan" "rowspan" "autofocus" "contenteditable" "onclick" "onchange" "onkeydown" "onkeyup" "onsubmit" "onfocus" "onblur")) @match"#,
            filter: Some(Keep(on_dom_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const d = <div onclick={go} />;",
            good: "const d = <div onClick={go} />;",
        }),
    },
    Rule {
        id: "js/context-provider-value",
        name: "React Context Provider values should have stable identities",
        description: "A new object on every render makes every consumer re-render.",
        message: "Memoize this value with useMemo or useCallback, or hoist it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S6481")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "value") (jsx_expression [(object) (array) (arrow_function) (function_expression)])) @match"#,
            filter: Some(Keep(on_context_provider)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const t = <ThemeContext.Provider value={{ dark }}><App /></ThemeContext.Provider>;",
            good: "const t = <ThemeContext.Provider value={theme}><App /></ThemeContext.Provider>;",
        }),
    },
    Rule {
        id: "js/nested-component",
        name: "React components should not be nested",
        description: "A component defined inside another is a new component on every render, so its state is lost and the DOM is rebuilt.",
        message: "Move this component out of its parent.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S6478")],
        check: Check::Query {
            langs: JSX,
            query: r#"(function_declaration name: (identifier) @n (#match? @n "^[A-Z]")) @match"#,
            filter: Some(Find(nested_component)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function Page() { function Row() { return <li />; } return <ul><Row /></ul>; }",
            good: "function Row() { return <li />; }\nfunction Page() { return <ul><Row /></ul>; }",
        }),
    },
    Rule {
        id: "js/unused-component-method",
        name: "Unused methods of React components should be removed",
        description: "A method nothing calls is dead code that readers still have to understand.",
        message: "Remove this unused method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S6441")],
        check: Check::Query {
            langs: JSX,
            query: r#"(class_declaration (class_heritage) @h) @match"#,
            filter: Some(Find(unused_component_method)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A extends React.Component { helper() { return 1; } render() { return <p />; } }",
            good: "class A extends React.Component { helper() { return 1; } render() { return <p>{this.helper()}</p>; } }",
        }),
    },
    Rule {
        id: "js/noninteractive-tabindex",
        name: "Non-interactive DOM elements should not have the tabIndex property",
        description: "Putting a plain element in the tab order makes keyboard users stop on something they can't use.",
        message: "Remove tabIndex, or give the element an interactive role.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6845")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "tabIndex")) @match"#,
            filter: Some(Keep(tabindex_on_plain_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const d = <div tabIndex={0}>text</div>;",
            good: "const d = <div tabIndex={-1}>text</div>;",
        }),
    },
    Rule {
        id: "js/activedescendant-focus",
        name: "DOM elements with aria-activedescendant should be reachable by keyboard",
        description: "aria-activedescendant only works on an element that can take focus.",
        message: "Add tabIndex to this element.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6823")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "aria-activedescendant")) @match"#,
            filter: Some(Keep(activedescendant_not_focusable)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const l = <div aria-activedescendant={id} />;",
            good: "const l = <div aria-activedescendant={id} tabIndex={0} />;",
        }),
    },
    Rule {
        id: "js/prefer-semantic-tag",
        name: "Native HTML tags should be preferred over ARIA roles",
        description: "<button> brings keyboard handling and focus for free; role=\"button\" on a div brings none.",
        message: "Use the native element instead of the role.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S6819")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(role_has_native_tag)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const b = <div role=\"button\" tabIndex={0} />;",
            good: "const b = <button />;",
        }),
    },
    Rule {
        id: "js/role-needs-focus",
        name: "Elements with an interactive role should support focus",
        description: "A div that acts as a button but can't be focused can't be used from the keyboard.",
        message: "Add tabIndex to this element.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6852")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(interactive_role_not_focusable)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const b = <div role=\"button\" />;",
            good: "const b = <div role=\"button\" tabIndex={0} />;",
        }),
    },
    Rule {
        id: "js/aria-on-unsupported-element",
        name: "ARIA roles and properties should not be used on elements that do not support them",
        description: "<meta>, <script> and similar elements aren't rendered for users, so ARIA attributes on them do nothing.",
        message: "Remove this ARIA attribute.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6824")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#match? @a "^(role$|aria-)")) @match"#,
            filter: Some(Keep(on_non_rendered_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const m = <meta role=\"note\" />;",
            good: "const m = <meta name=\"x\" />;",
        }),
    },
    Rule {
        id: "js/aria-invalid-value",
        name: "ARIA properties in DOM elements should have valid values",
        description: "aria-hidden=\"yes\" isn't a value the specification defines, so it's ignored.",
        message: "Use one of the values the property accepts.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S6793")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#match? @a "^aria-(hidden|disabled|expanded|pressed|selected|checked|busy|atomic|modal|multiline|multiselectable|readonly|required)$")) @match"#,
            filter: Some(Keep(aria_value_not_allowed)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const d = <div aria-hidden=\"yes\" />;",
            good: "const d = <div aria-hidden=\"true\" />;",
        }),
    },
];

// ---------------------------------------------------- filters

fn element_of_attribute(attr: Node) -> Option<Node> {
    attr.parent()
}

fn opening_name<'s>(opening: Node, src: &'s [u8]) -> &'s [u8] {
    tag_name(opening, src).unwrap_or(b"")
}

fn html_lacks_lang(element: Node, src: &[u8]) -> bool {
    opening_tag(element).is_some_and(|o| !has_spread(o) && attribute(o, "lang", src).is_none())
}

fn media_lacks_track(element: Node, src: &[u8]) -> bool {
    let Some(opening) = opening_tag(element) else {
        return false;
    };
    if has_spread(opening) || attribute(opening, "muted", src).is_some() {
        return false;
    }
    !collect_below(element, |n| {
        n.kind() == "jsx_self_closing_element" || n.kind() == "jsx_opening_element"
    })
    .into_iter()
    .any(|n| opening_name(n, src) == b"track")
}

fn object_lacks_alternative(element: Node, src: &[u8]) -> bool {
    let Some(opening) = opening_tag(element) else {
        return false;
    };
    if has_spread(opening) {
        return false;
    }
    let labelled = ["aria-label", "aria-labelledby", "title"]
        .iter()
        .any(|a| attribute(opening, a, src).is_some());
    // A jsx_element's children: opening tag, content, closing tag.
    let has_content = element.kind() == "jsx_element" && element.named_child_count() > 2;
    !labelled && !has_content
}

const NATIVE_ROLES: &[(&[u8], &[u8])] = &[
    (b"button", b"button"),
    (b"nav", b"navigation"),
    (b"ul", b"list"),
    (b"ol", b"list"),
    (b"li", b"listitem"),
    (b"img", b"img"),
    (b"table", b"table"),
    (b"form", b"form"),
    (b"main", b"main"),
    (b"article", b"article"),
    (b"aside", b"complementary"),
    (b"footer", b"contentinfo"),
    (b"header", b"banner"),
    (b"section", b"region"),
    (b"a", b"link"),
    (b"h1", b"heading"),
    (b"h2", b"heading"),
    (b"h3", b"heading"),
    (b"h4", b"heading"),
    (b"h5", b"heading"),
    (b"h6", b"heading"),
    (b"hr", b"separator"),
    (b"dialog", b"dialog"),
    (b"textarea", b"textbox"),
];

fn role_repeats_element(attr: Node, src: &[u8]) -> bool {
    let Some(opening) = element_of_attribute(attr) else {
        return false;
    };
    let (tag, Some(role)) = (opening_name(opening, src), static_value(attr, src)) else {
        return false;
    };
    NATIVE_ROLES.iter().any(|(t, r)| *t == tag && *r == role)
}

const ROLES: &[&str] = &[
    "alert",
    "alertdialog",
    "application",
    "article",
    "banner",
    "blockquote",
    "button",
    "caption",
    "cell",
    "checkbox",
    "code",
    "columnheader",
    "combobox",
    "complementary",
    "contentinfo",
    "definition",
    "deletion",
    "dialog",
    "directory",
    "document",
    "emphasis",
    "feed",
    "figure",
    "form",
    "generic",
    "grid",
    "gridcell",
    "group",
    "heading",
    "img",
    "insertion",
    "link",
    "list",
    "listbox",
    "listitem",
    "log",
    "main",
    "marquee",
    "math",
    "menu",
    "menubar",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "meter",
    "navigation",
    "none",
    "note",
    "option",
    "paragraph",
    "presentation",
    "progressbar",
    "radio",
    "radiogroup",
    "region",
    "row",
    "rowgroup",
    "rowheader",
    "scrollbar",
    "search",
    "searchbox",
    "separator",
    "slider",
    "spinbutton",
    "status",
    "strong",
    "subscript",
    "superscript",
    "switch",
    "tab",
    "table",
    "tablist",
    "tabpanel",
    "term",
    "textbox",
    "time",
    "timer",
    "toolbar",
    "tooltip",
    "tree",
    "treegrid",
    "treeitem",
];

fn role_is_unknown(attr: Node, src: &[u8]) -> bool {
    if !on_dom_element(attr, src) {
        return false;
    }
    let Some(value) = static_value(attr, src) else {
        return false;
    };
    let value = String::from_utf8_lossy(value);
    let mut tokens = value.split_whitespace().peekable();
    tokens.peek().is_some()
        && !tokens
            .any(|t| ROLES.contains(&t) || t.starts_with("doc-") || t.starts_with("graphics-"))
}

fn on_context_provider(attr: Node, src: &[u8]) -> bool {
    element_of_attribute(attr)
        .and_then(|o| o.child_by_field_name("name"))
        .is_some_and(|n| {
            text(n, src).ends_with(b".Provider") || text(n, src).ends_with(b"Provider")
        })
}

fn contains_jsx(node: Node) -> bool {
    !collect_below(node, |n| {
        matches!(
            n.kind(),
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
        )
    })
    .is_empty()
}

fn nested_component<'t>(component: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = component.child_by_field_name("body")?;
    if !contains_jsx(body) {
        return None;
    }
    collect_below(body, |n| {
        let named_function = n.kind() == "function_declaration"
            && n.child_by_field_name("name")
                .is_some_and(|name| text(name, src).first().is_some_and(u8::is_ascii_uppercase));
        let named_arrow = n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|name| text(name, src).first().is_some_and(u8::is_ascii_uppercase))
            && n.child_by_field_name("value")
                .is_some_and(|v| matches!(v.kind(), "arrow_function" | "function_expression"));
        (named_function || named_arrow) && contains_jsx(n)
    })
    .into_iter()
    .next()
}

const LIFECYCLE: &[&str] = &[
    "render",
    "constructor",
    "shouldComponentUpdate",
    "getSnapshotBeforeUpdate",
    "getDerivedStateFromProps",
    "getDerivedStateFromError",
    "getChildContext",
];

fn unused_component_method<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let heritage = class
        .named_children(&mut class.walk())
        .find(|c| c.kind() == "class_heritage")?;
    if !text(heritage, src).windows(9).any(|w| w == b"Component") {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    let class_text = text(class, src);
    let mut cursor = body.walk();
    body.named_children(&mut cursor).find(|m| {
        if m.kind() != "method_definition"
            || has_token(*m, "static")
            || has_token(*m, "get")
            || has_token(*m, "set")
        {
            return false;
        }
        let Some(name) = m.child_by_field_name("name") else {
            return false;
        };
        let name = text(name, src);
        if LIFECYCLE.iter().any(|l| l.as_bytes() == name)
            || name.starts_with(b"component")
            || name.starts_with(b"UNSAFE_")
        {
            return false;
        }
        class_text
            .windows(name.len())
            .filter(|w| *w == name)
            .count()
            <= 1
    })
}

const PLAIN_TAGS: &[&[u8]] = &[
    b"div", b"span", b"p", b"section", b"article", b"h1", b"h2", b"h3", b"h4", b"h5", b"h6", b"li",
    b"ul", b"ol", b"table", b"tr", b"td", b"th", b"header", b"footer", b"main", b"aside",
];

fn tabindex_on_plain_element(attr: Node, src: &[u8]) -> bool {
    let Some(opening) = element_of_attribute(attr) else {
        return false;
    };
    PLAIN_TAGS.contains(&opening_name(opening, src))
        && attribute(opening, "role", src).is_none()
        && static_value(attr, src)
            .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse::<i64>().ok())
            .is_some_and(|n| n >= 0)
}

fn activedescendant_not_focusable(attr: Node, src: &[u8]) -> bool {
    let Some(opening) = element_of_attribute(attr) else {
        return false;
    };
    let tag = opening_name(opening, src);
    tag.first().is_some_and(u8::is_ascii_lowercase)
        && !matches!(tag, b"input" | b"select" | b"textarea" | b"button" | b"a")
        && !has_spread(opening)
        && attribute(opening, "tabIndex", src).is_none()
}

const NATIVE_TAG_FOR_ROLE: &[(&[u8], &str)] = &[
    (b"button", "button"),
    (b"checkbox", "input"),
    (b"link", "a"),
    (b"heading", "h1"),
    (b"list", "ul"),
    (b"listitem", "li"),
    (b"navigation", "nav"),
    (b"main", "main"),
    (b"table", "table"),
    (b"banner", "header"),
    (b"contentinfo", "footer"),
    (b"form", "form"),
    (b"article", "article"),
    (b"complementary", "aside"),
    (b"region", "section"),
];

fn role_has_native_tag(attr: Node, src: &[u8]) -> bool {
    let Some(opening) = element_of_attribute(attr) else {
        return false;
    };
    matches!(opening_name(opening, src), b"div" | b"span")
        && static_value(attr, src)
            .is_some_and(|role| NATIVE_TAG_FOR_ROLE.iter().any(|(r, _)| *r == role))
}

// `option` and `treeitem` are left out: inside a listbox or tree, focus is
// usually managed with aria-activedescendant, not on each item.
const INTERACTIVE_ROLES: &[&[u8]] = &[
    b"button",
    b"checkbox",
    b"link",
    b"menuitem",
    b"menuitemcheckbox",
    b"menuitemradio",
    b"radio",
    b"slider",
    b"spinbutton",
    b"switch",
    b"tab",
    b"textbox",
    b"combobox",
    b"searchbox",
];

fn interactive_role_not_focusable(attr: Node, src: &[u8]) -> bool {
    let Some(opening) = element_of_attribute(attr) else {
        return false;
    };
    matches!(
        opening_name(opening, src),
        b"div" | b"span" | b"p" | b"li" | b"section" | b"td"
    ) && !has_spread(opening)
        && attribute(opening, "tabIndex", src).is_none()
        && static_value(attr, src).is_some_and(|r| INTERACTIVE_ROLES.contains(&r))
}

fn on_non_rendered_element(attr: Node, src: &[u8]) -> bool {
    element_of_attribute(attr).is_some_and(|o| {
        matches!(
            opening_name(o, src),
            b"meta" | b"html" | b"head" | b"title" | b"script" | b"style" | b"base"
        )
    })
}

fn aria_value_not_allowed(attr: Node, src: &[u8]) -> bool {
    if !on_dom_element(attr, src) {
        return false;
    }
    let Some(name) = attr.named_child(0).map(|n| text(n, src)) else {
        return false;
    };
    // A string literal only: `{expr}` and `{true}` are fine or unknowable.
    let Some(value) = attr.named_child(1).filter(|v| v.kind() == "string") else {
        return false;
    };
    let value = string_content(value, src);
    let tristate = matches!(name, b"aria-checked" | b"aria-pressed");
    !(value == b"true" || value == b"false" || (tristate && value == b"mixed"))
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Tsx, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn media_with_tracks_or_muted_is_fine() {
        let src = "const a = <video src={u} />;\nconst b = <video src={u}><track kind=\"captions\" /></video>;\nconst c = <video muted src={u} />;\nconst d = <audio {...p} />;";
        assert_eq!(flagged("js/media-captions", src), [1]);
    }

    #[test]
    fn object_content() {
        let src = "const a = <object data={u} />;\nconst b = <object data={u}>fallback</object>;\nconst c = <object data={u} title=\"t\" />;";
        assert_eq!(flagged("js/object-alternative-content", src), [1]);
    }

    #[test]
    fn roles() {
        let src = "const a = <button role=\"button\" />;\nconst b = <div role=\"buton\" />;\nconst c = <div role=\"button link\" tabIndex={0} />;\nconst d = <Foo role=\"buton\" />;\nconst e = <div role=\"doc-chapter\" />;\nconst f = <div role={r} />;";
        assert_eq!(flagged("js/redundant-role", src), [1]);
        assert_eq!(flagged("js/invalid-role", src), [2]);
    }

    #[test]
    fn focus_rules() {
        let src = "const a = <div tabIndex={0}>x</div>;\nconst b = <div tabIndex={-1}>x</div>;\nconst c = <div tabIndex={0} role=\"tab\">x</div>;\nconst d = <div role=\"button\" />;\nconst e = <div role=\"button\" tabIndex={0} />;\nconst f = <div aria-activedescendant={i} />;\nconst g = <input aria-activedescendant={i} />;";
        assert_eq!(flagged("js/noninteractive-tabindex", src), [1]);
        assert_eq!(flagged("js/role-needs-focus", src), [4]);
        assert_eq!(flagged("js/activedescendant-focus", src), [6]);
    }

    #[test]
    fn aria_values_and_unknown_props() {
        let src = "const a = <div aria-hidden=\"yes\" />;\nconst b = <div aria-hidden={flag} />;\nconst c = <div aria-checked=\"mixed\" />;\nconst d = <div aria-hidden=\"true\" />;\nconst e = <div class=\"x\" />;\nconst f = <Foo class=\"x\" />;";
        assert_eq!(flagged("js/aria-invalid-value", src), [1]);
        assert_eq!(flagged("js/unknown-dom-property", src), [5]);
    }

    #[test]
    fn components() {
        let src = "function Page() { const Row = () => <li />; return <ul />; }\nfunction Plain() { function helper() { return 1; } return <p />; }\nconst a = <Ctx.Provider value={{ x }} />;\nconst b = <Ctx.Provider value={v} />;\nconst c = <div value={{ x }} />;";
        assert_eq!(flagged("js/nested-component", src), [1]);
        assert_eq!(flagged("js/context-provider-value", src), [3]);
        let class = "class A extends React.Component {\n  used() { return 1; }\n  unused() { return 2; }\n  componentDidMount() {}\n  render() { return <p>{this.used()}</p>; }\n}\nclass B { unusedToo() {} }";
        assert_eq!(flagged("js/unused-component-method", class), [3]);
    }

    #[test]
    fn html_and_semantics() {
        let src = "const a = <html><body /></html>;\nconst b = <html lang=\"en\"><body /></html>;\nconst c = <meta aria-label=\"x\" />;\nconst d = <div role=\"navigation\" />;\nconst e = <span role=\"img\" aria-label=\"ok\" />;\nconst f = <div role=\"option\" />;";
        assert_eq!(flagged("js/html-lang", src), [1]);
        assert_eq!(flagged("js/aria-on-unsupported-element", src), [3]);
        assert_eq!(flagged("js/prefer-semantic-tag", src), [4]);
        assert!(flagged("js/role-needs-focus", src).is_empty());
    }
}
