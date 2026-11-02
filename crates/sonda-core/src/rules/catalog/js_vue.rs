//! Vue rules for JavaScript and TypeScript (ADR-0007, batch 28): props,
//! emitted events and refs in the `<script>` of single-file components
//! (`.vue` files are read as their script, in place) and in plain modules
//! that use the same compiler macros, plus the PropTypes twin of the
//! unused-props rule.

use super::js::{has_token, string_content, text};
use super::js_extra::named;
use super::js_syntax::{root_node, walk};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/vue-props-untyped",
        name: "Vue component props should declare a type",
        description: "A prop listed by name accepts anything.",
        message: "Declare a type for each prop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S8957")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(call_expression function: (identifier) @f (#eq? @f "defineProps")) (pair key: (property_identifier) @k value: (array) (#eq? @k "props"))] @match"#,
            filter: Some(Keep(props_lack_a_type)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const props = defineProps(['title']);",
            good: "const props = defineProps<{ title: string }>();",
        }),
    },
    Rule {
        id: "js/vue-required-prop-with-default",
        name: "Vue props with a default value should not be required",
        description: "A required prop is always passed, so its default never applies.",
        message: "Make it optional, or drop the default.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8950")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(pair value: (object)) (call_expression function: (identifier) @f (#eq? @f "withDefaults"))] @match"#,
            filter: Some(Keep(required_prop_has_a_default)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const props = defineProps({ size: { type: Number, required: true, default: 3 } });",
            good: "const props = defineProps({ size: { type: Number, default: 3 } });",
        }),
    },
    Rule {
        id: "js/vue-prop-mutated",
        name: "Vue component props should not be mutated directly",
        description: "Props belong to the parent; writing to them breaks one-way data flow.",
        message: "Emit an event, or copy the prop into local state.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8951")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(assignment_expression left: (member_expression object: (identifier) @o)) (augmented_assignment_expression left: (member_expression object: (identifier) @o)) (update_expression argument: (member_expression object: (identifier) @o))] @match"#,
            filter: Some(Keep(writes_to_props)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const props = defineProps<{ n: number }>(); props.n = 2;",
            good: "const props = defineProps<{ n: number }>(); const n = ref(props.n); n.value = 2;",
        }),
    },
    Rule {
        id: "js/vue-event-not-declared",
        name: "Vue component events should be explicitly declared",
        description: "An undeclared event is invisible to tooling and falls through to the root element.",
        message: "Declare the event in defineEmits.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S8961")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) arguments: (arguments . (string))) @match"#,
            filter: Some(Keep(emits_an_undeclared_event)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const emit = defineEmits(['save']); emit('close');",
            good: "const emit = defineEmits(['save', 'close']); emit('close');",
        }),
    },
    Rule {
        id: "js/vue-ref-untyped",
        name: "Vue ref and shallowRef calls should be typed",
        description: "ref(null) is typed as null, so nothing can be assigned later.",
        message: "Give ref a type argument.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8962")],
        check: Check::Query {
            langs: TS,
            query: r#"(call_expression function: (identifier) @f (#any-of? @f "ref" "shallowRef")) @match"#,
            filter: Some(Keep(ref_has_no_type)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "import { ref } from 'vue'; const user = ref(null);",
            good: "import { ref } from 'vue'; const user = ref<User | null>(null);",
        }),
    },
    Rule {
        id: "js/proptypes-unused",
        name: "Unused React typed props should be removed",
        description: "A prop type nobody reads is dead weight.",
        message: "Remove the prop from propTypes.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6767")],
        check: Check::Query {
            langs: JSX,
            query: r#"(program) @match"#,
            filter: Some(Find(declares_unused_prop_type)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function Hello(props) { return <p>{props.name}</p>; } Hello.propTypes = { name: PropTypes.string, age: PropTypes.number };",
            good: "function Hello(props) { return <p>{props.name}</p>; } Hello.propTypes = { name: PropTypes.string };",
        }),
    },
];

// ------------------------------------------------------------- helpers

/// The name bound by `const <name> = <macro>(...)` in the file.
fn macro_binding<'a>(root: Node, macro_name: &[u8], src: &'a [u8]) -> Option<&'a [u8]> {
    let mut found = None;
    walk(root, &mut |n| {
        if found.is_none()
            && n.kind() == "variable_declarator"
            && let (Some(name), Some(value)) = (
                n.child_by_field_name("name"),
                n.child_by_field_name("value"),
            )
        {
            let call = match value.kind() {
                "call_expression" => Some(value),
                _ => None,
            };
            let is_macro = call.is_some_and(|c| {
                c.child_by_field_name("function")
                    .is_some_and(|f| text(f, src) == macro_name)
            }) || (macro_name == b"defineProps"
                && call.is_some_and(|c| {
                    // const props = withDefaults(defineProps<...>(), {...})
                    c.child_by_field_name("function")
                        .is_some_and(|f| text(f, src) == b"withDefaults")
                }));
            if is_macro && name.kind() == "identifier" {
                found = Some(text(name, src));
            }
        }
        found.is_none()
    });
    found
}

fn key_text<'a>(pair: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    let k = pair.child_by_field_name("key")?;
    Some(if k.kind() == "string" {
        string_content(k, src)
    } else {
        text(k, src)
    })
}

fn find_pair<'t>(object: Node<'t>, key: &[u8], src: &[u8]) -> Option<Node<'t>> {
    named(object)
        .into_iter()
        .find(|p| p.kind() == "pair" && key_text(*p, src) == Some(key))
}

// ------------------------------------------------------------- props

fn props_lack_a_type(node: Node, src: &[u8]) -> bool {
    match node.kind() {
        "pair" => node
            .child_by_field_name("value")
            .is_some_and(|a| named(a).iter().all(|e| e.kind() == "string") && !named(a).is_empty()),
        "call_expression" => {
            let Some(arg) = node
                .child_by_field_name("arguments")
                .and_then(|a| a.named_child(0))
            else {
                return false;
            };
            match arg.kind() {
                "array" => {
                    named(arg).iter().all(|e| e.kind() == "string") && !named(arg).is_empty()
                }
                "object" => named(arg).iter().any(|p| {
                    p.kind() == "pair"
                        && p.child_by_field_name("value")
                            .is_some_and(|v| match v.kind() {
                                "null" | "undefined" => true,
                                "object" => find_pair(v, b"type", src).is_none(),
                                _ => false,
                            })
                }),
                _ => false,
            }
        }
        _ => false,
    }
}

fn inside_props_definition(node: Node, src: &[u8]) -> bool {
    let mut cur = node.parent();
    let mut steps = 0;
    while let Some(p) = cur {
        steps += 1;
        if steps > 8 {
            return false;
        }
        match p.kind() {
            "call_expression"
                if p.child_by_field_name("function")
                    .is_some_and(|f| text(f, src) == b"defineProps") =>
            {
                return true;
            }
            "pair" if key_text(p, src) == Some(b"props") => return true,
            _ => {}
        }
        cur = p.parent();
    }
    false
}

fn required_prop_has_a_default(node: Node, src: &[u8]) -> bool {
    if node.kind() == "pair" {
        let Some(object) = node
            .child_by_field_name("value")
            .filter(|v| v.kind() == "object")
        else {
            return false;
        };
        let required = find_pair(object, b"required", src)
            .and_then(|p| p.child_by_field_name("value"))
            .is_some_and(|v| v.kind() == "true");
        return required
            && find_pair(object, b"default", src).is_some()
            && inside_props_definition(node, src);
    }
    // withDefaults(defineProps<{ a: string }>(), { a: 'x' })
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    let args = named(arguments);
    let (Some(props_call), Some(defaults)) = (args.first(), args.get(1)) else {
        return false;
    };
    if defaults.kind() != "object" {
        return false;
    }
    let Some(members) = props_call
        .child_by_field_name("type_arguments")
        .and_then(|t| t.named_child(0))
        .filter(|t| t.kind() == "object_type")
    else {
        return false;
    };
    named(members).into_iter().any(|m| {
        m.kind() == "property_signature"
            && !has_token(m, "?")
            && m.child_by_field_name("name")
                .is_some_and(|n| find_pair(*defaults, text(n, src), src).is_some())
    })
}

fn writes_to_props(node: Node, src: &[u8]) -> bool {
    let target = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("argument"));
    let Some(object) = target.and_then(|t| t.child_by_field_name("object")) else {
        return false;
    };
    macro_binding(root_node(node), b"defineProps", src) == Some(text(object, src))
}

// ------------------------------------------------------------- events

fn declared_events(call: Node, src: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(arg) = call
        .child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
    {
        match arg.kind() {
            "array" => {
                for e in named(arg).into_iter().filter(|e| e.kind() == "string") {
                    out.push(string_content(e, src).to_vec());
                }
            }
            "object" => {
                for p in named(arg) {
                    if let Some(k) = key_text(p, src) {
                        out.push(k.to_vec());
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(types) = call
        .child_by_field_name("type_arguments")
        .and_then(|t| t.named_child(0))
        .filter(|t| t.kind() == "object_type")
    {
        for m in named(types) {
            match m.kind() {
                "call_signature" => {
                    // (e: 'change', value: string): void
                    let mut strings = Vec::new();
                    walk(m, &mut |n| {
                        if n.kind() == "string" && strings.is_empty() {
                            strings.push(string_content(n, src).to_vec());
                        }
                        strings.is_empty()
                    });
                    out.append(&mut strings);
                }
                "property_signature" => {
                    if let Some(n) = m.child_by_field_name("name") {
                        out.push(match n.kind() {
                            "string" => string_content(n, src).to_vec(),
                            _ => text(n, src).to_vec(),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    out
}

fn emits_an_undeclared_event(call: Node, src: &[u8]) -> bool {
    let Some(callee) = call.child_by_field_name("function") else {
        return false;
    };
    let root = root_node(call);
    let mut define = None;
    walk(root, &mut |n| {
        if define.is_none()
            && n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == text(callee, src))
            && let Some(v) = n.child_by_field_name("value")
            && v.kind() == "call_expression"
            && v.child_by_field_name("function")
                .is_some_and(|f| text(f, src) == b"defineEmits")
        {
            define = Some(v);
        }
        define.is_none()
    });
    let Some(define) = define else {
        return false;
    };
    let declared = declared_events(define, src);
    if declared.is_empty() {
        return false;
    }
    let Some(event) = call
        .child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
    else {
        return false;
    };
    !declared
        .iter()
        .any(|d| d.as_slice() == string_content(event, src))
}

// ------------------------------------------------------------- refs

fn ref_has_no_type(call: Node, src: &[u8]) -> bool {
    if call.child_by_field_name("type_arguments").is_some() {
        return false;
    }
    let root = text(root_node(call), src);
    if !(root.windows(5).any(|w| w == b"'vue'") || root.windows(5).any(|w| w == b"\"vue\"")) {
        return false;
    }
    match call
        .child_by_field_name("arguments")
        .map(named)
        .unwrap_or_default()
        .as_slice()
    {
        [] => true,
        [only] => match only.kind() {
            "null" | "undefined" => true,
            "array" => named(*only).is_empty(),
            _ => false,
        },
        _ => false,
    }
}

// ------------------------------------------------------------- PropTypes

fn declares_unused_prop_type<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut found = None;
    walk(program, &mut |n| {
        if found.is_some() {
            return false;
        }
        if n.kind() == "assignment_expression"
            && let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
            && left.kind() == "member_expression"
            && right.kind() == "object"
            && left
                .child_by_field_name("property")
                .is_some_and(|p| text(p, src) == b"propTypes")
            && let Some(component) = left.child_by_field_name("object")
        {
            found = unused_prop_in(program, text(component, src), right, src);
        }
        found.is_none()
    });
    found
}

fn unused_prop_in<'t>(
    program: Node<'t>,
    component: &[u8],
    prop_types: Node<'t>,
    src: &[u8],
) -> Option<Node<'t>> {
    let mut function = None;
    walk(program, &mut |n| {
        if function.is_none() {
            let named_it = |name: Option<Node>| name.is_some_and(|x| text(x, src) == component);
            match n.kind() {
                "function_declaration" if named_it(n.child_by_field_name("name")) => {
                    function = Some(n);
                }
                "variable_declarator" if named_it(n.child_by_field_name("name")) => {
                    function = n
                        .child_by_field_name("value")
                        .filter(|v| matches!(v.kind(), "arrow_function" | "function_expression"));
                }
                _ => {}
            }
        }
        function.is_none()
    });
    let body = text(function?.child_by_field_name("body")?, src);
    // The whole props object, or a spread, may hand any prop on.
    let hands_on = body.windows(3).any(|w| w == b"...")
        || body
            .windows(6)
            .enumerate()
            .any(|(i, w)| w == b"props)" || (w == b"props," && i > 0));
    if hands_on {
        return None;
    }
    let word_in_body = |word: &[u8]| {
        body.windows(word.len()).enumerate().any(|(i, w)| {
            w == word
                && !body
                    .get(i.wrapping_sub(1))
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                && !body
                    .get(i + word.len())
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        })
    };
    named(prop_types)
        .into_iter()
        .find(|p| p.kind() == "pair" && key_text(*p, src).is_some_and(|k| !word_in_body(k)))
}
