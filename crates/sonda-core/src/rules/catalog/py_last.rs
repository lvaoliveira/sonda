//! The last Python rules that need only one file's syntax (ADR-0007,
//! batch 17): documentation, call signatures, protocol return types, and a
//! few library checks.

use super::js_extra::count_word;
use super::py_extra::BUILTIN_NAMES;
use super::py_more::{
    body_of, imported_names, in_class, is_decorated, literal_family, name_of, receiver_text,
};
use super::py_quality::{SCOPE_STOPS, find_in_scope, statements};
use super::py_security::{
    call_arguments, callee_name, contains_ignoring_case, keyword_value, string_value, text,
};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    // Documentation and licence-header policies are a project decision.
    "py/missing-docstring",
    "py/missing-license-header",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/missing-docstring",
        name: "Docstrings should be defined",
        description: "Public modules, classes and functions are documented in their docstring.",
        message: "Add a docstring.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1720")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match
(function_definition) @match
(class_definition) @match"#,
            filter: Some(Find(lacks_a_docstring)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def run():\n    return 1\n",
            good: "\"\"\"Tools.\"\"\"\ndef run():\n    \"\"\"Run it.\"\"\"\n    return 1\n",
        }),
    },
    Rule {
        id: "py/missing-license-header",
        name: "Track lack of copyright and license headers",
        description: "A header states who owns the file and under which terms it is shared.",
        message: "Add the header.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S1451")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match"#,
            filter: Some(Find(lacks_a_license_header)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import os\n",
            good: "# Copyright 2026 Example Ltd.\nimport os\n",
        }),
    },
    Rule {
        id: "py/aws-polling-loop",
        name: "AWS waiters should be used instead of custom polling loops",
        description: "A waiter polls with the right delays and gives up cleanly.",
        message: "Use client.get_waiter().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7621")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(while_statement) @match"#,
            filter: Some(Keep(loop_polls_an_aws_call)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import boto3\nwhile True:\n    s = ec2.describe_instances()\n    time.sleep(5)\n",
            good: "import boto3\nec2.get_waiter('instance_running').wait()\n",
        }),
    },
    Rule {
        id: "py/lambda-tmp-not-cleaned",
        name: "AWS Lambda handlers should clean up temporary files in /tmp directory",
        description: "The directory survives between invocations and fills up.",
        message: "Delete the file when done.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7620")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(handler_leaves_tmp_files)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def lambda_handler(event, context):\n    open('/tmp/out', 'w').write('x')\n",
            good: "import os\ndef lambda_handler(event, context):\n    open('/tmp/out', 'w').write('x')\n    os.remove('/tmp/out')\n",
        }),
    },
    Rule {
        id: "py/lambda-non-json-return",
        name: "AWS Lambda handlers should return only JSON serializable values",
        description: "The runtime serializes the return value with json.",
        message: "Return plain dicts, lists, strings and numbers.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7613")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(handler_returns_non_json)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import datetime\ndef lambda_handler(event, context):\n    return {'at': datetime.datetime.now()}\n",
            good: "def lambda_handler(event, context):\n    return {'at': 'now'}\n",
        }),
    },
    Rule {
        id: "py/flask-single-method-route",
        name: "Generic route decorators should not be used",
        description: "@app.get says the method without a keyword argument.",
        message: "Use @app.get, @app.post and so on.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8412")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorator (call function: (attribute attribute: (identifier) @m (#eq? @m "route"))) @match)"#,
            filter: Some(Keep(route_names_a_single_method)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.route('/x', methods=['GET'])\ndef x():\n    pass\n",
            good: "@app.get('/x')\ndef x():\n    pass\n",
        }),
    },
    Rule {
        id: "py/flask-view-decorator",
        name: "Flask class-based view decorators should be applied using the decorators attribute",
        description: "Wrapping as_view() hides the view's name and breaks routing.",
        message: "Set `decorators = [...]` on the view class.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8374")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: [(identifier) (attribute attribute: (identifier))] @f arguments: (argument_list (call function: (attribute attribute: (identifier) @a (#eq? @a "as_view"))))) @match"#,
            filter: Some(Keep(wraps_as_view)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.add_url_rule('/x', view_func=login_required(V.as_view('x')))\n",
            good: "class V(View):\n    decorators = [login_required]\napp.add_url_rule('/x', view_func=V.as_view('x'))\n",
        }),
    },
    Rule {
        id: "py/pandas-datetime-format",
        name: "Dates should be formatted correctly when using pandas.to_datetime with dayfirst or yearfirst",
        description: "An explicit format makes dayfirst and yearfirst ignored.",
        message: "Drop one of them.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6894")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "to_datetime"))) @match"#,
            filter: Some(Keep(format_beside_dayfirst)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = pd.to_datetime(s, format='%d/%m/%Y', dayfirst=True)\n",
            good: "d = pd.to_datetime(s, format='%d/%m/%Y')\n",
        }),
    },
    Rule {
        id: "py/einops-pattern",
        name: "Einops pattern should be valid",
        description: "A pattern needs an arrow and balanced parentheses.",
        message: "Fix the pattern.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6984")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: [(identifier) @f (attribute attribute: (identifier) @f)] (#any-of? @f "rearrange" "reduce" "repeat")) @match"#,
            filter: Some(Keep(einops_pattern_is_invalid)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import einops\ny = einops.rearrange(x, 'b c h w')\n",
            good: "import einops\ny = einops.rearrange(x, 'b c h w -> b (c h) w')\n",
        }),
    },
    Rule {
        id: "py/special-method-return",
        name: "Functions and methods should only return expected values",
        description: "Python rejects a __len__ that returns text or a __bool__ that returns a number.",
        message: "Return the type the protocol asks for.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S935")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(special_method_returns_wrong_type)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __len__(self):\n        return 'a'\n",
            good: "class A:\n    def __len__(self):\n        return 1\n",
        }),
    },
    Rule {
        id: "py/call-argument-mismatch",
        name: "The number and name of arguments passed to a function should match its parameters",
        description: "A wrong count or name raises TypeError.",
        message: "Fix the call.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S930")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier)) @match"#,
            filter: Some(Keep(call_does_not_fit_signature)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(a, b):\n    return a\nf(1, 2, 3)\n",
            good: "def f(a, b):\n    return a\nf(1, 2)\n",
        }),
    },
    Rule {
        id: "py/builtin-argument-type",
        name: "Arguments given to functions should be of an expected type",
        description: "A number is not iterable and has no length.",
        message: "Pass the expected type.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5655")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "len" "sorted" "sum" "min" "max" "iter" "list" "tuple" "set" "enumerate" "reversed" "zip")) @match"#,
            filter: Some(Keep(builtin_gets_a_scalar)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "n = len(5)\n",
            good: "n = len([5])\n",
        }),
    },
    Rule {
        id: "py/used-before-defined",
        name: "Variables, classes and functions should be defined before being used",
        description: "At module level a name must exist when the statement runs.",
        message: "Move the definition up.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S3827")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match"#,
            filter: Some(Find(module_uses_name_before_definition)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "print(later)\nlater = 1\n",
            good: "later = 1\nprint(later)\n",
        }),
    },
    Rule {
        id: "py/typevar-generic-function",
        name: "Generic functions should be defined using the type parameter syntax",
        description: "Python 3.12 declares type parameters on the function.",
        message: "Use def f[T](x: T).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6796")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(function_uses_a_typevar)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from typing import TypeVar\nT = TypeVar('T')\ndef first(x: list[T]) -> T:\n    return x[0]\n",
            good: "def first[T](x: list[T]) -> T:\n    return x[0]\n",
        }),
    },
    Rule {
        id: "py/keras-input-shape",
        name: "The input_shape parameter should not be specified for tf.keras.Model subclasses",
        description: "A subclassed model builds on the first call; input_shape is ignored.",
        message: "Remove input_shape.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6919")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(model_layer_sets_input_shape)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class M(tf.keras.Model):\n    def __init__(self):\n        super().__init__()\n        self.d = Dense(1, input_shape=(3,))\n",
            good: "class M(tf.keras.Model):\n    def __init__(self):\n        super().__init__()\n        self.d = Dense(1)\n",
        }),
    },
    Rule {
        id: "py/xml-signature-no-x509",
        name: "XML signatures should be validated securely",
        description: "Without a certificate check anyone can sign the document.",
        message: "Keep require_x509 on, and pin the certificate.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S6377")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "verify"))) @match"#,
            filter: Some(Keep(verifies_without_certificate)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import signxml\nXMLVerifier().verify(data, require_x509=False)\n",
            good: "import signxml\nXMLVerifier().verify(data, x509_cert=cert)\n",
        }),
    },
];

// ---------------------------------------------------- filters

fn root_of(node: Node) -> Node {
    let mut n = node;
    while let Some(p) = n.parent() {
        n = p;
    }
    n
}

fn is_docstring(statement: Node) -> bool {
    statement.kind() == "expression_statement"
        && statement
            .named_child(0)
            .is_some_and(|e| e.kind() == "string")
}

fn lacks_a_docstring<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    match node.kind() {
        "module" => {
            let first = statements(node).into_iter().next()?;
            (!is_docstring(first)).then_some(first)
        }
        kind => {
            let name = name_of(node, src);
            let owner = node.parent()?;
            let top = owner.kind() == "module"
                || (owner.kind() == "block"
                    && owner
                        .parent()
                        .is_some_and(|c| c.kind() == "class_definition"));
            if !top
                || name.starts_with(b"_")
                || name.starts_with(b"test")
                || (kind == "function_definition" && is_decorated(node))
            {
                return None;
            }
            let first = statements(body_of(node)?).into_iter().next()?;
            (!is_docstring(first))
                .then(|| node.child_by_field_name("name"))
                .flatten()
        }
    }
}

fn lacks_a_license_header<'t>(module: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let head: Vec<u8> = src
        .split(|&b| b == b'\n')
        .take(5)
        .flat_map(|l| l.iter().copied().chain(*b"\n"))
        .collect();
    let has = ["copyright", "license", "licence"]
        .iter()
        .any(|w| contains_ignoring_case(&head, w.as_bytes()));
    (!has)
        .then(|| statements(module).into_iter().next())
        .flatten()
}

fn loop_polls_an_aws_call(loop_: Node, src: &[u8]) -> bool {
    if !contains_ignoring_case(src, b"boto3") {
        return false;
    }
    let Some(body) = loop_.child_by_field_name("body") else {
        return false;
    };
    let calls: Vec<&[u8]> = super::py_extra::collect_calls(body, src);
    calls.contains(&&b"sleep"[..])
        && calls.iter().any(|c| {
            c.starts_with(b"describe_") || c.starts_with(b"get_") || c.starts_with(b"head_")
        })
}

fn is_lambda_handler(function: Node, src: &[u8]) -> bool {
    matches!(name_of(function, src), b"lambda_handler" | b"handler")
        && super::py_more::first_parameter_name(function, src) == Some(b"event")
}

fn handler_leaves_tmp_files<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_lambda_handler(function, src) {
        return None;
    }
    let body = body_of(function)?;
    let whole = text(body, src);
    let cleans = [
        "remove(",
        "unlink(",
        "rmtree(",
        "TemporaryDirectory",
        "NamedTemporaryFile",
        "cleanup",
    ]
    .iter()
    .any(|w| contains_ignoring_case(whole, w.as_bytes()));
    if cleans {
        return None;
    }
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "string" && contains_ignoring_case(text(n, src), b"/tmp")
    })
}

fn handler_returns_non_json<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_lambda_handler(function, src) {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "return_statement"
            && n.named_child(0).is_some_and(|v| {
                let t = text(v, src);
                v.kind() == "set"
                    || (v.kind() == "string"
                        && t.first().is_some_and(|b| b.eq_ignore_ascii_case(&b'b')))
                    || contains_ignoring_case(t, b"datetime.")
                    || contains_ignoring_case(t, b"Decimal(")
                    || contains_ignoring_case(t, b"timedelta(")
                    || t.starts_with(b"set(")
            })
    })
}

fn route_names_a_single_method(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "methods", src)
        .is_some_and(|m| matches!(m.kind(), "list" | "tuple") && statements(m).len() == 1)
}

fn wraps_as_view(call: Node, src: &[u8]) -> bool {
    let name = callee_name(call, src);
    name != b"as_view"
        && (name.ends_with(b"_required")
            || matches!(
                name,
                b"csrf_exempt"
                    | b"never_cache"
                    | b"cache_page"
                    | b"cache_control"
                    | b"decorator"
                    | b"method_decorator"
                    | b"require_http_methods"
                    | b"require_GET"
                    | b"require_POST"
            ))
}

fn format_beside_dayfirst(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "format", src).is_some()
        && (keyword_value(call, "dayfirst", src).is_some()
            || keyword_value(call, "yearfirst", src).is_some())
}

fn einops_pattern_is_invalid(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let positional: Vec<&Node> = args
        .iter()
        .filter(|a| a.kind() != "keyword_argument")
        .collect();
    let Some(pattern) = keyword_value(call, "pattern", src)
        .or_else(|| positional.get(1).map(|n| **n))
        .and_then(|p| string_value(p, src))
    else {
        return false;
    };
    let mut depth = 0i32;
    let mut balanced = true;
    for &b in pattern {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                balanced &= depth >= 0;
            }
            _ => {}
        }
    }
    !pattern.windows(2).any(|w| w == b"->") || !balanced || depth != 0
}

fn special_method_returns_wrong_type<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let want = match name_of(function, src) {
        b"__bool__" => "bool",
        b"__len__" | b"__hash__" | b"__index__" | b"__int__" | b"__float__" => "number",
        b"__str__" | b"__repr__" | b"__format__" => "string",
        _ => return None,
    };
    if !in_class(function) {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "return_statement"
            && n.named_child(0).is_some_and(|v| {
                let is_bytes = v.kind() == "string"
                    && text(v, src)
                        .first()
                        .is_some_and(|b| b.eq_ignore_ascii_case(&b'b'));
                match literal_family(v.kind()) {
                    Some(got) => !is_bytes && got != want && !(want == "number" && got == "bool"),
                    None => false,
                }
            })
    })
}

struct Signature<'s> {
    required: usize,
    positional: Vec<&'s [u8]>,
    keyword_only: Vec<&'s [u8]>,
    star_args: bool,
    star_kwargs: bool,
}

fn signature<'s>(function: Node, src: &'s [u8]) -> Option<Signature<'s>> {
    let params = function.child_by_field_name("parameters")?;
    let mut sig = Signature {
        required: 0,
        positional: Vec::new(),
        keyword_only: Vec::new(),
        star_args: false,
        star_kwargs: false,
    };
    let mut after_star = false;
    for p in statements(params) {
        let (name, has_default) = match p.kind() {
            "identifier" => (Some(text(p, src)), false),
            "typed_parameter" => (
                p.named_child(0)
                    .filter(|n| n.kind() == "identifier")
                    .map(|n| text(n, src)),
                false,
            ),
            "default_parameter" | "typed_default_parameter" => {
                (p.child_by_field_name("name").map(|n| text(n, src)), true)
            }
            "list_splat_pattern" => {
                sig.star_args = true;
                after_star = true;
                continue;
            }
            "keyword_separator" => {
                after_star = true;
                continue;
            }
            "dictionary_splat_pattern" => {
                sig.star_kwargs = true;
                continue;
            }
            "positional_separator" => continue,
            _ => return None,
        };
        let name = name?;
        if after_star {
            sig.keyword_only.push(name);
        } else {
            sig.positional.push(name);
            if !has_default {
                sig.required += 1;
            }
        }
    }
    Some(sig)
}

fn call_does_not_fit_signature(call: Node, src: &[u8]) -> bool {
    let Some(callee) = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "identifier")
    else {
        return false;
    };
    let name = text(callee, src);
    let root = root_of(call);
    let defs: Vec<Node> = statements(root)
        .into_iter()
        .filter(|s| s.kind() == "function_definition" && name_of(*s, src) == name)
        .collect();
    let [def] = defs.as_slice() else { return false };
    let mut def_marker = b"def ".to_vec();
    def_marker.extend_from_slice(name);
    if src
        .windows(def_marker.len())
        .filter(|w| *w == def_marker.as_slice())
        .count()
        != 1
    {
        return false;
    }
    let Some(sig) = signature(*def, src) else {
        return false;
    };
    let args = call_arguments(call);
    if args
        .iter()
        .any(|a| matches!(a.kind(), "list_splat" | "dictionary_splat"))
    {
        return false;
    }
    let positional = args
        .iter()
        .filter(|a| a.kind() != "keyword_argument")
        .count();
    let keywords: Vec<&[u8]> = args
        .iter()
        .filter(|a| a.kind() == "keyword_argument")
        .filter_map(|a| a.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    if positional > sig.positional.len() && !sig.star_args {
        return true;
    }
    for k in &keywords {
        let known = sig.positional.contains(k) || sig.keyword_only.contains(k);
        if !known && !sig.star_kwargs {
            return true;
        }
    }
    let covered = positional
        + keywords
            .iter()
            .filter(|k| sig.positional.iter().skip(positional).any(|p| p == *k))
            .count();
    covered < sig.required
}

fn builtin_gets_a_scalar(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let name = callee_name(call, src);
    let [only] = args.as_slice() else {
        return false;
    };
    let _ = name;
    matches!(only.kind(), "integer" | "float" | "true" | "false" | "none")
}

fn top_level_bindings<'s>(module: Node, src: &'s [u8]) -> Vec<(&'s [u8], usize)> {
    let mut out = Vec::new();
    let nested = ["function_definition", "class_definition", "lambda"];
    let mut cursor = module.walk();
    let mut descend = true;
    if !cursor.goto_first_child() {
        return out;
    }
    loop {
        let n = cursor.node();
        if descend {
            match n.kind() {
                "function_definition" | "class_definition" => {
                    if let Some(name) = n.child_by_field_name("name") {
                        out.push((text(name, src), n.start_byte()));
                    }
                }
                "assignment" | "augmented_assignment" | "for_statement" => {
                    if let Some(l) = n.child_by_field_name("left") {
                        for id in super::py_extra::identifiers_in(l) {
                            out.push((text(id, src), id.start_byte()));
                        }
                    }
                }
                "import_statement" | "import_from_statement" => {
                    for name in imported_names(n, src) {
                        out.push((name, n.start_byte()));
                    }
                }
                "with_item" | "as_pattern" | "named_expression" | "except_clause"
                | "global_statement" => {
                    for id in super::py_extra::identifiers_in(n) {
                        out.push((text(id, src), id.start_byte()));
                    }
                }
                _ => {}
            }
        }
        if descend && !nested.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        descend = true;
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return out;
            }
        }
    }
}

fn module_uses_name_before_definition<'t>(module: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if find_in_scope(module, &[], |n| n.kind() == "wildcard_import").is_some()
        || contains_ignoring_case(src, b"globals()")
    {
        return None;
    }
    let bindings = top_level_bindings(module, src);
    for s in statements(module) {
        if s.kind() != "expression_statement" {
            continue;
        }
        // Comprehension variables are local to the comprehension.
        let stops = [
            "function_definition",
            "class_definition",
            "lambda",
            "list_comprehension",
            "set_comprehension",
            "dictionary_comprehension",
            "generator_expression",
        ];
        let hit = find_in_scope(s, &stops, |n| {
            if n.kind() != "identifier" {
                return false;
            }
            let name = text(n, src);
            if BUILTIN_NAMES.iter().any(|b| b.as_bytes() == name) {
                return false;
            }
            let loaded = match n.parent() {
                Some(p) => match p.kind() {
                    "attribute" => p.child_by_field_name("object") == Some(n),
                    "keyword_argument" => p.child_by_field_name("value") == Some(n),
                    "assignment" => p.child_by_field_name("left") != Some(n),
                    _ => true,
                },
                None => false,
            };
            if !loaded {
                return false;
            }
            let mut mine = bindings
                .iter()
                .filter(|(b, _)| *b == name)
                .map(|(_, at)| *at);
            let first = mine.clone().min();
            first.is_some_and(|f| f > n.start_byte()) && mine.all(|at| at > n.start_byte())
        });
        if hit.is_some() {
            return hit;
        }
    }
    None
}

fn function_uses_a_typevar(function: Node, src: &[u8]) -> bool {
    if in_class(function) {
        return false;
    }
    let Some(name) = function.child_by_field_name("name") else {
        return false;
    };
    if src.get(name.end_byte()) == Some(&b'[') {
        return false;
    }
    let root = root_of(function);
    let vars: Vec<&[u8]> = statements(root)
        .into_iter()
        .filter_map(|s| {
            let a = super::py_more::assignment_of(s)?;
            let call = a
                .child_by_field_name("right")
                .filter(|r| r.kind() == "call")?;
            matches!(
                callee_name(call, src),
                b"TypeVar" | b"ParamSpec" | b"TypeVarTuple"
            )
            .then(|| a.child_by_field_name("left").map(|l| text(l, src)))
            .flatten()
        })
        .collect();
    let mut annotations: Vec<&[u8]> = Vec::new();
    if let Some(p) = function.child_by_field_name("parameters") {
        annotations.push(text(p, src));
    }
    if let Some(r) = function.child_by_field_name("return_type") {
        annotations.push(text(r, src));
    }
    vars.iter()
        .any(|v| annotations.iter().any(|a| count_word(a, v) > 0))
}

fn model_layer_sets_input_shape<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let supers = class.child_by_field_name("superclasses")?;
    if !contains_ignoring_case(text(supers, src), b"Model") {
        return None;
    }
    find_in_scope(body_of(class)?, &["class_definition"], |n| {
        n.kind() == "call" && keyword_value(n, "input_shape", src).is_some()
    })
}

fn verifies_without_certificate(call: Node, src: &[u8]) -> bool {
    contains_ignoring_case(receiver_text(call, src), b"Verifier")
        && keyword_value(call, "require_x509", src).is_some_and(|v| text(v, src) == b"False")
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Python, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn calls_against_signatures() {
        let src = "def f(a, b=1, *, c=2):\n    return a\nf(1)\nf(1, 2, 3)\nf(1, c=3)\nf(1, d=3)\nf()\ndef g(*args, **kw):\n    pass\ng(1, 2, x=3)\nf(*xs)";
        assert_eq!(flagged("py/call-argument-mismatch", src), [4, 6, 7]);
    }

    #[test]
    fn module_order() {
        let src = "print(later)\nlater = 1\nx = x_defined\nx_defined = 2\nok = 1\nprint(ok)\ndef f():\n    return other\nother = 3";
        assert_eq!(flagged("py/used-before-defined", src), [1]);
    }

    #[test]
    fn protocol_returns_and_typevars() {
        let src = "from typing import TypeVar\nT = TypeVar('T')\ndef first(x: list[T]) -> T:\n    return x[0]\ndef plain(x: int) -> int:\n    return x\nclass A:\n    def __len__(self):\n        return 'a'\n    def __bool__(self):\n        return 1\n    def __str__(self):\n        return 's'";
        assert_eq!(flagged("py/typevar-generic-function", src), [3]);
        assert_eq!(flagged("py/special-method-return", src), [9, 11]);
    }

    #[test]
    fn docstrings_and_headers() {
        let src = "\"\"\"Module.\"\"\"\ndef documented():\n    \"\"\"Yes.\"\"\"\ndef bare():\n    pass\ndef _private():\n    pass";
        assert_eq!(flagged("py/missing-docstring", src), [4]);
        assert!(flagged("py/missing-license-header", "# Copyright 2026\nx = 1\n").is_empty());
        assert_eq!(flagged("py/missing-license-header", "x = 1\n"), [1]);
    }
}
