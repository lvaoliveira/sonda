//! The Python rules that were left (ADR-0007, batch 21): call signatures
//! and overrides inside one file, tests, TensorFlow, scikit-learn, boto3,
//! Flask, GraphQL, template strings and suppression comments. Each reads
//! only the file it reports on.

use super::js_syntax::walk;
use super::py_last::{Signature, is_lambda_handler, signature};
use super::py_more::{body_of, name_of};
use super::py_quality::statements;
use super::py_security::{call_arguments, callee_name, keyword_value, text};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &["py/long-integer-suffix"];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/argument-passed-twice",
        name: "Function arguments should be passed only once",
        description: "A parameter given by position and again by keyword raises a TypeError.",
        message: "Pass this argument once.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S5549")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier)) @match"#,
            filter: Some(Keep(passes_an_argument_twice)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def area(width, height):\n    return width * height\n\narea(2, width=3)\n",
            good: "def area(width, height):\n    return width * height\n\narea(2, height=3)\n",
        }),
    },
    Rule {
        id: "py/override-changes-contract",
        name: "Method overrides should not change contracts",
        description: "An override that drops or renames a parameter, or requires a new one, cannot be called the way the base method is.",
        message: "Keep the base method's parameters.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2638")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(override_changes_contract)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def run(self, x):\n        return x\n\nclass B(A):\n    def run(self, x, y):\n        return x + y\n",
            good: "class A:\n    def run(self, x):\n        return x\n\nclass B(A):\n    def run(self, x, y=0):\n        return x + y\n",
        }),
    },
    Rule {
        id: "py/similar-tests",
        name: "Similar tests should be grouped in a single Parameterized test",
        description: "Three tests that differ only in their literals are one test with three rows.",
        message: "Use pytest.mark.parametrize.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S5976")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match
(class_definition) @match"#,
            filter: Some(Find(similar_tests)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def test_a():\n    assert add(1, 2) == 3\n    assert add(1, 2) != 4\n\ndef test_b():\n    assert add(2, 3) == 5\n    assert add(2, 3) != 6\n\ndef test_c():\n    assert add(3, 4) == 7\n    assert add(3, 4) != 8\n",
            good: "@pytest.mark.parametrize('a,b,c', [(1, 2, 3), (2, 3, 5), (3, 4, 7)])\ndef test_add(a, b, c):\n    assert add(a, b) == c\n",
        }),
    },
    Rule {
        id: "py/except-star-exception-group",
        name: "ExceptionGroup and BaseExceptionGroup should not be caught with except*",
        description: "except* splits an exception group by type; naming the group itself raises a TypeError.",
        message: "Catch the group with a plain except.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6468")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(except_clause) @match"#,
            filter: Some(Keep(except_star_catches_a_group)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    run()\nexcept* ExceptionGroup:\n    pass\n",
            good: "try:\n    run()\nexcept ExceptionGroup:\n    pass\n",
        }),
    },
    Rule {
        id: "py/graphql-introspection-enabled",
        name: "GraphQL introspection should be disabled in production",
        description: "Introspection hands an attacker the whole schema.",
        message: "Add NoSchemaIntrospectionCustomRule to validation_rules.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6786")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call) @match"#,
            filter: Some(Keep(graphql_view_allows_introspection)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from graphql_server.flask import GraphQLView\napp.add_url_rule('/g', view_func=GraphQLView.as_view('graphql', schema=schema))\n",
            good: "from graphql_server.flask import GraphQLView\napp.add_url_rule('/g', view_func=GraphQLView.as_view('graphql', schema=schema, validation_rules=[NoSchemaIntrospectionCustomRule]))\n",
        }),
    },
    Rule {
        id: "py/graphql-no-depth-limit",
        name: "GraphQL queries should not be vulnerable to Denial of Service attacks",
        description: "A deeply nested query makes the server resolve far more than any client needs.",
        message: "Add depth_limit_validator to validation_rules.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6785")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call) @match"#,
            filter: Some(Keep(graphql_view_has_no_depth_limit)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from graphql_server.flask import GraphQLView\napp.add_url_rule('/g', view_func=GraphQLView.as_view('graphql', schema=schema))\n",
            good: "from graphql_server.flask import GraphQLView\napp.add_url_rule('/g', view_func=GraphQLView.as_view('graphql', schema=schema, validation_rules=[depth_limit_validator(max_depth=10)]))\n",
        }),
    },
    Rule {
        id: "py/typevar-in-type-statement",
        name: "Generic type statements should not use \"TypeVars\"",
        description: "A type statement declares its own type parameters; a TypeVar from outside is rejected.",
        message: "Declare the parameter on the type statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6795")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(type_alias_statement) @match"#,
            filter: Some(Keep(type_statement_uses_a_typevar)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from typing import TypeVar\n_T = TypeVar('_T')\ntype MyAlias = set[_T]\n",
            good: "type MyAlias[T] = set[T]\n",
        }),
    },
    Rule {
        id: "py/tf-function-global-variable",
        name: "\"tf.function\" should not depend on global or free Python variables",
        description: "A tf.function traces a global once; later changes to it are silently ignored.",
        message: "Pass the value as an argument.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6911")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Find(tf_function_reads_a_global)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import tensorflow as tf\nfoo = 4\n\n@tf.function\ndef addition():\n    return 1 + foo\n",
            good: "import tensorflow as tf\n\n@tf.function\ndef addition(foo):\n    return 1 + foo\n",
        }),
    },
    Rule {
        id: "py/flask-route-without-methods",
        name: "REST API actions should be annotated with an HTTP verb attribute",
        description: "A Flask route without methods answers only GET; a handler that reads request.method then gets a 405 before it runs.",
        message: "Name the HTTP methods this route accepts.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6965")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorator (call function: (attribute attribute: (identifier) @m (#eq? @m "route")))) @match"#,
            filter: Some(Keep(route_names_no_methods)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/users')\ndef users():\n    return 'x'\n",
            good: "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/users', methods=['GET'])\ndef users():\n    return 'x'\n",
        }),
    },
    Rule {
        id: "py/sklearn-cached-transformer-access",
        name: "Transformers should not be accessed directly when a Scikit-Learn Pipeline uses caching",
        description: "A cached pipeline clones its transformers when it is fitted: the objects outside it are never updated.",
        message: "Read it through pipeline.named_steps.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6971")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match"#,
            filter: Some(Find(reads_a_cached_transformer)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from sklearn.pipeline import Pipeline\nfrom sklearn.preprocessing import RobustScaler\nscaler = RobustScaler()\npipeline = Pipeline([('scaler', scaler)], memory='cache')\npipeline.fit(data)\nprint(scaler.center_)\n",
            good: "from sklearn.pipeline import Pipeline\nfrom sklearn.preprocessing import RobustScaler\nscaler = RobustScaler()\npipeline = Pipeline([('scaler', scaler)], memory='cache')\npipeline.fit(data)\nprint(pipeline.named_steps['scaler'].center_)\n",
        }),
    },
    Rule {
        id: "py/sklearn-unknown-pipeline-step",
        name: "Nested estimator parameters modification in a Pipeline should refer to valid parameters",
        description: "set_params(step__param=...) on a step the pipeline does not have raises a ValueError.",
        message: "Use the name of a step in this pipeline.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6972")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "set_params"))) @match"#,
            filter: Some(Keep(sets_params_of_an_unknown_step)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from sklearn.pipeline import Pipeline\nfrom sklearn.decomposition import PCA\npipe = Pipeline(steps=[('reduce_dim', PCA())])\npipe.set_params(reduce__n_components=2)\n",
            good: "from sklearn.pipeline import Pipeline\nfrom sklearn.decomposition import PCA\npipe = Pipeline(steps=[('reduce_dim', PCA())])\npipe.set_params(reduce_dim__n_components=2)\n",
        }),
    },
    Rule {
        id: "py/boto3-client-error",
        name: "\"botocore.exceptions.ClientError\" should be explicitly caught and handled",
        description: "boto3 reports a failed call as ClientError; a handler that never names it hides the cause.",
        message: "Catch botocore.exceptions.ClientError around this call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7619")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(boto_call_without_client_error)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import boto3\ns3 = boto3.client('s3')\n\ndef lambda_handler(event, context):\n    return s3.get_object(Bucket='b', Key='k')\n",
            good: "import boto3\nfrom botocore.exceptions import ClientError\ns3 = boto3.client('s3')\n\ndef lambda_handler(event, context):\n    try:\n        return s3.get_object(Bucket='b', Key='k')\n    except ClientError as e:\n        raise\n",
        }),
    },
    Rule {
        id: "py/suppression-comment-format",
        name: "Issue suppression comment should have the correct format",
        description: "A NOSONAR or noqa comment with a malformed list suppresses nothing, or more than meant.",
        message: "Fix the format of this suppression comment.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S7632")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comment) @match"#,
            filter: Some(Keep(suppression_is_malformed)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = 1  # noqa- E501\n",
            good: "x = 1  # noqa: E501\n",
        }),
    },
    Rule {
        id: "py/django-custom-password-hasher",
        name: "Custom cryptographic algorithms should not be used",
        description: "A hasher written by subclassing BasePasswordHasher skips the review a standard algorithm has had.",
        message: "Use one of Django's own hashers.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S2257")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition superclasses: (argument_list) @s) @match"#,
            filter: Some(Keep(subclasses_the_base_hasher)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from django.contrib.auth.hashers import BasePasswordHasher\nclass Mine(BasePasswordHasher):\n    pass\n",
            good: "from django.contrib.auth.hashers import Argon2PasswordHasher\nclass Mine(Argon2PasswordHasher):\n    pass\n",
        }),
    },
    Rule {
        id: "py/backticks",
        name: "Backticks should not be used",
        description: "Backticks are Python 2's repr(); Python 3 rejects them.",
        message: "Use repr().",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("BackticksUsage")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(string) @match"#,
            filter: Some(Keep(is_backtick_string)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = `value`\n",
            good: "x = repr(value)\n",
        }),
    },
    Rule {
        id: "py/long-integer-suffix",
        name: "Long suffix \"L\" should be upper case",
        description: "A lower case l is easily read as the digit 1.",
        message: "Write the suffix as L.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("LongIntegerWithLowercaseSuffixUsage")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(integer) @match"#,
            filter: Some(Keep(has_lowercase_long_suffix)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = 10l\n",
            good: "x = 10L\n",
        }),
    },
    Rule {
        id: "py/template-string-concatenated",
        name: "Template and str should not be concatenated directly",
        description: "Adding a string to a t-string raises a TypeError.",
        message: "Process the template first.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7943")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(binary_operator) @match"#,
            filter: Some(Keep(adds_to_a_template)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "name = 'x'\nmessage = t'hello {name}' + '!'\n",
            good: "name = 'x'\nmessage = render(t'hello {name}') + '!'\n",
        }),
    },
    Rule {
        id: "py/template-string-used-as-str",
        name: "Template strings should be processed before use",
        description: "A t-string is a Template, not a str: printing or measuring it directly does not do what an f-string does.",
        message: "Process the template into a string first.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7942")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call) @match"#,
            filter: Some(Keep(template_is_used_as_a_string)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "name = 'x'\nprint(t'hello {name}')\n",
            good: "name = 'x'\nprint(render(t'hello {name}'))\n",
        }),
    },
    Rule {
        id: "py/template-processing-with-isinstance",
        name: "Template string processing should use structural pattern matching",
        description: "Telling a Template's parts apart is what match statements are for.",
        message: "Use a match statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7945")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "isinstance")) @match"#,
            filter: Some(Keep(isinstance_picks_interpolation)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def render(template):\n    for part in template:\n        if isinstance(part, Interpolation):\n            print(part.value)\n",
            good: "def render(template):\n    for part in template:\n        match part:\n            case Interpolation(value=v):\n                print(v)\n",
        }),
    },
];

// ---------------------------------------------------------------- helpers

fn root_of(node: Node) -> Node {
    let mut n = node;
    while let Some(p) = n.parent() {
        n = p;
    }
    n
}

/// The decorators of a function or class, as source text.
fn decorator_texts<'s>(definition: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    definition
        .parent()
        .filter(|p| p.kind() == "decorated_definition")
        .map(|d| {
            let mut cursor = d.walk();
            d.children(&mut cursor)
                .filter(|c| c.kind() == "decorator")
                .map(|c| text(c, src))
                .collect()
        })
        .unwrap_or_default()
}

fn top_level_definition<'t>(
    root: Node<'t>,
    kind: &str,
    name: &[u8],
    src: &[u8],
) -> Option<Node<'t>> {
    let mut found = Vec::new();
    for s in statements(root) {
        let s = if s.kind() == "decorated_definition" {
            match s.child_by_field_name("definition") {
                Some(d) => d,
                None => continue,
            }
        } else {
            s
        };
        if s.kind() == kind && name_of(s, src) == name {
            found.push(s);
        }
    }
    match found.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

// ---------------------------------------------------------------- signatures

fn passes_an_argument_twice(call: Node, src: &[u8]) -> bool {
    let Some(callee) = call.child_by_field_name("function") else {
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
    // The same keyword twice is a syntax error the parser may still accept.
    if keywords
        .iter()
        .enumerate()
        .any(|(i, k)| keywords[..i].contains(k))
    {
        return true;
    }
    let Some(def) =
        top_level_definition(root_of(call), "function_definition", text(callee, src), src)
    else {
        return false;
    };
    let Some(sig) = signature(def, src) else {
        return false;
    };
    keywords
        .iter()
        .any(|k| sig.positional.iter().take(positional).any(|p| p == k))
}

fn method_signature<'s>(method: Node, src: &'s [u8]) -> Option<Signature<'s>> {
    // Decorated methods (properties, overloads, static and class methods) have
    // contracts of their own kind.
    if method
        .parent()
        .is_some_and(|p| p.kind() == "decorated_definition")
    {
        return None;
    }
    signature(method, src)
}

fn override_changes_contract<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let supers = class.child_by_field_name("superclasses")?;
    let root = root_of(class);
    let bases: Vec<Node> = statements(supers)
        .into_iter()
        .filter(|s| s.kind() == "identifier")
        .filter_map(|s| top_level_definition(root, "class_definition", text(s, src), src))
        .collect();
    let [base] = bases.as_slice() else {
        return None;
    };
    // Only a single base in this file, and no other base to supply the method.
    if statements(supers).len() != 1 {
        return None;
    }
    let methods = |c: Node<'t>| -> Vec<Node<'t>> {
        body_of(c)
            .map(statements)
            .unwrap_or_default()
            .into_iter()
            .filter(|s| s.kind() == "function_definition")
            .collect()
    };
    let base_methods = methods(*base);
    methods(class).into_iter().find(|m| {
        let name = name_of(*m, src);
        if name.starts_with(b"__") && name.ends_with(b"__") {
            return false;
        }
        let Some(b) = base_methods.iter().find(|b| name_of(**b, src) == name) else {
            return false;
        };
        let (Some(bs), Some(os)) = (method_signature(*b, src), method_signature(*m, src)) else {
            return false;
        };
        if os.star_args && os.star_kwargs {
            return false;
        }
        let dropped_or_renamed = bs
            .positional
            .iter()
            .enumerate()
            .any(|(i, n)| os.positional.get(i) != Some(n) && !os.star_args);
        let more_required = os.required > bs.required;
        let lost_keyword_only = bs
            .keyword_only
            .iter()
            .any(|k| !os.keyword_only.contains(k) && !os.positional.contains(k) && !os.star_kwargs);
        dropped_or_renamed || more_required || lost_keyword_only
    })
}

// ---------------------------------------------------------------- tests

fn normalized(node: Node, src: &[u8]) -> Vec<u8> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    walk(node, &mut |n| {
        if matches!(n.kind(), "string" | "integer" | "float") {
            ranges.push((n.start_byte(), n.end_byte()));
            return false;
        }
        true
    });
    let mut out = Vec::new();
    let mut at = node.start_byte();
    for (s, e) in ranges {
        out.extend_from_slice(&src[at..s]);
        out.push(b'#');
        at = e;
    }
    out.extend_from_slice(&src[at..node.end_byte()]);
    out.retain(|b| !b.is_ascii_whitespace());
    out
}

fn similar_tests<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let block = if container.kind() == "class_definition" {
        body_of(container)?
    } else {
        container
    };
    let tests: Vec<Node> = statements(block)
        .into_iter()
        .filter_map(|s| {
            if s.kind() == "decorated_definition" {
                s.child_by_field_name("definition").map(|d| (s, d))
            } else {
                Some((s, s))
            }
        })
        .filter(|(_, d)| d.kind() == "function_definition" && name_of(*d, src).starts_with(b"test"))
        // Parametrized or fixture-decorated tests are already grouped.
        .filter(|(whole, d)| whole.id() == d.id())
        .map(|(_, d)| d)
        .collect();
    let keys: Vec<Vec<u8>> = tests
        .iter()
        .map(|t| {
            t.child_by_field_name("body")
                .map(|b| normalized(b, src))
                .unwrap_or_default()
        })
        .collect();
    (0..tests.len()).find_map(|i| {
        let same = keys.iter().filter(|k| **k == keys[i]).count();
        (keys[i].len() >= 20 && same >= 3 && !keys[..i].contains(&keys[i])).then_some(tests[i])
    })
}

// ---------------------------------------------------------------- exceptions

fn except_star_catches_a_group(clause: Node, src: &[u8]) -> bool {
    let Some(value) = clause.child_by_field_name("value") else {
        return false;
    };
    let before = &src[clause.start_byte()..value.start_byte()];
    if !before.contains(&b'*') {
        return false;
    }
    let mut named_group = false;
    walk(value, &mut |n| {
        if n.kind() == "identifier"
            && matches!(text(n, src), b"ExceptionGroup" | b"BaseExceptionGroup")
        {
            named_group = true;
        }
        true
    });
    if value.kind() == "identifier" {
        named_group |= matches!(text(value, src), b"ExceptionGroup" | b"BaseExceptionGroup");
    }
    named_group
}

// ---------------------------------------------------------------- GraphQL

fn is_graphql_view_call(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let t = text(function, src);
    t == b"GraphQLView" || t.ends_with(b"GraphQLView.as_view") || t.ends_with(b".GraphQLView")
}

fn validation_rules_text<'s>(call: Node, src: &'s [u8]) -> &'s [u8] {
    keyword_value(call, "validation_rules", src).map_or(&b""[..], |v| text(v, src))
}

fn mentions(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn graphql_view_allows_introspection(call: Node, src: &[u8]) -> bool {
    is_graphql_view_call(call, src)
        && !mentions(
            validation_rules_text(call, src),
            b"NoSchemaIntrospectionCustomRule",
        )
}

fn graphql_view_has_no_depth_limit(call: Node, src: &[u8]) -> bool {
    is_graphql_view_call(call, src) && !mentions(validation_rules_text(call, src), b"depth_limit")
}

// ---------------------------------------------------------------- typing

fn type_statement_uses_a_typevar(statement: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        statement.child_by_field_name("left"),
        statement.child_by_field_name("right"),
    ) else {
        return false;
    };
    // `type A[T] = ...` declares its own parameters.
    let mut generic = false;
    walk(left, &mut |n| {
        generic |= n.kind() == "generic_type";
        true
    });
    if generic {
        return false;
    }
    let mut typevars: Vec<&[u8]> = Vec::new();
    for s in statements(root_of(statement)) {
        if s.kind() != "expression_statement" {
            continue;
        }
        let Some(a) = s.named_child(0).filter(|a| a.kind() == "assignment") else {
            continue;
        };
        if let (Some(l), Some(r)) = (
            a.child_by_field_name("left"),
            a.child_by_field_name("right"),
        ) && l.kind() == "identifier"
            && r.kind() == "call"
            && matches!(
                callee_name(r, src),
                b"TypeVar" | b"ParamSpec" | b"TypeVarTuple"
            )
        {
            typevars.push(text(l, src));
        }
    }
    let mut uses = false;
    walk(right, &mut |n| {
        uses |= n.kind() == "identifier" && typevars.contains(&text(n, src));
        true
    });
    uses
}

// ---------------------------------------------------------------- TensorFlow

fn tf_function_reads_a_global<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = decorated
        .child_by_field_name("definition")
        .filter(|d| d.kind() == "function_definition")?;
    let is_tf = decorator_texts(function, src)
        .iter()
        .any(|d| mentions(d, b"tf.function") || mentions(d, b"tensorflow.function"));
    if !is_tf {
        return None;
    }
    let body = function.child_by_field_name("body")?;
    // Names the function itself binds.
    let mut local: Vec<&[u8]> = Vec::new();
    if let Some(params) = function.child_by_field_name("parameters") {
        walk(params, &mut |n| {
            if n.kind() == "identifier" {
                local.push(text(n, src));
            }
            true
        });
    }
    walk(body, &mut |n| {
        match n.kind() {
            "assignment" | "augmented_assignment" => {
                if let Some(l) = n.child_by_field_name("left") {
                    if l.kind() == "identifier" {
                        local.push(text(l, src));
                    } else {
                        walk(l, &mut |c| {
                            if c.kind() == "identifier" {
                                local.push(text(c, src));
                            }
                            true
                        });
                    }
                }
            }
            "for_statement" | "for_in_clause" | "as_pattern" => {
                if let Some(l) = n
                    .child_by_field_name("left")
                    .or_else(|| n.child_by_field_name("alias"))
                {
                    walk(l, &mut |c| {
                        if c.kind() == "identifier" {
                            local.push(text(c, src));
                        }
                        true
                    });
                    if l.kind() == "identifier" {
                        local.push(text(l, src));
                    }
                }
            }
            _ => {}
        }
        true
    });
    // Module-level variables: assigned there, not constants, imports or defs.
    let mut globals: Vec<&[u8]> = Vec::new();
    for s in statements(root_of(function)) {
        if s.kind() != "expression_statement" {
            continue;
        }
        if let Some(a) = s.named_child(0).filter(|a| a.kind() == "assignment")
            && let Some(l) = a
                .child_by_field_name("left")
                .filter(|l| l.kind() == "identifier")
        {
            let name = text(l, src);
            let constant = name
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_');
            if !constant {
                globals.push(name);
            }
        }
    }
    let mut found = None;
    walk(body, &mut |n| {
        if found.is_some() {
            return false;
        }
        if n.kind() == "identifier"
            && globals.contains(&text(n, src))
            && !local.contains(&text(n, src))
            && n.parent().is_none_or(|p| {
                !(p.kind() == "attribute" && p.child_by_field_name("attribute") == Some(n))
                    && !(p.kind() == "keyword_argument" && p.child_by_field_name("name") == Some(n))
            })
        {
            found = Some(n);
        }
        true
    });
    found
}

// ---------------------------------------------------------------- Flask

fn route_names_no_methods(decorator: Node, src: &[u8]) -> bool {
    let Some(call) = decorator.named_child(0).filter(|c| c.kind() == "call") else {
        return false;
    };
    let file = text(root_of(decorator), src).to_ascii_lowercase();
    mentions(&file, b"flask") && keyword_value(call, "methods", src).is_none()
}

// ---------------------------------------------------------------- scikit-learn

/// `name = Pipeline(...)` assignments: the variable and the call.
fn pipelines<'t>(root: Node<'t>, src: &[u8]) -> Vec<(Node<'t>, Node<'t>)> {
    let mut out = Vec::new();
    walk(root, &mut |n| {
        if n.kind() == "assignment"
            && let (Some(l), Some(r)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
            && l.kind() == "identifier"
            && r.kind() == "call"
            && callee_name(r, src) == b"Pipeline"
        {
            out.push((l, r));
        }
        true
    });
    out
}

/// The `(name, estimator)` tuples of a pipeline call.
fn pipeline_steps<'t>(call: Node<'t>, src: &[u8]) -> Vec<(Vec<u8>, Option<Node<'t>>)> {
    let list = keyword_value(call, "steps", src).or_else(|| {
        call_arguments(call)
            .into_iter()
            .next()
            .filter(|a| a.kind() != "keyword_argument")
    });
    let Some(list) = list.filter(|l| l.kind() == "list") else {
        return Vec::new();
    };
    statements(list)
        .into_iter()
        .filter(|t| t.kind() == "tuple")
        .filter_map(|t| {
            let parts = statements(t);
            let name = parts.first().filter(|n| n.kind() == "string")?;
            let t = text(*name, src);
            Some((
                t[1..t.len().saturating_sub(1)].to_vec(),
                parts.get(1).copied(),
            ))
        })
        .collect()
}

fn reads_a_cached_transformer<'t>(module: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut variables: Vec<&[u8]> = Vec::new();
    for (_, call) in pipelines(module, src) {
        if keyword_value(call, "memory", src).is_none() {
            continue;
        }
        for (_, estimator) in pipeline_steps(call, src) {
            if let Some(e) = estimator.filter(|e| e.kind() == "identifier") {
                variables.push(text(e, src));
            }
        }
    }
    if variables.is_empty() {
        return None;
    }
    let mut found = None;
    walk(module, &mut |n| {
        if found.is_none()
            && n.kind() == "attribute"
            && let (Some(o), Some(a)) = (
                n.child_by_field_name("object"),
                n.child_by_field_name("attribute"),
            )
            && o.kind() == "identifier"
            && variables.contains(&text(o, src))
            && text(a, src).ends_with(b"_")
            && !text(a, src).ends_with(b"__")
        {
            found = Some(n);
        }
        found.is_none()
    });
    found
}

fn sets_params_of_an_unknown_step(call: Node, src: &[u8]) -> bool {
    let Some(object) = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
        .filter(|o| o.kind() == "identifier")
    else {
        return false;
    };
    let root = root_of(call);
    let declared: Vec<_> = pipelines(root, src)
        .into_iter()
        .filter(|(l, _)| text(*l, src) == text(object, src))
        .collect();
    let [(_, pipeline)] = declared.as_slice() else {
        return false;
    };
    let steps = pipeline_steps(*pipeline, src);
    if steps.is_empty() {
        return false;
    }
    call_arguments(call).into_iter().any(|a| {
        a.kind() == "keyword_argument"
            && a.child_by_field_name("name").is_some_and(|n| {
                let t = text(n, src);
                t.windows(2)
                    .position(|w| w == b"__")
                    .is_some_and(|i| !steps.iter().any(|(s, _)| s.as_slice() == &t[..i]))
            })
    })
}

// ---------------------------------------------------------------- boto3

fn boto_call_without_client_error<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_lambda_handler(function, src) {
        return None;
    }
    let root = root_of(function);
    // Variables holding a boto3 client or resource.
    let mut clients: Vec<&[u8]> = Vec::new();
    walk(root, &mut |n| {
        if n.kind() == "assignment"
            && let (Some(l), Some(r)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
            && l.kind() == "identifier"
            && r.kind() == "call"
            && r.child_by_field_name("function").is_some_and(|f| {
                let t = text(f, src);
                t.ends_with(b".client") || t.ends_with(b".resource")
            })
            && mentions(text(root, src), b"boto3")
        {
            clients.push(text(l, src));
        }
        true
    });
    if clients.is_empty() {
        return None;
    }
    let body = function.child_by_field_name("body")?;
    let mut found = None;
    walk(body, &mut |n| {
        if found.is_some() {
            return false;
        }
        if n.kind() == "call"
            && let Some(f) = n.child_by_field_name("function")
            && f.kind() == "attribute"
            && f.child_by_field_name("object")
                .is_some_and(|o| o.kind() == "identifier" && clients.contains(&text(o, src)))
        {
            // Inside a try whose handlers name ClientError?
            let mut handled = false;
            let mut up = n.parent();
            while let Some(p) = up {
                if p.id() == function.id() {
                    break;
                }
                if p.kind() == "try_statement" {
                    let mut cursor = p.walk();
                    handled |= p
                        .children(&mut cursor)
                        .filter(|c| {
                            c.kind() == "except_clause" || c.kind() == "except_group_clause"
                        })
                        .any(|c| mentions(text(c, src), b"ClientError"));
                }
                up = p.parent();
            }
            if !handled {
                found = Some(n);
            }
        }
        true
    });
    found
}

// ---------------------------------------------------------------- comments

fn suppression_is_malformed(comment: Node, src: &[u8]) -> bool {
    let t = String::from_utf8_lossy(text(comment, src)).into_owned();
    let body = t.trim_start_matches('#').trim_start();
    let rule_key = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric());
    if let Some(rest) = body.strip_prefix("NOSONAR") {
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            return false;
        }
        let Some(inner) = rest.strip_prefix('(') else {
            return true;
        };
        let Some(close) = inner.find(')') else {
            return true;
        };
        let keys = inner[..close].trim();
        return !keys.is_empty() && !keys.split(',').all(|k| rule_key(k.trim()));
    }
    let lower = body.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("noqa") {
        let rest_original = &body[4..];
        let _ = rest;
        if rest_original.is_empty() || rest_original.starts_with(char::is_whitespace) {
            return false;
        }
        let Some(list) = rest_original.strip_prefix(':') else {
            return rest_original.starts_with(|c: char| c.is_ascii_punctuation());
        };
        let list = list.split('#').next().unwrap_or("").trim();
        return list.is_empty() || !list.split(',').all(|k| rule_key(k.trim()));
    }
    false
}

// ---------------------------------------------------------------- Python 2 leftovers

fn is_backtick_string(string: Node, src: &[u8]) -> bool {
    text(string, src).first() == Some(&b'`')
}

fn has_lowercase_long_suffix(integer: Node, src: &[u8]) -> bool {
    text(integer, src).last() == Some(&b'l')
}

// ---------------------------------------------------------------- Django

fn subclasses_the_base_hasher(class: Node, src: &[u8]) -> bool {
    class
        .child_by_field_name("superclasses")
        .is_some_and(|s| mentions(text(s, src), b"BasePasswordHasher"))
}

// ---------------------------------------------------------------- template strings

fn is_template_string(node: Node, src: &[u8]) -> bool {
    node.kind() == "string"
        && node
            .child(0)
            .filter(|c| c.kind() == "string_start")
            .is_some_and(|start| {
                text(start, src)
                    .iter()
                    .take_while(|b| b.is_ascii_alphabetic())
                    .any(|b| b.eq_ignore_ascii_case(&b't'))
            })
}

fn adds_to_a_template(binary: Node, src: &[u8]) -> bool {
    binary
        .child_by_field_name("operator")
        .is_some_and(|o| text(o, src) == b"+")
        && ["left", "right"].iter().any(|f| {
            binary
                .child_by_field_name(f)
                .is_some_and(|c| is_template_string(c, src))
        })
}

fn template_is_used_as_a_string(call: Node, src: &[u8]) -> bool {
    const STRING_USES: &[&[u8]] = &[
        b"print",
        b"str",
        b"len",
        b"repr",
        b"write",
        b"join",
        b"info",
        b"debug",
        b"warning",
        b"error",
        b"critical",
        b"log",
        b"startswith",
        b"endswith",
        b"encode",
        b"format",
    ];
    if let Some(function) = call.child_by_field_name("function")
        && function.kind() == "attribute"
        && function
            .child_by_field_name("object")
            .is_some_and(|o| is_template_string(o, src))
    {
        return true;
    }
    STRING_USES.contains(&callee_name(call, src))
        && call_arguments(call)
            .into_iter()
            .any(|a| is_template_string(a, src))
}

fn isinstance_picks_interpolation(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .get(1)
        .is_some_and(|c| mentions(text(*c, src), b"Interpolation"))
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
    fn arguments_given_twice() {
        let src = "def f(a, b, *, c=1):\n    pass\nf(1, a=2)\nf(1, b=2)\nf(1, 2, c=3)\nf(a=1, a=2)\nf(*xs, a=1)";
        assert_eq!(flagged("py/argument-passed-twice", src), [3, 6]);
    }

    #[test]
    fn overrides_keep_the_contract() {
        let src = "class A:\n    def f(self, x, y=1):\n        pass\n    def g(self, x):\n        pass\n    def h(self, x, *, k):\n        pass\nclass B(A):\n    def f(self, x):\n        pass\n    def g(self, y):\n        pass\n    def h(self, x):\n        pass\nclass C(A):\n    def f(self, x, y=1, z=2):\n        pass\n    def g(self, x, *args, **kw):\n        pass\n";
        assert_eq!(flagged("py/override-changes-contract", src), [9]);
    }

    #[test]
    fn suppression_comments() {
        let src = "a = 1  # NOSONAR\nb = 2  # NOSONAR(S1)\nc = 3  # NOSONAR(a,)\nd = 4  # NOSONAR(\ne = 5  # noqa: E501,W291\nf = 6  # noqa: ,E501\ng = 7  # noqa- E501\nh = 8  # noqa\ni = 9  # NOSONAR(python:S7632)";
        assert_eq!(
            flagged("py/suppression-comment-format", src),
            [3, 4, 6, 7, 9]
        );
    }

    #[test]
    fn tensorflow_free_variables() {
        let src = "import tensorflow as tf\nfoo = 4\nLIMIT = 3\n@tf.function\ndef a():\n    return 1 + foo\n@tf.function\ndef b(foo):\n    return 1 + foo\n@tf.function\ndef c():\n    return 1 + LIMIT\n";
        assert_eq!(flagged("py/tf-function-global-variable", src), [6]);
    }

    #[test]
    fn boto_calls_in_handlers() {
        let src = "import boto3\nfrom botocore.exceptions import ClientError\ns3 = boto3.client('s3')\ndef lambda_handler(event, context):\n    try:\n        s3.get_object(Key='k')\n    except Exception:\n        pass\n    try:\n        s3.put_object(Key='k')\n    except ClientError:\n        pass\n    s3.list_buckets()\n";
        assert_eq!(flagged("py/boto3-client-error", src), [6]);
    }

    #[test]
    fn pipelines() {
        let src = "from sklearn.pipeline import Pipeline\ns = Scaler()\nk = Knn()\np = Pipeline([('scaler', s), ('knn', k)], memory='c')\nprint(s.center_)\nprint(k.n_neighbors)\np.set_params(scaler__a=1)\np.set_params(scale__a=1)\n";
        assert_eq!(flagged("py/sklearn-cached-transformer-access", src), [5]);
        assert_eq!(flagged("py/sklearn-unknown-pipeline-step", src), [8]);
    }

    #[test]
    fn template_strings() {
        let src = "name = 'x'\na = t'a {name}' + 'b'\nb = f'a {name}' + 'b'\nprint(t'a {name}')\nprint(f'a {name}')\nc = t'a'.upper()\n";
        assert_eq!(flagged("py/template-string-concatenated", src), [2]);
        assert_eq!(flagged("py/template-string-used-as-str", src), [4, 6]);
    }

    #[test]
    fn graphql_and_flask() {
        let src = "from flask import Flask\nfrom graphql_server.flask import GraphQLView\napp = Flask(__name__)\n@app.route('/a')\ndef a():\n    pass\n@app.route('/b', methods=['POST'])\ndef b():\n    pass\nv = GraphQLView.as_view('g', schema=s)\nw = GraphQLView.as_view('g', schema=s, validation_rules=[NoSchemaIntrospectionCustomRule, depth_limit_validator(max_depth=5)])\n";
        assert_eq!(flagged("py/flask-route-without-methods", src), [4]);
        assert_eq!(flagged("py/graphql-introspection-enabled", src), [10]);
        assert_eq!(flagged("py/graphql-no-depth-limit", src), [10]);
    }

    #[test]
    fn similar_tests_and_type_statements() {
        let src = "def test_a():\n    assert add(1, 2) == 3\n    assert add(1, 2) != 4\ndef test_b():\n    assert add(2, 3) == 5\n    assert add(2, 3) != 6\ndef test_c():\n    assert add(3, 4) == 7\n    assert add(3, 4) != 8\ndef test_d():\n    assert sub(3, 4) == -1\n";
        assert_eq!(flagged("py/similar-tests", src), [1]);
        let ts = "from typing import TypeVar\n_T = TypeVar('_T')\ntype A = set[_T]\ntype B[T] = set[T]\ntype C = set[int]\n";
        assert_eq!(flagged("py/typevar-in-type-statement", ts), [3]);
    }
}
