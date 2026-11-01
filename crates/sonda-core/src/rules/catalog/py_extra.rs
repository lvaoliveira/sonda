//! More Python rules (ADR-0007, batch 14): frameworks, async libraries, and
//! the type-hint and ML-library checks.

use super::js_extra::count_word;
use super::py_more::{
    assignment_of, body_of, call_statement_of, first_parameter_name, imported_names, in_class,
    is_decorated, is_dunder, is_generator, is_private_name, is_stub_body, literal_family,
    loop_pair, name_of, receiver_text,
};
use super::py_quality::{
    SCOPE_STOPS, children_of_kind, find_in_scope, has_token, nearest_function, statements,
    two_operands,
};
use super::py_security::{
    call_arguments, callee_name, contains_ignoring_case, integer_value, keyword_value,
    string_value, text,
};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    // Style rules that fire on most real Python: every method that skips
    // self, every untyped signature, every trailing comment. Python 3.14
    // moved the compression modules, which most projects don't target yet.
    "py/method-could-be-static",
    "py/hint-missing-return",
    "py/hint-missing-parameter",
    "py/compression-namespace",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/jump-outside-loop",
        name: "break and continue should not be used outside a loop",
        description: "Outside a loop they are a SyntaxError, and in a loop's else clause they belong to the enclosing loop.",
        message: "Remove this jump, or move it into the loop.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S1716")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(break_statement) @match
(continue_statement) @match"#,
            filter: Some(Keep(jump_is_outside_a_loop)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    break\n",
            good: "def f(xs):\n    for x in xs:\n        break\n",
        }),
    },
    Rule {
        id: "py/silly-equality",
        name: "Unnecessary equality checks should not be made",
        description: "Values of different kinds are never equal, so the comparison has a fixed result.",
        message: "Compare comparable values.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2159")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(equality_between_different_literals)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if 1 == 'a':\n    pass\n",
            good: "if x == 'a':\n    pass\n",
        }),
    },
    Rule {
        id: "py/ignored-pure-call",
        name: "Return values from functions without side effects should not be ignored",
        description: "Calling len() or sorted() and dropping the result does nothing.",
        message: "Use the result, or remove the call.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2201")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(expression_statement (call function: (identifier) @f (#any-of? @f "len" "sorted" "reversed" "abs" "min" "max" "sum" "round" "any" "all" "repr" "map" "filter" "zip" "enumerate" "range" "isinstance" "hash" "id" "chr" "ord" "divmod" "pow")) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(xs):\n    sorted(xs)\n",
            good: "def f(xs):\n    return sorted(xs)\n",
        }),
    },
    Rule {
        id: "py/method-could-be-static",
        name: "Methods and properties that don't access instance data should be static",
        description: "A method that never uses self does not need an instance.",
        message: "Make this a static method, or a function.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2325")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(method_ignores_self)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def double(self, x):\n        return x * 2\n",
            good: "class A:\n    @staticmethod\n    def double(x):\n        return x * 2\n",
        }),
    },
    Rule {
        id: "py/invariant-return",
        name: "Functions returns should not be invariant",
        description: "If every return gives the same constant, the return value carries no information.",
        message: "Return something that varies, or return nothing.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S3516")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(returns_are_all_the_same_constant)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x):\n    if x:\n        return 0\n    return 0\n",
            good: "def f(x):\n    if x:\n        return 0\n    return 1\n",
        }),
    },
    Rule {
        id: "py/result-of-no-return-function",
        name: "The output of functions that don't return anything should not be used",
        description: "The function always yields None.",
        message: "Don't use this result, or make the function return one.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3699")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment right: (call function: (identifier))) @match"#,
            filter: Some(Keep(assigns_result_of_function_without_return)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def log(x):\n    print(x)\nr = log(1)\n",
            good: "def double(x):\n    return x * 2\nr = double(1)\n",
        }),
    },
    Rule {
        id: "py/route-mixed-methods",
        name: "HTTP routes should restrict allowed HTTP methods",
        description: "One route that serves GET and a state-changing verb makes CSRF and caching mistakes easy.",
        message: "Serve safe and unsafe methods from separate routes.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3752")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorator (call function: (attribute attribute: (identifier) @m (#eq? @m "route"))) @match)"#,
            filter: Some(Keep(route_mixes_safe_and_unsafe_methods)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.route('/x', methods=['GET', 'POST'])\ndef x():\n    pass\n",
            good: "@app.route('/x', methods=['GET'])\ndef x():\n    pass\n",
        }),
    },
    Rule {
        id: "py/undefined-name",
        name: "Variables, classes and functions should be either defined or imported",
        description: "Using a name nothing defines raises NameError.",
        message: "Define or import this name.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[related("S5953")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match"#,
            filter: Some(Find(first_undefined_name)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "print(missing_name)\n",
            good: "print(len('a'))\n",
        }),
    },
    Rule {
        id: "py/private-class-unused",
        name: "Unused private nested classes should be removed",
        description: "Nothing in the class uses it, and name mangling hides it from outside.",
        message: "Remove this class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3985")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(unused_private_class)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    class __Hidden:\n        pass\n",
            good: "class A:\n    class __Hidden:\n        pass\n    def make(self):\n        return self.__Hidden()\n",
        }),
    },
    Rule {
        id: "py/nested-definition-unused",
        name: "Unused scope-limited definitions should be removed",
        description: "A function or class defined inside another and never used is dead code.",
        message: "Remove this definition.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5603")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match
(class_definition) @match"#,
            filter: Some(Keep(nested_definition_is_unused)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def outer():\n    def helper():\n        pass\n    return 1\n",
            good: "def outer():\n    def helper():\n        pass\n    return helper()\n",
        }),
    },
    Rule {
        id: "py/walrus-as-statement",
        name: "Walrus operator should not make code confusing",
        description: "As a statement, := is just a harder-to-read assignment.",
        message: "Use a plain assignment.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5685")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(named_expression) @match"#,
            filter: Some(Keep(walrus_is_a_whole_statement)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "(x := f())\n",
            good: "x = f()\n",
        }),
    },
    Rule {
        id: "py/except-non-exception",
        name: "Caught Exceptions must derive from BaseException",
        description: "Catching a string or number raises TypeError once an exception is raised.",
        message: "Catch an exception class.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5708")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(except_clause) @match"#,
            filter: Some(Keep(catches_a_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept 'error':\n    pass\n",
            good: "try:\n    f()\nexcept ValueError:\n    pass\n",
        }),
    },
    Rule {
        id: "py/except-parent-and-child",
        name: "A subclass should not be in the same except statement as a parent class",
        description: "The parent already catches the subclass.",
        message: "Remove the subclass.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5713")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(except_clause) @match"#,
            filter: Some(Keep(except_lists_parent_and_child)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept (Exception, ValueError):\n    pass\n",
            good: "try:\n    f()\nexcept (ValueError, KeyError):\n    pass\n",
        }),
    },
    Rule {
        id: "py/none-comparison-constant",
        name: "Comparison to None should not be constant",
        description: "The result never changes.",
        message: "Compare a variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5727")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(compares_a_literal_to_none)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if [] is None:\n    pass\n",
            good: "if x is None:\n    pass\n",
        }),
    },
    Rule {
        id: "py/all-undefined-name",
        name: "Only defined names should be listed in __all__",
        description: "An undefined entry makes `from m import *` fail.",
        message: "Define the name, or remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5807")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) @n (#eq? @n "__all__") right: [(list) (tuple)]) @match"#,
            filter: Some(Find(all_lists_an_undefined_name)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "__all__ = ['Missing']\n",
            good: "class Missing:\n    pass\n__all__ = ['Missing']\n",
        }),
    },
    Rule {
        id: "py/assert-incompatible-types",
        name: "Assertions comparing incompatible types should not be made",
        description: "Values of different kinds are never equal.",
        message: "Compare comparable values.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5845")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "assertEqual" "assertNotEqual" "assertIs" "assertIsNot"))) @match"#,
            filter: Some(Keep(asserts_across_literal_kinds)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "self.assertEqual(1, 'a')\n",
            good: "self.assertEqual(1, x)\n",
        }),
    },
    Rule {
        id: "py/confusing-type-check",
        name: "Type checks shouldn't be confusing",
        description: "isinstance needs a class, and a type compared with a string is never equal.",
        message: "Check against a class.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5864")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "isinstance")) @match
(comparison_operator) @match"#,
            filter: Some(Keep(type_check_is_confusing)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if isinstance(x, 'str'):\n    pass\n",
            good: "if isinstance(x, str):\n    pass\n",
        }),
    },
    Rule {
        id: "py/return-type-mismatch",
        name: "Function return types should be consistent with their type hint",
        description: "The literal returned is not what the signature promises.",
        message: "Return the declared type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5886")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition return_type: (type)) @match"#,
            filter: Some(Find(returns_against_the_hint)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f() -> int:\n    return 'a'\n",
            good: "def f() -> int:\n    return 1\n",
        }),
    },
    Rule {
        id: "py/annotation-mismatch",
        name: "Values assigned to variables should match their type annotations",
        description: "The literal does not fit the annotation.",
        message: "Fix the value or the annotation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5890")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment type: (type) right: (_)) @match"#,
            filter: Some(Keep(assigned_value_contradicts_annotation)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x: int = 'a'\n",
            good: "x: int = 1\n",
        }),
    },
    Rule {
        id: "py/test-name-case",
        name: "Test methods should be discoverable",
        description: "unittest only collects methods that start with a lowercase test.",
        message: "Rename it to start with test.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5899")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition name: (identifier) @n) @match"#,
            filter: Some(Keep(test_method_name_is_miscased)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import unittest\nclass T(unittest.TestCase):\n    def Test_a(self):\n        pass\n",
            good: "import unittest\nclass T(unittest.TestCase):\n    def test_a(self):\n        pass\n",
        }),
    },
    Rule {
        id: "py/test-returns-early",
        name: "Tests should be skipped explicitly",
        description: "A bare return makes a test pass without checking anything.",
        message: "Use skip so it shows in the report.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5918")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition name: (identifier) @n (#match? @n "^test")) @match"#,
            filter: Some(Keep(test_starts_with_return)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def test_a():\n    return\n    assert False\n",
            good: "import unittest\n@unittest.skip('not ready')\ndef test_a():\n    assert False\n",
        }),
    },
    Rule {
        id: "py/field-named-after-class",
        name: "A field should not duplicate the name of its containing class",
        description: "It reads like a constructor call.",
        message: "Rename the field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1700")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(field_repeats_class_name)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class Point:\n    point = 1\n",
            good: "class Point:\n    origin = 1\n",
        }),
    },
    Rule {
        id: "py/names-differ-by-case",
        name: "Methods and field names should not differ only by capitalization",
        description: "They are easy to confuse.",
        message: "Rename one of them.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1845")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(member_differs_only_by_case)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def run(self):\n        pass\n    def Run(self):\n        pass\n",
            good: "class A:\n    def run(self):\n        pass\n    def stop(self):\n        pass\n",
        }),
    },
    Rule {
        id: "py/jsonresponse-unsafe",
        name: "The safe flag should be set to False when serializing non-dictionary objects",
        description: "JsonResponse raises TypeError for a list unless safe=False.",
        message: "Pass safe=False.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6560")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "JsonResponse")) @match"#,
            filter: Some(Keep(jsonresponse_gets_a_list)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "return JsonResponse([1, 2])\n",
            good: "return JsonResponse([1, 2], safe=False)\n",
        }),
    },
    Rule {
        id: "py/random-state-missing",
        name: "Results that depend on random number generation should be reproducible",
        description: "Without a seed, every run gives different results.",
        message: "Pass random_state.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6709")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "train_test_split" "ShuffleSplit" "StratifiedShuffleSplit" "make_classification" "make_regression" "make_blobs" "make_moons" "make_circles" "RandomForestClassifier" "RandomForestRegressor" "ExtraTreesClassifier" "ExtraTreesRegressor" "GradientBoostingClassifier" "GradientBoostingRegressor" "DecisionTreeClassifier" "DecisionTreeRegressor" "KMeans" "SGDClassifier" "MLPClassifier" "MLPRegressor" "KFold" "StratifiedKFold")) @match
(call function: (attribute attribute: (identifier) @f (#any-of? @f "train_test_split" "ShuffleSplit" "StratifiedShuffleSplit" "make_classification" "make_regression" "make_blobs" "make_moons" "make_circles" "RandomForestClassifier" "RandomForestRegressor" "ExtraTreesClassifier" "ExtraTreesRegressor" "GradientBoostingClassifier" "GradientBoostingRegressor" "DecisionTreeClassifier" "DecisionTreeRegressor" "KMeans" "SGDClassifier" "MLPClassifier" "MLPRegressor" "KFold" "StratifiedKFold"))) @match"#,
            filter: Some(Keep(random_call_has_no_seed)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "X_train, X_test = train_test_split(X)\n",
            good: "X_train, X_test = train_test_split(X, random_state=0)\n",
        }),
    },
    Rule {
        id: "py/pandas-long-chain",
        name: "pandas.pipe method should be preferred over long chains of instructions",
        description: "Long chains hide intermediate steps.",
        message: "Use pipe() with named steps.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6742")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute)) @match"#,
            filter: Some(Keep(is_a_long_dataframe_chain)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "out = df.a().b().c().d().e().f()\n",
            good: "out = df.pipe(step_one).pipe(step_two)\n",
        }),
    },
    Rule {
        id: "py/generic-class-syntax",
        name: "Generic classes should be defined using the type parameter syntax",
        description: "Python 3.12 declares type parameters on the class.",
        message: "Use class A[T]:.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6792")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition superclasses: (argument_list (subscript value: (identifier) @g (#eq? @g "Generic")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A(Generic[T]):\n    pass\n",
            good: "class A[T]:\n    pass\n",
        }),
    },
    Rule {
        id: "py/type-alias-annotation",
        name: "Type aliases should be declared with a type statement",
        description: "Python 3.12 has a dedicated statement.",
        message: "Use `type X = ...`.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6794")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment type: (type (identifier) @t (#eq? @t "TypeAlias"))) @match
(assignment type: (type (attribute attribute: (identifier) @t (#eq? @t "TypeAlias")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "X: TypeAlias = int\n",
            good: "type X = int\n",
        }),
    },
    Rule {
        id: "py/error-handler-without-status",
        name: "Flask error handlers should set HTTP status code",
        description: "Returning only a body sends status 200 for an error.",
        message: "Return (body, status).",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6863")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Keep(error_handler_returns_no_status)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.errorhandler(404)\ndef missing(e):\n    return 'not found'\n",
            good: "@app.errorhandler(404)\ndef missing(e):\n    return 'not found', 404\n",
        }),
    },
    Rule {
        id: "py/time-format-mix",
        name: "The 12-hour format should be used with the AM/PM marker",
        description: "%I without %p is ambiguous, and %p with %H is ignored.",
        message: "Pair %I with %p.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6883")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "strftime" "strptime"))) @match"#,
            filter: Some(Keep(time_format_mixes_hours)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "s = now.strftime('%I:%M')\n",
            good: "s = now.strftime('%I:%M %p')\n",
        }),
    },
    Rule {
        id: "py/weekmask-invalid",
        name: "Numpy weekmask should have a valid value",
        description: "It must be seven 0/1 flags, or day abbreviations.",
        message: "Fix the weekmask.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6900")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "weekmask") value: (string) @match)"#,
            filter: Some(Keep(weekmask_is_invalid)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "n = np.busday_count(a, b, weekmask='11111')\n",
            good: "n = np.busday_count(a, b, weekmask='1111100')\n",
        }),
    },
    Rule {
        id: "py/tf-gather-validate-indices",
        name: "The validate_indices argument should not be set for tf.gather",
        description: "It is deprecated and ignored.",
        message: "Remove validate_indices.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6925")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "tf") (#eq? @a "gather"))) @match"#,
            filter: Some(Keep(call_has_validate_indices)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "y = tf.gather(x, i, validate_indices=True)\n",
            good: "y = tf.gather(x, i)\n",
        }),
    },
    Rule {
        id: "py/tf-reduction-axis",
        name: "The reduction axis should be specified when using reduction operations",
        description: "Without an axis everything is reduced to a scalar, which is rarely meant.",
        message: "Pass axis.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6929")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "tf") (#any-of? @a "reduce_sum" "reduce_mean" "reduce_max" "reduce_min" "reduce_prod" "reduce_all" "reduce_any" "reduce_std" "reduce_variance" "reduce_logsumexp"))) @match"#,
            filter: Some(Keep(reduction_without_axis)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "y = tf.reduce_sum(x)\n",
            good: "y = tf.reduce_sum(x, axis=0)\n",
        }),
    },
    Rule {
        id: "py/tf-function-recursive",
        name: "tf.function should not be recursive",
        description: "A traced function cannot call itself.",
        message: "Use a loop, or tf.while_loop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6908")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Find(tf_function_calls_itself)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@tf.function\ndef f(n):\n    return f(n - 1)\n",
            good: "@tf.function\ndef f(n):\n    return n\n",
        }),
    },
    Rule {
        id: "py/tf-function-side-effects",
        name: "Python side effects should not be used inside a tf.function",
        description: "They run once during tracing, not on every call.",
        message: "Use tf.print or TensorFlow ops.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6928")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Find(tf_function_has_python_side_effect)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@tf.function\ndef f(x):\n    print(x)\n    return x\n",
            good: "@tf.function\ndef f(x):\n    tf.print(x)\n    return x\n",
        }),
    },
    Rule {
        id: "py/tf-variable-in-function",
        name: "tf.Variable objects should be singletons when created inside of a tf.function",
        description: "A new variable is created on every trace.",
        message: "Create it outside the function.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6918")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Find(tf_function_creates_a_variable)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@tf.function\ndef f(x):\n    v = tf.Variable(1)\n    return v\n",
            good: "v = tf.Variable(1)\n@tf.function\ndef f(x):\n    return v\n",
        }),
    },
    Rule {
        id: "py/sklearn-pipeline-memory",
        name: "memory parameter should be specified for Scikit-Learn Pipeline",
        description: "Caching avoids refitting unchanged steps.",
        message: "Pass memory.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6969")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "Pipeline" "make_pipeline")) @match
(call function: (attribute attribute: (identifier) @f (#any-of? @f "Pipeline" "make_pipeline"))) @match"#,
            filter: Some(Keep(pipeline_has_no_memory)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "p = Pipeline([('s', s)])\n",
            good: "p = Pipeline([('s', s)], memory='cache')\n",
        }),
    },
    Rule {
        id: "py/ml-hyperparameters",
        name: "Important hyperparameters should be specified for machine learning estimators",
        description: "Library defaults rarely suit a given problem.",
        message: "Set the hyperparameters that matter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6973")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "RandomForestClassifier" "RandomForestRegressor" "GradientBoostingClassifier" "GradientBoostingRegressor" "SVC" "SVR" "KNeighborsClassifier" "KNeighborsRegressor" "DecisionTreeClassifier" "DecisionTreeRegressor" "LogisticRegression" "MLPClassifier" "MLPRegressor" "XGBClassifier" "XGBRegressor")) @match
(call function: (attribute attribute: (identifier) @f (#any-of? @f "RandomForestClassifier" "RandomForestRegressor" "GradientBoostingClassifier" "GradientBoostingRegressor" "SVC" "SVR" "KNeighborsClassifier" "KNeighborsRegressor" "DecisionTreeClassifier" "DecisionTreeRegressor" "LogisticRegression" "MLPClassifier" "MLPRegressor" "XGBClassifier" "XGBRegressor"))) @match"#,
            filter: Some(Keep(call_has_no_arguments)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "m = RandomForestClassifier()\n",
            good: "m = RandomForestClassifier(n_estimators=200)\n",
        }),
    },
    Rule {
        id: "py/estimator-init-attribute",
        name: "Subclasses of BaseEstimator should not set attributes ending with _ in __init__",
        description: "Scikit-learn reserves them for values learned in fit.",
        message: "Set it in fit().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6974")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(estimator_sets_fitted_attribute_in_init)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class E(BaseEstimator):\n    def __init__(self):\n        self.coef_ = None\n",
            good: "class E(BaseEstimator):\n    def __init__(self):\n        self.alpha = 1\n",
        }),
    },
    Rule {
        id: "py/torch-state-without-mode",
        name: "model.eval() or model.train() should be called after loading the state of a PyTorch model",
        description: "Dropout and batch norm behave differently in each mode.",
        message: "Call eval() or train().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6982")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "load_state_dict"))) @match"#,
            filter: Some(Keep(state_loaded_without_a_mode)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "model.load_state_dict(state)\nuse(model)\n",
            good: "model.load_state_dict(state)\nmodel.eval()\n",
        }),
    },
    Rule {
        id: "py/async-polling-loop",
        name: "Events should be used instead of sleep in asynchronous loops",
        description: "Polling wakes up for nothing and reacts late.",
        message: "Wait on an Event.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7484")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(while_statement) @match"#,
            filter: Some(Keep(loop_polls_with_sleep)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    while not done:\n        await asyncio.sleep(1)\n",
            good: "async def f():\n    await done_event.wait()\n",
        }),
    },
    Rule {
        id: "py/sleep-forever",
        name: "Long sleep durations should use sleep_forever() instead of arbitrary intervals",
        description: "A huge sleep is a forever-wait in disguise.",
        message: "Use sleep_forever().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7486")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#any-of? @o "asyncio" "trio" "anyio") (#eq? @a "sleep")) arguments: (argument_list (integer) @i)) @match"#,
            filter: Some(Keep(sleeps_for_a_day_or_more)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "await trio.sleep(86400)\n",
            good: "await trio.sleep_forever()\n",
        }),
    },
    Rule {
        id: "py/cancel-scope-without-checkpoint",
        name: "Cancellation scopes should contain checkpoints",
        description: "A scope can only cancel code at an await.",
        message: "Await something inside the scope.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7490")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(with_statement) @match"#,
            filter: Some(Keep(cancel_scope_has_no_await)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    with trio.fail_after(1):\n        work()\n",
            good: "async def f():\n    with trio.fail_after(1):\n        await work()\n",
        }),
    },
    Rule {
        id: "py/cancellation-swallowed",
        name: "Cancellation exceptions should be re-raised after cleanup",
        description: "Swallowing it breaks timeouts and task groups.",
        message: "Re-raise after cleanup.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7497")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(except_clause) @match"#,
            filter: Some(Keep(cancelled_error_is_swallowed)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    await f()\nexcept asyncio.CancelledError:\n    cleanup()\n",
            good: "try:\n    await f()\nexcept asyncio.CancelledError:\n    cleanup()\n    raise\n",
        }),
    },
    Rule {
        id: "py/nursery-single-start",
        name: "TaskGroup/Nursery should not be used for a single start call",
        description: "A group of one is just a call.",
        message: "Await the call directly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7513")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(with_statement) @match"#,
            filter: Some(Keep(group_starts_a_single_task)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    async with trio.open_nursery() as n:\n        n.start_soon(g)\n",
            good: "async def f():\n    await g()\n",
        }),
    },
    Rule {
        id: "py/nursery-control-flow",
        name: "Control flow statements should not be used inside TaskGroup or Nursery blocks",
        description: "A return or break inside cancels sibling tasks in surprising ways.",
        message: "Move it outside the block.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7514")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(with_statement) @match"#,
            filter: Some(Find(group_body_jumps_out)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    async with trio.open_nursery() as n:\n        n.start_soon(g)\n        return 1\n",
            good: "async def f():\n    async with trio.open_nursery() as n:\n        n.start_soon(g)\n    return 1\n",
        }),
    },
    Rule {
        id: "py/sync-with-async-manager",
        name: "async with should be used for asynchronous resource management",
        description: "A plain `with` never calls the async enter and exit.",
        message: "Use async with.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7515")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(with_statement) @match"#,
            filter: Some(Keep(sync_with_on_async_manager)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    with aiohttp.ClientSession() as s:\n        pass\n",
            good: "async def f():\n    async with aiohttp.ClientSession() as s:\n        pass\n",
        }),
    },
    Rule {
        id: "py/not-implemented-boolean",
        name: "NotImplemented should not be used in boolean contexts",
        description: "It is truthy, and a DeprecationWarning since Python 3.9.",
        message: "Compare, or return it.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7931")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement condition: (identifier) @match (#eq? @match "NotImplemented"))
(not_operator argument: (identifier) @match (#eq? @match "NotImplemented"))
(boolean_operator [left: (identifier) right: (identifier)] @match (#eq? @match "NotImplemented"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if NotImplemented:\n    pass\n",
            good: "def __eq__(self, o):\n    return NotImplemented\n",
        }),
    },
    Rule {
        id: "py/compression-namespace",
        name: "Compression modules should be imported from the compression namespace",
        description: "Python 3.14 moved them under compression.",
        message: "Import from compression.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7941")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(import_statement name: (dotted_name) @match (#any-of? @match "gzip" "bz2" "lzma" "zlib"))
(import_from_statement module_name: (dotted_name) @match (#any-of? @match "gzip" "bz2" "lzma" "zlib"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import gzip\n",
            good: "from compression import gzip\n",
        }),
    },
    Rule {
        id: "py/post-reads-query-args",
        name: "Query parameters should not be used in Flask POST requests",
        description: "POST data belongs in the body.",
        message: "Read request.form or request.json.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8370")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Find(post_route_reads_query_args)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.route('/x', methods=['POST'])\ndef x():\n    return request.args.get('a')\n",
            good: "@app.route('/x', methods=['POST'])\ndef x():\n    return request.form.get('a')\n",
        }),
    },
    Rule {
        id: "py/preprocess-request-ignored",
        name: "Flask preprocess_request return values should be handled",
        description: "A returned response means the request is already answered.",
        message: "Use the return value.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8375")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(expression_statement (call function: (attribute attribute: (identifier) @m (#eq? @m "preprocess_request"))) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.preprocess_request()\n",
            good: "rv = app.preprocess_request()\n",
        }),
    },
    Rule {
        id: "py/send-file-metadata",
        name: "send_file should specify mimetype or download_name when used with file-like objects",
        description: "Without a name Flask cannot guess either.",
        message: "Pass mimetype or download_name.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8385")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "send_file")) @match
(call function: (attribute attribute: (identifier) @f (#any-of? @f "send_file"))) @match"#,
            filter: Some(Keep(send_file_lacks_metadata)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "return send_file(io.BytesIO(data))\n",
            good: "return send_file(io.BytesIO(data), mimetype='text/plain')\n",
        }),
    },
    Rule {
        id: "py/upload-with-body",
        name: "FastAPI file upload endpoints should use Form() with Pydantic validators instead of Body() or Depends()",
        description: "File uploads are multipart, so Body() and Depends() can't carry the other fields.",
        message: "Use Form().",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S8389")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(upload_endpoint_mixes_body)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def up(f: UploadFile, meta: Meta = Body()):\n    pass\n",
            good: "def up(f: UploadFile, meta: str = Form()):\n    pass\n",
        }),
    },
    Rule {
        id: "py/no-content-with-body",
        name: "Endpoints returning 204 status should have an empty response body",
        description: "A 204 response must not carry a body.",
        message: "Return nothing.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8400")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Find(no_content_returns_a_body)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.get('/x', status_code=204)\ndef x():\n    return {'a': 1}\n",
            good: "@app.get('/x', status_code=204)\ndef x():\n    return None\n",
        }),
    },
    Rule {
        id: "py/router-included-late",
        name: "Child routers should be included before parent router registration",
        description: "A router copies its routes when it is included.",
        message: "Include children first.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8401")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(block) @match
(module) @match"#,
            filter: Some(Find(child_router_included_after_parent)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.include_router(parent)\nparent.include_router(child)\n",
            good: "parent.include_router(child)\napp.include_router(parent)\n",
        }),
    },
    Rule {
        id: "py/testclient-data",
        name: "TestClient requests should use the content parameter for bytes or text",
        description: "data= is for form fields.",
        message: "Use content=.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8405")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "post" "put" "patch" "delete"))) @match"#,
            filter: Some(Keep(client_sends_text_as_data)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "client.post('/x', data='raw')\n",
            good: "client.post('/x', content='raw')\n",
        }),
    },
    Rule {
        id: "py/redundant-response-model",
        name: "FastAPI routes should not specify redundant response_model parameters",
        description: "The return annotation already says it.",
        message: "Remove response_model.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8409")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Keep(response_model_repeats_return_type)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.get('/x', response_model=Item)\ndef x() -> Item:\n    pass\n",
            good: "@app.get('/x')\ndef x() -> Item:\n    pass\n",
        }),
    },
    Rule {
        id: "py/include-router-prefix",
        name: "Router prefixes should be defined during APIRouter initialization",
        description: "Declaring it with the router keeps it in one place.",
        message: "Set prefix on APIRouter().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8413")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "include_router"))) @match"#,
            filter: Some(Keep(include_router_sets_prefix)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.include_router(router, prefix='/v1')\n",
            good: "router = APIRouter(prefix='/v1')\napp.include_router(router)\n",
        }),
    },
    Rule {
        id: "py/cors-not-last",
        name: "CORSMiddleware should be added last in the middleware chain",
        description: "Middleware added later runs first, so errors from outer layers skip CORS headers.",
        message: "Add it last.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8414")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(block) @match
(module) @match"#,
            filter: Some(Find(cors_middleware_added_before_others)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.add_middleware(CORSMiddleware)\napp.add_middleware(GZipMiddleware)\n",
            good: "app.add_middleware(GZipMiddleware)\napp.add_middleware(CORSMiddleware)\n",
        }),
    },
    Rule {
        id: "py/http-exception-undocumented",
        name: "HTTPException responses should be documented in endpoint metadata",
        description: "Without responses= the OpenAPI document hides the error.",
        message: "Add responses=.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S8415")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Keep(raises_undocumented_http_exception)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.get('/x')\ndef x():\n    raise HTTPException(404)\n",
            good: "@app.get('/x', responses={404: {}})\ndef x():\n    raise HTTPException(404)\n",
        }),
    },
    Rule {
        id: "py/slots-assignment",
        name: "Attributes should only be assigned if they are declared in __slots__",
        description: "Other names raise AttributeError.",
        message: "Add it to __slots__.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8494")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(assigns_outside_slots)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    __slots__ = ('a',)\n    def __init__(self):\n        self.b = 1\n",
            good: "class A:\n    __slots__ = ('a',)\n    def __init__(self):\n        self.a = 1\n",
        }),
    },
    Rule {
        id: "py/tuple-length-inconsistent",
        name: "Functions should return tuples of consistent length",
        description: "Callers unpack a fixed number of values.",
        message: "Return the same number everywhere.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8495")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(returns_tuples_of_different_lengths)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x):\n    if x:\n        return 1, 2\n    return 1, 2, 3\n",
            good: "def f(x):\n    if x:\n        return 1, 2\n    return 3, 4\n",
        }),
    },
    Rule {
        id: "py/comparison-methods-incomplete",
        name: "Comparison methods should be defined completely",
        description: "Defining only some of <, <=, > and >= gives surprising errors.",
        message: "Define all four, or use functools.total_ordering.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8500")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Keep(defines_some_ordering_methods)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __lt__(self, o):\n        return True\n",
            good: "import functools\n@functools.total_ordering\nclass A:\n    def __eq__(self, o):\n        return True\n    def __lt__(self, o):\n        return True\n",
        }),
    },
    Rule {
        id: "py/singledispatch-mixup",
        name: "@singledispatch and @singledispatchmethod should not be confused",
        description: "The wrong one dispatches on self.",
        message: "Use singledispatchmethod for methods.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8505")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Keep(singledispatch_on_wrong_target)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    @singledispatch\n    def f(self, x):\n        pass\n",
            good: "class A:\n    @singledispatchmethod\n    def f(self, x):\n        pass\n",
        }),
    },
    Rule {
        id: "py/mro-conflict",
        name: "Multiple inheritance should not create Method Resolution Order conflicts",
        description: "A base listed before its own subclass makes class creation fail.",
        message: "Reorder the bases.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8511")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Keep(bases_conflict_in_mro)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    pass\nclass B(A):\n    pass\nclass C(A, B):\n    pass\n",
            good: "class A:\n    pass\nclass B(A):\n    pass\nclass C(B, A):\n    pass\n",
        }),
    },
    Rule {
        id: "py/groupby-iterator-reused",
        name: "Group iterators from itertools.groupby should not be reused",
        description: "A group is consumed when the next key is requested, and only once.",
        message: "Copy it with list() first.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8516")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(group_iterator_is_consumed_twice)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for k, g in groupby(xs):\n    a = list(g)\n    b = list(g)\n",
            good: "for k, g in groupby(xs):\n    a = list(g)\n",
        }),
    },
    Rule {
        id: "py/bs4-html-string",
        name: "HTML elements should be created with new_tag() instead of inserting raw HTML strings",
        description: "Inserting a string makes escaped text, not an element.",
        message: "Use soup.new_tag().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8903")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "append" "insert" "insert_before" "insert_after" "replace_with")) arguments: (argument_list (string) @s)) @match"#,
            filter: Some(Keep(inserts_markup_as_text)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "soup.body.append('<b>hi</b>')\n",
            good: "tag = soup.new_tag('b')\nsoup.body.append(tag)\n",
        }),
    },
    Rule {
        id: "py/bs4-find-unchecked",
        name: "BeautifulSoup elements should be checked for None before accessing",
        description: "find() returns None when nothing matches.",
        message: "Check the result first.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8904")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(attribute object: (call function: (attribute attribute: (identifier) @m (#any-of? @m "find" "select_one" "find_next" "find_parent" "find_previous"))) attribute: (identifier)) @match"#,
            filter: Some(Keep(find_result_is_used_directly)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "title = soup.find('h1').text\n",
            good: "h = soup.find('h1')\ntitle = h.text if h else ''\n",
        }),
    },
    Rule {
        id: "py/bs4-class-selector",
        name: "CSS selectors should be used when selecting elements with multiple required classes",
        description: "class_='a b' matches only that exact attribute string.",
        message: "Use soup.select('.a.b').",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8906")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "class_") value: (string) @match)"#,
            filter: Some(Keep(string_has_a_space)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "els = soup.find_all('div', class_='a b')\n",
            good: "els = soup.select('div.a.b')\n",
        }),
    },
    Rule {
        id: "py/hint-missing-return",
        name: "Function returns should have type hints",
        description: "A signature without a return type tells callers nothing.",
        message: "Add a return type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6538")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(function_lacks_return_hint)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    return 1\n",
            good: "def f() -> int:\n    return 1\n",
        }),
    },
    Rule {
        id: "py/hint-missing-parameter",
        name: "Function parameters should have type hints",
        description: "An untyped parameter tells callers nothing.",
        message: "Add a type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6540")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(parameter_lacks_hint)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x):\n    return x\n",
            good: "def f(x: int):\n    return x\n",
        }),
    },
];

// ---------------------------------------------------- filters

const NESTED_STOPS: &[&str] = &["function_definition", "class_definition", "lambda"];

fn collect_in_scope<'t>(
    root: Node<'t>,
    stops: &[&str],
    pred: impl Fn(Node<'t>) -> bool,
) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return out;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            out.push(n);
        }
        if !stops.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return out;
            }
        }
    }
}

fn root_of(node: Node) -> Node {
    let mut n = node;
    while let Some(p) = n.parent() {
        n = p;
    }
    n
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

fn head_of<'s>(node: Node, src: &'s [u8]) -> &'s [u8] {
    let end = body_of(node).map_or(node.end_byte(), |b| b.start_byte());
    &src[node.start_byte()..end]
}

fn decorator_calls<'t>(decorated: Node<'t>) -> Vec<Node<'t>> {
    children_of_kind(decorated, "decorator")
        .into_iter()
        .filter_map(|d| d.named_child(0))
        .collect()
}

fn function_of(decorated: Node) -> Option<Node> {
    decorated
        .child_by_field_name("definition")
        .filter(|d| d.kind() == "function_definition")
}

fn has_decorator(decorated: Node, src: &[u8], needle: &[u8]) -> bool {
    children_of_kind(decorated, "decorator")
        .iter()
        .any(|d| contains_ignoring_case(text(*d, src), needle))
}

fn is_route_decorator(call: Node, src: &[u8]) -> bool {
    call.kind() == "call"
        && call
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "attribute")
        && matches!(
            callee_name(call, src),
            b"route" | b"get" | b"post" | b"put" | b"delete" | b"patch" | b"api_route"
        )
}

fn methods_text<'s>(call: Node, src: &'s [u8]) -> &'s [u8] {
    keyword_value(call, "methods", src).map_or(&b""[..], |m| text(m, src))
}

fn nearest_async(node: Node) -> bool {
    let mut p = node.parent();
    while let Some(n) = p {
        if n.kind() == "function_definition" {
            return has_token(n, "async");
        }
        if n.kind() == "class_definition" {
            return false;
        }
        p = n.parent();
    }
    false
}

// ---- bugs

fn jump_is_outside_a_loop(jump: Node, _: &[u8]) -> bool {
    let mut child = jump;
    let mut p = jump.parent();
    while let Some(n) = p {
        match n.kind() {
            "for_statement" | "while_statement" if child.kind() != "else_clause" => return false,
            "function_definition" | "class_definition" | "lambda" | "module" => return true,
            _ => {}
        }
        child = n;
        p = n.parent();
    }
    true
}

fn equality_between_different_literals(cmp: Node, src: &[u8]) -> bool {
    let Some((left, op, right)) = two_operands(cmp, src) else {
        return false;
    };
    if !matches!(op, b"==" | b"!=") {
        return false;
    }
    match (literal_family(left.kind()), literal_family(right.kind())) {
        (Some(a), Some(b)) => {
            // bool is a number in Python: 1 == True
            let norm = |f: &'static str| if f == "bool" { "number" } else { f };
            norm(a) != norm(b)
        }
        _ => false,
    }
}

fn method_ignores_self(function: Node, src: &[u8]) -> bool {
    if !in_class(function) || is_decorated(function) {
        return false;
    }
    let name = name_of(function, src);
    if is_dunder(name)
        || name.starts_with(b"test")
        || first_parameter_name(function, src) != Some(b"self")
    {
        return false;
    }
    let Some(body) = body_of(function) else {
        return false;
    };
    if is_stub_body(body) {
        return false;
    }
    let whole = text(body, src);
    count_word(whole, b"self") == 0
        && count_word(whole, b"super") == 0
        && count_word(whole, b"__class__") == 0
}

fn returns_are_all_the_same_constant(function: Node, src: &[u8]) -> bool {
    if is_generator(function) {
        return false;
    }
    let Some(body) = body_of(function) else {
        return false;
    };
    let returns = collect_in_scope(body, SCOPE_STOPS, |n| n.kind() == "return_statement");
    if returns.len() < 2 {
        return false;
    }
    let values: Vec<Option<Node>> = returns.iter().map(|r| r.named_child(0)).collect();
    let Some(Some(first)) = values.first() else {
        return false;
    };
    matches!(
        first.kind(),
        "integer" | "float" | "string" | "true" | "false" | "none"
    ) && values
        .iter()
        .all(|v| v.is_some_and(|v| text(v, src) == text(*first, src)))
}

fn assigns_result_of_function_without_return(assignment: Node, src: &[u8]) -> bool {
    let Some(call) = assignment
        .child_by_field_name("right")
        .filter(|r| r.kind() == "call")
    else {
        return false;
    };
    let Some(callee) = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "identifier")
    else {
        return false;
    };
    let name = text(callee, src);
    let root = root_of(assignment);
    statements(root).into_iter().any(|s| {
        s.kind() == "function_definition"
            && name_of(s, src) == name
            && !has_token(s, "async")
            && body_of(s).is_some_and(|b| {
                !is_stub_body(b)
                    && find_in_scope(b, SCOPE_STOPS, |n| {
                        n.kind() == "yield"
                            || (n.kind() == "return_statement" && n.named_child_count() > 0)
                    })
                    .is_none()
            })
    })
}

fn route_mixes_safe_and_unsafe_methods(call: Node, src: &[u8]) -> bool {
    let m = methods_text(call, src);
    contains_ignoring_case(m, b"GET")
        && [&b"POST"[..], b"PUT", b"DELETE", b"PATCH"]
            .iter()
            .any(|v| contains_ignoring_case(m, v))
}

pub(super) const BUILTIN_NAMES: &[&str] = &[
    "abs",
    "aiter",
    "all",
    "anext",
    "any",
    "ascii",
    "bin",
    "bool",
    "breakpoint",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "classmethod",
    "compile",
    "complex",
    "copyright",
    "credits",
    "delattr",
    "dict",
    "dir",
    "divmod",
    "enumerate",
    "eval",
    "exec",
    "exit",
    "filter",
    "float",
    "format",
    "frozenset",
    "getattr",
    "globals",
    "hasattr",
    "hash",
    "help",
    "hex",
    "id",
    "input",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "license",
    "list",
    "locals",
    "map",
    "max",
    "memoryview",
    "min",
    "next",
    "object",
    "oct",
    "open",
    "ord",
    "pow",
    "print",
    "property",
    "quit",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "setattr",
    "slice",
    "sorted",
    "staticmethod",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "vars",
    "zip",
    "__import__",
    "__name__",
    "__file__",
    "__doc__",
    "__package__",
    "__spec__",
    "__loader__",
    "__builtins__",
    "__class__",
    "__path__",
    "__qualname__",
    "__module__",
    "__debug__",
    "__annotations__",
    "__dict__",
    "__slots__",
    "self",
    "cls",
    "None",
    "True",
    "False",
    "NotImplemented",
    "Ellipsis",
    "BaseException",
    "BaseExceptionGroup",
    "Exception",
    "ExceptionGroup",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BlockingIOError",
    "BrokenPipeError",
    "BufferError",
    "BytesWarning",
    "ChildProcessError",
    "ConnectionAbortedError",
    "ConnectionError",
    "ConnectionRefusedError",
    "ConnectionResetError",
    "DeprecationWarning",
    "EOFError",
    "EncodingWarning",
    "EnvironmentError",
    "FileExistsError",
    "FileNotFoundError",
    "FloatingPointError",
    "FutureWarning",
    "GeneratorExit",
    "IOError",
    "ImportError",
    "ImportWarning",
    "IndentationError",
    "IndexError",
    "InterruptedError",
    "IsADirectoryError",
    "KeyError",
    "KeyboardInterrupt",
    "LookupError",
    "MemoryError",
    "ModuleNotFoundError",
    "NameError",
    "NotADirectoryError",
    "NotImplementedError",
    "OSError",
    "OverflowError",
    "PendingDeprecationWarning",
    "PermissionError",
    "ProcessLookupError",
    "PythonFinalizationError",
    "RecursionError",
    "ReferenceError",
    "ResourceWarning",
    "RuntimeError",
    "RuntimeWarning",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SyntaxWarning",
    "SystemError",
    "SystemExit",
    "TabError",
    "TimeoutError",
    "TypeError",
    "UnboundLocalError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "UnicodeError",
    "UnicodeTranslateError",
    "UnicodeWarning",
    "UserWarning",
    "ValueError",
    "Warning",
    "WindowsError",
    "ZeroDivisionError",
    "WindowsError",
    "unicode",
    "long",
    "xrange",
    "basestring",
    "raw_input",
    "unichr",
    "reduce",
    "file",
    "cmp",
    "execfile",
    "reload",
    "apply",
    "buffer",
    "intern",
    "coerce",
];

/// Every identifier that is bound somewhere in the file, scopes ignored: a
/// name found here is never reported, so the rule errs towards silence.
fn bound_names<'s>(root: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names: Vec<&[u8]> = Vec::new();
    let add_all = |node: Node, names: &mut Vec<&'s [u8]>| {
        if node.kind() == "identifier" {
            names.push(text(node, src));
            return;
        }
        for n in collect_in_scope(node, &[], |n| n.kind() == "identifier") {
            names.push(text(n, src));
        }
    };
    let mut cursor = root.walk();
    let mut descend = true;
    loop {
        let node = cursor.node();
        if descend {
            match node.kind() {
                "function_definition" | "class_definition" => {
                    if let Some(n) = node.child_by_field_name("name") {
                        names.push(text(n, src));
                    }
                    if let Some(p) = node.child_by_field_name("parameters") {
                        add_all(p, &mut names);
                    }
                }
                "lambda" => {
                    if let Some(p) = node.child_by_field_name("parameters") {
                        add_all(p, &mut names);
                    }
                }
                "assignment" | "augmented_assignment" | "for_statement" | "for_in_clause" => {
                    if let Some(l) = node.child_by_field_name("left") {
                        add_all(l, &mut names);
                    }
                }
                "import_statement"
                | "import_from_statement"
                | "global_statement"
                | "nonlocal_statement"
                | "as_pattern"
                | "except_clause"
                | "with_item"
                | "case_clause"
                | "type_alias_statement"
                | "delete_statement"
                | "type_parameter" => {
                    add_all(node, &mut names);
                }
                "named_expression" => {
                    if let Some(n) = node.child_by_field_name("name") {
                        names.push(text(n, src));
                    }
                }
                _ => {}
            }
        }
        if descend && cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            descend = true;
            continue;
        }
        if !cursor.goto_parent() {
            return names;
        }
        descend = false;
    }
}

fn first_undefined_name<'t>(module: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let whole = text(module, src);
    if [
        "import *",
        "exec(",
        "globals()",
        "locals()",
        "__getattr__",
        "eval(",
    ]
    .iter()
    .any(|w| contains_ignoring_case(whole, w.as_bytes()))
        || has_wildcard_import(module)
    {
        return None;
    }
    let bound = bound_names(module, src);
    find_in_scope(module, &[], |n| {
        if n.kind() != "identifier" {
            return false;
        }
        let name = text(n, src);
        if bound.contains(&name) || BUILTIN_NAMES.iter().any(|b| b.as_bytes() == name) {
            return false;
        }
        match n.parent() {
            Some(p) => match p.kind() {
                "attribute" => p.child_by_field_name("object") == Some(n),
                "keyword_argument" => p.child_by_field_name("value") == Some(n),
                "dotted_name" | "aliased_import" | "relative_import" | "import_prefix" => false,
                _ => true,
            },
            None => false,
        }
    })
}

fn has_wildcard_import(module: Node) -> bool {
    find_in_scope(module, &[], |n| n.kind() == "wildcard_import").is_some()
}

fn unused_private_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = body_of(class)?;
    let whole = text(class, src);
    statements(body).into_iter().find(|s| {
        s.kind() == "class_definition"
            && is_private_name(name_of(*s, src))
            && count_word(whole, name_of(*s, src)) == 1
    })
}

fn nested_definition_is_unused(definition: Node, src: &[u8]) -> bool {
    if is_decorated(definition) {
        return false;
    }
    let Some(block) = definition.parent().filter(|p| p.kind() == "block") else {
        return false;
    };
    let Some(owner) = block.parent().filter(|p| p.kind() == "function_definition") else {
        return false;
    };
    let name = name_of(definition, src);
    !name.starts_with(b"_") && count_word(text(owner, src), name) == 1
}

fn walrus_is_a_whole_statement(walrus: Node, _: &[u8]) -> bool {
    let mut p = walrus.parent();
    while let Some(n) = p.filter(|n| n.kind() == "parenthesized_expression") {
        p = n.parent();
    }
    p.is_some_and(|n| {
        matches!(
            n.kind(),
            "expression_statement" | "assignment" | "augmented_assignment" | "return_statement"
        )
    })
}

fn is_literal_for_catch(kind: &str) -> bool {
    matches!(
        kind,
        "string" | "integer" | "float" | "true" | "false" | "none" | "list" | "dictionary"
    )
}

fn catches_a_literal(clause: Node, _: &[u8]) -> bool {
    statements(clause)
        .into_iter()
        .take_while(|n| n.kind() != "block")
        .any(|n| {
            is_literal_for_catch(n.kind())
                || (n.kind() == "tuple"
                    && statements(n).iter().any(|e| is_literal_for_catch(e.kind())))
        })
}

fn builtin_parents(name: &[u8]) -> &'static [&'static [u8]] {
    match name {
        b"ValueError"
        | b"TypeError"
        | b"OSError"
        | b"IOError"
        | b"EnvironmentError"
        | b"KeyError"
        | b"IndexError"
        | b"LookupError"
        | b"AttributeError"
        | b"RuntimeError"
        | b"ArithmeticError"
        | b"ZeroDivisionError"
        | b"OverflowError"
        | b"ImportError"
        | b"NameError"
        | b"EOFError"
        | b"AssertionError"
        | b"MemoryError"
        | b"StopIteration"
        | b"SyntaxError"
        | b"UnicodeError"
        | b"FileNotFoundError"
        | b"PermissionError"
        | b"TimeoutError"
        | b"NotImplementedError"
        | b"ModuleNotFoundError"
        | b"ConnectionError" => &[b"Exception", b"BaseException"],
        _ => &[b"BaseException"],
    }
}

fn is_builtin_subclass(child: &[u8], parent: &[u8]) -> bool {
    if child == parent {
        return false;
    }
    let direct: &[(&[u8], &[u8])] = &[
        (b"KeyError", b"LookupError"),
        (b"IndexError", b"LookupError"),
        (b"ZeroDivisionError", b"ArithmeticError"),
        (b"OverflowError", b"ArithmeticError"),
        (b"FloatingPointError", b"ArithmeticError"),
        (b"FileNotFoundError", b"OSError"),
        (b"PermissionError", b"OSError"),
        (b"FileExistsError", b"OSError"),
        (b"IsADirectoryError", b"OSError"),
        (b"NotADirectoryError", b"OSError"),
        (b"TimeoutError", b"OSError"),
        (b"ConnectionError", b"OSError"),
        (b"BrokenPipeError", b"ConnectionError"),
        (b"ConnectionResetError", b"ConnectionError"),
        (b"ConnectionRefusedError", b"ConnectionError"),
        (b"IOError", b"OSError"),
        (b"UnicodeError", b"ValueError"),
        (b"UnicodeDecodeError", b"UnicodeError"),
        (b"UnicodeEncodeError", b"UnicodeError"),
        (b"ModuleNotFoundError", b"ImportError"),
        (b"NotImplementedError", b"RuntimeError"),
        (b"RecursionError", b"RuntimeError"),
    ];
    if direct.iter().any(|(c, p)| *c == child && *p == parent) {
        return true;
    }
    if direct
        .iter()
        .any(|(c, mid)| *c == child && is_builtin_subclass(mid, parent))
    {
        return true;
    }
    (parent == b"Exception"
        && builtin_parents(child).contains(&&b"Exception"[..])
        && child != b"BaseException")
        || (parent == b"BaseException" && child != b"BaseException" && child.ends_with(b"Error"))
}

fn except_lists_parent_and_child(clause: Node, src: &[u8]) -> bool {
    let Some(tuple) = statements(clause)
        .into_iter()
        .take_while(|n| n.kind() != "block")
        .find(|n| n.kind() == "tuple")
    else {
        return false;
    };
    let names: Vec<&[u8]> = statements(tuple)
        .iter()
        .filter(|n| n.kind() == "identifier")
        .map(|n| text(*n, src))
        .collect();
    names
        .iter()
        .any(|c| names.iter().any(|p| is_builtin_subclass(c, p)))
}

fn compares_a_literal_to_none(cmp: Node, src: &[u8]) -> bool {
    let Some((left, op, right)) = two_operands(cmp, src) else {
        return false;
    };
    if !matches!(op, b"is" | b"is not" | b"==" | b"!=") {
        return false;
    }
    let (a, b) = (left.kind(), right.kind());
    let other = |k: &str| literal_family(k).is_some();
    (a == "none" && other(b)) || (b == "none" && other(a))
}

fn module_level_names<'s>(module: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names = Vec::new();
    for n in collect_in_scope(module, NESTED_STOPS, |n| {
        matches!(
            n.kind(),
            "function_definition"
                | "class_definition"
                | "import_statement"
                | "import_from_statement"
                | "assignment"
                | "for_statement"
                | "with_item"
                | "named_expression"
        )
    }) {
        match n.kind() {
            "function_definition" | "class_definition" => {
                if n.parent().is_some_and(|p| {
                    p.kind() == "module"
                        || p.kind() == "decorated_definition"
                        || p.kind() == "block"
                }) {
                    names.push(name_of(n, src));
                }
            }
            "import_statement" | "import_from_statement" => {
                names.extend(imported_names(n, src));
                for c in collect_in_scope(n, &[], |c| c.kind() == "identifier") {
                    names.push(text(c, src));
                }
            }
            "assignment" | "for_statement" => {
                if let Some(l) = n.child_by_field_name("left") {
                    for c in collect_in_scope(l, &[], |c| c.kind() == "identifier") {
                        names.push(text(c, src));
                    }
                    if l.kind() == "identifier" {
                        names.push(text(l, src));
                    }
                }
            }
            _ => {}
        }
    }
    names
}

fn all_lists_an_undefined_name<'t>(assignment: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let list = assignment.child_by_field_name("right")?;
    let root = root_of(assignment);
    if assignment
        .parent()
        .is_none_or(|p| p.kind() != "expression_statement")
        || assignment.parent().and_then(|p| p.parent()) != Some(root)
        || has_wildcard_import(root)
        || count_word(text(root, src), b"__getattr__") > 0
    {
        return None;
    }
    let names = module_level_names(root, src);
    // A lowercase entry may be a submodule of the package, which is valid.
    statements(list).into_iter().find(|e| {
        string_value(*e, src)
            .is_some_and(|v| !v.is_empty() && !v[0].is_ascii_lowercase() && !names.contains(&v))
    })
}

fn asserts_across_literal_kinds(call: Node, _: &[u8]) -> bool {
    let args = call_arguments(call);
    let [a, b, ..] = args.as_slice() else {
        return false;
    };
    match (literal_family(a.kind()), literal_family(b.kind())) {
        (Some(x), Some(y)) => x != y,
        _ => false,
    }
}

fn type_check_is_confusing(node: Node, src: &[u8]) -> bool {
    if node.kind() == "call" {
        let args = call_arguments(node);
        return args.get(1).is_some_and(|c| {
            matches!(
                c.kind(),
                "string" | "integer" | "float" | "true" | "false" | "none"
            )
        });
    }
    // type(x) == 'str'
    let Some((left, op, right)) = two_operands(node, src) else {
        return false;
    };
    matches!(op, b"==" | b"is" | b"!=" | b"is not")
        && left.kind() == "call"
        && callee_name(left, src) == b"type"
        && matches!(right.kind(), "string")
}

fn hint_family(hint: &[u8]) -> Option<&'static str> {
    match hint {
        b"int" | b"float" | b"complex" => Some("number"),
        b"str" => Some("string"),
        b"bool" => Some("bool"),
        b"list" => Some("list"),
        b"dict" => Some("dict"),
        b"set" => Some("set"),
        b"tuple" => Some("tuple"),
        b"None" => Some("none"),
        _ => None,
    }
}

fn contradicts(hint_text: &[u8], value: Node, src: &[u8]) -> bool {
    let Some(want) = hint_family(hint_text) else {
        return false;
    };
    let Some(got) = literal_family(value.kind()) else {
        return false;
    };
    // bool is a number; bytes literals are not str
    if value.kind() == "string"
        && text(value, src)
            .first()
            .is_some_and(|b| b.eq_ignore_ascii_case(&b'b'))
    {
        return false;
    }
    if want == got {
        return false;
    }
    !(want == "number" && got == "bool")
}

fn returns_against_the_hint<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let hint = function.child_by_field_name("return_type")?;
    let hint_text = text(hint, src);
    hint_family(hint_text)?;
    if is_generator(function) {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "return_statement"
            && n.named_child(0)
                .is_some_and(|v| contradicts(hint_text, v, src))
    })
}

fn assigned_value_contradicts_annotation(assignment: Node, src: &[u8]) -> bool {
    let (Some(hint), Some(value)) = (
        assignment.child_by_field_name("type"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    contradicts(text(hint, src), value, src)
}

fn test_method_name_is_miscased(function: Node, src: &[u8]) -> bool {
    let name = name_of(function, src);
    let miscased =
        name.len() > 4 && name[..4].eq_ignore_ascii_case(b"test") && &name[..4] != b"test";
    if !miscased {
        return false;
    }
    let mut p = function.parent();
    while let Some(n) = p {
        if n.kind() == "class_definition" {
            return n
                .child_by_field_name("superclasses")
                .is_some_and(|s| contains_ignoring_case(text(s, src), b"TestCase"));
        }
        p = n.parent();
    }
    false
}

fn test_starts_with_return(function: Node, _: &[u8]) -> bool {
    let Some(body) = body_of(function) else {
        return false;
    };
    statements(body)
        .into_iter()
        .find(|s| {
            !(s.kind() == "expression_statement"
                && s.named_child(0).is_some_and(|e| e.kind() == "string"))
        })
        .is_some_and(|s| s.kind() == "return_statement" && s.named_child_count() == 0)
}

fn field_repeats_class_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = name_of(class, src);
    statements(body_of(class)?).into_iter().find(|s| {
        assignment_of(*s)
            .and_then(|a| a.child_by_field_name("left"))
            .is_some_and(|l| l.kind() == "identifier" && text(l, src).eq_ignore_ascii_case(name))
    })
}

fn member_differs_only_by_case<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<&[u8]> = Vec::new();
    for s in statements(body_of(class)?) {
        let function = if s.kind() == "decorated_definition" {
            function_of(s)
        } else if s.kind() == "function_definition" {
            Some(s)
        } else {
            None
        };
        let Some(f) = function else { continue };
        let name = name_of(f, src);
        if is_dunder(name) {
            continue;
        }
        if seen
            .iter()
            .any(|o| *o != name && o.eq_ignore_ascii_case(name))
        {
            return Some(f);
        }
        seen.push(name);
    }
    None
}

fn jsonresponse_gets_a_list(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .is_some_and(|a| matches!(a.kind(), "list" | "tuple" | "list_comprehension"))
        && keyword_value(call, "safe", src).is_none()
}

fn random_call_has_no_seed(call: Node, src: &[u8]) -> bool {
    if call_arguments(call)
        .iter()
        .any(|a| a.kind() == "dictionary_splat")
    {
        return false;
    }
    if keyword_value(call, "random_state", src).is_some() {
        return false;
    }
    match callee_name(call, src) {
        b"KFold" | b"StratifiedKFold" => {
            keyword_value(call, "shuffle", src).is_some_and(|v| v.kind() == "true")
        }
        _ => true,
    }
}

fn is_a_long_dataframe_chain(call: Node, src: &[u8]) -> bool {
    // only the outermost call of a chain
    if call
        .parent()
        .is_some_and(|p| p.kind() == "attribute" && p.child_by_field_name("object") == Some(call))
    {
        return false;
    }
    let mut depth = 0;
    let mut node = call;
    loop {
        match node.kind() {
            "call" => {
                depth += 1;
                let Some(f) = node.child_by_field_name("function") else {
                    return false;
                };
                node = f;
            }
            "attribute" => {
                let Some(o) = node.child_by_field_name("object") else {
                    return false;
                };
                node = o;
            }
            "identifier" => {
                let n = text(node, src);
                return depth >= 6 && (n == b"df" || n.starts_with(b"df_") || n.ends_with(b"_df"));
            }
            _ => return false,
        }
    }
}

fn error_handler_returns_no_status(decorated: Node, src: &[u8]) -> bool {
    let Some(function) = function_of(decorated) else {
        return false;
    };
    if !has_decorator(decorated, src, b".errorhandler(") {
        return false;
    }
    let Some(body) = body_of(function) else {
        return false;
    };
    let returns = collect_in_scope(body, SCOPE_STOPS, |n| n.kind() == "return_statement");
    !returns.is_empty()
        && returns.iter().all(|r| {
            r.named_child(0).is_some_and(|v| {
                !matches!(v.kind(), "tuple" | "expression_list")
                    && !(v.kind() == "call"
                        && matches!(
                            callee_name(v, src),
                            b"make_response" | b"abort" | b"Response"
                        ))
            })
        })
}

fn time_format_mixes_hours(call: Node, src: &[u8]) -> bool {
    call_arguments(call).iter().any(|a| {
        string_value(*a, src).is_some_and(|f| {
            let has = |p: &[u8]| f.windows(2).any(|w| w == p);
            f.contains(&b'%') && (has(b"%I") != has(b"%p"))
        })
    })
}

fn weekmask_is_invalid(string: Node, src: &[u8]) -> bool {
    let Some(v) = string_value(string, src) else {
        return false;
    };
    if v.len() == 7 && v.iter().all(|b| matches!(b, b'0' | b'1')) {
        return false;
    }
    let compact: Vec<u8> = v
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let days: &[&[u8]] = &[b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat", b"Sun"];
    let valid = !compact.is_empty()
        && compact.len().is_multiple_of(3)
        && compact.chunks(3).all(|c| days.contains(&c));
    !valid
}

fn call_has_validate_indices(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "validate_indices", src).is_some()
}

fn reduction_without_axis(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    keyword_value(call, "axis", src).is_none()
        && args
            .iter()
            .filter(|a| a.kind() != "keyword_argument")
            .count()
            < 2
        && !args.iter().any(|a| a.kind() == "dictionary_splat")
}

fn tf_function<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = function_of(decorated)?;
    has_decorator(decorated, src, b"tf.function").then_some(function)
}

fn tf_function_calls_itself<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = tf_function(decorated, src)?;
    let name = name_of(function, src);
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "call"
            && n.child_by_field_name("function")
                .is_some_and(|f| f.kind() == "identifier" && text(f, src) == name)
    })
}

fn tf_function_has_python_side_effect<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = tf_function(decorated, src)?;
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "call"
            && n.child_by_field_name("function")
                .is_some_and(|f| match f.kind() {
                    "identifier" => text(f, src) == b"print",
                    "attribute" => {
                        matches!(callee_name(n, src), b"append" | b"extend")
                            && f.child_by_field_name("object")
                                .is_some_and(|o| text(o, src) != b"tf")
                    }
                    _ => false,
                })
    })
}

fn tf_function_creates_a_variable<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = tf_function(decorated, src)?;
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "call"
            && text(n.child_by_field_name("function").unwrap_or(n), src) == b"tf.Variable"
    })
}

fn pipeline_has_no_memory(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "memory", src).is_none()
        && !call_arguments(call)
            .iter()
            .any(|a| a.kind() == "dictionary_splat")
}

fn call_has_no_arguments(call: Node, _: &[u8]) -> bool {
    call_arguments(call).is_empty()
}

fn estimator_sets_fitted_attribute_in_init<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let supers = class.child_by_field_name("superclasses")?;
    if !contains_ignoring_case(text(supers, src), b"BaseEstimator") {
        return None;
    }
    let init = statements(body_of(class)?)
        .into_iter()
        .find(|s| s.kind() == "function_definition" && name_of(*s, src) == b"__init__")?;
    find_in_scope(body_of(init)?, SCOPE_STOPS, |n| {
        n.kind() == "assignment"
            && n.child_by_field_name("left").is_some_and(|l| {
                l.kind() == "attribute"
                    && l.child_by_field_name("object")
                        .is_some_and(|o| text(o, src) == b"self")
                    && l.child_by_field_name("attribute").is_some_and(|a| {
                        text(a, src).ends_with(b"_") && !text(a, src).starts_with(b"_")
                    })
            })
    })
}

fn state_loaded_without_a_mode(call: Node, src: &[u8]) -> bool {
    let rest_start = call.end_byte();
    let scope_end = nearest_function(call, 20).map_or(src.len(), |f| f.end_byte());
    let rest = &src[rest_start..scope_end.max(rest_start)];
    !(contains_ignoring_case(rest, b".eval(") || contains_ignoring_case(rest, b".train("))
}

fn loop_polls_with_sleep(loop_: Node, src: &[u8]) -> bool {
    if !nearest_async(loop_) {
        return false;
    }
    let (Some(cond), Some(body)) = (
        loop_.child_by_field_name("condition"),
        loop_.child_by_field_name("body"),
    ) else {
        return false;
    };
    cond.kind() != "true"
        && find_in_scope(body, SCOPE_STOPS, |n| {
            n.kind() == "call"
                && callee_name(n, src) == b"sleep"
                && n.child_by_field_name("function").is_some_and(|f| {
                    f.kind() == "attribute"
                        && f.child_by_field_name("object").is_some_and(|o| {
                            matches!(text(o, src), b"asyncio" | b"trio" | b"anyio")
                        })
                })
        })
        .is_some()
}

fn sleeps_for_a_day_or_more(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .and_then(|a| integer_value(*a, src))
        .is_some_and(|v| v >= 86_400)
}

fn cancel_scope_has_no_await(with: Node, src: &[u8]) -> bool {
    let head = head_of(with, src);
    let scoped = [
        &b"move_on_after("[..],
        b"move_on_at(",
        b"fail_after(",
        b"fail_at(",
        b"CancelScope(",
    ]
    .iter()
    .any(|w| contains_ignoring_case(head, w));
    scoped
        && !has_token(with, "async")
        && body_of(with).is_some_and(|b| {
            find_in_scope(b, NESTED_STOPS, |n| {
                matches!(n.kind(), "await" | "yield")
                    || (matches!(n.kind(), "for_statement" | "with_statement")
                        && has_token(n, "async"))
            })
            .is_none()
        })
}

fn cancelled_error_is_swallowed(clause: Node, src: &[u8]) -> bool {
    let head = head_of(clause, src);
    if !(contains_ignoring_case(head, b"CancelledError")
        || contains_ignoring_case(head, b"trio.Cancelled"))
    {
        return false;
    }
    body_of(clause).is_some_and(|b| {
        find_in_scope(b, NESTED_STOPS, |n| n.kind() == "raise_statement").is_none()
            && find_in_scope(b, NESTED_STOPS, |n| n.kind() == "return_statement").is_none()
    })
}

fn is_task_group(with: Node, src: &[u8]) -> bool {
    let head = head_of(with, src);
    [&b"open_nursery("[..], b"create_task_group(", b"TaskGroup("]
        .iter()
        .any(|w| contains_ignoring_case(head, w))
}

fn group_starts_a_single_task(with: Node, src: &[u8]) -> bool {
    if !is_task_group(with, src) {
        return false;
    }
    let Some(body) = body_of(with) else {
        return false;
    };
    let items = statements(body);
    let [only] = items.as_slice() else {
        return false;
    };
    call_statement_of(*only).is_some_and(|c| {
        matches!(
            callee_name(c, src),
            b"start_soon" | b"start" | b"create_task"
        )
    })
}

fn group_body_jumps_out<'t>(with: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_task_group(with, src) {
        return None;
    }
    let body = body_of(with)?;
    find_in_scope(body, NESTED_STOPS, |n| n.kind() == "return_statement").or_else(|| {
        find_in_scope(
            body,
            &[
                "for_statement",
                "while_statement",
                "function_definition",
                "class_definition",
                "lambda",
            ],
            |n| matches!(n.kind(), "break_statement" | "continue_statement"),
        )
    })
}

fn sync_with_on_async_manager(with: Node, src: &[u8]) -> bool {
    if has_token(with, "async") {
        return false;
    }
    let head = head_of(with, src);
    [
        &b"aiohttp.ClientSession("[..],
        b"ClientSession(",
        b"open_nursery(",
        b"create_task_group(",
        b"asyncio.Lock(",
        b"asyncio.Semaphore(",
        b"asyncio.timeout(",
        b"asyncio.TaskGroup(",
    ]
    .iter()
    .any(|w| contains_ignoring_case(head, w))
        && nearest_async(with)
}

fn post_route_reads_query_args<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = function_of(decorated)?;
    let posts_only = decorator_calls(decorated).iter().any(|c| {
        is_route_decorator(*c, src) && {
            let m = methods_text(*c, src);
            contains_ignoring_case(m, b"POST") && !contains_ignoring_case(m, b"GET")
        }
    });
    if !posts_only {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "attribute" && text(n, src) == b"request.args"
    })
}

fn send_file_lacks_metadata(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let file_like = args.first().is_some_and(|a| {
        a.kind() == "call" && matches!(callee_name(*a, src), b"open" | b"BytesIO" | b"StringIO")
    });
    file_like
        && keyword_value(call, "mimetype", src).is_none()
        && keyword_value(call, "download_name", src).is_none()
        && keyword_value(call, "attachment_filename", src).is_none()
}

fn upload_endpoint_mixes_body(function: Node, src: &[u8]) -> bool {
    let Some(params) = function.child_by_field_name("parameters") else {
        return false;
    };
    let t = text(params, src);
    (contains_ignoring_case(t, b"UploadFile") || contains_ignoring_case(t, b"= File("))
        && (t.windows(5).any(|w| w == b"Body(") || t.windows(8).any(|w| w == b"Depends("))
}

fn no_content_returns_a_body<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = function_of(decorated)?;
    let no_content = decorator_calls(decorated).iter().any(|c| {
        is_route_decorator(*c, src)
            && keyword_value(*c, "status_code", src).is_some_and(|v| {
                let t = text(v, src);
                t == b"204" || t.ends_with(b"HTTP_204_NO_CONTENT")
            })
    });
    if !no_content {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "return_statement" && n.named_child(0).is_some_and(|v| v.kind() != "none")
    })
}

fn child_router_included_after_parent<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut includes: Vec<(&[u8], &[u8], Node<'t>)> = Vec::new();
    for s in statements(container) {
        let Some(call) = call_statement_of(s).filter(|c| callee_name(*c, src) == b"include_router")
        else {
            continue;
        };
        let Some(arg) = call_arguments(call).first().map(|a| text(*a, src)) else {
            continue;
        };
        let recv = receiver_text(call, src);
        if includes.iter().any(|(_, a, _)| *a == recv) {
            return Some(s);
        }
        includes.push((recv, arg, s));
    }
    None
}

fn client_sends_text_as_data(call: Node, src: &[u8]) -> bool {
    contains_ignoring_case(receiver_text(call, src), b"client")
        && keyword_value(call, "data", src).is_some_and(|v| {
            v.kind() == "string" || (v.kind() == "call" && callee_name(v, src) == b"dumps")
        })
}

fn response_model_repeats_return_type(decorated: Node, src: &[u8]) -> bool {
    let Some(function) = function_of(decorated) else {
        return false;
    };
    let Some(hint) = function.child_by_field_name("return_type") else {
        return false;
    };
    decorator_calls(decorated).iter().any(|c| {
        is_route_decorator(*c, src)
            && keyword_value(*c, "response_model", src)
                .is_some_and(|m| text(m, src) == text(hint, src))
    })
}

fn include_router_sets_prefix(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "prefix", src).is_some()
        && call_arguments(call)
            .first()
            .is_some_and(|a| a.kind() == "identifier")
}

fn cors_middleware_added_before_others<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let adds: Vec<(Node<'t>, bool)> = statements(container)
        .into_iter()
        .filter_map(|s| {
            let c = call_statement_of(s).filter(|c| callee_name(*c, src) == b"add_middleware")?;
            let cors = call_arguments(c)
                .first()
                .is_some_and(|a| contains_ignoring_case(text(*a, src), b"CORSMiddleware"));
            Some((s, cors))
        })
        .collect();
    let last_cors = adds.iter().rposition(|(_, cors)| *cors)?;
    (last_cors + 1 < adds.len()).then(|| adds[last_cors].0)
}

fn raises_undocumented_http_exception(decorated: Node, src: &[u8]) -> bool {
    let Some(function) = function_of(decorated) else {
        return false;
    };
    let routed = decorator_calls(decorated)
        .iter()
        .find(|c| is_route_decorator(**c, src) && callee_name(**c, src) != b"route")
        .copied();
    let Some(route) = routed else { return false };
    keyword_value(route, "responses", src).is_none()
        && body_of(function).is_some_and(|b| {
            find_in_scope(b, SCOPE_STOPS, |n| {
                n.kind() == "raise_statement" && text(n, src).starts_with(b"raise HTTPException")
            })
            .is_some()
        })
}

fn assigns_outside_slots<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if class.child_by_field_name("superclasses").is_some() {
        return None;
    }
    let body = body_of(class)?;
    let slots = statements(body).into_iter().find_map(|s| {
        let a = assignment_of(s)?;
        (a.child_by_field_name("left")
            .is_some_and(|l| text(l, src) == b"__slots__"))
        .then(|| a.child_by_field_name("right"))
        .flatten()
    })?;
    let declared: Vec<&[u8]> = match slots.kind() {
        "list" | "tuple" | "set" => statements(slots)
            .iter()
            .filter_map(|e| string_value(*e, src))
            .collect(),
        "string" => string_value(slots, src).into_iter().collect(),
        _ => return None,
    };
    if declared.contains(&&b"__dict__"[..]) {
        return None;
    }
    find_in_scope(body, &["class_definition"], |n| {
        n.kind() == "attribute"
            && n.parent().is_some_and(|p| {
                p.kind() == "assignment" && p.child_by_field_name("left") == Some(n)
            })
            && n.child_by_field_name("object")
                .is_some_and(|o| text(o, src) == b"self")
            && n.child_by_field_name("attribute")
                .is_some_and(|a| !declared.contains(&text(a, src)))
    })
}

fn returns_tuples_of_different_lengths<'t>(function: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = body_of(function)?;
    let tuples: Vec<(Node, usize)> =
        collect_in_scope(body, SCOPE_STOPS, |n| n.kind() == "return_statement")
            .into_iter()
            .filter_map(|r| {
                let v = r.named_child(0)?;
                (v.kind() == "tuple" || v.kind() == "expression_list")
                    .then(|| (r, v.named_child_count()))
            })
            .collect();
    let first = tuples.first()?.1;
    tuples.iter().find(|(_, n)| *n != first).map(|(r, _)| *r)
}

fn defines_some_ordering_methods(class: Node, src: &[u8]) -> bool {
    let Some(body) = body_of(class) else {
        return false;
    };
    if class.parent().is_some_and(|p| {
        p.kind() == "decorated_definition" && has_decorator(p, src, b"total_ordering")
    }) {
        return false;
    }
    let defined = statements(body)
        .iter()
        .filter(|s| {
            s.kind() == "function_definition"
                && matches!(
                    name_of(**s, src),
                    b"__lt__" | b"__le__" | b"__gt__" | b"__ge__"
                )
        })
        .count();
    (1..4).contains(&defined)
}

fn singledispatch_on_wrong_target(decorated: Node, src: &[u8]) -> bool {
    let Some(function) = function_of(decorated) else {
        return false;
    };
    let method = in_class(function);
    let dispatch_method = has_decorator(decorated, src, b"singledispatchmethod");
    let dispatch = !dispatch_method && has_decorator(decorated, src, b"singledispatch");
    (dispatch && method && first_parameter_name(function, src) == Some(b"self"))
        || (dispatch_method && !method)
}

fn bases_conflict_in_mro(class: Node, src: &[u8]) -> bool {
    let Some(supers) = class.child_by_field_name("superclasses") else {
        return false;
    };
    let bases: Vec<&[u8]> = statements(supers)
        .iter()
        .filter(|n| n.kind() == "identifier")
        .map(|n| text(*n, src))
        .collect();
    if bases.len() < 2 {
        return false;
    }
    let root = root_of(class);
    let classes = statements(root);
    (0..bases.len()).any(|i| {
        (i + 1..bases.len()).any(|j| {
            classes.iter().any(|c| {
                c.kind() == "class_definition"
                    && name_of(*c, src) == bases[j]
                    && c.child_by_field_name("superclasses")
                        .is_some_and(|s| statements(s).iter().any(|b| text(*b, src) == bases[i]))
            })
        })
    })
}

fn group_iterator_is_consumed_twice(for_statement: Node, src: &[u8]) -> bool {
    let (Some((_, group)), Some(right), Some(body)) = (
        loop_pair(for_statement, src),
        for_statement.child_by_field_name("right"),
        for_statement.child_by_field_name("body"),
    ) else {
        return false;
    };
    if right.kind() != "call" || callee_name(right, src) != b"groupby" {
        return false;
    }
    let whole = text(body, src);
    let mut call = group.to_vec();
    call.insert(0, b'(');
    call.push(b')');
    let mut iterated = b"in ".to_vec();
    iterated.extend_from_slice(group);
    occurrences(whole, &call) + occurrences(whole, &iterated) >= 2
}

fn inserts_markup_as_text(call: Node, src: &[u8]) -> bool {
    let recv = receiver_text(call, src);
    let tagged = ["soup", "tag", "body", "div", "html", "element"]
        .iter()
        .any(|w| contains_ignoring_case(recv, w.as_bytes()));
    tagged
        && call_arguments(call).first().is_some_and(|a| {
            string_value(*a, src).is_some_and(|v| {
                let t = v.trim_ascii_start();
                t.starts_with(b"<") && t.contains(&b'>')
            })
        })
}

fn find_result_is_used_directly(attribute: Node, src: &[u8]) -> bool {
    let Some(call) = attribute.child_by_field_name("object") else {
        return false;
    };
    let recv = receiver_text(call, src);
    ["soup", "bs", "tag"]
        .iter()
        .any(|w| contains_ignoring_case(recv, w.as_bytes()))
}

fn string_has_a_space(string: Node, src: &[u8]) -> bool {
    string_value(string, src).is_some_and(|v| v.trim_ascii().contains(&b' '))
}

fn function_lacks_return_hint(function: Node, src: &[u8]) -> bool {
    function.child_by_field_name("return_type").is_none() && name_of(function, src) != b"__init__"
}

fn parameter_lacks_hint<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let params = function.child_by_field_name("parameters")?;
    statements(params).into_iter().find(|p| {
        let name = match p.kind() {
            "identifier" => Some(text(*p, src)),
            "default_parameter" => p.child_by_field_name("name").map(|n| text(n, src)),
            _ => None,
        };
        name.is_some_and(|n| !matches!(n, b"self" | b"cls") && !n.starts_with(b"_"))
    })
}

/// Names of the functions called anywhere inside `root`.
pub(super) fn collect_calls<'s>(root: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    collect_in_scope(root, &[], |n| n.kind() == "call")
        .into_iter()
        .map(|c| callee_name(c, src))
        .collect()
}

pub(super) fn identifiers_in(node: Node) -> Vec<Node> {
    if node.kind() == "identifier" {
        return vec![node];
    }
    collect_in_scope(node, &[], |n| n.kind() == "identifier")
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
        let file = analyze("t", Lang::Python, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn jumps_and_equality() {
        let src = "def f():\n    break\nfor x in y:\n    break\nfor x in y:\n    pass\nelse:\n    continue\n1 == 'a'\nx == 'a'\n1 == True\nNone == 1\n[] is None\nx is None";
        assert_eq!(flagged("py/jump-outside-loop", src), [2, 8]);
        assert_eq!(flagged("py/silly-equality", src), [9, 12]);
        assert_eq!(flagged("py/none-comparison-constant", src), [12, 13]);
    }

    #[test]
    fn nested_definitions_and_walrus() {
        let src = "def outer():\n    def used():\n        pass\n    def unused():\n        pass\n    (y := f())\n    if (z := g()):\n        pass\n    return used()";
        assert_eq!(flagged("py/nested-definition-unused", src), [4]);
        assert_eq!(flagged("py/walrus-as-statement", src), [6]);
    }

    #[test]
    fn exceptions_and_types() {
        let src = "try:\n    f()\nexcept (OSError, FileNotFoundError):\n    pass\nexcept (KeyError, ValueError):\n    pass\nexcept 'x':\n    pass\nisinstance(a, 'str')\nisinstance(a, str)\ntype(a) == 'str'\ndef g() -> int:\n    return 'a'\ndef h() -> None:\n    return 1\ndef i() -> float:\n    return 1\nx: int = 'a'\ny: float = 1";
        assert_eq!(flagged("py/except-parent-and-child", src), [3]);
        assert_eq!(flagged("py/except-non-exception", src), [7]);
        assert_eq!(flagged("py/confusing-type-check", src), [9, 11]);
        assert_eq!(flagged("py/return-type-mismatch", src), [13, 15]);
        assert_eq!(flagged("py/annotation-mismatch", src), [18]);
    }

    #[test]
    fn classes() {
        let src = "class A:\n    def run(self):\n        pass\n    def Run(self):\n        pass\nclass B:\n    __slots__ = ('a',)\n    def __init__(self):\n        self.a = 1\n        self.b = 2\nclass C:\n    def __lt__(self, o):\n        return True\nclass D(Exception):\n    pass\nclass E1:\n    pass\nclass E2(E1):\n    pass\nclass F(E1, E2):\n    pass";
        assert_eq!(flagged("py/names-differ-by-case", src), [4]);
        assert_eq!(flagged("py/slots-assignment", src), [10]);
        assert_eq!(flagged("py/comparison-methods-incomplete", src), [11]);
        assert_eq!(flagged("py/mro-conflict", src), [20]);
    }

    #[test]
    fn returns() {
        let src = "def a(x):\n    if x:\n        return 1, 2\n    return 1, 2, 3\ndef b(x):\n    if x:\n        return 1, 2\n    return 3, 4\ndef c(x):\n    if x:\n        return 0\n    return 0\ndef d(x):\n    if x:\n        return 0\n    return 1";
        assert_eq!(flagged("py/tuple-length-inconsistent", src), [4]);
        assert_eq!(flagged("py/invariant-return", src), [9]);
    }

    #[test]
    fn fastapi_and_flask() {
        let src = "@app.post('/a', status_code=204)\ndef a():\n    return {'x': 1}\n@app.post('/b', status_code=204)\ndef b():\n    return None\n@app.route('/c', methods=['GET', 'POST'])\ndef c():\n    pass\n@app.route('/d', methods=['POST'])\ndef d():\n    return request.args\napp.include_router(parent)\nparent.include_router(child)\napp.add_middleware(CORSMiddleware)\napp.add_middleware(Other)";
        assert_eq!(flagged("py/no-content-with-body", src), [3]);
        assert_eq!(flagged("py/route-mixed-methods", src), [7]);
        assert_eq!(flagged("py/post-reads-query-args", src), [12]);
        assert_eq!(flagged("py/router-included-late", src), [14]);
        assert_eq!(flagged("py/cors-not-last", src), [15]);
    }

    #[test]
    fn libraries() {
        let src = "n = np.busday_count(a, b, weekmask='1111100')\nn = np.busday_count(a, b, weekmask='11111')\nn = np.busday_count(a, b, weekmask='Mon Tue')\ns = d.strftime('%I:%M')\ns = d.strftime('%I:%M %p')\nm = RandomForestClassifier()\nm = RandomForestClassifier(n_estimators=3)\nx, y = train_test_split(a, random_state=1)\nx, y = train_test_split(a)\nfor k, g in groupby(xs):\n    a = list(g)\n    b = list(g)";
        assert_eq!(flagged("py/weekmask-invalid", src), [2]);
        assert_eq!(flagged("py/time-format-mix", src), [4]);
        assert_eq!(flagged("py/ml-hyperparameters", src), [6]);
        assert_eq!(flagged("py/random-state-missing", src), [6, 7, 9]);
        assert_eq!(flagged("py/groupby-iterator-reused", src), [10]);
    }

    #[test]
    fn module_names() {
        let src = "import os\n__all__ = ['f', 'Missing', 'sub']\ndef f():\n    pass\nprint(os.name, nothing_here, len)";
        assert_eq!(flagged("py/all-undefined-name", src), [2]);
        assert_eq!(flagged("py/undefined-name", src), [5]);
    }
}
