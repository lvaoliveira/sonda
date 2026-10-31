//! More Python rules (ADR-0007, batch 13). Queries stay cheap on deep trees:
//! see the notes in `js_modern.rs`; whole-block checks run as `Find` filters.

use super::js_extra::count_word;
use super::py_quality::{
    SCOPE_STOPS, children_of_kind, find_in_scope, has_token, nearest_function, statements,
    two_operands,
};
use super::py_security::{
    call_arguments, callee_name, contains_ignoring_case, has_interpolation, integer_value,
    keyword_value, string_value, text,
};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/except-only-reraises",
        name: "except clauses should do more than re-raise",
        description: "An except that only raises again changes nothing, unless it shields a later clause.",
        message: "Handle the exception, or remove this clause.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2737")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(except_clause) @match"#,
            filter: Some(Keep(except_only_reraises)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept ValueError:\n    raise\n",
            good: "try:\n    f()\nexcept ValueError:\n    log()\n    raise\n",
        }),
    },
    Rule {
        id: "py/all-not-strings",
        name: "Only strings should be listed in __all__",
        description: "Any other entry makes `from m import *` fail.",
        message: "Use the name as a string.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2823")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) @n (#eq? @n "__all__") right: [(list) (tuple)]) @match"#,
            filter: Some(Find(all_entry_not_string)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    pass\n__all__ = [f]\n",
            good: "def f():\n    pass\n__all__ = ['f']\n",
        }),
    },
    Rule {
        id: "py/iter-returns-non-iterator",
        name: "__iter__ should return an iterator",
        description: "Returning a list or other container makes iter() raise TypeError.",
        message: "Return iter(...) or self.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2876")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition name: (identifier) @n (#eq? @n "__iter__")) @match"#,
            filter: Some(Find(iter_returns_container)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __iter__(self):\n        return [1, 2]\n",
            good: "class A:\n    def __iter__(self):\n        return iter([1, 2])\n",
        }),
    },
    Rule {
        id: "py/is-with-literal",
        name: "Identity comparisons should not be used with cached types",
        description: "`x is 'a'` and `x is 1` depend on interning, which is an implementation detail.",
        message: "Use == instead of is.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5795")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(identity_with_value_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x is 'a':\n    pass\n",
            good: "if x == 'a':\n    pass\n",
        }),
    },
    Rule {
        id: "py/is-with-new-object",
        name: "New objects should not be created only to check their identity",
        description: "`x is []` is always False: the literal is a fresh object.",
        message: "Compare with == or check emptiness.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5796")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(identity_with_new_object)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x is []:\n    pass\n",
            good: "if not x:\n    pass\n",
        }),
    },
    Rule {
        id: "py/identity-dissimilar-types",
        name: "Identity operators should not be used with dissimilar types",
        description: "Operands of different kinds never share an identity.",
        message: "Fix the comparison.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3403")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(identity_between_different_literals)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if 1 is 'a':\n    pass\n",
            good: "if x is None:\n    pass\n",
        }),
    },
    Rule {
        id: "py/inconsistent-return",
        name: "Functions should use return consistently",
        description: "Some paths return a value and others a bare return, so callers get None unexpectedly.",
        message: "Return a value on every path.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3801")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(bare_return_beside_valued_return)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x):\n    if x:\n        return 1\n    return\n",
            good: "def f(x):\n    if x:\n        return 1\n    return 0\n",
        }),
    },
    Rule {
        id: "py/return-in-generator",
        name: "return with a value should not be used in an async generator",
        description: "An async generator cannot return a value: it is a SyntaxError.",
        message: "Yield the value, or drop it.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2712")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(valued_return_in_generator)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    yield 1\n    return 2\n",
            good: "async def f():\n    yield 1\n    return\n",
        }),
    },
    Rule {
        id: "py/collection-replaced",
        name: "Collection content should not be replaced unconditionally",
        description: "The first assignment to the same key is overwritten before it is read.",
        message: "Remove the first assignment.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4143")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(block) @match
(module) @match"#,
            filter: Some(Find(key_assigned_twice)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d['k'] = 1\nd['k'] = 2\n",
            good: "d['k'] = 2\n",
        }),
    },
    Rule {
        id: "py/dead-store",
        name: "Unused assignments should be removed",
        description: "The value assigned first is overwritten before anything reads it.",
        message: "Remove the first assignment.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1854")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(block) @match
(module) @match"#,
            filter: Some(Find(assigned_then_overwritten)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = compute()\nx = other()\n",
            good: "x = other()\n",
        }),
    },
    Rule {
        id: "py/exception-cause-literal",
        name: "Exception causes must be exceptions or None",
        description: "`raise A from 'text'` fails with TypeError.",
        message: "Chain an exception, or None.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5707")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(raise_statement cause: [(string) (integer) (float) (true) (false) (list) (dictionary) (tuple)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "raise ValueError('x') from 'reason'\n",
            good: "raise ValueError('x') from err\n",
        }),
    },
    Rule {
        id: "py/except-boolean-expression",
        name: "Boolean expressions of exceptions should not be used in except statements",
        description: "`except A or B` catches only A: or evaluates to its first operand.",
        message: "List the exceptions in a tuple.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5714")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(except_clause (boolean_operator) @match)
(except_clause (parenthesized_expression (boolean_operator) @match))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept ValueError or TypeError:\n    pass\n",
            good: "try:\n    f()\nexcept (ValueError, TypeError):\n    pass\n",
        }),
    },
    Rule {
        id: "py/bare-raise-in-finally",
        name: "Bare raise statements should not be used in finally blocks",
        description: "Outside a handler a bare raise fails, and after one it hides the real error.",
        message: "Raise a named exception.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5704")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(finally_clause) @match"#,
            filter: Some(Find(bare_raise_in_finally)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nfinally:\n    raise\n",
            good: "try:\n    f()\nfinally:\n    cleanup()\n",
        }),
    },
    Rule {
        id: "py/exit-reraises",
        name: "__exit__ should not re-raise the exception it receives",
        description: "Returning a falsy value already lets the exception propagate.",
        message: "Return False instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5706")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition name: (identifier) @n (#eq? @n "__exit__")) @match"#,
            filter: Some(Find(exit_raises_its_argument)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __exit__(self, t, v, tb):\n        raise v\n",
            good: "class A:\n    def __exit__(self, t, v, tb):\n        return False\n",
        }),
    },
    Rule {
        id: "py/exception-base-class",
        name: "Custom exception classes should inherit from Exception",
        description: "A class with no base cannot be raised or caught.",
        message: "Derive from Exception.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5709")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Keep(exception_without_base)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class AppError:\n    pass\n",
            good: "class AppError(Exception):\n    pass\n",
        }),
    },
    Rule {
        id: "py/not-implemented-error",
        name: "Special methods should return NotImplemented, not raise NotImplementedError",
        description: "Operators fall back to the other operand only when NotImplemented is returned.",
        message: "Return NotImplemented.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5712")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(operator_raises_not_implemented)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __eq__(self, o):\n        raise NotImplementedError\n",
            good: "class A:\n    def __eq__(self, o):\n        return NotImplemented\n",
        }),
    },
    Rule {
        id: "py/special-method-arity",
        name: "Special methods should have an expected number of parameters",
        description: "Python calls them with a fixed signature.",
        message: "Fix the parameter list.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5722")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(special_method_has_wrong_arity)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __len__(self, extra):\n        return 0\n",
            good: "class A:\n    def __len__(self):\n        return 0\n",
        }),
    },
    Rule {
        id: "py/property-arity",
        name: "Property getter, setter and deleter methods should have the expected number of parameters",
        description: "A getter takes self, a setter self and the value.",
        message: "Fix the parameter list.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5724")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Keep(property_has_wrong_arity)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    @property\n    def x(self, y):\n        return 1\n",
            good: "class A:\n    @property\n    def x(self):\n        return 1\n",
        }),
    },
    Rule {
        id: "py/call-non-callable",
        name: "Calls should not be made to non-callable values",
        description: "Calling a literal raises TypeError.",
        message: "Remove the call.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5756")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: [(string) (integer) (float) (list) (dictionary) (true) (false) (none) (tuple)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = 'abc'()\n",
            good: "x = 'abc'\n",
        }),
    },
    Rule {
        id: "py/in-on-non-container",
        name: "in and not in should be used on objects supporting them",
        description: "A number or None has no members to test.",
        message: "Test against a collection.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5642")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(membership_in_a_scalar)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x in 5:\n    pass\n",
            good: "if x in (5,):\n    pass\n",
        }),
    },
    Rule {
        id: "py/subscript-on-scalar",
        name: "Item operations should be done on objects supporting them",
        description: "Indexing a number or None raises TypeError.",
        message: "Index a collection.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5644")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(subscript value: [(integer) (float) (true) (false) (none)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = 5[0]\n",
            good: "x = [5][0]\n",
        }),
    },
    Rule {
        id: "py/iterate-scalar",
        name: "Iteration should use an Iterable object",
        description: "Looping over a number or None raises TypeError.",
        message: "Iterate over a collection.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3862")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement right: [(integer) (float) (true) (false) (none)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for i in 5:\n    pass\n",
            good: "for i in range(5):\n    pass\n",
        }),
    },
    Rule {
        id: "py/incompatible-operands",
        name: "Operators should be used on compatible types",
        description: "Adding a string and a number, or doing arithmetic on None, raises TypeError.",
        message: "Convert an operand.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5607")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(binary_operator) @match"#,
            filter: Some(Keep(operands_of_different_kinds)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = 'a' + 1\n",
            good: "x = 'a' + str(1)\n",
        }),
    },
    Rule {
        id: "py/unhashable-member",
        name: "Set members and dictionary keys should be hashable",
        description: "Lists, dicts and sets raise TypeError as keys.",
        message: "Use a tuple or frozenset.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6662")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(pair key: [(list) (dictionary) (set) (list_comprehension)] @match)
(set [(list) (dictionary) (set)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = {[1]: 'a'}\n",
            good: "d = {(1,): 'a'}\n",
        }),
    },
    Rule {
        id: "py/float-index",
        name: "Sequence indexes must have an __index__ method",
        description: "A float cannot index a sequence.",
        message: "Use an integer.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6663")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(subscript subscript: (float) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = items[1.5]\n",
            good: "x = items[1]\n",
        }),
    },
    Rule {
        id: "py/string-format-count",
        name: "String formatting should not lead to runtime errors",
        description: "Fewer arguments than placeholders raises TypeError or IndexError.",
        message: "Match the arguments to the placeholders.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2275")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(binary_operator) @match
(call function: (attribute object: (string) attribute: (identifier) @m (#eq? @m "format"))) @match"#,
            filter: Some(Keep(format_arguments_do_not_match)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "msg = '%s and %s' % (a,)\n",
            good: "msg = '%s and %s' % (a, b)\n",
        }),
    },
    Rule {
        id: "py/fstring-without-fields",
        name: "String formatting should be used correctly",
        description: "An f-string with no field is just a string.",
        message: "Remove the f prefix, or add a field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S3457")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(string) @match"#,
            filter: Some(Keep(fstring_has_no_field)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "msg = f'hello'\n",
            good: "msg = 'hello'\n",
        }),
    },
    Rule {
        id: "py/infinite-recursion",
        name: "Recursion should not be infinite",
        description: "A function that calls itself with no branch can never stop.",
        message: "Add a base case.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2190")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(recurses_without_a_branch)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(n):\n    return f(n - 1)\n",
            good: "def f(n):\n    if n == 0:\n        return 0\n    return f(n - 1)\n",
        }),
    },
    Rule {
        id: "py/overwritten-parameter",
        name: "Function parameters initial values should not be ignored",
        description: "The first thing the function does is replace the argument it was given.",
        message: "Use the parameter, or drop it.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1226")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(parameter_overwritten_first)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x):\n    x = 1\n    return x\n",
            good: "def f(x):\n    y = x + 1\n    return y\n",
        }),
    },
    Rule {
        id: "py/private-method-unused",
        name: "Unused class-private methods should be removed",
        description: "Nothing in the class calls it, and name mangling hides it from outside.",
        message: "Remove this method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1144")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(unused_private_method)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __hidden(self):\n        pass\n",
            good: "class A:\n    def __hidden(self):\n        pass\n    def run(self):\n        self.__hidden()\n",
        }),
    },
    Rule {
        id: "py/private-attribute-unread",
        name: "Unread private attributes should be removed",
        description: "The value is written and never read back.",
        message: "Remove this attribute.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4487")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(unread_private_attribute)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __init__(self):\n        self.__x = 1\n",
            good: "class A:\n    def __init__(self):\n        self.__x = 1\n    def x(self):\n        return self.__x\n",
        }),
    },
    Rule {
        id: "py/identical-functions",
        name: "Functions and methods should not have identical implementations",
        description: "Two copies of a body drift apart.",
        message: "Reuse the first implementation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4144")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match
(class_definition body: (block) @match)"#,
            filter: Some(Find(function_repeats_a_body)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def a():\n    x = 1\n    return x\ndef b():\n    x = 1\n    return x\n",
            good: "def a():\n    x = 1\n    return x\ndef b():\n    return a()\n",
        }),
    },
    Rule {
        id: "py/duplicated-branch",
        name: "Two branches in a conditional structure should not have exactly the same implementation",
        description: "Merge the conditions instead of repeating the body.",
        message: "Merge these branches.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1871")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement) @match"#,
            filter: Some(Find(branch_repeats_a_body)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if a:\n    x = 1\n    y = 2\nelif b:\n    x = 1\n    y = 2\nelse:\n    z = 3\n",
            good: "if a or b:\n    x = 1\n    y = 2\nelse:\n    z = 3\n",
        }),
    },
    Rule {
        id: "py/loop-variable-closure",
        name: "Functions and lambdas should not reference variables defined in enclosing loops",
        description: "The closure sees the variable's final value, not the one from its iteration.",
        message: "Bind the value with a default argument.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1515")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(lambda) @match
(function_definition) @match"#,
            filter: Some(Keep(closes_over_loop_variable)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "fs = []\nfor i in r:\n    fs.append(lambda: i)\n",
            good: "fs = []\nfor i in r:\n    fs.append(lambda i=i: i)\n",
        }),
    },
    Rule {
        id: "py/class-name",
        name: "Class names should comply with a naming convention",
        description: "PascalCase makes classes recognisable.",
        message: "Rename this class to PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S101")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition name: (identifier) @match)"#,
            filter: Some(Keep(class_name_is_not_pascal_case)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class my_class:\n    pass\n",
            good: "class MyClass:\n    pass\n",
        }),
    },
    Rule {
        id: "py/method-name",
        name: "Method names should comply with a naming convention",
        description: "snake_case is the Python convention.",
        message: "Rename this method to snake_case.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S100")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition name: (identifier) @match)"#,
            filter: Some(Keep(method_name_is_not_snake_case)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def doThing(self):\n        pass\n",
            good: "class A:\n    def do_thing(self):\n        pass\n",
        }),
    },
    Rule {
        id: "py/function-name",
        name: "Function names should comply with a naming convention",
        description: "snake_case is the Python convention.",
        message: "Rename this function to snake_case.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1542")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition name: (identifier) @match)"#,
            filter: Some(Keep(function_name_is_not_snake_case)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def doThing():\n    pass\n",
            good: "def do_thing():\n    pass\n",
        }),
    },
    Rule {
        id: "py/field-name",
        name: "Field names should comply with a naming convention",
        description: "snake_case is the Python convention.",
        message: "Rename this field to snake_case.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S116")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (attribute object: (identifier) @o attribute: (identifier) @match (#eq? @o "self")))"#,
            filter: Some(Keep(name_is_not_snake_case)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __init__(self):\n        self.myField = 1\n",
            good: "class A:\n    def __init__(self):\n        self.my_field = 1\n",
        }),
    },
    Rule {
        id: "py/local-name",
        name: "Local variable and function parameter names should comply with a naming convention",
        description: "snake_case is the Python convention.",
        message: "Rename this variable to snake_case.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S117")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) @match)
(parameters (identifier) @match)
(default_parameter name: (identifier) @match)
(typed_parameter (identifier) @match)
(typed_default_parameter name: (identifier) @match)"#,
            filter: Some(Keep(local_name_is_not_snake_case)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(myArg):\n    return myArg\n",
            good: "def f(my_arg):\n    return my_arg\n",
        }),
    },
    Rule {
        id: "py/self-parameter-name",
        name: "self should be the first argument to instance methods",
        description: "Another name confuses readers and tools.",
        message: "Name it self.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5720")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(instance_method_first_parameter)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def run(this):\n        pass\n",
            good: "class A:\n    def run(self):\n        pass\n",
        }),
    },
    Rule {
        id: "py/cls-parameter-name",
        name: "The first argument to class methods should follow the naming convention",
        description: "Use cls.",
        message: "Name it cls.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2710")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Find(class_method_first_parameter)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    @classmethod\n    def make(self):\n        pass\n",
            good: "class A:\n    @classmethod\n    def make(cls):\n        pass\n",
        }),
    },
    Rule {
        id: "py/wildcard-import",
        name: "Wildcard imports should not be used",
        description: "They hide where names come from and can shadow each other.",
        message: "Import the names you use.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2208")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(import_from_statement (wildcard_import) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "from os import *\n",
            good: "from os import path\n",
        }),
    },
    Rule {
        id: "py/unused-import",
        name: "Unnecessary imports should be removed",
        description: "An import nothing uses only slows start-up.",
        message: "Remove this import.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1128")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(import_statement) @match
(import_from_statement) @match"#,
            filter: Some(Keep(import_is_unused)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import os\n",
            good: "import os\nprint(os.name)\n",
        }),
    },
    Rule {
        id: "py/unused-local",
        name: "Unused local variables should be removed",
        description: "A variable that is never read is dead code or a typo.",
        message: "Remove this variable, or use it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1481")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) @match)"#,
            filter: Some(Keep(local_is_never_read)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    x = compute()\n    return 1\n",
            good: "def f():\n    x = compute()\n    return x\n",
        }),
    },
    Rule {
        id: "py/unused-parameter",
        name: "Unused function parameters should be removed",
        description: "Callers pass a value that is ignored.",
        message: "Remove this parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1172")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(parameter_is_unused)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(a, b):\n    return a\n",
            good: "def f(a):\n    return a\n",
        }),
    },
    Rule {
        id: "py/too-many-returns",
        name: "Functions should not contain too many return statements",
        description: "Many exits make the flow hard to follow.",
        message: "Reduce the number of returns.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S1142")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(has_many_returns)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x):\n    if x == 1:\n        return 1\n    if x == 2:\n        return 2\n    if x == 3:\n        return 3\n    return 4\n",
            good: "def f(x):\n    return x\n",
        }),
    },
    Rule {
        id: "py/nesting-depth",
        name: "Control flow statements should not be nested too deeply",
        description: "Deep nesting hides the main path.",
        message: "Extract a function or use early returns.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S134")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement) @match
(for_statement) @match
(while_statement) @match
(try_statement) @match
(with_statement) @match"#,
            filter: Some(Keep(is_nested_too_deeply)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if a:\n    if b:\n        if c:\n            if d:\n                if e:\n                    f()\n",
            good: "if a and b:\n    f()\n",
        }),
    },
    Rule {
        id: "py/function-complexity",
        name: "Cyclomatic Complexity of functions should not be too high",
        description: "Every branch is another path to test.",
        message: "Split this function.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("FunctionComplexity")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(is_too_complex)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(a, b, c, d, e, g, h, i, j, k):\n    if a: pass\n    if b: pass\n    if c: pass\n    if d: pass\n    if e: pass\n    if g: pass\n    if h: pass\n    if i: pass\n    if j: pass\n    if k: pass\n",
            good: "def f(a):\n    if a:\n        return 1\n    return 0\n",
        }),
    },
    Rule {
        id: "py/hardcoded-ip",
        name: "IP addresses should not be hardcoded",
        description: "A fixed address has to be changed in the code when the network moves.",
        message: "Read the address from configuration.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1313")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(string) @match"#,
            filter: Some(Keep(string_is_an_ip_address)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "host = '192.168.1.10'\n",
            good: "host = os.environ['HOST']\n",
        }),
    },
    Rule {
        id: "py/noqa-comment",
        name: "Uses of noqa comments should be tracked",
        description: "Each one silences a check.",
        message: "Review this suppression.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 1,
        sonar: &[exact("S1309")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comment) @match"#,
            filter: Some(Keep(is_noqa)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import os  # noqa\n",
            good: "import os\n",
        }),
    },
    Rule {
        id: "py/trailing-comment",
        name: "Comments should not be located at the end of lines of code",
        description: "They push lines past the screen edge and are easy to miss.",
        message: "Move the comment above the line.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S139")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comment) @match"#,
            filter: Some(Keep(comment_trails_code)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = 1  # the count\n",
            good: "# the count\nx = 1\n",
        }),
    },
    Rule {
        id: "py/semicolon-statements",
        name: "Statements should be on separate lines",
        description: "Several statements on one line are easy to misread.",
        message: "Put each statement on its own line.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("OneStatementPerLine")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"";" @match"#,
            filter: Some(Keep(semicolon_joins_statements)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "a = 1; b = 2\n",
            good: "a = 1\nb = 2\n",
        }),
    },
    Rule {
        id: "py/increment-operator",
        name: "Increment and decrement operators should not be used",
        description: "`++x` is two unary plus signs and does nothing.",
        message: "Use x += 1.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("PreIncrementDecrement")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(unary_operator argument: (unary_operator)) @match"#,
            filter: Some(Keep(looks_like_increment)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = 1\n++x\n",
            good: "x = 1\nx += 1\n",
        }),
    },
    Rule {
        id: "py/lambda-assigned",
        name: "Assignments of lambdas to variables should be replaced by function definitions",
        description: "A def has a name in tracebacks and can carry a docstring.",
        message: "Use def.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6661")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) right: (lambda)) @match"#,
            filter: Some(Keep(assignment_is_not_annotated)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "f = lambda x: x + 1\n",
            good: "def f(x):\n    return x + 1\n",
        }),
    },
    Rule {
        id: "py/hint-any",
        name: "Any should not be used as a type hint",
        description: "It switches off type checking for that value.",
        message: "Use a precise type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6542")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(type (identifier) @match (#eq? @match "Any"))
(type (attribute attribute: (identifier) @match (#eq? @match "Any")))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x: Any):\n    pass\n",
            good: "def f(x: int):\n    pass\n",
        }),
    },
    Rule {
        id: "py/hint-bare-generic",
        name: "Type hints of generic types should specify their type parameters",
        description: "A bare list or dict says nothing about its contents.",
        message: "Add the type parameters.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6543")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(type (identifier) @match (#any-of? @match "List" "Dict" "Set" "FrozenSet" "Tuple" "list" "dict" "set" "frozenset" "tuple"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x: list):\n    pass\n",
            good: "def f(x: list[int]):\n    pass\n",
        }),
    },
    Rule {
        id: "py/hint-typing-alias",
        name: "Built-in generic types should be preferred over the typing module in type hints",
        description: "List[int] is list[int] since Python 3.9.",
        message: "Use the built-in type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6545")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(type (generic_type (identifier) @match (#any-of? @match "List" "Dict" "Set" "FrozenSet" "Tuple" "Type" "Deque" "DefaultDict")))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(x: List[int]):\n    pass\n",
            good: "def f(x: list[int]):\n    pass\n",
        }),
    },
    Rule {
        id: "py/nested-fstring",
        name: "f-strings should not be nested too deeply",
        description: "Three levels of quotes and braces are unreadable.",
        message: "Compute the inner value first.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6799")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(string (interpolation (string (interpolation (string (interpolation)))))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "s = f\"{f'{f\"{x}\"}'}\"\n",
            good: "inner = f'{x}'\ns = f'{inner}'\n",
        }),
    },
    Rule {
        id: "py/dataclass-annotation",
        name: "Dataclass attributes should use type annotations",
        description: "Without an annotation the attribute is a class variable, not a field.",
        message: "Annotate this attribute.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8514")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition definition: (class_definition)) @match"#,
            filter: Some(Find(dataclass_unannotated_attribute)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@dataclass\nclass A:\n    x = 1\n",
            good: "@dataclass\nclass A:\n    x: int = 1\n",
        }),
    },
    Rule {
        id: "py/dataclass-mutable-default",
        name: "Mutable values should not be used as default values in dataclass attributes",
        description: "dataclass rejects list, dict and set defaults at class creation.",
        message: "Use field(default_factory=...).",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8685")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition definition: (class_definition)) @match"#,
            filter: Some(Find(dataclass_mutable_default)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@dataclass\nclass A:\n    x: list = []\n",
            good: "@dataclass\nclass A:\n    x: list = field(default_factory=list)\n",
        }),
    },
    Rule {
        id: "py/pydantic-optional-default",
        name: "Optional Pydantic fields should have explicit default values",
        description: "In Pydantic v2 an Optional field without a default is still required.",
        message: "Give it a default, such as None.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8396")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(optional_field_without_default)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class M(BaseModel):\n    x: Optional[int]\n",
            good: "class M(BaseModel):\n    x: Optional[int] = None\n",
        }),
    },
    Rule {
        id: "py/django-model-str",
        name: "Django models should define a __str__ method",
        description: "Without it the admin and shell show 'Model object (1)'.",
        message: "Add __str__.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6554")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Keep(model_lacks_str)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class P(models.Model):\n    name = models.CharField()\n",
            good: "class P(models.Model):\n    name = models.CharField()\n    def __str__(self):\n        return self.name\n",
        }),
    },
    Rule {
        id: "py/decorator-order",
        name: "The @receiver (Django) and @route (Flask) decorators should be the outermost decorators",
        description: "Decorators applied above them never reach the registered function.",
        message: "Move it to the top.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6552")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Keep(registering_decorator_is_not_outermost)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@login_required\n@app.route('/')\ndef home():\n    pass\n",
            good: "@app.route('/')\n@login_required\ndef home():\n    pass\n",
        }),
    },
    Rule {
        id: "py/fastapi-path-parameter",
        name: "FastAPI path parameters should be included in route function signatures",
        description: "FastAPI fails to pass the value, and the endpoint returns 422.",
        message: "Add the parameter.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8411")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition) @match"#,
            filter: Some(Keep(path_parameter_missing_from_signature)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@app.get('/items/{item_id}')\ndef read():\n    pass\n",
            good: "@app.get('/items/{item_id}')\ndef read(item_id):\n    pass\n",
        }),
    },
    Rule {
        id: "py/fastapi-annotated",
        name: "FastAPI dependencies should use Annotated type hints",
        description: "Annotated keeps the default free for a real default and works with type checkers.",
        message: "Use Annotated[T, Depends(...)].",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8410")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(default_parameter value: (call function: (identifier) @f (#any-of? @f "Depends" "Query" "Path" "Body" "Header" "Cookie"))) @match
(typed_default_parameter value: (call function: (identifier) @f (#any-of? @f "Depends" "Query" "Path" "Body" "Header" "Cookie"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(db=Depends(get_db)):\n    pass\n",
            good: "def f(db: Annotated[Db, Depends(get_db)]):\n    pass\n",
        }),
    },
    Rule {
        id: "py/bs4-parser",
        name: "BeautifulSoup parser should be explicitly specified",
        description: "Without one the result depends on which parsers are installed.",
        message: "Pass 'html.parser' or another parser.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S8905")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "BeautifulSoup")) @match
(call function: (attribute attribute: (identifier) @f (#eq? @f "BeautifulSoup"))) @match"#,
            filter: Some(Keep(soup_has_no_parser)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "soup = BeautifulSoup(html)\n",
            good: "soup = BeautifulSoup(html, 'html.parser')\n",
        }),
    },
    Rule {
        id: "py/bs4-deprecated",
        name: "Deprecated Beautiful Soup methods should be replaced with their modern equivalents",
        description: "The camelCase names were renamed in Beautiful Soup 4.",
        message: "Use the snake_case method.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S8900")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @match (#any-of? @match "findAll" "findChild" "findChildren" "findNext" "findNextSibling" "findNextSiblings" "findParent" "findParents" "findPrevious" "findPreviousSibling" "findPreviousSiblings" "findAllNext" "findAllPrevious" "renderContents" "replaceWith")))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "links = soup.findAll('a')\n",
            good: "links = soup.find_all('a')\n",
        }),
    },
    Rule {
        id: "py/logging-formatted-message",
        name: "Logging statements should follow Python best practices",
        description: "Formatting the message up front costs time even when the level is off.",
        message: "Pass the arguments to the logging call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8554")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#any-of? @o "logger" "logging" "log" "LOGGER" "LOG" "_logger" "_log") (#any-of? @m "debug" "info" "warning" "warn" "error" "critical" "exception"))) @match"#,
            filter: Some(Keep(log_message_is_preformatted)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "logger.info(f'user {name}')\n",
            good: "logger.info('user %s', name)\n",
        }),
    },
    Rule {
        id: "py/test-fail-in-try",
        name: "Dedicated exception assertions should be used instead of try-except with fail()",
        description: "assertRaises states the intent and reports it better.",
        message: "Use assertRaises.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8714")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(try_statement) @match"#,
            filter: Some(Keep(try_ends_with_fail)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\n    self.fail('no error')\nexcept ValueError:\n    pass\n",
            good: "with self.assertRaises(ValueError):\n    f()\n",
        }),
    },
    Rule {
        id: "py/raises-multiple-statements",
        name: "Only one method invocation is expected when testing runtime exceptions",
        description: "Any other statement in the block could be the one that raises.",
        message: "Keep only the call under test.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5778")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(with_statement) @match"#,
            filter: Some(Keep(raises_block_has_many_statements)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "with pytest.raises(ValueError):\n    a = make()\n    a.run()\n",
            good: "a = make()\nwith pytest.raises(ValueError):\n    a.run()\n",
        }),
    },
    Rule {
        id: "py/assert-in-raises",
        name: "Assertions should not be made at the end of blocks expecting an exception",
        description: "Code after the raising call never runs.",
        message: "Move the assertion out of the block.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5915")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(with_statement) @match"#,
            filter: Some(Keep(raises_block_ends_with_assertion)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "with pytest.raises(ValueError):\n    run()\n    assert flag\n",
            good: "with pytest.raises(ValueError):\n    run()\nassert flag\n",
        }),
    },
    Rule {
        id: "py/raises-too-generic",
        name: "Tests should check which exception is thrown",
        description: "Exception matches every failure, including test bugs.",
        message: "Name the expected exception, or add match=.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5958")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "raises" "assertRaises"))) @match"#,
            filter: Some(Keep(raises_a_generic_exception)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "with pytest.raises(Exception):\n    run()\n",
            good: "with pytest.raises(ValueError):\n    run()\n",
        }),
    },
    Rule {
        id: "py/async-timeout-parameter",
        name: "Asynchronous functions should not accept timeout parameters",
        description: "Callers can cancel with the event loop's own timeouts.",
        message: "Use asyncio.timeout in the caller.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7483")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Find(async_function_takes_timeout)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def fetch(url, timeout=5):\n    pass\n",
            good: "async def fetch(url):\n    pass\n",
        }),
    },
    Rule {
        id: "py/async-without-await",
        name: "Async functions should use async features",
        description: "Without await, async for or async with there is nothing asynchronous.",
        message: "Make it a plain function, or await something.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7503")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(async_function_never_awaits)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    return 1\n",
            good: "async def f():\n    return await g()\n",
        }),
    },
    Rule {
        id: "py/checkpoint-sleep-zero",
        name: "Checkpoints should be used instead of sleep(0)",
        description: "trio and anyio have a dedicated checkpoint call.",
        message: "Use checkpoint().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7491")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#any-of? @o "trio" "anyio") (#eq? @a "sleep")) arguments: (argument_list (integer) @i (#eq? @i "0"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "await trio.sleep(0)\n",
            good: "await trio.lowlevel.checkpoint()\n",
        }),
    },
    Rule {
        id: "py/items-unused-half",
        name: "Using .items() to iterate over a dictionary should be avoided if possible",
        description: "If the key or the value is never used, iterate the keys or values.",
        message: "Iterate keys() or values().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7512")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(items_half_unused)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for k, v in d.items():\n    print(k)\n",
            good: "for k in d:\n    print(k)\n",
        }),
    },
    Rule {
        id: "py/dict-lookup-in-loop",
        name: "Iteration over a dictionary key value pairs should be done with the items() method call",
        description: "Looking each key up again costs a hash per iteration.",
        message: "Use .items().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7517")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement) @match"#,
            filter: Some(Find(key_looked_up_again)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for k in d:\n    print(d[k])\n",
            good: "for k, v in d.items():\n    print(v)\n",
        }),
    },
    Rule {
        id: "py/enumerate-index-lookup",
        name: "enumerate() values should be unpacked instead of using index lookups",
        description: "The loop already has the element.",
        message: "Use the element variable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8518")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement) @match"#,
            filter: Some(Find(enumerate_index_lookup)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for i, x in enumerate(items):\n    print(items[i])\n",
            good: "for i, x in enumerate(items):\n    print(x)\n",
        }),
    },
    Rule {
        id: "py/set-discard",
        name: "set.discard() should be used instead of checking membership before removal",
        description: "discard does not raise when the item is absent.",
        message: "Use discard().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8492")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(remove_after_membership)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x in s:\n    s.remove(x)\n",
            good: "s.discard(x)\n",
        }),
    },
    Rule {
        id: "py/set-update-loop",
        name: "set.update() should be used instead of a for-loop with add()",
        description: "One call replaces the loop.",
        message: "Use update().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8502")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(loop_only_adds)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for x in xs:\n    s.add(x)\n",
            good: "s.update(xs)\n",
        }),
    },
    Rule {
        id: "py/datetime-range",
        name: "Constructor attributes of date and time objects should be in the range of possible values",
        description: "Month 13 or day 32 raises ValueError.",
        message: "Fix the value.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6882")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call) @match"#,
            filter: Some(Keep(datetime_argument_out_of_range)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = datetime(2020, 13, 1)\n",
            good: "d = datetime(2020, 12, 1)\n",
        }),
    },
    Rule {
        id: "py/pandas-merge-args",
        name: "When using pandas.merge or pandas.join, the parameters on, how and validate should be provided",
        description: "The defaults hide intent and let duplicate keys through.",
        message: "Pass on, how and validate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6735")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "merge" "join"))) @match"#,
            filter: Some(Keep(merge_lacks_explicit_arguments)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "out = pd.merge(a, b)\n",
            good: "out = pd.merge(a, b, on='k', how='inner', validate='one_to_one')\n",
        }),
    },
    Rule {
        id: "py/read-csv-dtype",
        name: "dtype parameter should be provided when using pandas.read_csv or pandas.read_table",
        description: "Guessing types per chunk is slow and inconsistent.",
        message: "Pass dtype.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6740")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "read_csv" "read_table"))) @match"#,
            filter: Some(Keep(read_without_dtype)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "df = pd.read_csv('a.csv')\n",
            good: "df = pd.read_csv('a.csv', dtype={'id': 'int64'})\n",
        }),
    },
    Rule {
        id: "py/dataframe-values",
        name: "The DataFrame.to_numpy() method should be preferred to the DataFrame.values attribute",
        description: "values has no defined result type for mixed columns.",
        message: "Use to_numpy().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6741")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(attribute object: (identifier) attribute: (identifier) @a (#eq? @a "values")) @match"#,
            filter: Some(Keep(values_of_a_dataframe)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "a = df.values\n",
            good: "a = df.to_numpy()\n",
        }),
    },
    Rule {
        id: "py/ecb-mode",
        name: "Encryption algorithms should be used with secure mode and padding scheme",
        description: "ECB encrypts equal blocks to equal ciphertext and leaks structure.",
        message: "Use an authenticated mode such as GCM.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S5542")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(attribute attribute: (identifier) @match (#eq? @match "MODE_ECB"))
(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "modes") (#eq? @a "ECB"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "c = AES.new(key, AES.MODE_ECB)\n",
            good: "c = AES.new(key, AES.MODE_GCM, nonce=n)\n",
        }),
    },
    Rule {
        id: "py/static-iv",
        name: "Cipher Block Chaining IVs should be unpredictable",
        description: "A fixed IV makes equal plaintexts encrypt to equal ciphertexts.",
        message: "Generate the IV randomly for every message.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S3329")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call) @match"#,
            filter: Some(Keep(cbc_with_literal_iv)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "c = AES.new(key, AES.MODE_CBC, b'0123456789abcdef')\n",
            good: "c = AES.new(key, AES.MODE_CBC, os.urandom(16))\n",
        }),
    },
    Rule {
        id: "py/static-salt",
        name: "Password hashing functions should use an unpredictable salt",
        description: "A fixed salt lets one precomputed table crack every password.",
        message: "Generate a random salt per password.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S2053")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "pbkdf2_hmac" "scrypt" "hashpw"))) @match"#,
            filter: Some(Keep(salt_is_a_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "h = hashlib.pbkdf2_hmac('sha256', pw, b'salt', 100000)\n",
            good: "h = hashlib.pbkdf2_hmac('sha256', pw, os.urandom(16), 100000)\n",
        }),
    },
    Rule {
        id: "py/ldap-anonymous-bind",
        name: "LDAP connections should be authenticated",
        description: "An anonymous bind lets anyone read the directory.",
        message: "Bind with credentials.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S4433")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#eq? @m "simple_bind_s"))) @match"#,
            filter: Some(Keep(bind_without_credentials)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "conn.simple_bind_s()\n",
            good: "conn.simple_bind_s(dn, secret)\n",
        }),
    },
    Rule {
        id: "py/password-fast-hash",
        name: "Passwords should not be stored in plaintext or with a fast hashing algorithm",
        description: "MD5 and SHA-2 are cheap to brute-force.",
        message: "Use bcrypt, scrypt or argon2.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S5344")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "hashlib") (#any-of? @a "md5" "sha1" "sha224" "sha256" "sha384" "sha512"))) @match"#,
            filter: Some(Keep(hashes_a_password)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "h = hashlib.sha256(password.encode()).hexdigest()\n",
            good: "h = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n",
        }),
    },
];

// ---------------------------------------------------- filters

pub(super) fn body_of(node: Node) -> Option<Node> {
    node.child_by_field_name("body")
        .or_else(|| children_of_kind(node, "block").pop())
}

pub(super) fn name_of<'s>(node: Node, src: &'s [u8]) -> &'s [u8] {
    node.child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src))
}

pub(super) fn in_class(function: Node) -> bool {
    let mut owner = function.parent();
    if let Some(decorated) = owner.filter(|p| p.kind() == "decorated_definition") {
        owner = decorated.parent();
    }
    owner
        .filter(|b| b.kind() == "block")
        .and_then(|b| b.parent())
        .is_some_and(|c| c.kind() == "class_definition")
}

pub(super) fn is_decorated(function: Node) -> bool {
    function
        .parent()
        .is_some_and(|p| p.kind() == "decorated_definition")
}

fn decorator_texts<'s>(function: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    function
        .parent()
        .filter(|p| p.kind() == "decorated_definition")
        .map(|d| {
            children_of_kind(d, "decorator")
                .into_iter()
                .map(|n| text(n, src))
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn is_stub_body(body: Node) -> bool {
    statements(body).iter().all(|s| match s.kind() {
        "pass_statement" | "raise_statement" => true,
        "expression_statement" => s
            .named_child(0)
            .is_some_and(|e| matches!(e.kind(), "string" | "ellipsis")),
        _ => false,
    })
}

/// Plain parameters of a function: (node, name); the flag is true when the
/// list also has *args or **kwargs.
fn plain_parameters<'t, 's>(
    function: Node<'t>,
    src: &'s [u8],
) -> (Vec<(Node<'t>, &'s [u8])>, bool) {
    let mut out = Vec::new();
    let mut splat = false;
    let Some(params) = function.child_by_field_name("parameters") else {
        return (out, splat);
    };
    for p in statements(params) {
        let name = match p.kind() {
            "identifier" => Some(p),
            "typed_parameter" => p.named_child(0).filter(|n| n.kind() == "identifier"),
            "default_parameter" | "typed_default_parameter" => p.child_by_field_name("name"),
            "list_splat_pattern" | "dictionary_splat_pattern" => {
                splat = true;
                None
            }
            _ => None,
        };
        if let Some(n) = name {
            out.push((p, text(n, src)));
        }
    }
    (out, splat)
}

fn count_in_scope(root: Node, stops: &[&str], pred: impl Fn(Node) -> bool) -> usize {
    let mut count = 0;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return 0;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            count += 1;
        }
        if !stops.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return count;
            }
        }
    }
}

fn is_literal_scalar(kind: &str) -> bool {
    matches!(kind, "integer" | "float" | "true" | "false" | "none")
}

pub(super) fn call_statement_of(statement: Node) -> Option<Node> {
    (statement.kind() == "expression_statement")
        .then(|| statement.named_child(0))
        .flatten()
        .filter(|c| c.kind() == "call")
}

pub(super) fn assignment_of(statement: Node) -> Option<Node> {
    (statement.kind() == "expression_statement")
        .then(|| statement.named_child(0))
        .flatten()
        .filter(|c| c.kind() == "assignment")
}

// ---- bugs

fn except_only_reraises(clause: Node, _: &[u8]) -> bool {
    let Some(body) = body_of(clause) else {
        return false;
    };
    let items = statements(body);
    let bare = matches!(items.as_slice(), [r] if r.kind() == "raise_statement" && r.named_child_count() == 0);
    bare && {
        let mut next = clause.next_named_sibling();
        let mut later = false;
        while let Some(n) = next {
            later |= matches!(n.kind(), "except_clause" | "except_group_clause");
            next = n.next_named_sibling();
        }
        !later
    }
}

fn all_entry_not_string<'t>(assignment: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let list = assignment.child_by_field_name("right")?;
    statements(list)
        .into_iter()
        .find(|e| e.kind() != "string" && e.kind() != "concatenated_string")
}

fn iter_returns_container<'t>(function: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "return_statement"
            && n.named_child(0).is_some_and(|v| {
                matches!(
                    v.kind(),
                    "list"
                        | "dictionary"
                        | "set"
                        | "tuple"
                        | "list_comprehension"
                        | "dictionary_comprehension"
                        | "set_comprehension"
                        | "integer"
                        | "float"
                        | "string"
                )
            })
    })
}

pub(super) fn literal_family(kind: &str) -> Option<&'static str> {
    match kind {
        "string" => Some("string"),
        "integer" | "float" => Some("number"),
        "true" | "false" => Some("bool"),
        "none" => Some("none"),
        "list" | "list_comprehension" => Some("list"),
        "dictionary" | "dictionary_comprehension" => Some("dict"),
        "set" | "set_comprehension" => Some("set"),
        "tuple" => Some("tuple"),
        _ => None,
    }
}

fn uses_is(cmp: Node) -> bool {
    has_token(cmp, "is") || has_token(cmp, "is not")
}

fn identity_with_value_literal(cmp: Node, _: &[u8]) -> bool {
    uses_is(cmp)
        && statements(cmp)
            .iter()
            .any(|o| matches!(o.kind(), "string" | "integer" | "float"))
}

fn identity_with_new_object(cmp: Node, _: &[u8]) -> bool {
    uses_is(cmp)
        && statements(cmp).iter().any(|o| {
            matches!(
                o.kind(),
                "list"
                    | "dictionary"
                    | "set"
                    | "list_comprehension"
                    | "dictionary_comprehension"
                    | "set_comprehension"
                    | "lambda"
            )
        })
}

fn identity_between_different_literals(cmp: Node, _: &[u8]) -> bool {
    if !uses_is(cmp) {
        return false;
    }
    let families: Vec<&str> = statements(cmp)
        .iter()
        .filter_map(|o| literal_family(o.kind()))
        .collect();
    families.len() >= 2 && families.windows(2).any(|w| w[0] != w[1])
}

pub(super) fn is_generator(function: Node) -> bool {
    body_of(function)
        .is_some_and(|b| find_in_scope(b, SCOPE_STOPS, |n| n.kind() == "yield").is_some())
}

fn bare_return_beside_valued_return<'t>(function: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = body_of(function)?;
    if is_generator(function) {
        return None;
    }
    let returns = |valued: bool| {
        find_in_scope(body, SCOPE_STOPS, |n| {
            n.kind() == "return_statement" && (n.named_child_count() > 0) == valued
        })
    };
    returns(true)?;
    returns(false)
}

fn valued_return_in_generator<'t>(function: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = body_of(function)?;
    if !has_token(function, "async") || !is_generator(function) {
        return None;
    }
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "return_statement" && n.named_child_count() > 0
    })
}

fn key_assigned_twice<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|w| {
        let (first, second) = (assignment_of(w[0])?, assignment_of(w[1])?);
        let (l1, l2) = (
            first.child_by_field_name("left")?,
            second.child_by_field_name("left")?,
        );
        let r2 = second.child_by_field_name("right")?;
        let key = text(l1, src);
        (l1.kind() == "subscript"
            && l2.kind() == "subscript"
            && first.child_by_field_name("type").is_none()
            && key == text(l2, src)
            && !text(r2, src).windows(key.len()).any(|win| win == key))
        .then_some(w[0])
    })
}

fn assigned_then_overwritten<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|w| {
        let (first, second) = (assignment_of(w[0])?, assignment_of(w[1])?);
        let (l1, l2) = (
            first.child_by_field_name("left")?,
            second.child_by_field_name("left")?,
        );
        let (r1, r2) = (
            first.child_by_field_name("right")?,
            second.child_by_field_name("right")?,
        );
        let name = text(l1, src);
        let defensive_initial = matches!(
            r1.kind(),
            "none"
                | "true"
                | "false"
                | "integer"
                | "float"
                | "string"
                | "list"
                | "dictionary"
                | "set"
                | "tuple"
        );
        (l1.kind() == "identifier"
            && l2.kind() == "identifier"
            && name == text(l2, src)
            && first.child_by_field_name("type").is_none()
            && !defensive_initial
            && count_word(text(r2, src), name) == 0)
            .then_some(w[0])
    })
}

fn bare_raise_in_finally<'t>(finally: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    // Inside an except block the bare raise re-raises the handled exception.
    let mut p = finally.parent();
    while let Some(n) = p {
        if matches!(n.kind(), "except_clause" | "except_group_clause") {
            return None;
        }
        if matches!(
            n.kind(),
            "function_definition" | "class_definition" | "module"
        ) {
            break;
        }
        p = n.parent();
    }
    find_in_scope(
        finally,
        &[
            "except_clause",
            "except_group_clause",
            "function_definition",
            "class_definition",
            "lambda",
        ],
        |n| n.kind() == "raise_statement" && n.named_child_count() == 0,
    )
}

fn exit_raises_its_argument<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (params, _) = plain_parameters(function, src);
    let names: Vec<&[u8]> = params.iter().skip(1).take(2).map(|(_, n)| *n).collect();
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "raise_statement"
            && n.named_child(0)
                .is_some_and(|e| e.kind() == "identifier" && names.contains(&text(e, src)))
    })
}

fn exception_without_base(class: Node, src: &[u8]) -> bool {
    let name = name_of(class, src);
    if !(name.ends_with(b"Exception") || name.ends_with(b"Error")) {
        return false;
    }
    match class.child_by_field_name("superclasses") {
        None => true,
        Some(s) => text(s, src) == b"(object)",
    }
}

fn operator_raises_not_implemented<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const OPERATORS: &[&[u8]] = &[
        b"__eq__",
        b"__ne__",
        b"__lt__",
        b"__le__",
        b"__gt__",
        b"__ge__",
        b"__add__",
        b"__sub__",
        b"__mul__",
        b"__truediv__",
        b"__floordiv__",
        b"__mod__",
        b"__pow__",
        b"__and__",
        b"__or__",
        b"__xor__",
        b"__lshift__",
        b"__rshift__",
        b"__matmul__",
    ];
    if !OPERATORS.contains(&name_of(function, src)) {
        return None;
    }
    find_in_scope(body_of(function)?, SCOPE_STOPS, |n| {
        n.kind() == "raise_statement" && text(n, src).starts_with(b"raise NotImplementedError")
    })
}

fn expected_special_arity(name: &[u8]) -> Option<usize> {
    Some(match name {
        b"__len__" | b"__bool__" | b"__str__" | b"__repr__" | b"__hash__" | b"__iter__"
        | b"__next__" | b"__enter__" | b"__aenter__" | b"__aiter__" | b"__anext__" | b"__neg__"
        | b"__pos__" | b"__invert__" | b"__abs__" | b"__int__" | b"__float__" | b"__index__"
        | b"__bytes__" | b"__reversed__" => 1,
        b"__getitem__" | b"__delitem__" | b"__contains__" | b"__eq__" | b"__ne__" | b"__lt__"
        | b"__le__" | b"__gt__" | b"__ge__" | b"__add__" | b"__sub__" | b"__mul__"
        | b"__truediv__" | b"__floordiv__" | b"__mod__" | b"__and__" | b"__or__" | b"__xor__"
        | b"__lshift__" | b"__rshift__" | b"__getattr__" | b"__delattr__" | b"__format__"
        | b"__delete__" => 2,
        b"__setitem__" | b"__setattr__" | b"__get__" | b"__set__" => 3,
        b"__exit__" | b"__aexit__" => 4,
        _ => return None,
    })
}

/// (required, total) parameter counts; None when *args, **kwargs or a
/// separator makes the count meaningless.
fn arity_range(function: Node) -> Option<(usize, usize)> {
    let params = function.child_by_field_name("parameters")?;
    let items = statements(params);
    if items.iter().any(|p| {
        matches!(
            p.kind(),
            "list_splat_pattern"
                | "dictionary_splat_pattern"
                | "keyword_separator"
                | "positional_separator"
        )
    }) {
        return None;
    }
    let required = items
        .iter()
        .filter(|p| !matches!(p.kind(), "default_parameter" | "typed_default_parameter"))
        .count();
    Some((required, items.len()))
}

fn special_method_has_wrong_arity(function: Node, src: &[u8]) -> bool {
    let Some(expected) = expected_special_arity(name_of(function, src)) else {
        return false;
    };
    if !in_class(function)
        || decorator_texts(function, src)
            .iter()
            .any(|d| contains_ignoring_case(d, b"staticmethod"))
    {
        return false;
    }
    arity_range(function).is_some_and(|(required, total)| required > expected || total < expected)
}

fn property_has_wrong_arity(decorated: Node, src: &[u8]) -> bool {
    let Some(function) = decorated
        .child_by_field_name("definition")
        .filter(|d| d.kind() == "function_definition")
    else {
        return false;
    };
    let Some(expected) = children_of_kind(decorated, "decorator")
        .iter()
        .find_map(|d| {
            let t = text(*d, src);
            if t == b"@property" {
                Some(1)
            } else if t.ends_with(b".setter") {
                Some(2)
            } else if t.ends_with(b".deleter") || t.ends_with(b".getter") {
                Some(1)
            } else {
                None
            }
        })
    else {
        return false;
    };
    arity_range(function).is_some_and(|(required, total)| required > expected || total < expected)
}

fn membership_in_a_scalar(cmp: Node, src: &[u8]) -> bool {
    let Some((_, op, right)) = two_operands(cmp, src) else {
        return false;
    };
    matches!(op, b"in" | b"not in") && is_literal_scalar(right.kind())
}

fn operands_of_different_kinds(binary: Node, src: &[u8]) -> bool {
    let (Some(left), Some(op), Some(right)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("operator"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    let op = text(op, src);
    let (lk, rk) = (left.kind(), right.kind());
    let number = |k: &str| matches!(k, "integer" | "float");
    let plain_string = |n: Node| n.kind() == "string" && !has_interpolation(n);
    let arithmetic = matches!(op, b"+" | b"-" | b"*" | b"/" | b"//" | b"**");
    if arithmetic && (lk == "none" || rk == "none") {
        return true;
    }
    match op {
        b"+" => {
            (plain_string(left) && number(rk))
                || (number(lk) && plain_string(right))
                || (lk == "list" && number(rk))
                || (number(lk) && rk == "list")
        }
        b"-" | b"/" => plain_string(left) || plain_string(right),
        b"*" => plain_string(left) && plain_string(right),
        _ => false,
    }
}

fn percent_specifiers(format: &[u8]) -> Option<usize> {
    let mut count = 0;
    let mut i = 0;
    while i < format.len() {
        if format[i] == b'%' {
            match format.get(i + 1) {
                Some(b'%') => i += 1,
                Some(b'(') | Some(b'*') | None => return None,
                Some(_) => count += 1,
            }
        }
        i += 1;
    }
    Some(count)
}

fn brace_auto_fields(format: &[u8]) -> Option<usize> {
    let mut count = 0;
    let mut i = 0;
    while i < format.len() {
        match format[i] {
            b'{' if format.get(i + 1) == Some(&b'{') => i += 1,
            b'{' => {
                let end = format[i..].iter().position(|&b| b == b'}')? + i;
                let name = format[i + 1..end]
                    .split(|&b| b == b':' || b == b'!')
                    .next()
                    .unwrap_or(b"");
                if name.is_empty() {
                    count += 1;
                } else {
                    return None;
                }
                i = end;
            }
            _ => {}
        }
        i += 1;
    }
    Some(count)
}

fn format_arguments_do_not_match(node: Node, src: &[u8]) -> bool {
    if node.kind() == "binary_operator" {
        let (Some(left), Some(op), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("operator"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        if text(op, src) != b"%" || left.kind() != "string" || right.kind() != "tuple" {
            return false;
        }
        let items = statements(right);
        if items.iter().any(|i| i.kind() == "list_splat") {
            return false;
        }
        return string_value(left, src)
            .and_then(percent_specifiers)
            .is_some_and(|n| n != items.len());
    }
    // "{} {}".format(a)
    let Some(object) = node
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
    else {
        return false;
    };
    let args = call_arguments(node);
    if args.iter().any(|a| {
        matches!(
            a.kind(),
            "keyword_argument" | "list_splat" | "dictionary_splat"
        )
    }) {
        return false;
    }
    string_value(object, src)
        .and_then(brace_auto_fields)
        .is_some_and(|n| n > args.len())
}

fn fstring_has_no_field(string: Node, src: &[u8]) -> bool {
    let t = text(string, src);
    let prefix_end = t.iter().position(|&b| b == b'"' || b == b'\'').unwrap_or(0);
    t[..prefix_end]
        .iter()
        .any(|b| b.eq_ignore_ascii_case(&b'f'))
        && !has_interpolation(string)
        && !t.windows(2).any(|w| w == b"{{" || w == b"}}")
}

fn recurses_without_a_branch<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const BRANCHING: &[&str] = &[
        "if_statement",
        "for_statement",
        "while_statement",
        "try_statement",
        "match_statement",
        "conditional_expression",
        "boolean_operator",
        "with_statement",
        "assert_statement",
        "raise_statement",
        "list_comprehension",
        "generator_expression",
        "lambda",
        "yield",
        "await",
        "global_statement",
    ];
    let name = name_of(function, src);
    let body = body_of(function)?;
    if find_in_scope(body, &["function_definition", "class_definition"], |n| {
        BRANCHING.contains(&n.kind())
    })
    .is_some()
    {
        return None;
    }
    let method = in_class(function);
    let top_level = function.parent().is_some_and(|p| p.kind() == "module");
    if !(method || top_level)
        || plain_parameters(function, src)
            .0
            .iter()
            .any(|(_, p)| *p == name)
    {
        return None;
    }
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "call"
            && n.child_by_field_name("function").is_some_and(|f| {
                if method {
                    f.kind() == "attribute"
                        && f.child_by_field_name("object")
                            .is_some_and(|o| text(o, src) == b"self")
                        && f.child_by_field_name("attribute")
                            .is_some_and(|a| text(a, src) == name)
                } else {
                    f.kind() == "identifier" && text(f, src) == name
                }
            })
    })
}

fn parameter_overwritten_first<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = body_of(function)?;
    let (params, _) = plain_parameters(function, src);
    let first = statements(body).into_iter().find(|s| {
        !(s.kind() == "expression_statement"
            && s.named_child(0).is_some_and(|e| e.kind() == "string"))
    })?;
    let assignment = assignment_of(first)?;
    let left = assignment.child_by_field_name("left")?;
    let right = assignment.child_by_field_name("right")?;
    let name = text(left, src);
    (left.kind() == "identifier"
        && params.iter().any(|(_, p)| *p == name)
        && count_word(text(right, src), name) == 0)
        .then_some(first)
}

pub(super) fn is_private_name(name: &[u8]) -> bool {
    name.starts_with(b"__") && !name.ends_with(b"__") && name.len() > 2
}

fn unused_private_method<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = body_of(class)?;
    let whole = text(class, src);
    statements(body).into_iter().find(|s| {
        let function = if s.kind() == "decorated_definition" {
            s.child_by_field_name("definition")
        } else {
            Some(*s)
        };
        function.is_some_and(|f| {
            f.kind() == "function_definition"
                && is_private_name(name_of(f, src))
                && count_word(whole, name_of(f, src)) == 1
        })
    })
}

fn unread_private_attribute<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let whole = text(class, src);
    find_in_scope(class, &["class_definition"], |n| {
        n.kind() == "attribute"
            && n.child_by_field_name("object")
                .is_some_and(|o| text(o, src) == b"self")
            && n.child_by_field_name("attribute").is_some_and(|a| {
                is_private_name(text(a, src)) && count_word(whole, text(a, src)) == 1
            })
    })
}

fn function_repeats_a_body<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<(&[u8], &[u8])> = Vec::new();
    for s in statements(container) {
        if s.kind() != "function_definition" {
            continue;
        }
        let Some(body) = body_of(s) else { continue };
        if statements(body).len() < 2 {
            continue;
        }
        let (name, b) = (name_of(s, src), text(body, src));
        if seen.iter().any(|(n, other)| *other == b && *n != name) {
            return Some(s);
        }
        seen.push((name, b));
    }
    None
}

fn branch_block(branch: Node) -> Option<Node> {
    branch
        .child_by_field_name("consequence")
        .or_else(|| branch.child_by_field_name("body"))
        .or_else(|| children_of_kind(branch, "block").pop())
}

fn branch_repeats_a_body<'t>(if_statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut blocks = Vec::new();
    if let Some(b) = branch_block(if_statement) {
        blocks.push(b);
    }
    let mut has_else = false;
    let mut cursor = if_statement.walk();
    for alt in if_statement.children_by_field_name("alternative", &mut cursor) {
        has_else |= alt.kind() == "else_clause";
        if let Some(b) = branch_block(alt) {
            blocks.push(b);
        }
    }
    let mut distinct: Vec<&[u8]> = Vec::new();
    let mut repeated = None;
    for b in &blocks {
        let t = text(*b, src);
        if statements(*b).len() < 2 {
            continue;
        }
        if distinct.contains(&t) {
            repeated.get_or_insert(*b);
        } else {
            distinct.push(t);
        }
    }
    // Every branch the same is `py/identical-branches`.
    if has_else && blocks.iter().all(|b| text(*b, src) == text(blocks[0], src)) {
        return None;
    }
    repeated
}

fn closes_over_loop_variable(closure: Node, src: &[u8]) -> bool {
    let Some(body) = closure.child_by_field_name("body") else {
        return false;
    };
    let params = closure
        .child_by_field_name("parameters")
        .map_or(&b""[..], |p| text(p, src));
    let mut p = closure.parent();
    let mut hops = 0;
    while let Some(n) = p {
        hops += 1;
        if hops > 12
            || matches!(
                n.kind(),
                "function_definition" | "class_definition" | "lambda"
            )
        {
            return false;
        }
        if n.kind() == "for_statement" {
            let Some(left) = n.child_by_field_name("left") else {
                return false;
            };
            let in_body = n
                .child_by_field_name("body")
                .is_some_and(|b| b.byte_range().contains(&closure.start_byte()));
            if in_body && left.kind() == "identifier" {
                let name = text(left, src);
                return count_word(params, name) == 0 && count_word(text(body, src), name) > 0;
            }
        }
        p = n.parent();
    }
    false
}

// ---- naming and structure

fn is_snake_case(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

pub(super) fn is_dunder(name: &[u8]) -> bool {
    name.starts_with(b"__") && name.ends_with(b"__")
}

fn class_name_is_not_pascal_case(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let t = n.trim_ascii_start();
    let t = t.strip_prefix(b"_").unwrap_or(t);
    let t = t.strip_prefix(b"_").unwrap_or(t);
    let all_caps = t
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_');
    !t.is_empty()
        && !is_dunder(n)
        && !all_caps
        && !(t[0].is_ascii_uppercase() && !t.contains(&b'_'))
}

const FRAMEWORK_METHODS: &[&[u8]] = &[
    b"setUp",
    b"tearDown",
    b"setUpClass",
    b"tearDownClass",
    b"setUpModule",
    b"tearDownModule",
    b"asyncSetUp",
    b"asyncTearDown",
    b"countTestCases",
    b"defaultTestResult",
];

fn method_name_is_not_snake_case(name: Node, src: &[u8]) -> bool {
    let Some(function) = name.parent() else {
        return false;
    };
    let n = text(name, src);
    in_class(function)
        && !is_dunder(n)
        && !FRAMEWORK_METHODS.contains(&n)
        && !is_snake_case(n.strip_prefix(b"_").unwrap_or(n))
}

fn function_name_is_not_snake_case(name: Node, src: &[u8]) -> bool {
    let Some(function) = name.parent() else {
        return false;
    };
    let n = text(name, src);
    !in_class(function) && !is_dunder(n) && !is_snake_case(n.strip_prefix(b"_").unwrap_or(n))
}

fn name_is_not_snake_case(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let t = n.trim_ascii_start();
    let t = t.strip_prefix(b"_").unwrap_or(t);
    !is_dunder(n) && !t.is_empty() && !is_snake_case(t)
}

fn local_name_is_not_snake_case(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let t = n.strip_prefix(b"_").unwrap_or(n);
    if t.is_empty() || is_snake_case(t) {
        return false;
    }
    match name.parent().map(|p| p.kind()) {
        // module and class level names are constants, not locals
        Some("assignment") => nearest_function(name, 20).is_some(),
        Some(_) => true,
        None => false,
    }
}

fn first_parameter(function: Node) -> Option<Node> {
    statements(function.child_by_field_name("parameters")?)
        .into_iter()
        .next()
}

pub(super) fn first_parameter_name<'s>(function: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let first = first_parameter(function)?;
    let name = match first.kind() {
        "identifier" => Some(first),
        "typed_parameter" => first.named_child(0).filter(|n| n.kind() == "identifier"),
        "default_parameter" | "typed_default_parameter" => first.child_by_field_name("name"),
        _ => None,
    }?;
    Some(text(name, src))
}

fn instance_method_first_parameter<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !in_class(function) || is_decorated(function) {
        return None;
    }
    let name = first_parameter_name(function, src)?;
    let own = name_of(function, src);
    let ok = name == b"self"
        || name.starts_with(b"_")
        || own == b"__new__"
        || own == b"__init_subclass__"
        || own == b"__class_getitem__"
        || matches!(name, b"cls" | b"mcs" | b"mcls" | b"metacls" | b"klass");
    (!ok).then(|| first_parameter(function)).flatten()
}

fn class_method_first_parameter<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = decorated
        .child_by_field_name("definition")
        .filter(|d| d.kind() == "function_definition")?;
    if !children_of_kind(decorated, "decorator")
        .iter()
        .any(|d| text(*d, src) == b"@classmethod")
    {
        return None;
    }
    let name = first_parameter_name(function, src)?;
    let ok =
        name.starts_with(b"_") || matches!(name, b"cls" | b"mcs" | b"mcls" | b"metacls" | b"klass");
    (!ok).then(|| first_parameter(function)).flatten()
}

pub(super) fn imported_names<'s>(import: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names = Vec::new();
    let mut cursor = import.walk();
    for c in import.children_by_field_name("name", &mut cursor) {
        let item = match c.kind() {
            "aliased_import" => c.child_by_field_name("alias").map(|a| text(a, src)),
            "dotted_name" => text(c, src).split(|&b| b == b'.').next(),
            "identifier" => Some(text(c, src)),
            _ => None,
        };
        if let Some(n) = item {
            names.push(n);
        }
    }
    names
}

fn import_is_unused(import: Node, src: &[u8]) -> bool {
    if import.kind() == "import_from_statement" {
        let module = import
            .child_by_field_name("module_name")
            .map_or(&b""[..], |m| text(m, src));
        if module == b"__future__" {
            return false;
        }
    }
    // __all__ re-exports count as use
    if count_word(src, b"__all__") > 0 {
        return false;
    }
    let own = text(import, src);
    let line_end = src[import.end_byte()..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(src.len(), |i| import.end_byte() + i);
    if contains_ignoring_case(&src[import.end_byte()..line_end], b"noqa") {
        return false;
    }
    imported_names(import, src).iter().any(|n| {
        let mut doubled = n.to_vec();
        doubled.extend_from_slice(b" as ");
        doubled.extend_from_slice(n);
        // `import x as x` marks an intentional re-export
        count_word(src, n) == count_word(own, n)
            && !own.windows(doubled.len()).any(|w| w == doubled.as_slice())
    })
}

fn local_is_never_read(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    if n.starts_with(b"_") || name.parent().is_none_or(|p| p.kind() != "assignment") {
        return false;
    }
    let Some(function) = nearest_function(name, 20) else {
        return false;
    };
    let whole = text(function, src);
    count_word(whole, n) == 1
        && !contains_ignoring_case(whole, b"locals()")
        && !contains_ignoring_case(whole, b"eval(")
        && !contains_ignoring_case(whole, b"exec(")
}

fn parameter_is_unused<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Nested functions are often callbacks with a fixed signature.
    if !function.parent().is_some_and(|p| p.kind() == "module") {
        return None;
    }
    let body = body_of(function)?;
    if is_stub_body(body) {
        return None;
    }
    let (params, _) = plain_parameters(function, src);
    let whole = text(body, src);
    if contains_ignoring_case(whole, b"locals()") {
        return None;
    }
    params
        .into_iter()
        .find(|(_, n)| !n.starts_with(b"_") && count_word(whole, n) == 0)
        .map(|(p, _)| p)
}

fn has_many_returns(function: Node, _: &[u8]) -> bool {
    count_in_scope(function, SCOPE_STOPS, |n| n.kind() == "return_statement") > 3
}

fn is_nested_too_deeply(statement: Node, _: &[u8]) -> bool {
    const CONTROL: &[&str] = &[
        "if_statement",
        "for_statement",
        "while_statement",
        "try_statement",
        "with_statement",
        "match_statement",
    ];
    let mut depth = 0;
    let mut p = statement.parent();
    while let Some(n) = p {
        if matches!(
            n.kind(),
            "function_definition" | "class_definition" | "lambda"
        ) {
            break;
        }
        if CONTROL.contains(&n.kind()) {
            depth += 1;
        }
        p = n.parent();
    }
    depth == 4
}

fn is_too_complex(function: Node, _: &[u8]) -> bool {
    let branches = count_in_scope(function, SCOPE_STOPS, |n| {
        matches!(
            n.kind(),
            "if_statement"
                | "elif_clause"
                | "for_statement"
                | "while_statement"
                | "except_clause"
                | "conditional_expression"
                | "for_in_clause"
                | "if_clause"
                | "case_clause"
                | "boolean_operator"
        )
    });
    branches + 1 > 10
}

fn string_is_an_ip_address(string: Node, src: &[u8]) -> bool {
    let Some(v) = string_value(string, src) else {
        return false;
    };
    let parts: Vec<&[u8]> = v.split(|&b| b == b'.').collect();
    if parts.len() != 4
        || parts
            .iter()
            .any(|p| p.is_empty() || p.len() > 3 || !p.iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let octets: Vec<u32> = parts
        .iter()
        .map(|p| {
            std::str::from_utf8(p)
                .unwrap_or("999")
                .parse()
                .unwrap_or(999)
        })
        .collect();
    octets.iter().all(|&o| o <= 255)
        && octets[0] != 127
        && octets != [0, 0, 0, 0]
        && octets != [255, 255, 255, 255]
}

fn is_noqa(comment: Node, src: &[u8]) -> bool {
    contains_ignoring_case(text(comment, src), b"noqa")
}

fn comment_trails_code(comment: Node, src: &[u8]) -> bool {
    let start = comment.start_byte();
    let line_start = src[..start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    if src[line_start..start].iter().all(u8::is_ascii_whitespace) {
        return false;
    }
    let t = text(comment, src);
    let body = t.strip_prefix(b"#").unwrap_or(t).trim_ascii_start();
    ![
        &b"noqa"[..],
        b"type:",
        b"pylint:",
        b"pragma",
        b"fmt:",
        b"isort:",
        b"nosec",
        b"mypy:",
        b"pyright:",
        b"NOSONAR",
        b"flake8",
        b"ruff:",
        b"yapf:",
    ]
    .iter()
    .any(|p| body.starts_with(p))
}

fn semicolon_joins_statements(semicolon: Node, _: &[u8]) -> bool {
    semicolon
        .next_sibling()
        .is_some_and(|n| n.is_named() && n.start_position().row == semicolon.start_position().row)
}

fn looks_like_increment(unary: Node, src: &[u8]) -> bool {
    let t = text(unary, src);
    t.starts_with(b"++") || t.starts_with(b"--")
}

fn assignment_is_not_annotated(assignment: Node, _: &[u8]) -> bool {
    assignment.child_by_field_name("type").is_none()
}

// ---- libraries

fn dataclass_body<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let is_dataclass = children_of_kind(decorated, "decorator")
        .iter()
        .any(|d| contains_ignoring_case(text(*d, src), b"dataclass"));
    if !is_dataclass {
        return None;
    }
    body_of(decorated.child_by_field_name("definition")?)
}

fn dataclass_unannotated_attribute<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = dataclass_body(decorated, src)?;
    statements(body).into_iter().find(|s| {
        assignment_of(*s).is_some_and(|a| {
            a.child_by_field_name("type").is_none()
                && a.child_by_field_name("left")
                    .is_some_and(|l| l.kind() == "identifier" && !is_dunder(text(l, src)))
                && a.child_by_field_name("right")
                    .is_some_and(|r| r.kind() != "lambda")
        })
    })
}

fn dataclass_mutable_default<'t>(decorated: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = dataclass_body(decorated, src)?;
    statements(body).into_iter().find(|s| {
        assignment_of(*s).is_some_and(|a| {
            a.child_by_field_name("type").is_some()
                && a.child_by_field_name("right").is_some_and(|r| {
                    matches!(
                        r.kind(),
                        "list" | "dictionary" | "set" | "list_comprehension"
                    ) || (r.kind() == "call"
                        && r.child_by_field_name("function")
                            .is_some_and(|f| matches!(text(f, src), b"list" | b"dict" | b"set")))
                })
        })
    })
}

fn optional_field_without_default<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let supers = class.child_by_field_name("superclasses")?;
    let sup = text(supers, src);
    if !(contains_ignoring_case(sup, b"BaseModel") || contains_ignoring_case(sup, b"BaseSettings"))
    {
        return None;
    }
    statements(body_of(class)?).into_iter().find(|s| {
        assignment_of(*s).is_some_and(|a| {
            a.child_by_field_name("right").is_none()
                && a.child_by_field_name("type").is_some_and(|t| {
                    let t = text(t, src);
                    t.starts_with(b"Optional[")
                        || t.starts_with(b"typing.Optional[")
                        || t.ends_with(b"| None")
                        || t.starts_with(b"None |")
                })
        })
    })
}

fn model_lacks_str(class: Node, src: &[u8]) -> bool {
    let Some(supers) = class.child_by_field_name("superclasses") else {
        return false;
    };
    if text(supers, src) != b"(models.Model)" {
        return false;
    }
    let Some(body) = body_of(class) else {
        return false;
    };
    let whole = text(body, src);
    !whole.windows(7).any(|w| w == b"__str__") && !contains_ignoring_case(whole, b"abstract = True")
}

fn registering_decorator_is_not_outermost(decorated: Node, src: &[u8]) -> bool {
    children_of_kind(decorated, "decorator")
        .iter()
        .skip(1)
        .any(|d| {
            let t = text(*d, src);
            t.starts_with(b"@receiver(") || t.windows(7).any(|w| w == b".route(")
        })
}

fn path_parameter_missing_from_signature(decorated: Node, src: &[u8]) -> bool {
    let Some(function) = decorated
        .child_by_field_name("definition")
        .filter(|d| d.kind() == "function_definition")
    else {
        return false;
    };
    let (params, splat) = plain_parameters(function, src);
    if splat {
        return false;
    }
    children_of_kind(decorated, "decorator").iter().any(|d| {
        let Some(call) = d.named_child(0).filter(|c| c.kind() == "call") else {
            return false;
        };
        let verb = callee_name(call, src);
        if !matches!(verb, b"get" | b"post" | b"put" | b"delete" | b"patch")
            || call
                .child_by_field_name("function")
                .is_none_or(|f| f.kind() != "attribute")
        {
            return false;
        }
        let Some(path) = call_arguments(call)
            .into_iter()
            .next()
            .and_then(|a| string_value(a, src))
        else {
            return false;
        };
        let mut rest = path;
        while let Some(open) = rest.iter().position(|&b| b == b'{') {
            let Some(close) = rest[open..].iter().position(|&b| b == b'}') else {
                break;
            };
            let name = rest[open + 1..open + close]
                .split(|&b| b == b':')
                .next()
                .unwrap_or(b"");
            if !name.is_empty() && !params.iter().any(|(_, p)| *p == name) {
                return true;
            }
            rest = &rest[open + close + 1..];
        }
        false
    })
}

fn soup_has_no_parser(call: Node, _: &[u8]) -> bool {
    let args = call_arguments(call);
    args.len() == 1
        && !matches!(
            args[0].kind(),
            "keyword_argument" | "list_splat" | "dictionary_splat"
        )
}

fn log_message_is_preformatted(call: Node, src: &[u8]) -> bool {
    let Some(first) = call_arguments(call).into_iter().next() else {
        return false;
    };
    match first.kind() {
        "string" => has_interpolation(first),
        "binary_operator" => first
            .child_by_field_name("operator")
            .is_some_and(|o| text(o, src) == b"%"),
        "call" => first
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "attribute" && callee_name(first, src) == b"format"),
        _ => false,
    }
}

fn try_ends_with_fail(try_statement: Node, src: &[u8]) -> bool {
    let Some(body) = body_of(try_statement) else {
        return false;
    };
    let has_handler = !children_of_kind(try_statement, "except_clause").is_empty();
    has_handler
        && statements(body)
            .last()
            .and_then(|s| call_statement_of(*s))
            .is_some_and(|c| callee_name(c, src) == b"fail")
}

fn is_raises_block(with: Node, src: &[u8]) -> bool {
    let end = body_of(with).map_or(with.end_byte(), |b| b.start_byte());
    let head = &src[with.start_byte()..end];
    head.windows(8).any(|w| w == b".raises(")
        || head.windows(13).any(|w| w == b"assertRaises(")
        || head.windows(18).any(|w| w == b"assertRaisesRegex(")
}

fn raises_block_has_many_statements(with: Node, src: &[u8]) -> bool {
    is_raises_block(with, src) && body_of(with).is_some_and(|b| statements(b).len() > 1)
}

fn raises_block_ends_with_assertion(with: Node, src: &[u8]) -> bool {
    if !is_raises_block(with, src) {
        return false;
    }
    let Some(items) = body_of(with).map(statements) else {
        return false;
    };
    items.len() > 1
        && items.last().is_some_and(|s| {
            s.kind() == "assert_statement"
                || call_statement_of(*s).is_some_and(|c| callee_name(c, src).starts_with(b"assert"))
        })
}

fn raises_a_generic_exception(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let generic = args.first().is_some_and(|a| {
        a.kind() == "identifier" && matches!(text(*a, src), b"Exception" | b"BaseException")
    });
    generic && keyword_value(call, "match", src).is_none() && args.len() == 1
}

fn async_function_takes_timeout<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_token(function, "async") {
        return None;
    }
    plain_parameters(function, src)
        .0
        .into_iter()
        .find(|(_, n)| *n == b"timeout" || n.ends_with(b"_timeout") || n.starts_with(b"timeout_"))
        .map(|(p, _)| p)
}

fn async_function_never_awaits(function: Node, _: &[u8]) -> bool {
    if !has_token(function, "async") || in_class(function) || is_decorated(function) {
        return false;
    }
    let Some(body) = body_of(function) else {
        return false;
    };
    if is_stub_body(body) {
        return false;
    }
    find_in_scope(body, SCOPE_STOPS, |n| {
        matches!(n.kind(), "await" | "yield")
            || (matches!(
                n.kind(),
                "for_statement" | "with_statement" | "for_in_clause"
            ) && has_token(n, "async"))
    })
    .is_none()
}

pub(super) fn loop_pair<'s>(for_statement: Node, src: &'s [u8]) -> Option<(&'s [u8], &'s [u8])> {
    let left = for_statement.child_by_field_name("left")?;
    let items = statements(left);
    let [a, b] = items.as_slice() else {
        return None;
    };
    (a.kind() == "identifier" && b.kind() == "identifier").then(|| (text(*a, src), text(*b, src)))
}

fn items_half_unused(for_statement: Node, src: &[u8]) -> bool {
    let (Some((key, value)), Some(right), Some(body)) = (
        loop_pair(for_statement, src),
        for_statement.child_by_field_name("right"),
        for_statement.child_by_field_name("body"),
    ) else {
        return false;
    };
    if right.kind() != "call"
        || callee_name(right, src) != b"items"
        || !call_arguments(right).is_empty()
        || right
            .child_by_field_name("function")
            .is_none_or(|f| f.kind() != "attribute")
    {
        return false;
    }
    let whole = text(body, src);
    (!key.starts_with(b"_") && count_word(whole, key) == 0)
        || (!value.starts_with(b"_") && count_word(whole, value) == 0)
}

fn is_assignment_target(subscript: Node) -> bool {
    subscript.parent().is_some_and(|p| {
        (matches!(p.kind(), "assignment" | "augmented_assignment")
            && p.child_by_field_name("left") == Some(subscript))
            || p.kind() == "delete_statement"
    })
}

fn key_looked_up_again<'t>(for_statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let left = for_statement
        .child_by_field_name("left")
        .filter(|l| l.kind() == "identifier")?;
    let right = for_statement
        .child_by_field_name("right")
        .filter(|r| r.kind() == "identifier")?;
    let (key, dict) = (text(left, src), text(right, src));
    let body = for_statement.child_by_field_name("body")?;
    let is_lookup = |n: Node| {
        n.kind() == "subscript"
            && n.child_by_field_name("value")
                .is_some_and(|v| text(v, src) == dict)
            && n.child_by_field_name("subscript")
                .is_some_and(|s| text(s, src) == key)
    };
    // Writing through the key needs the dict itself, so leave it alone.
    if find_in_scope(body, &[], |n| is_lookup(n) && is_assignment_target(n)).is_some() {
        return None;
    }
    find_in_scope(body, &[], is_lookup)
}

fn enumerate_index_lookup<'t>(for_statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (index, _) = loop_pair(for_statement, src)?;
    let right = for_statement
        .child_by_field_name("right")
        .filter(|r| r.kind() == "call")?;
    if callee_name(right, src) != b"enumerate" {
        return None;
    }
    let args = call_arguments(right);
    let [seq] = args.as_slice() else {
        return None;
    };
    if seq.kind() != "identifier" {
        return None;
    }
    let seq = text(*seq, src);
    let body = for_statement.child_by_field_name("body")?;
    find_in_scope(body, &[], |n| {
        n.kind() == "subscript"
            && !is_assignment_target(n)
            && n.child_by_field_name("value")
                .is_some_and(|v| text(v, src) == seq)
            && n.child_by_field_name("subscript")
                .is_some_and(|s| text(s, src) == index)
    })
}

fn remove_after_membership(if_statement: Node, src: &[u8]) -> bool {
    if if_statement.child_by_field_name("alternative").is_some() {
        return false;
    }
    let (Some(cond), Some(body)) = (
        if_statement.child_by_field_name("condition"),
        if_statement.child_by_field_name("consequence"),
    ) else {
        return false;
    };
    if cond.kind() != "comparison_operator" {
        return false;
    }
    let Some((item, op, set)) = two_operands(cond, src) else {
        return false;
    };
    let items = statements(body);
    let [only] = items.as_slice() else {
        return false;
    };
    let Some(call) = call_statement_of(*only) else {
        return false;
    };
    let args = call_arguments(call);
    op == b"in"
        && callee_name(call, src) == b"remove"
        && call
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("object"))
            .is_some_and(|o| text(o, src) == text(set, src))
        && args.len() == 1
        && text(args[0], src) == text(item, src)
}

fn loop_only_adds(for_statement: Node, src: &[u8]) -> bool {
    let (Some(left), Some(body)) = (
        for_statement.child_by_field_name("left"),
        for_statement.child_by_field_name("body"),
    ) else {
        return false;
    };
    let items = statements(body);
    let [only] = items.as_slice() else {
        return false;
    };
    let Some(call) = call_statement_of(*only) else {
        return false;
    };
    let args = call_arguments(call);
    left.kind() == "identifier"
        && callee_name(call, src) == b"add"
        && call
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "attribute")
        && args.len() == 1
        && text(args[0], src) == text(left, src)
}

fn datetime_argument_out_of_range(call: Node, src: &[u8]) -> bool {
    let name = callee_name(call, src);
    let args = call_arguments(call);
    if args.is_empty() || args.iter().any(|a| a.kind() != "integer") {
        return false;
    }
    let values: Vec<u64> = args.iter().filter_map(|a| integer_value(*a, src)).collect();
    if values.len() != args.len() {
        return false;
    }
    let module_call = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "attribute")
        .and_then(|f| f.child_by_field_name("object"))
        .is_some_and(|o| text(o, src) == b"time");
    let limits: &[(u64, u64)] = match name {
        b"datetime" => &[
            (1, 9999),
            (1, 12),
            (1, 31),
            (0, 23),
            (0, 59),
            (0, 59),
            (0, 999_999),
        ],
        b"date" => &[(1, 9999), (1, 12), (1, 31)],
        b"time" if !module_call => &[(0, 23), (0, 59), (0, 59), (0, 999_999)],
        _ => return false,
    };
    values
        .iter()
        .zip(limits)
        .any(|(v, (lo, hi))| v < lo || v > hi)
}

pub(super) fn receiver_text<'s>(call: Node, src: &'s [u8]) -> &'s [u8] {
    call.child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
        .map_or(&b""[..], |o| text(o, src))
}

fn merge_lacks_explicit_arguments(call: Node, src: &[u8]) -> bool {
    let receiver = receiver_text(call, src);
    let frame = matches!(receiver, b"pd" | b"pandas") || contains_ignoring_case(receiver, b"df");
    if !frame
        || call_arguments(call)
            .iter()
            .any(|a| a.kind() == "dictionary_splat")
    {
        return false;
    }
    let has = |k: &str| keyword_value(call, k, src).is_some();
    let on =
        has("on") || has("left_on") || has("right_on") || has("left_index") || has("right_index");
    !(on && has("how") && has("validate"))
}

fn read_without_dtype(call: Node, src: &[u8]) -> bool {
    matches!(receiver_text(call, src), b"pd" | b"pandas")
        && keyword_value(call, "dtype", src).is_none()
        && !call_arguments(call)
            .iter()
            .any(|a| a.kind() == "dictionary_splat")
}

fn values_of_a_dataframe(attribute: Node, src: &[u8]) -> bool {
    let Some(object) = attribute.child_by_field_name("object") else {
        return false;
    };
    let name = text(object, src);
    let called = attribute.parent().is_some_and(|p| {
        p.kind() == "call" && p.child_by_field_name("function") == Some(attribute)
    });
    !called && (name == b"df" || name.starts_with(b"df_") || name.ends_with(b"_df"))
}

fn is_literal_bytes_or_string(node: Node) -> bool {
    node.kind() == "string" && !has_interpolation(node)
}

fn cbc_with_literal_iv(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    match callee_name(call, src) {
        b"new" => {
            let mode = args
                .iter()
                .position(|a| a.kind() == "attribute" && text(*a, src).ends_with(b"MODE_CBC"));
            let iv = keyword_value(call, "iv", src)
                .or_else(|| mode.and_then(|i| args.get(i + 1).copied()));
            mode.is_some() && iv.is_some_and(is_literal_bytes_or_string)
        }
        b"CBC" => args.len() == 1 && is_literal_bytes_or_string(args[0]),
        _ => false,
    }
}

fn salt_is_a_literal(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let positional: Vec<&Node> = args
        .iter()
        .filter(|a| a.kind() != "keyword_argument")
        .collect();
    match callee_name(call, src) {
        b"pbkdf2_hmac" => positional
            .get(2)
            .is_some_and(|a| is_literal_bytes_or_string(**a)),
        b"scrypt" => keyword_value(call, "salt", src).is_some_and(is_literal_bytes_or_string),
        b"hashpw" => positional
            .get(1)
            .is_some_and(|a| is_literal_bytes_or_string(**a)),
        _ => false,
    }
}

fn bind_without_credentials(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    args.is_empty()
        || args
            .iter()
            .all(|a| string_value(*a, src).is_some_and(<[u8]>::is_empty))
}

fn hashes_a_password(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|a| {
        ["password", "passwd", "pwd"]
            .iter()
            .any(|w| contains_ignoring_case(text(*a, src), w.as_bytes()))
    })
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
    fn identity_and_literals() {
        let src = "a is 'x'\na is 1\na is None\na is not 'y'\na is []\n1 is 'a'\na == 'x'";
        assert_eq!(flagged("py/is-with-literal", src), [1, 2, 4, 6]);
        assert_eq!(flagged("py/is-with-new-object", src), [5]);
        assert_eq!(flagged("py/identity-dissimilar-types", src), [6]);
    }

    #[test]
    fn returns_and_generators() {
        let src = "def a(x):\n    if x:\n        return 1\n    return\ndef b(x):\n    if x:\n        return 1\n    return None\nasync def c():\n    yield 1\n    return 2\nasync def d():\n    yield 1\n    return";
        assert_eq!(flagged("py/inconsistent-return", src), [4]);
        assert_eq!(flagged("py/return-in-generator", src), [11]);
    }

    #[test]
    fn overwritten_values() {
        let src = "d['k'] = 1\nd['k'] = 2\nd['j'] = 1\nd['j'] = d['j'] + 1\nx = f()\nx = g()\ny = None\ny = g()\nz = 1\nz = z + 1";
        assert_eq!(flagged("py/collection-replaced", src), [1]);
        assert_eq!(flagged("py/dead-store", src), [5]);
    }

    #[test]
    fn except_and_finally() {
        let src = "try:\n    f()\nexcept ValueError:\n    raise\ntry:\n    f()\nexcept ValueError:\n    raise\nexcept Exception:\n    pass\ntry:\n    f()\nfinally:\n    raise\ntry:\n    f()\nexcept A or B:\n    pass";
        assert_eq!(flagged("py/except-only-reraises", src), [3]);
        assert_eq!(flagged("py/bare-raise-in-finally", src), [14]);
        assert_eq!(flagged("py/except-boolean-expression", src), [17]);
    }

    #[test]
    fn special_methods_and_properties() {
        let src = "class A:\n    def __len__(self, x):\n        return 0\n    def __eq__(self, o, extra=1):\n        return True\n    def __exit__(self, *a):\n        pass\n    @property\n    def p(self, q):\n        return 1\n    @p.setter\n    def p(self, v):\n        pass\n    @staticmethod\n    def __str__():\n        return ''";
        assert_eq!(flagged("py/special-method-arity", src), [2]);
        assert_eq!(flagged("py/property-arity", src), [8]);
    }

    #[test]
    fn formatting_counts() {
        let src = "'%s %s' % (a,)\n'%s %s' % (a, b)\n'%s %%' % (a,)\n'{} {}'.format(a)\n'{} {}'.format(a, b)\n'{x}'.format(x=1)\nf'plain'\nf'{x}'\nf'{{}}'";
        assert_eq!(flagged("py/string-format-count", src), [1, 4]);
        assert_eq!(flagged("py/fstring-without-fields", src), [7]);
    }

    #[test]
    fn naming() {
        let src = "class my_class:\n    def doThing(self):\n        self.myField = 1\n    def __init__(self):\n        pass\n    def setUp(self):\n        pass\ndef fooBar(ArgOne, ok_arg):\n    LocalVar = 1\n    good = 2\nMODULE_CONST = 3\n";
        assert_eq!(flagged("py/class-name", src), [1]);
        assert_eq!(flagged("py/method-name", src), [2]);
        assert_eq!(flagged("py/function-name", src), [8]);
        assert_eq!(flagged("py/field-name", src), [3]);
        assert_eq!(flagged("py/local-name", src), [8, 9]);
    }

    #[test]
    fn unused_things() {
        let src = "import os\nimport sys\nfrom a import b, c\nprint(sys.argv, b)\ndef f(p, q):\n    x = 1\n    y = 2\n    return p + y";
        assert_eq!(flagged("py/unused-import", src), [1, 3]);
        assert_eq!(flagged("py/unused-local", src), [6]);
        assert_eq!(flagged("py/unused-parameter", src), [5]);
    }

    #[test]
    fn dedup_and_branches() {
        let src = "def a():\n    x = 1\n    return x\ndef b():\n    x = 1\n    return x\nif p:\n    x = 1\n    y = 2\nelif q:\n    x = 1\n    y = 2\nelse:\n    z = 3";
        assert_eq!(flagged("py/identical-functions", src), [4]);
        assert_eq!(flagged("py/duplicated-branch", src), [11]);
    }

    #[test]
    fn closures_and_loops() {
        let src = "for i in r:\n    a.append(lambda: i)\n    b.append(lambda i=i: i)\nfor k, v in d.items():\n    use(k)\nfor k in d:\n    use(d[k])\nfor i, x in enumerate(xs):\n    use(xs[i])\nfor x in xs:\n    s.add(x)";
        assert_eq!(flagged("py/loop-variable-closure", src), [2]);
        assert_eq!(flagged("py/items-unused-half", src), [4]);
        assert_eq!(flagged("py/dict-lookup-in-loop", src), [7]);
        assert_eq!(flagged("py/enumerate-index-lookup", src), [9]);
        assert_eq!(flagged("py/set-update-loop", src), [10]);
    }

    #[test]
    fn comments_and_ips() {
        let src = "x = 0\nx = 1  # note\ny = 2  # noqa\nz = 3  # NOSONAR\nh = '192.168.0.4'\nl = '127.0.0.1'\na = 1; b = 2\nc = 3;";
        assert_eq!(flagged("py/noqa-comment", src), [3]);
        assert_eq!(flagged("py/hardcoded-ip", src), [5]);
        assert_eq!(flagged("py/semicolon-statements", src), [7]);
    }

    #[test]
    fn crypto_and_libraries() {
        let src = "AES.new(k, AES.MODE_CBC, b'0123456789abcdef')\nAES.new(k, AES.MODE_CBC, iv)\nhashlib.pbkdf2_hmac('sha256', pw, b'salt', 1)\nhashlib.sha256(password.encode())\nhashlib.sha256(data)\nBeautifulSoup(html)\nBeautifulSoup(html, 'lxml')\ndatetime(2020, 13, 1)\ndatetime(2020, 12, 1)\ndf.values\ndf.values()\npd.read_csv('a')";
        assert_eq!(flagged("py/static-iv", src), [1]);
        assert_eq!(flagged("py/static-salt", src), [3]);
        assert_eq!(flagged("py/password-fast-hash", src), [4]);
        assert_eq!(flagged("py/bs4-parser", src), [6]);
        assert_eq!(flagged("py/datetime-range", src), [8]);
        assert_eq!(flagged("py/dataframe-values", src), [10]);
        assert_eq!(flagged("py/read-csv-dtype", src), [12]);
    }
}
