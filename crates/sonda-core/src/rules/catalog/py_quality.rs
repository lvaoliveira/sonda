//! Python bug and code-smell rules (ADR-0007, batch 5). Queries stay cheap on
//! deep trees: see the notes in `js_modern.rs`.

use super::py_security::{
    call_arguments, call_of, callee_name, contains_ignoring_case, keyword_value, string_value, text,
};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/self-assignment",
        name: "Variables should not be self-assigned",
        description: "Assigning a value to itself does nothing and usually hides a typo.",
        message: "Remove this self-assignment, or fix the name.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1656")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (_) right: (_)) @match"#,
            filter: Some(Keep(assigns_to_itself)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = x\n",
            good: "x = y\n",
        }),
    },
    Rule {
        id: "py/identical-operands",
        name: "Identical expressions should not be used on both sides of a binary operator",
        description: "`a == a` is always true and `a - a` always zero: one side is almost certainly a typo.",
        message: "Fix one of these identical operands.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1764")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match
(boolean_operator) @match
(binary_operator) @match"#,
            filter: Some(Keep(operands_are_identical)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if a > a:\n    pass\n",
            good: "if a > b:\n    pass\n",
        }),
    },
    Rule {
        id: "py/duplicate-condition",
        name: "Related if/elif statements should not have the same condition",
        description: "The second branch can never run.",
        message: "Change or remove the repeated condition.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1862")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement) @match"#,
            filter: Some(Find(repeated_branch_condition)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if a:\n    f()\nelif a:\n    g()\n",
            good: "if a:\n    f()\nelif b:\n    g()\n",
        }),
    },
    Rule {
        id: "py/identical-branches",
        name: "All branches in a conditional structure should not have exactly the same implementation",
        description: "If every branch does the same thing, the condition decides nothing.",
        message: "Remove the condition, or fix the branch that should differ.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3923")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(all_branches_identical)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if a:\n    f()\nelse:\n    f()\n",
            good: "if a:\n    f()\nelse:\n    g()\n",
        }),
    },
    Rule {
        id: "py/single-iteration-loop",
        name: "Loops with at most one iteration should be refactored",
        description: "A loop whose body always ends in a jump runs its body once.",
        message: "Replace this loop with an if, or fix the jump.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1751")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement) @match
(while_statement) @match"#,
            filter: Some(Keep(loop_always_exits)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for x in xs:\n    return x\n",
            good: "for x in xs:\n    if ok(x):\n        return x\n",
        }),
    },
    Rule {
        id: "py/unreachable-code",
        name: "All code should be reachable",
        description: "Statements after a return, raise, break or continue never run.",
        message: "Remove this unreachable code.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1763")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(block) @match"#,
            filter: Some(Find(statement_after_jump)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    return 1\n    g()\n",
            good: "def f():\n    g()\n    return 1\n",
        }),
    },
    Rule {
        id: "py/jump-in-finally",
        name: "Jump statements should not occur in finally blocks",
        description: "A return, break or continue in finally discards any exception that is propagating.",
        message: "Move this jump out of the finally block.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1143")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(finally_clause) @match"#,
            filter: Some(Find(jump_in_finally)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    try:\n        g()\n    finally:\n        return 1\n",
            good: "def f():\n    try:\n        g()\n    finally:\n        cleanup()\n    return 1\n",
        }),
    },
    Rule {
        id: "py/bare-raise-outside-handler",
        name: "Bare raise statements should only be used in except blocks",
        description: "With no exception being handled, a bare raise fails with RuntimeError.",
        message: "Name the exception to raise.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5747")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(raise_statement) @match"#,
            filter: Some(Keep(bare_raise_outside_handler)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "raise\n",
            good: "try:\n    f()\nexcept ValueError:\n    raise\n",
        }),
    },
    Rule {
        id: "py/unreachable-except",
        name: "All except blocks should be able to catch exceptions",
        description: "An except clause after a catch-all one never runs.",
        message: "Move the catch-all clause last.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1045")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(try_statement) @match"#,
            filter: Some(Find(except_after_catch_all)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept Exception:\n    pass\nexcept ValueError:\n    pass\n",
            good: "try:\n    f()\nexcept ValueError:\n    pass\nexcept Exception:\n    pass\n",
        }),
    },
    Rule {
        id: "py/exception-not-raised",
        name: "Exceptions should not be created without being raised",
        description: "`ValueError('x')` on its own builds an object and drops it.",
        message: "Raise this exception.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3984")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(expression_statement (call function: (identifier) @f (#match? @f "(Error|Exception)$"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "ValueError('bad')\n",
            good: "raise ValueError('bad')\n",
        }),
    },
    Rule {
        id: "py/raise-non-exception",
        name: "Raised exceptions must derive from BaseException",
        description: "Only exception classes and instances can be raised.",
        message: "Raise an exception.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5632")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(raise_statement) @match"#,
            filter: Some(Keep(raises_a_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "raise 'failed'\n",
            good: "raise RuntimeError('failed')\n",
        }),
    },
    Rule {
        id: "py/init-returns-value",
        name: "__init__ should not return a value",
        description: "A constructor that returns something other than None raises TypeError.",
        message: "Remove this return value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2734")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition name: (identifier) @n (#eq? @n "__init__")) @match"#,
            filter: Some(Find(returns_a_value)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def __init__(self):\n        return 1\n",
            good: "class A:\n    def __init__(self):\n        self.x = 1\n",
        }),
    },
    Rule {
        id: "py/return-outside-function",
        name: "return and yield should not be used outside functions",
        description: "They are syntax errors at module or class level.",
        message: "Move this into a function.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2711")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(return_statement) @match
(yield) @match"#,
            filter: Some(Keep(outside_any_function)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "return 1\n",
            good: "def f():\n    return 1\n",
        }),
    },
    Rule {
        id: "py/misleading-operator",
        name: "Non-existent operators like =+ should not be used",
        description: "`x =+ 1` assigns +1, which is almost never what was meant.",
        message: "Use += or add a space.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2757")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment right: (unary_operator)) @match"#,
            filter: Some(Keep(sign_glued_to_equals)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x =+ 1\n",
            good: "x += 1\n",
        }),
    },
    Rule {
        id: "py/open-mode",
        name: "The open builtin should be called with a valid mode",
        description: "An invalid mode string raises ValueError at runtime.",
        message: "Use a valid mode such as 'r', 'wb' or 'a+'.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5828")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "open")) @match"#,
            filter: Some(Keep(open_mode_is_invalid)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "f = open(path, 'rw')\n",
            good: "f = open(path, 'r+')\n",
        }),
    },
    Rule {
        id: "py/dict-duplicate-key",
        name: "Dictionary literals should not have duplicate keys",
        description: "Later values silently replace earlier ones.",
        message: "Remove the duplicate key.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5780")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(dictionary) @match"#,
            filter: Some(Find(duplicate_dictionary_key)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = {'a': 1, 'a': 2}\n",
            good: "d = {'a': 1, 'b': 2}\n",
        }),
    },
    Rule {
        id: "py/set-duplicate-value",
        name: "Set literals should not have duplicate values",
        description: "The repeated value does nothing.",
        message: "Remove the duplicate value.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5781")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(set) @match"#,
            filter: Some(Find(duplicate_set_value)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "s = {1, 2, 1}\n",
            good: "s = {1, 2, 3}\n",
        }),
    },
    Rule {
        id: "py/float-equality",
        name: "Floating point numbers should not be tested for equality",
        description: "Rounding makes two mathematically equal results differ in the last bits.",
        message: "Compare with a tolerance, using math.isclose().",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1244")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(compares_float_for_equality)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if total == 0.1:\n    pass\n",
            good: "if math.isclose(total, 0.1):\n    pass\n",
        }),
    },
    Rule {
        id: "py/assert-constant",
        name: "Assertions should not succeed unconditionally",
        description: "`assert True` checks nothing.",
        message: "Remove this assertion, or assert something.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5914")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assert_statement) @match"#,
            filter: Some(Keep(asserts_a_constant)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "assert True\n",
            good: "assert ready\n",
        }),
    },
    Rule {
        id: "py/length-comparison",
        name: "Collection size comparisons should make sense",
        description: "A length is never negative, so `len(x) < 0` is always false and `len(x) >= 0` always true.",
        message: "Fix this comparison.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3981")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(compares_length_with_zero_nonsensically)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if len(x) < 0:\n    pass\n",
            good: "if len(x) == 0:\n    pass\n",
        }),
    },
    Rule {
        id: "py/numpy-nan-equality",
        name: "Equality checks should not be made against numpy.nan",
        description: "NaN is not equal to anything, itself included, so the check is always false.",
        message: "Use numpy.isnan() instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6725")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(compares_with_nan)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x == np.nan:\n    pass\n",
            good: "if np.isnan(x):\n    pass\n",
        }),
    },
    Rule {
        id: "py/isclose-without-abs-tol",
        name: "The abs_tol parameter should be provided when comparing to zero",
        description: "With the default relative tolerance only, nothing but zero is close to zero.",
        message: "Pass abs_tol.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6727")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "math") (#eq? @a "isclose"))) @match"#,
            filter: Some(Keep(isclose_to_zero_without_abs_tol)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "math.isclose(x, 0)\n",
            good: "math.isclose(x, 0, abs_tol=1e-9)\n",
        }),
    },
    Rule {
        id: "py/dict-fromkeys-mutable",
        name: "Mutable default values should not be used with dict.fromkeys()",
        description: "Every key shares the same list or dict.",
        message: "Build the values in a comprehension.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8508")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "dict") (#eq? @a "fromkeys")) arguments: (argument_list (_) [(list) (dictionary) (set)])) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = dict.fromkeys(keys, [])\n",
            good: "d = {k: [] for k in keys}\n",
        }),
    },
    Rule {
        id: "py/enum-dataclass",
        name: "Enum classes should not be decorated with @dataclass",
        description: "The decorator generates methods that clash with Enum's.",
        message: "Remove the decorator.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8490")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition (decorator) definition: (class_definition superclasses: (argument_list))) @match"#,
            filter: Some(Keep(dataclass_enum)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@dataclass\nclass Color(Enum):\n    RED = 1\n",
            good: "class Color(Enum):\n    RED = 1\n",
        }),
    },
    Rule {
        id: "py/typevar-variance",
        name: "TypeVars should not be both covariant and contravariant",
        description: "The two are mutually exclusive.",
        message: "Pick one variance.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8515")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "TypeVar")) @match"#,
            filter: Some(Keep(typevar_is_both_variances)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "T = TypeVar('T', covariant=True, contravariant=True)\n",
            good: "T = TypeVar('T', covariant=True)\n",
        }),
    },
    Rule {
        id: "py/stopiteration-in-generator",
        name: "StopIteration should not be raised inside generators",
        description: "Since Python 3.7 it becomes RuntimeError.",
        message: "Use return instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8493")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(raise_statement) @match"#,
            filter: Some(Keep(raises_stop_iteration_in_generator)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def g():\n    yield 1\n    raise StopIteration\n",
            good: "def g():\n    yield 1\n    return\n",
        }),
    },
    Rule {
        id: "py/property-without-return",
        name: "Property methods should have a return statement",
        description: "A property that returns nothing always reads as None.",
        message: "Return a value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8504")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorated_definition (decorator (identifier) @d (#eq? @d "property")) definition: (function_definition) @match)"#,
            filter: Some(Keep(function_never_returns)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    @property\n    def size(self):\n        self.x = 1\n",
            good: "class A:\n    @property\n    def size(self):\n        return 1\n",
        }),
    },
    Rule {
        id: "py/async-blocking-sleep",
        name: "Non-blocking sleep functions should be used in asynchronous code",
        description: "time.sleep stops the whole event loop.",
        message: "Use asyncio.sleep.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7488")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "time") (#eq? @a "sleep"))) @match"#,
            filter: Some(Keep(in_async_function)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    time.sleep(1)\n",
            good: "async def f():\n    await asyncio.sleep(1)\n",
        }),
    },
    Rule {
        id: "py/async-blocking-subprocess",
        name: "Async functions should not contain synchronous subprocess calls",
        description: "A blocking subprocess call stops the event loop until the process ends.",
        message: "Use asyncio.create_subprocess_exec.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7487")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "subprocess") (#any-of? @a "run" "call" "check_call" "check_output"))) @match"#,
            filter: Some(Keep(in_async_function)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    subprocess.run(['ls'])\n",
            good: "async def f():\n    await asyncio.create_subprocess_exec('ls')\n",
        }),
    },
    Rule {
        id: "py/async-blocking-http",
        name: "Async functions should not contain synchronous HTTP client calls",
        description: "requests blocks the event loop while waiting for the response.",
        message: "Use an async HTTP client such as httpx or aiohttp.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7499")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "requests") (#any-of? @a "get" "post" "put" "delete" "patch" "head" "request"))) @match"#,
            filter: Some(Keep(in_async_function)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    requests.get(url)\n",
            good: "async def f():\n    await client.get(url)\n",
        }),
    },
    Rule {
        id: "py/async-blocking-open",
        name: "Async functions should not contain synchronous file operations",
        description: "open() blocks the event loop on slow disks and network mounts.",
        message: "Use an async file library or run it in an executor.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7493")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "open")) @match"#,
            filter: Some(Keep(in_async_function)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    data = open(p).read()\n",
            good: "async def f():\n    data = await aiofiles_read(p)\n",
        }),
    },
    Rule {
        id: "py/async-blocking-input",
        name: "Async functions should not contain input() calls",
        description: "input() waits for the user and blocks everything else.",
        message: "Read input in an executor.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7501")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "input")) @match"#,
            filter: Some(Keep(in_async_function)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    name = input()\n",
            good: "async def f():\n    name = await ask()\n",
        }),
    },
    Rule {
        id: "py/async-blocking-os",
        name: "Async functions should not contain synchronous OS calls",
        description: "os.system and os.popen block until the command finishes.",
        message: "Use asyncio subprocess functions.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7489")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "os") (#any-of? @a "system" "popen"))) @match"#,
            filter: Some(Keep(in_async_function)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    os.system('ls')\n",
            good: "async def f():\n    await run('ls')\n",
        }),
    },
    Rule {
        id: "py/task-not-saved",
        name: "Asyncio tasks should be saved to prevent premature garbage collection",
        description: "The event loop keeps only a weak reference to a task, so it can be collected before it finishes.",
        message: "Keep a reference to the task.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7502")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(expression_statement (call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "asyncio") (#any-of? @a "create_task" "ensure_future")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "async def f():\n    asyncio.create_task(work())\n",
            good: "async def f():\n    task = asyncio.create_task(work())\n",
        }),
    },
    Rule {
        id: "py/torch-module-init",
        name: "Subclasses of torch.nn.Module should call the initializer",
        description: "Without super().__init__(), the module's parameters aren't registered.",
        message: "Call super().__init__().",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6978")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition) @match"#,
            filter: Some(Find(module_init_without_super)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class Net(nn.Module):\n    def __init__(self):\n        self.fc = 1\n",
            good: "class Net(nn.Module):\n    def __init__(self):\n        super().__init__()\n        self.fc = 1\n",
        }),
    },
    Rule {
        id: "py/fastapi-reload-object",
        name: "FastAPI applications should be passed as import strings when using reload",
        description: "uvicorn can only reload an app it can import by name.",
        message: "Pass the app as 'module:app'.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8397")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "uvicorn") (#eq? @a "run"))) @match"#,
            filter: Some(Keep(reload_with_app_object)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "uvicorn.run(app, reload=True)\n",
            good: "uvicorn.run('main:app', reload=True)\n",
        }),
    },
    Rule {
        id: "py/flask-header-keyerror",
        name: "HTTP headers should be accessed safely",
        description: "A missing header makes `request.headers['X']` raise KeyError, and the client sees a 500.",
        message: "Use request.headers.get().",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8371")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(subscript value: (attribute object: (identifier) @o attribute: (identifier) @h (#eq? @o "request") (#eq? @h "headers"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "token = request.headers['X-Token']\n",
            good: "token = request.headers.get('X-Token')\n",
        }),
    },
    Rule {
        id: "py/doubled-prefix-operator",
        name: "Doubled prefix operators not and ~ should not be used",
        description: "`not not x` and `~~x` cancel out, or are a clumsy way of casting.",
        message: "Remove the doubled operator.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2761")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(not_operator argument: (not_operator)) @match
(unary_operator operator: "~" argument: (unary_operator operator: "~")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "y = not not x\n",
            good: "y = bool(x)\n",
        }),
    },
    Rule {
        id: "py/needless-pass",
        name: "pass should not be used needlessly",
        description: "A block that has other statements doesn't need pass.",
        message: "Remove this pass.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2772")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(block) @match"#,
            filter: Some(Find(pass_with_other_statements)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    g()\n    pass\n",
            good: "def f():\n    g()\n",
        }),
    },
    Rule {
        id: "py/loop-else-without-break",
        name: "Loops without break should not have else clauses",
        description: "else on a loop runs when the loop wasn't broken out of, so without a break it always runs.",
        message: "Remove the else, or add the break it depends on.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2836")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement alternative: (else_clause)) @match
(while_statement alternative: (else_clause)) @match"#,
            filter: Some(Keep(loop_has_no_break)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for x in xs:\n    f(x)\nelse:\n    g()\n",
            good: "for x in xs:\n    if ok(x):\n        break\nelse:\n    g()\n",
        }),
    },
    Rule {
        id: "py/nested-conditional",
        name: "Conditional expressions should not be nested",
        description: "A ternary inside a ternary is hard to read.",
        message: "Use if statements, or a variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3358")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(conditional_expression [(conditional_expression) (parenthesized_expression (conditional_expression))] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = a if p else (b if q else c)\n",
            good: "if p:\n    x = a\nelif q:\n    x = b\nelse:\n    x = c\n",
        }),
    },
    Rule {
        id: "py/redundant-jump",
        name: "Jump statements should not be redundant",
        description: "A return at the end of a function, or a continue at the end of a loop, changes nothing.",
        message: "Remove this jump.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3626")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(return_statement) @match
(continue_statement) @match"#,
            filter: Some(Keep(jump_is_redundant)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    g()\n    return\n",
            good: "def f():\n    g()\n",
        }),
    },
    Rule {
        id: "py/empty-function",
        name: "Functions and methods should not be empty",
        description: "An empty body gives no hint whether it is unfinished or deliberate.",
        message: "Implement this function, or explain why it is empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1186")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(function_body_is_only_pass)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f():\n    pass\n",
            good: "def f():\n    # Deliberately empty: subclasses override.\n    pass\n",
        }),
    },
    Rule {
        id: "py/empty-nested-block",
        name: "Nested blocks of code should not be left empty",
        description: "An empty if, loop or except hides whether the case was forgotten.",
        message: "Fill this block, or say why it is empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S108")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(block) @match"#,
            filter: Some(Keep(statement_block_is_only_pass)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept ValueError:\n    pass\n",
            good: "try:\n    f()\nexcept ValueError:\n    log.warning('ignored')\n",
        }),
    },
    Rule {
        id: "py/generic-exception-raised",
        name: "Exception and BaseException should not be raised",
        description: "Callers can't catch a generic exception without catching everything.",
        message: "Raise a more specific exception.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S112")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(raise_statement) @match"#,
            filter: Some(Keep(raises_base_exception)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "raise Exception('bad')\n",
            good: "raise ValueError('bad')\n",
        }),
    },
    Rule {
        id: "py/duplicated-string",
        name: "String literals should not be duplicated",
        description: "A literal repeated across the file is easy to change in one place and miss in the others.",
        message: "Define a constant for this string.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1192")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(module) @match"#,
            filter: Some(Find(string_repeated_often)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "a = 'connection failed'\nb = 'connection failed'\nc = 'connection failed'\n",
            good: "MSG = 'connection failed'\na = MSG\nb = MSG\nc = MSG\n",
        }),
    },
    Rule {
        id: "py/inverted-boolean",
        name: "Boolean checks should not be inverted",
        description: "`not a == b` is clearer as `a != b`.",
        message: "Use the opposite operator.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1940")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(not_operator argument: (comparison_operator)) @match"#,
            filter: Some(Keep(negates_a_simple_comparison)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if not a == b:\n    pass\n",
            good: "if a != b:\n    pass\n",
        }),
    },
    Rule {
        id: "py/redundant-parentheses",
        name: "Unnecessary parentheses should be removed",
        description: "Parentheses around a whole condition add noise.",
        message: "Remove the parentheses.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1110")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement condition: (parenthesized_expression) @match)
(elif_clause condition: (parenthesized_expression) @match)
(while_statement condition: (parenthesized_expression) @match)
(return_statement (parenthesized_expression) @match)"#,
            filter: Some(Keep(parentheses_fit_on_one_line)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if (x > 1):\n    pass\n",
            good: "if x > 1:\n    pass\n",
        }),
    },
    Rule {
        id: "py/mergeable-if",
        name: "Mergeable if statements should be combined",
        description: "An if whose only content is another if can use `and`.",
        message: "Merge these conditions.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1066")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(if_only_wraps_another_if)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if a:\n    if b:\n        f()\n",
            good: "if a and b:\n    f()\n",
        }),
    },
    Rule {
        id: "py/constant-condition",
        name: "Constants should not be used as conditions",
        description: "The branch is either always or never taken.",
        message: "Remove the condition, or use a real one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5797")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(if_statement condition: [(true) (false) (none) (integer) (float)] @match)
(elif_clause condition: [(true) (false) (none) (integer) (float)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if True:\n    f()\n",
            good: "if ready:\n    f()\n",
        }),
    },
    Rule {
        id: "py/statement-without-effect",
        name: "Non-empty statements should change control flow or have a side effect",
        description: "An expression whose value is thrown away does nothing.",
        message: "Remove this statement, or use its value.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S905")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(expression_statement [(comparison_operator) (binary_operator) (boolean_operator) (identifier) (integer) (float) (list) (dictionary) (set) (not_operator)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x == 1\n",
            good: "assert x == 1\n",
        }),
    },
    Rule {
        id: "py/builtin-shadowed",
        name: "Builtins should not be shadowed by local variables",
        description: "Reusing `list` or `id` as a name hides the builtin for the rest of the scope.",
        message: "Rename this variable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5806")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) @match (#any-of? @match "list" "dict" "set" "str" "int" "float" "bool" "tuple" "type" "id" "input" "len" "max" "min" "sum" "map" "filter" "object" "format" "range" "sorted" "iter" "next" "open" "print" "vars" "dir" "hash" "all" "any" "bytes" "zip" "file" "compile"))
(parameters (identifier) @match (#any-of? @match "list" "dict" "set" "str" "int" "float" "bool" "tuple" "type" "id" "input" "len" "max" "min" "sum" "map" "filter" "object" "format" "range" "sorted" "iter" "next" "open" "print" "vars" "dir" "hash" "all" "any" "bytes" "zip" "file" "compile"))
(default_parameter name: (identifier) @match (#any-of? @match "list" "dict" "set" "str" "int" "float" "bool" "tuple" "type" "id" "input" "len" "max" "min" "sum" "map" "filter" "object" "format" "range" "sorted" "iter" "next" "open" "print" "vars" "dir" "hash" "all" "any" "bytes" "zip" "file" "compile"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "list = [1, 2]\n",
            good: "items = [1, 2]\n",
        }),
    },
    Rule {
        id: "py/method-without-self",
        name: "Instance and class methods should have a self or cls parameter",
        description: "Without it, calling the method on an instance fails.",
        message: "Add self (or cls) as the first parameter.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5719")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(function_definition) @match"#,
            filter: Some(Keep(method_lacks_self)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    def run():\n        pass\n",
            good: "class A:\n    def run(self):\n        pass\n",
        }),
    },
    Rule {
        id: "py/implicit-string-concatenation",
        name: "Implicit string concatenations should not be confusing",
        description: "In a list or call, a missing comma silently joins two strings.",
        message: "Add the comma, or use + explicitly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5799")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(concatenated_string) @match"#,
            filter: Some(Keep(joins_inside_a_collection)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "names = ['a' 'b', 'c']\n",
            good: "names = ['a', 'b', 'c']\n",
        }),
    },
    Rule {
        id: "py/startswith-slice",
        name: "startswith and endswith should be used instead of string slicing",
        description: "`s[:3] == 'abc'` hides what it checks and builds a new string.",
        message: "Use startswith() or endswith().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6659")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(compares_a_slice_with_a_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if s[:3] == 'abc':\n    pass\n",
            good: "if s.startswith('abc'):\n    pass\n",
        }),
    },
    Rule {
        id: "py/type-comparison",
        name: "isinstance() should be preferred to direct type comparisons",
        description: "`type(x) == T` fails for subclasses.",
        message: "Use isinstance().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6660")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator) @match"#,
            filter: Some(Keep(compares_type_directly)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if type(x) == int:\n    pass\n",
            good: "if isinstance(x, int):\n    pass\n",
        }),
    },
    Rule {
        id: "py/empty-literal",
        name: "Literal syntax should be preferred for empty collections",
        description: "`[]` and `{}` are faster and clearer than `list()` and `dict()`.",
        message: "Use the literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7498")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "list" "dict" "tuple") arguments: (argument_list)) @match"#,
            filter: Some(Keep(no_arguments)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = list()\n",
            good: "x = []\n",
        }),
    },
    Rule {
        id: "py/generator-in-constructor",
        name: "Comprehensions should be used instead of constructors around generator expressions",
        description: "`list(x for x in y)` builds a generator to throw it away.",
        message: "Use a comprehension.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7494")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "list" "set") arguments: [(argument_list (generator_expression)) (generator_expression)]) @match"#,
            filter: Some(Keep(one_argument)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = list(a for a in b)\n",
            good: "x = [a for a in b]\n",
        }),
    },
    Rule {
        id: "py/comprehension-copy",
        name: "Comprehensions only used to copy should be replaced",
        description: "`[x for x in y]` is `list(y)`.",
        message: "Use list(), set() or dict() directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7500")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(list_comprehension) @match"#,
            filter: Some(Keep(copies_its_iterable)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = [a for a in b]\n",
            good: "x = list(b)\n",
        }),
    },
    Rule {
        id: "py/list-in-for",
        name: "list() should be avoided when iterating over an iterable",
        description: "Copying the iterable first costs memory for nothing, unless the loop changes it.",
        message: "Iterate over the object directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7504")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement right: (call function: (identifier) @f (#eq? @f "list"))) @match"#,
            filter: Some(Keep(list_copy_is_not_needed)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for x in list(items):\n    f(x)\n",
            good: "for x in items:\n    f(x)\n",
        }),
    },
    Rule {
        id: "py/redundant-collection-call",
        name: "Redundant collection functions should be avoided",
        description: "`sorted(list(x))` converts twice.",
        message: "Remove the inner call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7508")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "list" "sorted" "tuple" "set") arguments: (argument_list (call function: (identifier) @g))) @match"#,
            filter: Some(Keep(collection_call_is_redundant)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = sorted(list(y))\n",
            good: "x = sorted(y)\n",
        }),
    },
    Rule {
        id: "py/reversed-sorted",
        name: "sorted() should not be passed to reversed()",
        description: "`sorted(x, reverse=True)` does it in one step.",
        message: "Use reverse=True.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7510")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "reversed") arguments: (argument_list (call function: (identifier) @g (#eq? @g "sorted")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = reversed(sorted(y))\n",
            good: "x = sorted(y, reverse=True)\n",
        }),
    },
    Rule {
        id: "py/set-of-sorted",
        name: "sorted should not be wrapped directly inside set",
        description: "A set has no order, so sorting first is wasted.",
        message: "Remove the sorted() call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7516")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "set") arguments: (argument_list (call function: (identifier) @g (#eq? @g "sorted")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = set(sorted(y))\n",
            good: "x = set(y)\n",
        }),
    },
    Rule {
        id: "py/reversed-wrapper",
        name: "Passing a reversed iterable to set(), sorted() or reversed() is pointless",
        description: "The order is thrown away or restored.",
        message: "Remove the reversed() call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7511")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "set" "sorted" "reversed") arguments: (argument_list (call function: (identifier) @g (#eq? @g "reversed")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = set(reversed(y))\n",
            good: "x = set(y)\n",
        }),
    },
    Rule {
        id: "py/dict-keys-iteration",
        name: "The .keys() method should not be called when testing or iterating over a dictionary",
        description: "A dictionary already tests and iterates its keys.",
        message: "Drop .keys().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8521")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator (call function: (attribute attribute: (identifier) @k (#eq? @k "keys")))) @match
(for_statement right: (call function: (attribute attribute: (identifier) @k2 (#eq? @k2 "keys")))) @match"#,
            filter: Some(Keep(keys_call_is_redundant)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if k in d.keys():\n    pass\n",
            good: "if k in d:\n    pass\n",
        }),
    },
    Rule {
        id: "py/list-first-element",
        name: "list(...)[0] should not be used to get the first element",
        description: "It builds a whole list for one item.",
        message: "Use next(iter(...)).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8519")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(subscript value: (call function: (identifier) @f (#eq? @f "list")) subscript: (integer) @i (#eq? @i "0")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "first = list(items)[0]\n",
            good: "first = next(iter(items))\n",
        }),
    },
    Rule {
        id: "py/sorted-for-extreme",
        name: "sorted() should not be used with indexing to find a minimum or maximum",
        description: "Sorting is O(n log n); min() and max() are O(n).",
        message: "Use min() or max().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8517")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(subscript value: (call function: (identifier) @f (#eq? @f "sorted")) subscript: [(integer) (unary_operator)] @i) @match"#,
            filter: Some(Keep(indexes_first_or_last)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "lowest = sorted(xs)[0]\n",
            good: "lowest = min(xs)\n",
        }),
    },
    Rule {
        id: "py/sum-concatenates-lists",
        name: "sum() should not be used with an empty list to concatenate lists",
        description: "It copies the growing list on every step.",
        message: "Use itertools.chain.from_iterable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8520")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "sum") arguments: (argument_list (_) (list) @l)) @match"#,
            filter: Some(Keep(sum_starts_from_empty_list)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "flat = sum(lists, [])\n",
            good: "flat = list(itertools.chain.from_iterable(lists))\n",
        }),
    },
    Rule {
        id: "py/startswith-or",
        name: "startswith and endswith calls should use tuples instead of multiple calls",
        description: "`s.startswith(('a', 'b'))` replaces two calls.",
        message: "Pass a tuple.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8513")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(boolean_operator) @match"#,
            filter: Some(Keep(repeats_startswith)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "ok = s.startswith('a') or s.startswith('b')\n",
            good: "ok = s.startswith(('a', 'b'))\n",
        }),
    },
    Rule {
        id: "py/loop-variable-reused",
        name: "Loop variables should not be reused in nested loops",
        description: "The inner loop overwrites the outer variable.",
        message: "Rename the inner loop variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8510")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(for_statement) @match"#,
            filter: Some(Find(inner_loop_reuses_variable)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "for i in a:\n    for i in b:\n        pass\n",
            good: "for i in a:\n    for j in b:\n        pass\n",
        }),
    },
    Rule {
        id: "py/unittest-specific-assertion",
        name: "The most specific unittest assertion should be used",
        description: "assertEqual shows both values when it fails; assertTrue(a == b) shows only False.",
        message: "Use assertEqual, assertIsNone or similar.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5906")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "self") (#any-of? @a "assertTrue" "assertFalse"))) @match"#,
            filter: Some(Keep(asserts_a_comparison)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "self.assertTrue(a == b)\n",
            good: "self.assertEqual(a, b)\n",
        }),
    },
    Rule {
        id: "py/skip-without-reason",
        name: "A reason should be provided when skipping a test",
        description: "Without a reason, nobody knows when the skip can go.",
        message: "Add a reason.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1607")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorator) @match"#,
            filter: Some(Keep(skip_lacks_reason)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@unittest.skip\ndef test_a():\n    pass\n",
            good: "@unittest.skip('flaky on CI')\ndef test_a():\n    pass\n",
        }),
    },
    Rule {
        id: "py/numpy-deprecated-alias",
        name: "Deprecated NumPy aliases of built-in types should not be used",
        description: "np.int, np.float and similar were removed in NumPy 1.24.",
        message: "Use the built-in type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6730")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(attribute object: (identifier) @o attribute: (identifier) @a (#any-of? @o "np" "numpy") (#any-of? @a "int" "float" "bool" "object" "str" "complex" "long" "unicode")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = np.int(3)\n",
            good: "x = int(3)\n",
        }),
    },
    Rule {
        id: "py/numpy-randomstate",
        name: "numpy.random.Generator should be preferred to RandomState",
        description: "Generator has better statistical quality and is faster.",
        message: "Use numpy.random.default_rng().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6711")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(attribute object: (attribute object: (identifier) @o attribute: (identifier) @r (#eq? @r "random")) attribute: (identifier) @a (#eq? @a "RandomState") (#any-of? @o "np" "numpy")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "rng = np.random.RandomState(0)\n",
            good: "rng = np.random.default_rng(0)\n",
        }),
    },
    Rule {
        id: "py/pandas-inplace",
        name: "inplace=True should not be used when modifying a Pandas DataFrame",
        description: "It often copies anyway, and it blocks method chaining.",
        message: "Assign the result instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6734")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "inplace") value: (true)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "df.drop('a', axis=1, inplace=True)\n",
            good: "df = df.drop('a', axis=1)\n",
        }),
    },
    Rule {
        id: "py/numpy-where-condition",
        name: "np.nonzero should be preferred over np.where with only a condition",
        description: "where(cond) is nonzero(cond) under a name that suggests it selects between values.",
        message: "Use np.nonzero.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6729")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#any-of? @o "np" "numpy") (#eq? @a "where"))) @match"#,
            filter: Some(Keep(one_argument)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "idx = np.where(mask)\n",
            good: "idx = np.nonzero(mask)\n",
        }),
    },
    Rule {
        id: "py/numpy-array-generator",
        name: "Passing a list to np.array should be preferred over passing a generator",
        description: "np.array can't consume a generator and creates a 0-d object array.",
        message: "Pass a list.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6714")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#any-of? @o "np" "numpy") (#eq? @a "array")) arguments: [(argument_list . (generator_expression)) (generator_expression)]) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "a = np.array(x for x in xs)\n",
            good: "a = np.array([x for x in xs])\n",
        }),
    },
    Rule {
        id: "py/pytz-timezone-argument",
        name: "pytz.timezone should not be passed to the datetime constructor",
        description: "The result is an odd historical offset, not the zone's real one.",
        message: "Use localize(), or zoneinfo.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6887")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "tzinfo") value: (call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "pytz") (#eq? @a "timezone")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = datetime(2024, 1, 1, tzinfo=pytz.timezone('Europe/Amsterdam'))\n",
            good: "d = datetime(2024, 1, 1, tzinfo=ZoneInfo('Europe/Amsterdam'))\n",
        }),
    },
    Rule {
        id: "py/pytz-import",
        name: "zoneinfo should be preferred to pytz",
        description: "zoneinfo is in the standard library since Python 3.9.",
        message: "Use zoneinfo.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6890")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(import_statement name: (dotted_name) @n (#eq? @n "pytz")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import pytz\n",
            good: "from zoneinfo import ZoneInfo\n",
        }),
    },
    Rule {
        id: "py/naive-utc-datetime",
        name: "Timezone-aware datetime objects should be preferred",
        description: "utcnow() returns a naive datetime that looks like local time.",
        message: "Use datetime.now(timezone.utc).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6903")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @a (#any-of? @a "utcnow" "utcfromtimestamp"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "now = datetime.utcnow()\n",
            good: "now = datetime.now(timezone.utc)\n",
        }),
    },
    Rule {
        id: "py/typing-union",
        name: "Union type expressions should be preferred over typing.Union",
        description: "`int | str` is shorter and needs no import.",
        message: "Use the | syntax.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6546")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(subscript value: [(identifier) (attribute)] @v (#match? @v "(^|[.])Union$")) @match
(generic_type [(identifier) (attribute)] @v (#match? @v "(^|[.])Union$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x: Union[int, str] = 1\n",
            good: "x: int | str = 1\n",
        }),
    },
    Rule {
        id: "py/django-null-string-field",
        name: "null=True should not be used on string-based fields",
        description: "Strings then have two empty values, '' and NULL.",
        message: "Remove null=True.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6553")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "models") (#any-of? @a "CharField" "TextField" "EmailField" "SlugField" "URLField")) arguments: (argument_list (keyword_argument name: (identifier) @n (#eq? @n "null") value: (true)))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "name = models.CharField(max_length=10, null=True)\n",
            good: "name = models.CharField(max_length=10)\n",
        }),
    },
    Rule {
        id: "py/django-locals-render",
        name: "locals() should not be passed to a Django render() function",
        description: "It exposes every local variable to the template.",
        message: "Pass an explicit context.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6556")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "render") arguments: (argument_list (call function: (identifier) @l (#eq? @l "locals")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "render(request, 'a.html', locals())\n",
            good: "render(request, 'a.html', {'a': a})\n",
        }),
    },
    Rule {
        id: "py/django-modelform-all",
        name: "Fields of a Django ModelForm should be defined explicitly",
        description: "'__all__' exposes any field added to the model later.",
        message: "List the fields.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6559")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) @l (#eq? @l "fields") right: (string) @r (#match? @r "__all__")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "fields = '__all__'\n",
            good: "fields = ['name', 'email']\n",
        }),
    },
    Rule {
        id: "py/typevar-name",
        name: "TypeVar names should match their assigned variable",
        description: "A mismatch confuses readers and type checkers.",
        message: "Use the same name.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8507")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (identifier) @l right: (call function: (identifier) @f (#any-of? @f "TypeVar" "ParamSpec" "NewType") arguments: (argument_list . (string)))) @match"#,
            filter: Some(Keep(typevar_name_differs)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "T = TypeVar('U')\n",
            good: "T = TypeVar('T')\n",
        }),
    },
    Rule {
        id: "py/duplicate-base-class",
        name: "Classes should not inherit from the same base class multiple times",
        description: "The second listing raises TypeError.",
        message: "Remove the duplicate.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8509")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition superclasses: (argument_list) @match)"#,
            filter: Some(Keep(bases_repeat)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A(B, B):\n    pass\n",
            good: "class A(B, C):\n    pass\n",
        }),
    },
    Rule {
        id: "py/duplicate-class-field",
        name: "Class fields should not be defined multiple times",
        description: "Only the last assignment survives.",
        message: "Remove the earlier definition.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8512")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(class_definition body: (block) @match)"#,
            filter: Some(Find(repeated_class_field)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "class A:\n    x = 1\n    x = 2\n",
            good: "class A:\n    x = 1\n    y = 2\n",
        }),
    },
    Rule {
        id: "py/torch-variable",
        name: "torch.tensor should be used instead of torch.autograd.Variable",
        description: "Variable has been merged into Tensor since PyTorch 0.4.",
        message: "Use torch.tensor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6979")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(attribute object: (attribute attribute: (identifier) @x (#eq? @x "autograd")) attribute: (identifier) @v (#eq? @v "Variable")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "v = torch.autograd.Variable(t)\n",
            good: "v = torch.tensor(t)\n",
        }),
    },
    Rule {
        id: "py/dataloader-workers",
        name: "The num_workers parameter should be specified for DataLoader",
        description: "The default loads data on the main process.",
        message: "Set num_workers.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6983")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#eq? @f "DataLoader")) @match"#,
            filter: Some(Keep(lacks_num_workers)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "loader = DataLoader(ds)\n",
            good: "loader = DataLoader(ds, num_workers=4)\n",
        }),
    },
    Rule {
        id: "py/aws-region-hardcoded",
        name: "AWS region should not be set with a hardcoded string",
        description: "A literal region makes the code awkward to deploy elsewhere.",
        message: "Read the region from configuration.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6262")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "region_name") value: (string)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "s3 = boto3.client('s3', region_name='eu-west-1')\n",
            good: "s3 = boto3.client('s3')\n",
        }),
    },
    Rule {
        id: "py/re-sub-literal",
        name: "str.replace should be preferred to re.sub",
        description: "When the pattern has no special characters, replace() is simpler and faster.",
        message: "Use str.replace().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5361")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "re") (#eq? @a "sub")) arguments: (argument_list . (string))) @match"#,
            filter: Some(Keep(sub_pattern_is_plain_text)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "s = re.sub('foo', 'bar', t)\n",
            good: "s = t.replace('foo', 'bar')\n",
        }),
    },
    Rule {
        id: "py/defaultdict-keyword",
        name: "defaultdict should not be initialized with default_factory as a keyword",
        description: "defaultdict takes the factory as its first positional argument.",
        message: "Pass the factory positionally.",
        category: Bug,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7507")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "default_factory")) @match"#,
            filter: Some(Keep(in_defaultdict)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = defaultdict(default_factory=list)\n",
            good: "d = defaultdict(list)\n",
        }),
    },
    Rule {
        id: "py/dict-comprehension-static-key",
        name: "Dictionary comprehensions should not use a static key",
        description: "Every iteration overwrites the same entry.",
        message: "Use a key that depends on the loop variable.",
        category: Bug,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7506")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(dictionary_comprehension body: (pair key: [(string) (integer)])) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = {'k': v for v in vs}\n",
            good: "d = {v: 1 for v in vs}\n",
        }),
    },
    Rule {
        id: "py/dict-fromkeys-comprehension",
        name: "Populating a dictionary with a constant value should be done with dict.fromkeys",
        description: "A comprehension that maps every key to the same constant is fromkeys.",
        message: "Use dict.fromkeys().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7519")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(dictionary_comprehension body: (pair key: (identifier) value: [(integer) (float) (string) (true) (false) (none)])) @match"#,
            filter: Some(Keep(maps_loop_variable_to_constant)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "d = {k: 0 for k in keys}\n",
            good: "d = dict.fromkeys(keys, 0)\n",
        }),
    },
    Rule {
        id: "py/map-filter-lambda",
        name: "Generators and comprehensions should be preferred over map and filter with a lambda",
        description: "A comprehension says the same without the lambda.",
        message: "Use a comprehension.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7505")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "list" "set" "tuple") arguments: (argument_list (call function: (identifier) @g (#any-of? @g "map" "filter") arguments: (argument_list . (lambda))))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = list(map(lambda a: a + 1, xs))\n",
            good: "x = [a + 1 for a in xs]\n",
        }),
    },
    Rule {
        id: "py/any-all-list",
        name: "List comprehensions should not be used with any() and all()",
        description: "A list is built completely before any() can stop at the first hit.",
        message: "Use a generator expression.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7492")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "any" "all") arguments: (argument_list (list_comprehension))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "ok = any([x > 1 for x in xs])\n",
            good: "ok = any(x > 1 for x in xs)\n",
        }),
    },
    Rule {
        id: "py/literal-in-constructor",
        name: "Creation of collections with literals or comprehensions should not be wrapped",
        description: "`list([...])` copies a list it just made.",
        message: "Drop the constructor.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7496")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "list" "set" "tuple") arguments: (argument_list [(list_comprehension) (list)])) @match"#,
            filter: Some(Keep(one_argument)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "x = list([a for a in b])\n",
            good: "x = [a for a in b]\n",
        }),
    },
    Rule {
        id: "py/empty-collection-membership",
        name: "Membership tests should not use empty collections",
        description: "Nothing is a member of an empty collection.",
        message: "Fix this test.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8503")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator [(list) (tuple) (dictionary) (set)] @e) @match"#,
            filter: Some(Keep(tests_membership_in_empty_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x in []:\n    pass\n",
            good: "if x in allowed:\n    pass\n",
        }),
    },
    Rule {
        id: "py/logging-error-in-except",
        name: "logging.exception() should be used instead of logging.error() in exception handlers",
        description: "exception() logs the traceback too.",
        message: "Use exception().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8572")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#match? @o "(?i)log") (#eq? @a "error"))) @match"#,
            filter: Some(Keep(inside_except_clause)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept ValueError:\n    logger.error('failed')\n",
            good: "try:\n    f()\nexcept ValueError:\n    logger.exception('failed')\n",
        }),
    },
    Rule {
        id: "py/python2-print",
        name: "The print statement should not be used",
        description: "It is Python 2 syntax.",
        message: "Call print().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("PrintStatementUsage")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(print_statement) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "print 'hello'\n",
            good: "print('hello')\n",
        }),
    },
    Rule {
        id: "py/python2-exec",
        name: "The exec statement should not be used",
        description: "It is Python 2 syntax, and exec runs arbitrary code.",
        message: "Call exec(), or better, avoid it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("ExecStatementUsage")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(exec_statement) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "exec 'x = 1'\n",
            good: "exec('x = 1')\n",
        }),
    },
    Rule {
        id: "py/python2-inequality",
        name: "<> should not be used to test inequality",
        description: "It is Python 2 syntax.",
        message: "Use !=.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("InequalityUsage")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(comparison_operator "<>") @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if a <> b:\n    pass\n",
            good: "if a != b:\n    pass\n",
        }),
    },
];

// ---------------------------------------------------- filters

const SCOPE_STOPS: &[&str] = &["function_definition", "class_definition", "lambda"];

/// The first node below `root` that satisfies `pred`, not descending into
/// nodes whose kind is in `stops` (they are still tested themselves).
fn find_in_scope<'t>(
    root: Node<'t>,
    stops: &[&str],
    pred: impl Fn(Node<'t>) -> bool,
) -> Option<Node<'t>> {
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            return Some(n);
        }
        if !stops.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return None;
            }
        }
    }
}

fn statements(block: Node) -> Vec<Node> {
    let mut cursor = block.walk();
    block
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}

fn children_of_kind<'t>(node: Node<'t>, kind: &str) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| n.kind() == kind)
        .collect()
}

fn has_token(node: Node, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| c.kind() == token)
}

/// `a OP b` with exactly two operands: (left, operator text, right).
fn two_operands<'s>(cmp: Node<'s>, src: &'s [u8]) -> Option<(Node<'s>, &'s [u8], Node<'s>)> {
    let mut cursor = cmp.walk();
    let operands: Vec<Node> = cmp
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect();
    let [left, right] = operands.as_slice() else {
        return None;
    };
    let between = &src[left.end_byte()..right.start_byte()];
    Some((*left, between.trim_ascii(), *right))
}

fn contains_call(node: Node) -> bool {
    node.kind() == "call"
        || find_in_scope(node, &[], |n| matches!(n.kind(), "call" | "await")).is_some()
}

fn nearest_function(node: Node, hops_allowed: usize) -> Option<Node> {
    let mut p = node.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if n.kind() == "function_definition" {
            return Some(n);
        }
        hops += 1;
        if hops > hops_allowed {
            return None;
        }
        p = n.parent();
    }
    None
}

fn assigns_to_itself(assignment: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    // `X = X` in a class body copies a name from the enclosing scope.
    let at_class_scope = assignment
        .parent()
        .and_then(|s| s.parent())
        .and_then(|b| b.parent())
        .is_some_and(|c| c.kind() == "class_definition");
    assignment.child_by_field_name("type").is_none()
        && !at_class_scope
        && matches!(left.kind(), "identifier" | "attribute" | "subscript")
        && text(left, src) == text(right, src)
}

fn operands_are_identical(node: Node, src: &[u8]) -> bool {
    let (left, operator, right) = match node.kind() {
        "comparison_operator" => {
            let Some((l, op, r)) = two_operands(node, src) else {
                return false;
            };
            if !matches!(op, b"==" | b"!=" | b"<" | b">" | b"<=" | b">=") {
                return false;
            }
            (l, op, r)
        }
        "boolean_operator" | "binary_operator" => {
            let (Some(l), Some(op), Some(r)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("operator"),
                node.child_by_field_name("right"),
            ) else {
                return false;
            };
            let op = text(op, src);
            let ok = if node.kind() == "boolean_operator" {
                matches!(op, b"and" | b"or")
            } else {
                matches!(op, b"-" | b"/" | b"//" | b"%" | b"^" | b"&" | b"|")
            };
            if !ok {
                return false;
            }
            (l, op, r)
        }
        _ => return false,
    };
    // `x != x` is how NaN is tested for.
    let nan_idiom =
        matches!(operator, b"==" | b"!=") && matches!(left.kind(), "identifier" | "attribute");
    text(left, src) == text(right, src) && !contains_call(left) && !nan_idiom
}

fn repeated_branch_condition<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<&[u8]> = Vec::new();
    if let Some(c) = statement.child_by_field_name("condition") {
        seen.push(text(c, src));
    }
    let mut cursor = statement.walk();
    for clause in statement.children_by_field_name("alternative", &mut cursor) {
        if clause.kind() != "elif_clause" {
            continue;
        }
        let condition = clause.child_by_field_name("condition")?;
        let t = text(condition, src);
        if seen.contains(&t) {
            return Some(condition);
        }
        seen.push(t);
    }
    None
}

fn all_branches_identical(statement: Node, src: &[u8]) -> bool {
    let mut cursor = statement.walk();
    let alternatives: Vec<Node> = statement
        .children_by_field_name("alternative", &mut cursor)
        .collect();
    if !alternatives.iter().any(|a| a.kind() == "else_clause") {
        return false;
    }
    let mut bodies: Vec<&[u8]> = Vec::new();
    if let Some(c) = statement.child_by_field_name("consequence") {
        bodies.push(text(c, src));
    }
    for a in &alternatives {
        let body = if a.kind() == "else_clause" {
            a.child_by_field_name("body")
        } else {
            a.child_by_field_name("consequence")
        };
        match body {
            Some(b) => bodies.push(text(b, src)),
            None => return false,
        }
    }
    bodies.len() >= 2 && bodies.windows(2).all(|w| w[0] == w[1])
}

/// Whether `body` has a `continue` that belongs to the loop around it: not
/// in a nested loop's body, but possibly in that loop's else clause.
fn continues_this_loop(body: Node) -> bool {
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            match child.kind() {
                "continue_statement" => return true,
                "function_definition" | "class_definition" | "lambda" => {}
                "for_statement" | "while_statement" => {
                    if let Some(otherwise) = child.child_by_field_name("alternative") {
                        stack.push(otherwise);
                    }
                }
                _ => stack.push(child),
            }
        }
    }
    false
}

fn loop_always_exits(loop_: Node, _: &[u8]) -> bool {
    let Some(body) = loop_.child_by_field_name("body") else {
        return false;
    };
    let last_exits = statements(body).last().is_some_and(|s| {
        matches!(
            s.kind(),
            "return_statement" | "break_statement" | "raise_statement"
        )
    });
    last_exits && !continues_this_loop(body)
}

fn statement_after_jump<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|pair| {
        matches!(
            pair[0].kind(),
            "return_statement" | "raise_statement" | "break_statement" | "continue_statement"
        )
        .then_some(pair[1])
    })
}

fn jump_in_finally<'t>(finally: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut found: Vec<Node> = Vec::new();
    let mut stack: Vec<(Node, bool)> = Vec::new();
    let mut cursor = finally.walk();
    for child in finally.named_children(&mut cursor) {
        stack.push((child, false));
    }
    while let Some((node, in_loop)) = stack.pop() {
        match node.kind() {
            "function_definition" | "class_definition" | "lambda" => continue,
            "return_statement" => found.push(node),
            "break_statement" | "continue_statement" if !in_loop => found.push(node),
            _ => {}
        }
        let nested = in_loop || matches!(node.kind(), "for_statement" | "while_statement");
        let mut c = node.walk();
        for child in node.named_children(&mut c) {
            stack.push((child, nested));
        }
    }
    found.into_iter().min_by_key(|n| n.start_byte())
}

fn bare_raise_outside_handler(raise: Node, _: &[u8]) -> bool {
    if raise.named_child_count() != 0 {
        return false;
    }
    let mut p = raise.parent();
    let mut hops = 0;
    while let Some(n) = p {
        match n.kind() {
            "except_clause" | "except_group_clause" | "finally_clause" => return false,
            // A function may be called from a handler, so say nothing there.
            "function_definition" | "lambda" => return false,
            _ => {}
        }
        hops += 1;
        if hops > 128 {
            return false;
        }
        p = n.parent();
    }
    true
}

fn is_catch_all(clause: Node, src: &[u8]) -> bool {
    match clause.named_child(0) {
        Some(first) if first.kind() == "block" => true,
        Some(first) => {
            matches!(text(first, src), b"Exception" | b"BaseException")
        }
        None => true,
    }
}

fn except_after_catch_all<'t>(try_: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let clauses = children_of_kind(try_, "except_clause");
    clauses
        .windows(2)
        .find_map(|pair| is_catch_all(pair[0], src).then_some(pair[1]))
}

fn raises_a_literal(raise: Node, _: &[u8]) -> bool {
    raise.named_child(0).is_some_and(|v| {
        matches!(
            v.kind(),
            "string"
                | "concatenated_string"
                | "integer"
                | "float"
                | "list"
                | "dictionary"
                | "tuple"
                | "true"
                | "false"
                | "none"
        )
    })
}

fn returns_a_value<'t>(function: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = function.child_by_field_name("body")?;
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "return_statement" && n.named_child(0).is_some_and(|v| v.kind() != "none")
    })
}

fn outside_any_function(node: Node, _: &[u8]) -> bool {
    let mut p = node.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if matches!(n.kind(), "function_definition" | "lambda") {
            return false;
        }
        hops += 1;
        if hops > 128 {
            return false;
        }
        p = n.parent();
    }
    true
}

fn sign_glued_to_equals(assignment: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    let between = &src[left.end_byte()..right.start_byte()];
    between.len() >= 2
        && between.ends_with(b"=")
        && between[between.len() - 2].is_ascii_whitespace()
}

fn open_mode_is_invalid(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let mode = args
        .iter()
        .filter(|a| a.kind() != "keyword_argument")
        .nth(1)
        .copied()
        .or_else(|| keyword_value(call, "mode", src));
    let Some(mode) = mode.and_then(|m| string_value(m, src)) else {
        return false;
    };
    let count = |set: &[u8]| mode.iter().filter(|b| set.contains(b)).count();
    mode.iter().any(|b| !b"rwxabt+U".contains(b))
        || count(b"rwxa") != 1
        || count(b"bt") > 1
        || count(b"+") > 1
}

fn literal_key(node: Node, src: &[u8]) -> Option<Vec<u8>> {
    match node.kind() {
        "string" => string_value(node, src).map(|v| [b"s:", v].concat()),
        "integer" => Some([b"i:", text(node, src)].concat()),
        "true" | "false" | "none" => Some([b"k:", text(node, src)].concat()),
        _ => None,
    }
}

fn duplicate_dictionary_key<'t>(dict: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for pair in children_of_kind(dict, "pair") {
        let Some(key) = pair
            .child_by_field_name("key")
            .and_then(|k| literal_key(k, src))
        else {
            continue;
        };
        if seen.contains(&key) {
            return Some(pair);
        }
        seen.push(key);
    }
    None
}

fn duplicate_set_value<'t>(set: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut cursor = set.walk();
    for element in set.named_children(&mut cursor) {
        let Some(key) = literal_key(element, src) else {
            continue;
        };
        if seen.contains(&key) {
            return Some(element);
        }
        seen.push(key);
    }
    None
}

fn compares_float_for_equality(cmp: Node, src: &[u8]) -> bool {
    let Some((l, op, r)) = two_operands(cmp, src) else {
        return false;
    };
    let is_float = |n: Node| {
        n.kind() == "float"
            || (n.kind() == "unary_operator"
                && n.named_child(0).is_some_and(|c| c.kind() == "float"))
    };
    matches!(op, b"==" | b"!=") && (is_float(l) || is_float(r))
}

fn asserts_a_constant(assertion: Node, src: &[u8]) -> bool {
    assertion.named_child(0).is_some_and(|c| match c.kind() {
        "true" => true,
        "integer" => text(c, src) != b"0",
        "string" => string_value(c, src).is_some_and(|v| !v.is_empty()),
        _ => false,
    })
}

fn compares_length_with_zero_nonsensically(cmp: Node, src: &[u8]) -> bool {
    let Some((l, op, r)) = two_operands(cmp, src) else {
        return false;
    };
    let is_len = |n: Node| {
        n.kind() == "call"
            && n.child_by_field_name("function")
                .is_some_and(|f| text(f, src) == b"len")
    };
    let is_zero = |n: Node| n.kind() == "integer" && text(n, src) == b"0";
    (is_len(l) && is_zero(r) && matches!(op, b"<" | b">="))
        || (is_zero(l) && is_len(r) && matches!(op, b">" | b"<="))
}

fn compares_with_nan(cmp: Node, src: &[u8]) -> bool {
    let Some((l, op, r)) = two_operands(cmp, src) else {
        return false;
    };
    let is_nan = |n: Node| {
        matches!(
            text(n, src),
            b"np.nan" | b"numpy.nan" | b"math.nan" | b"float('nan')"
        )
    };
    matches!(op, b"==" | b"!=") && (is_nan(l) || is_nan(r))
}

fn isclose_to_zero_without_abs_tol(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "abs_tol", src).is_none()
        && call_arguments(call)
            .iter()
            .filter(|a| a.kind() != "keyword_argument")
            .any(|a| {
                (a.kind() == "integer" && text(*a, src) == b"0")
                    || (a.kind() == "float"
                        && String::from_utf8_lossy(text(*a, src))
                            .parse::<f64>()
                            .is_ok_and(|v| v == 0.0))
            })
}

fn dataclass_enum(decorated: Node, src: &[u8]) -> bool {
    let decorators = children_of_kind(decorated, "decorator");
    let is_dataclass = decorators
        .iter()
        .any(|d| contains_ignoring_case(text(*d, src), b"dataclass"));
    let enum_base = decorated
        .child_by_field_name("definition")
        .and_then(|c| c.child_by_field_name("superclasses"))
        .is_some_and(|s| {
            let t = text(s, src);
            t.windows(4).any(|w| w == b"Enum") || t.windows(4).any(|w| w == b"Flag")
        });
    is_dataclass && enum_base
}

fn typevar_is_both_variances(call: Node, src: &[u8]) -> bool {
    ["covariant", "contravariant"]
        .iter()
        .all(|k| keyword_value(call, k, src).is_some_and(|v| v.kind() == "true"))
}

fn raises_stop_iteration_in_generator(raise: Node, src: &[u8]) -> bool {
    let Some(value) = raise.named_child(0) else {
        return false;
    };
    let name = if value.kind() == "call" {
        value.child_by_field_name("function")
    } else {
        Some(value)
    };
    if !name.is_some_and(|n| text(n, src) == b"StopIteration") {
        return false;
    }
    nearest_function(raise, 128)
        .and_then(|f| f.child_by_field_name("body"))
        .is_some_and(|b| find_in_scope(b, SCOPE_STOPS, |n| n.kind() == "yield").is_some())
}

fn function_never_returns(function: Node, _: &[u8]) -> bool {
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    let items = statements(body);
    // Placeholders (docstring, pass, ...) stand in for an implementation.
    let only_placeholders = items.iter().all(|s| {
        s.kind() == "pass_statement"
            || (s.kind() == "expression_statement"
                && s.named_child(0)
                    .is_some_and(|e| matches!(e.kind(), "string" | "ellipsis")))
    });
    !only_placeholders
        && find_in_scope(body, SCOPE_STOPS, |n| {
            matches!(n.kind(), "return_statement" | "yield" | "raise_statement")
        })
        .is_none()
}

fn in_async_function(node: Node, _: &[u8]) -> bool {
    nearest_function(node, 128).is_some_and(|f| has_token(f, "async"))
}

fn module_init_without_super<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let bases = class.child_by_field_name("superclasses")?;
    if !text(bases, src).windows(6).any(|w| w == b"Module") {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    children_of_kind(body, "function_definition")
        .into_iter()
        .find(|f| {
            f.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"__init__")
                && {
                    let t = text(*f, src);
                    !t.windows(6).any(|w| w == b"super(")
                        && !t.windows(15).any(|w| w == b"Module.__init__")
                }
        })
}

fn reload_with_app_object(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "reload", src).is_some_and(|v| v.kind() == "true")
        && call_arguments(call)
            .iter()
            .find(|a| a.kind() != "keyword_argument")
            .is_some_and(|a| a.kind() != "string")
}

fn pass_with_other_statements<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    if items.len() < 2 {
        return None;
    }
    items.into_iter().find(|s| s.kind() == "pass_statement")
}

fn loop_has_no_break(loop_: Node, _: &[u8]) -> bool {
    loop_.child_by_field_name("body").is_some_and(|b| {
        find_in_scope(
            b,
            &[
                "for_statement",
                "while_statement",
                "function_definition",
                "class_definition",
                "lambda",
            ],
            |n| n.kind() == "break_statement",
        )
        .is_none()
    })
}

fn jump_is_redundant(jump: Node, _: &[u8]) -> bool {
    let Some(block) = jump.parent().filter(|p| p.kind() == "block") else {
        return false;
    };
    if statements(block).last() != Some(&jump) {
        return false;
    }
    let Some(owner) = block.parent() else {
        return false;
    };
    if jump.kind() == "return_statement" {
        jump.named_child_count() == 0
            && owner.kind() == "function_definition"
            && owner.child_by_field_name("body") == Some(block)
    } else {
        matches!(owner.kind(), "for_statement" | "while_statement")
            && owner.child_by_field_name("body") == Some(block)
    }
}

/// Comments before a body's first statement are children of the owner, not
/// of the block, so look in the gap between them.
fn comment_before_body(owner: Node, block: Node, src: &[u8]) -> bool {
    src[owner.start_byte()..block.start_byte()].contains(&b'#')
}

fn function_body_is_only_pass(function: Node, src: &[u8]) -> bool {
    if function
        .parent()
        .is_some_and(|p| p.kind() == "decorated_definition")
    {
        return false;
    }
    function.child_by_field_name("body").is_some_and(|b| {
        b.named_child_count() == 1
            && b.named_child(0)
                .is_some_and(|s| s.kind() == "pass_statement")
            && !comment_before_body(function, b, src)
    })
}

fn statement_block_is_only_pass(block: Node, src: &[u8]) -> bool {
    block.parent().is_some_and(|p| {
        matches!(
            p.kind(),
            "if_statement"
                | "elif_clause"
                | "else_clause"
                | "for_statement"
                | "while_statement"
                | "try_statement"
                | "except_clause"
                | "finally_clause"
                | "with_statement"
        )
    }) && block.named_child_count() == 1
        && block
            .named_child(0)
            .is_some_and(|s| s.kind() == "pass_statement")
        && !block
            .parent()
            .is_some_and(|p| comment_before_body(p, block, src))
}

fn raises_base_exception(raise: Node, src: &[u8]) -> bool {
    let Some(value) = raise.named_child(0) else {
        return false;
    };
    let name = if value.kind() == "call" {
        value.child_by_field_name("function")
    } else {
        Some(value)
    };
    name.is_some_and(|n| matches!(text(n, src), b"Exception" | b"BaseException"))
}

fn string_repeated_often<'t>(module: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut counts: std::collections::HashMap<&[u8], (usize, Node<'t>)> =
        std::collections::HashMap::new();
    let mut cursor = module.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let n = cursor.node();
        if n.kind() == "string"
            && n.parent()
                .is_some_and(|p| p.kind() != "expression_statement")
            && let Some(value) = string_value(n, src).filter(|v| v.len() >= 10)
        {
            counts
                .entry(value)
                .and_modify(|e| e.0 += 1)
                .or_insert((1, n));
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return counts
                    .values()
                    .filter(|(count, _)| *count >= 3)
                    .map(|(_, node)| *node)
                    .min_by_key(|n| n.start_byte());
            }
        }
    }
}

fn negates_a_simple_comparison(not: Node, src: &[u8]) -> bool {
    not.child_by_field_name("argument")
        .and_then(|c| two_operands(c, src))
        .is_some_and(|(_, op, _)| matches!(op, b"==" | b"!=" | b"<" | b">" | b"<=" | b">="))
}

fn parentheses_fit_on_one_line(paren: Node, _: &[u8]) -> bool {
    paren.start_position().row == paren.end_position().row
        && paren.named_child(0).is_some_and(|c| {
            !matches!(
                c.kind(),
                "generator_expression" | "yield" | "tuple" | "list_splat" | "named_expression"
            )
        })
}

fn if_only_wraps_another_if(statement: Node, _: &[u8]) -> bool {
    if statement.child_by_field_name("alternative").is_some() {
        return false;
    }
    let Some(body) = statement.child_by_field_name("consequence") else {
        return false;
    };
    let items = statements(body);
    matches!(items.as_slice(), [only]
        if only.kind() == "if_statement" && only.child_by_field_name("alternative").is_none())
}

fn method_lacks_self(function: Node, src: &[u8]) -> bool {
    let mut owner = function.parent();
    if let Some(decorated) = owner.filter(|p| p.kind() == "decorated_definition") {
        if contains_ignoring_case(text(decorated, src), b"@staticmethod") {
            return false;
        }
        owner = decorated.parent();
    }
    let in_class = owner
        .filter(|b| b.kind() == "block")
        .and_then(|b| b.parent())
        .is_some_and(|c| c.kind() == "class_definition");
    if !in_class {
        return false;
    }
    let Some(params) = function.child_by_field_name("parameters") else {
        return false;
    };
    let items = statements(params);
    let Some(first) = items.first() else {
        return true;
    };
    let name = match first.kind() {
        "identifier" => Some(*first),
        "typed_parameter" | "default_parameter" | "typed_default_parameter" => first
            .child_by_field_name("name")
            .or_else(|| first.named_child(0)),
        _ => None, // *args, **kwargs, separators: self may arrive through them
    };
    name.is_some_and(|n| {
        let t = text(n, src);
        !(matches!(
            t,
            b"self" | b"cls" | b"mcs" | b"mcls" | b"metacls" | b"klass"
        ) || t.starts_with(b"_"))
    })
}

fn joins_inside_a_collection(joined: Node, _: &[u8]) -> bool {
    joined.start_position().row == joined.end_position().row
        && joined
            .parent()
            .is_some_and(|p| matches!(p.kind(), "list" | "tuple" | "set" | "argument_list"))
}

fn compares_a_slice_with_a_literal(cmp: Node, src: &[u8]) -> bool {
    let Some((l, op, r)) = two_operands(cmp, src) else {
        return false;
    };
    if !matches!(op, b"==" | b"!=") {
        return false;
    }
    let is_end_slice = |n: Node| {
        n.kind() == "subscript"
            && n.child_by_field_name("subscript").is_some_and(|s| {
                let t = text(s, src);
                s.kind() == "slice"
                    && ((t.starts_with(b":")
                        && t.len() > 1
                        && t[1..].iter().all(u8::is_ascii_digit))
                        || (t.starts_with(b"-") && t.ends_with(b":")))
            })
    };
    (l.kind() == "string" && is_end_slice(r)) || (r.kind() == "string" && is_end_slice(l))
}

fn compares_type_directly(cmp: Node, src: &[u8]) -> bool {
    let Some((l, op, r)) = two_operands(cmp, src) else {
        return false;
    };
    let is_type_call = |n: Node| {
        n.kind() == "call"
            && n.child_by_field_name("function")
                .is_some_and(|f| text(f, src) == b"type")
            && call_arguments(n).len() == 1
    };
    matches!(op, b"==" | b"!=" | b"is" | b"is not") && (is_type_call(l) || is_type_call(r))
}

fn no_arguments(call: Node, _: &[u8]) -> bool {
    call_arguments(call).is_empty()
}

fn one_argument(call: Node, _: &[u8]) -> bool {
    call_arguments(call).len() == 1
}

fn copies_its_iterable(comprehension: Node, src: &[u8]) -> bool {
    let Some(body) = comprehension.child_by_field_name("body") else {
        return false;
    };
    let parts = statements(comprehension);
    let [_, clause] = parts.as_slice() else {
        return false;
    };
    clause.kind() == "for_in_clause"
        && body.kind() == "identifier"
        && clause
            .child_by_field_name("left")
            .is_some_and(|l| text(l, src) == text(body, src))
}

fn list_copy_is_not_needed(for_: Node, src: &[u8]) -> bool {
    let (Some(call), Some(body)) = (
        for_.child_by_field_name("right"),
        for_.child_by_field_name("body"),
    ) else {
        return false;
    };
    let args = call_arguments(call);
    let [arg] = args.as_slice() else {
        return false;
    };
    if arg.kind() != "identifier" {
        return false;
    }
    let name = text(*arg, src);
    let body_text = text(body, src);
    let mutates = [
        ".remove(",
        ".append(",
        ".pop(",
        ".insert(",
        ".extend(",
        ".clear(",
        ".sort(",
        ".reverse(",
    ]
    .iter()
    .any(|m| {
        let needle = [name, m.as_bytes()].concat();
        body_text
            .windows(needle.len())
            .any(|w| w == needle.as_slice())
    }) || {
        let del = [&b"del "[..], name].concat();
        body_text.windows(del.len()).any(|w| w == del.as_slice())
    };
    !mutates
}

fn collection_call_is_redundant(outer: Node, src: &[u8]) -> bool {
    let Some(inner) = call_arguments(outer).into_iter().next() else {
        return false;
    };
    let name = |c: Node| {
        c.child_by_field_name("function")
            .map_or(&b""[..], |f| text(f, src))
    };
    matches!(
        (name(outer), name(inner)),
        (b"list", b"sorted")
            | (b"sorted", b"list")
            | (b"sorted", b"tuple")
            | (b"sorted", b"sorted")
            | (b"list", b"list")
            | (b"set", b"set")
            | (b"tuple", b"tuple")
    )
}

fn keys_call_is_redundant(node: Node, src: &[u8]) -> bool {
    let is_keys = |c: Node| {
        c.kind() == "call"
            && call_arguments(c).is_empty()
            && c.child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("attribute"))
                .is_some_and(|a| text(a, src) == b"keys")
    };
    if node.kind() == "for_statement" {
        return node.child_by_field_name("right").is_some_and(is_keys);
    }
    two_operands(node, src).is_some_and(|(_, op, r)| matches!(op, b"in" | b"not in") && is_keys(r))
}

fn indexes_first_or_last(subscript: Node, src: &[u8]) -> bool {
    subscript
        .child_by_field_name("subscript")
        .is_some_and(|i| matches!(text(i, src), b"0" | b"-1"))
}

fn sum_starts_from_empty_list(call: Node, _: &[u8]) -> bool {
    let args = call_arguments(call);
    matches!(args.as_slice(), [_, start] if start.kind() == "list" && start.named_child_count() == 0)
}

fn repeats_startswith(logical: Node, src: &[u8]) -> bool {
    let (Some(l), Some(op), Some(r)) = (
        logical.child_by_field_name("left"),
        logical.child_by_field_name("operator"),
        logical.child_by_field_name("right"),
    ) else {
        return false;
    };
    if text(op, src) != b"or" {
        return false;
    }
    let parts = |c: Node| -> Option<(&[u8], &[u8])> {
        let f = c
            .child_by_field_name("function")
            .filter(|_| c.kind() == "call")?;
        let attr = f.child_by_field_name("attribute")?;
        let obj = f.child_by_field_name("object")?;
        matches!(text(attr, src), b"startswith" | b"endswith")
            .then(|| (text(attr, src), text(obj, src)))
    };
    matches!((parts(l), parts(r)), (Some(a), Some(b)) if a == b)
}

fn inner_loop_reuses_variable<'t>(for_: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let left = for_
        .child_by_field_name("left")
        .filter(|l| l.kind() == "identifier")?;
    let body = for_.child_by_field_name("body")?;
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "for_statement"
            && n.child_by_field_name("left")
                .is_some_and(|l| text(l, src) == text(left, src))
    })
}

fn asserts_a_comparison(call: Node, _: &[u8]) -> bool {
    let args = call_arguments(call);
    matches!(args.as_slice(), [only] if only.kind() == "comparison_operator")
}

fn skip_lacks_reason(decorator: Node, src: &[u8]) -> bool {
    let Some(expr) = decorator.named_child(0) else {
        return false;
    };
    let is_skip = |n: Node| {
        matches!(
            text(n, src),
            b"unittest.skip" | b"pytest.mark.skip" | b"skip"
        )
    };
    match expr.kind() {
        "identifier" | "attribute" => is_skip(expr),
        "call" => {
            expr.child_by_field_name("function").is_some_and(is_skip)
                && call_arguments(expr).is_empty()
        }
        _ => false,
    }
}

fn typevar_name_differs(assignment: Node, src: &[u8]) -> bool {
    let (Some(left), Some(call)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    call_arguments(call)
        .first()
        .and_then(|a| string_value(*a, src))
        .is_some_and(|name| name != text(left, src))
}

fn bases_repeat(bases: Node, src: &[u8]) -> bool {
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut cursor = bases.walk();
    for base in bases.named_children(&mut cursor) {
        if !matches!(base.kind(), "identifier" | "attribute") {
            continue;
        }
        let t = text(base, src);
        if seen.contains(&t) {
            return true;
        }
        seen.push(t);
    }
    false
}

fn repeated_class_field<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<&[u8]> = Vec::new();
    for statement in children_of_kind(body, "expression_statement") {
        let Some(assignment) = statement
            .named_child(0)
            .filter(|a| a.kind() == "assignment")
        else {
            continue;
        };
        let Some(left) = assignment
            .child_by_field_name("left")
            .filter(|l| l.kind() == "identifier")
        else {
            continue;
        };
        let t = text(left, src);
        if seen.contains(&t) {
            return Some(statement);
        }
        seen.push(t);
    }
    None
}

fn lacks_num_workers(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "num_workers", src).is_none()
        && !call_arguments(call)
            .iter()
            .any(|a| a.kind() == "dictionary_splat")
}

fn sub_pattern_is_plain_text(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    if args.len() != 3 || args.iter().any(|a| a.kind() == "keyword_argument") {
        return false;
    }
    string_value(args[0], src)
        .is_some_and(|p| !p.is_empty() && !p.iter().any(|b| b".^$*+?{}[]\\|()".contains(b)))
}

fn in_defaultdict(keyword: Node, src: &[u8]) -> bool {
    call_of(keyword).is_some_and(|c| callee_name(c, src) == b"defaultdict")
}

fn maps_loop_variable_to_constant(comprehension: Node, src: &[u8]) -> bool {
    let key = comprehension
        .child_by_field_name("body")
        .and_then(|p| p.child_by_field_name("key"));
    let clause = children_of_kind(comprehension, "for_in_clause")
        .into_iter()
        .next();
    match (key, clause.and_then(|c| c.child_by_field_name("left"))) {
        (Some(k), Some(l)) => text(k, src) == text(l, src),
        _ => false,
    }
}

fn tests_membership_in_empty_literal(cmp: Node, src: &[u8]) -> bool {
    two_operands(cmp, src).is_some_and(|(_, op, r)| {
        matches!(op, b"in" | b"not in")
            && matches!(r.kind(), "list" | "tuple" | "dictionary" | "set")
            && r.named_child_count() == 0
    })
}

fn inside_except_clause(call: Node, _: &[u8]) -> bool {
    let mut p = call.parent();
    let mut hops = 0;
    while let Some(n) = p {
        match n.kind() {
            "except_clause" | "except_group_clause" => return true,
            "function_definition" => return false,
            _ => {}
        }
        hops += 1;
        if hops > 128 {
            return false;
        }
        p = n.parent();
    }
    false
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
    fn identical_operands_and_self_assignment() {
        let src = "a < a\na - a\na and a\nf() < f()\na < b\nx = x\nself.x = self.x\ny = z\nx: int = x\nclass K:\n    P = P\no != o";
        assert_eq!(flagged("py/identical-operands", src), [1, 2, 3]);
        assert_eq!(flagged("py/self-assignment", src), [6, 7]);
    }

    #[test]
    fn if_chains() {
        let src = "if a:\n    f()\nelif b:\n    g()\nelif a:\n    h()\nif c:\n    f()\nelse:\n    f()\nif d:\n    f()\nelif e:\n    f()\nelse:\n    f()\nif k:\n    f()\nelif m:\n    g()";
        assert_eq!(flagged("py/duplicate-condition", src), [5]);
        assert_eq!(flagged("py/identical-branches", src), [7, 11]);
    }

    #[test]
    fn loops_that_run_once() {
        let src = "for x in xs:\n    for y in ys:\n        pass\n    else:\n        continue\n    break\nfor x in xs:\n    return x\nfor x in xs:\n    if x:\n        return x\nwhile True:\n    f()\n    break\nfor x in xs:\n    if x:\n        continue\n    return x";
        assert_eq!(flagged("py/single-iteration-loop", src), [7, 12]);
    }

    #[test]
    fn code_after_jumps() {
        let src = "def f():\n    return 1\n    g()\ndef h():\n    if a:\n        return 1\n    g()\nfor x in xs:\n    continue\n    h()";
        assert_eq!(flagged("py/unreachable-code", src), [3, 10]);
    }

    #[test]
    fn finally_and_handlers() {
        let src = "def f():\n    try:\n        g()\n    finally:\n        return 1\ndef h():\n    try:\n        g()\n    finally:\n        for x in xs:\n            break\ntry:\n    f()\nexcept Exception:\n    pass\nexcept ValueError:\n    pass\ntry:\n    f()\nexcept ValueError:\n    pass\nexcept Exception:\n    pass";
        assert_eq!(flagged("py/jump-in-finally", src), [5]);
        assert_eq!(flagged("py/unreachable-except", src), [16]);
    }

    #[test]
    fn bare_raise() {
        let src = "def f():\n    raise\ndef g():\n    try:\n        h()\n    except ValueError:\n        raise\nraise\nraise ValueError('x')";
        assert_eq!(flagged("py/bare-raise-outside-handler", src), [8]);
    }

    #[test]
    fn constructors_and_scopes() {
        let src = "class A:\n    def __init__(self):\n        return 1\nclass B:\n    def __init__(self):\n        return None\nreturn 3\ndef f():\n    return 4";
        assert_eq!(flagged("py/init-returns-value", src), [3]);
        assert_eq!(flagged("py/return-outside-function", src), [7]);
    }

    #[test]
    fn open_modes() {
        let src = "open(p, 'r')\nopen(p, 'rb')\nopen(p, 'w+')\nopen(p, 'rw')\nopen(p, 'z')\nopen(p, mode='ab')\nopen(p)\nopen(p, m)";
        assert_eq!(flagged("py/open-mode", src), [4, 5]);
    }

    #[test]
    fn duplicates_in_literals() {
        let src = "d = {'a': 1, 'b': 2, 'a': 3}\ne = {1: 1, 2: 2}\ns = {1, 2, 1}\nt = {x, x}";
        assert_eq!(flagged("py/dict-duplicate-key", src), [1]);
        assert_eq!(flagged("py/set-duplicate-value", src), [3]);
    }

    #[test]
    fn comparisons() {
        let src = "x == 0.5\nx == 1\nlen(x) < 0\nlen(x) >= 0\nlen(x) > 0\nx == np.nan\ns[:3] == 'abc'\ns[1:3] == 'abc'\ntype(x) == int\ntype(x, y) == int\nnot a == b\nnot a in b\nx in []\nx in [1]";
        assert_eq!(flagged("py/float-equality", src), [1]);
        assert_eq!(flagged("py/length-comparison", src), [3, 4]);
        assert_eq!(flagged("py/numpy-nan-equality", src), [6]);
        assert_eq!(flagged("py/startswith-slice", src), [7]);
        assert_eq!(flagged("py/type-comparison", src), [9]);
        assert_eq!(flagged("py/inverted-boolean", src), [11]);
        assert_eq!(flagged("py/empty-collection-membership", src), [13]);
    }

    #[test]
    fn redundant_jumps_and_empty_bodies() {
        let src = "def f():\n    g()\n    return\ndef h():\n    return\n    g()\nfor x in xs:\n    g()\n    continue\ndef e():\n    pass\n@overload\ndef o():\n    pass\ntry:\n    f()\nexcept ValueError:\n    pass\ndef c():\n    # intentional\n    pass";
        assert_eq!(flagged("py/redundant-jump", src), [3, 9]);
        assert_eq!(flagged("py/empty-function", src), [10]);
        assert_eq!(flagged("py/empty-nested-block", src), [18]);
    }

    #[test]
    fn methods_without_self() {
        let src = "class A:\n    def a():\n        pass\n    def b(self):\n        pass\n    def c(x):\n        pass\n    @staticmethod\n    def d():\n        pass\n    @classmethod\n    def e(cls):\n        pass\n    def f(*args):\n        pass\n    def _g(_):\n        pass\ndef free():\n    pass";
        assert_eq!(flagged("py/method-without-self", src), [2, 6]);
    }

    #[test]
    fn collection_idioms() {
        let src = "list(sorted(x))\nsorted(list(x))\nsorted(x)\nreversed(sorted(x))\nset(sorted(x))\nset(reversed(x))\nx = list()\ny = [a for a in b]\nz = [a for a in b if a]\nk in d.keys()\nfor k in d.keys():\n    pass\nlist(xs)[0]\nsorted(xs)[0]\nsorted(xs)[1]\nsum(ls, [])\nsum(ls)";
        assert_eq!(flagged("py/redundant-collection-call", src), [1, 2]);
        assert_eq!(flagged("py/reversed-sorted", src), [4]);
        assert_eq!(flagged("py/set-of-sorted", src), [5]);
        assert_eq!(flagged("py/reversed-wrapper", src), [6]);
        assert_eq!(flagged("py/empty-literal", src), [7]);
        assert_eq!(flagged("py/comprehension-copy", src), [8]);
        assert_eq!(flagged("py/dict-keys-iteration", src), [10, 11]);
        assert_eq!(flagged("py/list-first-element", src), [13]);
        assert_eq!(flagged("py/sorted-for-extreme", src), [14]);
        assert_eq!(flagged("py/sum-concatenates-lists", src), [16]);
    }

    #[test]
    fn copying_a_list_for_a_reason() {
        let src = "for x in list(items):\n    f(x)\nfor x in list(items):\n    items.remove(x)\nfor x in list(d.items()):\n    f(x)";
        assert_eq!(flagged("py/list-in-for", src), [1]);
    }

    #[test]
    fn async_blocking_calls() {
        let src = "async def f():\n    time.sleep(1)\n    requests.get(u)\n    open(p)\ndef g():\n    time.sleep(1)\n    open(p)";
        assert_eq!(flagged("py/async-blocking-sleep", src), [2]);
        assert_eq!(flagged("py/async-blocking-http", src), [3]);
        assert_eq!(flagged("py/async-blocking-open", src), [4]);
    }

    #[test]
    fn strings_and_parens() {
        let src = "a = ['x' 'y', 'z']\nb = 'x' 'y'\nif (x > 1):\n    pass\nif (\n    x > 1\n):\n    pass\nx = 'a long literal'\ny = 'a long literal'\nz = 'a long literal'\ns = 'short'";
        assert_eq!(flagged("py/implicit-string-concatenation", src), [1]);
        assert_eq!(flagged("py/redundant-parentheses", src), [3]);
        assert_eq!(flagged("py/duplicated-string", src), [9]);
    }

    #[test]
    fn needless_pass_and_misleading_operators() {
        let src = "def f():\n    g()\n    pass\ndef h():\n    pass\nx =+ 1\ny = +1\nz=-1\nw = -1";
        assert_eq!(flagged("py/needless-pass", src), [3]);
        assert_eq!(flagged("py/misleading-operator", src), [6]);
    }

    #[test]
    fn conditions_and_merging() {
        let src = "if True:\n    pass\nif a:\n    if b:\n        f()\nif a:\n    if b:\n        f()\n    else:\n        g()\nx = a if p else (b if q else c)";
        assert_eq!(flagged("py/constant-condition", src), [1]);
        assert_eq!(flagged("py/mergeable-if", src), [3]);
        assert_eq!(flagged("py/nested-conditional", src), [11]);
    }

    #[test]
    fn tests_and_decorators() {
        let src = "@unittest.skip\ndef a(): pass\n@unittest.skip('why')\ndef b(): pass\n@pytest.mark.skip()\ndef c(): pass\nself.assertTrue(a == b)\nself.assertTrue(a)\nassert True\nassert x";
        assert_eq!(flagged("py/skip-without-reason", src), [1, 5]);
        assert_eq!(flagged("py/unittest-specific-assertion", src), [7]);
        assert_eq!(flagged("py/assert-constant", src), [9]);
    }

    #[test]
    fn classes() {
        let src = "class A(B, B):\n    x = 1\n    x = 2\n    y = 3\nclass C(D, E):\n    pass\n@dataclass\nclass F(Enum):\n    A = 1\nclass G(nn.Module):\n    def __init__(self):\n        self.a = 1\nclass H(nn.Module):\n    def __init__(self):\n        super().__init__()";
        assert_eq!(flagged("py/duplicate-base-class", src), [1]);
        assert_eq!(flagged("py/duplicate-class-field", src), [3]);
        assert_eq!(flagged("py/enum-dataclass", src), [7]);
        assert_eq!(flagged("py/torch-module-init", src), [11]);
    }

    #[test]
    fn exceptions() {
        let src = "ValueError('x')\nraise Exception('x')\nraise ValueError('x')\nraise 'x'\ndef g():\n    yield 1\n    raise StopIteration\ndef h():\n    raise StopIteration";
        assert_eq!(flagged("py/exception-not-raised", src), [1]);
        assert_eq!(flagged("py/generic-exception-raised", src), [2]);
        assert_eq!(flagged("py/raise-non-exception", src), [4]);
        assert_eq!(flagged("py/stopiteration-in-generator", src), [7]);
    }

    #[test]
    fn properties_and_loop_variables() {
        let src = "class A:\n    @property\n    def a(self):\n        self.x = 1\n    @property\n    def b(self):\n        return 1\n    @property\n    def c(self):\n        ...\nfor i in a:\n    for i in b:\n        pass\nfor i in a:\n    for j in b:\n        pass";
        assert_eq!(flagged("py/property-without-return", src), [3]);
        assert_eq!(flagged("py/loop-variable-reused", src), [12]);
    }

    #[test]
    fn small_library_rules() {
        let src = "re.sub('foo', 'bar', t)\nre.sub('fo+', 'bar', t)\nre.sub('foo', 'bar', t, flags=re.I)\nd = {'k': v for v in vs}\ne = {k: 0 for k in ks}\nf = {k: v for k in ks}\nlogger = 1\nt = TypeVar('U')\nU = TypeVar('U')\nl = DataLoader(ds)\nm = DataLoader(ds, num_workers=2)";
        assert_eq!(flagged("py/re-sub-literal", src), [1]);
        assert_eq!(flagged("py/dict-comprehension-static-key", src), [4]);
        assert_eq!(flagged("py/dict-fromkeys-comprehension", src), [5]);
        assert_eq!(flagged("py/typevar-name", src), [8]);
        assert_eq!(flagged("py/dataloader-workers", src), [10]);
    }
}
