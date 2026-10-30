//! Structural rules for every language, implemented in `analysis.rs`.

use super::*;

pub(super) static RULES: &[Rule] = &[
    // ---- Structural rules (all languages, implemented in analysis.rs) ----
    Rule {
        id: crate::rules::COGNITIVE_COMPLEXITY,
        name: "Cognitive complexity of functions should not be too high",
        description: "Deeply nested and heavily branched functions are hard to understand and change. \
                      Cognitive complexity adds 1 per branch, loop, catch or boolean-operator sequence, \
                      plus the current nesting depth for nested structures. Threshold: `thresholds.cognitive_complexity`.",
        message: "",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S3776")],
        check: Check::Structural,
        example: None,
    },
    Rule {
        id: crate::rules::FUNCTION_LENGTH,
        name: "Functions should not be too long",
        description: "Long functions usually do too many things. Threshold: `thresholds.function_lines`.",
        message: "",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S138")],
        check: Check::Structural,
        example: None,
    },
    Rule {
        id: crate::rules::TOO_MANY_PARAMETERS,
        name: "Functions should not have too many parameters",
        description: "Many parameters make calls hard to read; group them into an object. \
                      Threshold: `thresholds.parameters`.",
        message: "",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S107")],
        check: Check::Structural,
        example: None,
    },
    Rule {
        id: crate::rules::TODO_COMMENT,
        name: "Track TODO and FIXME comments",
        description: "TODO, FIXME and XXX comments mark unfinished work that should be tracked.",
        message: "",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 0,
        sonar: &[exact("S1134"), exact("S1135")],
        check: Check::Structural,
        example: None,
    },
];
