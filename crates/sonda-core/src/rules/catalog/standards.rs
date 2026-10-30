//! The CWE weaknesses and OWASP Top 10 (2021) categories each rule relates
//! to: facts about the rules, shown in `sonda rules`, SARIF and the web app.
//! For rules that cover a SonarQube key exactly, `scripts/sonar_parity.py`
//! reports where these differ from SonarQube's.

use crate::rules::Owasp;
use crate::rules::owasp::y2021::*;

/// (rule id, CWE ids, OWASP Top 10 2021 categories), in catalog order. The
/// 2025 categories are derived from the CWE ids.
pub(crate) static STANDARDS: &[(&str, &[u16], &[Owasp])] = &[
    ("js/no-eval", &[95], &[A03]),
    ("js/no-new-function", &[95], &[A03]),
    ("js/inner-html", &[79], &[A03]),
    ("js/tls-unverified", &[295], &[A02, A05, A07]),
    ("js/weak-hash", &[1240], &[A02]),
    ("js/weak-tls", &[295, 326, 327], &[A02, A07]),
    ("js/weak-key", &[326], &[A02]),
    ("js/tls-hostname-unverified", &[297], &[A02, A05, A07]),
    ("js/weak-cipher", &[326, 327], &[A02]),
    ("js/insecure-cipher-mode", &[327, 780], &[A02]),
    ("js/jwt-none", &[347], &[A02]),
    ("js/world-permissions", &[266, 732], &[A01, A04]),
    ("js/public-tmp", &[377, 379], &[A01]),
    ("js/window-open-opener", &[1022], &[A05]),
    ("js/jsx-target-blank", &[1022], &[A05]),
    ("js/command-path", &[426, 427], &[A08]),
    ("js/hardcoded-password", &[259, 798], &[A07]),
    ("js/hardcoded-secret", &[798], &[A07]),
    ("js/xxe", &[611, 827], &[A05]),
    ("js/cookie-not-secure", &[311, 315, 614], &[A04, A05]),
    ("js/cookie-not-httponly", &[1004], &[A05]),
    ("js/cors-any-origin", &[346, 942], &[A05, A07]),
    ("js/csp-disabled", &[79], &[A05]),
    ("js/nosniff-disabled", &[79, 436], &[A05]),
    ("js/unsafe-referrer-policy", &[200], &[A01]),
    ("js/hsts-disabled", &[319, 693], &[A05]),
    ("py/no-eval", &[95], &[A03]),
    ("py/subprocess-shell", &[78], &[A03]),
    ("py/pickle-load", &[502], &[A08]),
    ("java/weak-hash", &[1240], &[A02]),
    ("c/no-gets", &[120, 242], &[]),
    ("c/unsafe-string-function", &[120, 676], &[]),
];
