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
    ("js/angular-sanitizer-bypass", &[79], &[A03]),
    ("js/error-handler-middleware", &[215, 489], &[A05]),
    ("js/csrf-methods-ignored", &[352], &[A01]),
    ("js/upload-without-limit", &[400, 434], &[A04]),
    ("js/template-built-dynamically", &[20], &[A03]),
    ("js/express-version-disclosure", &[200], &[A05]),
    ("js/cleartext-url", &[200, 319], &[A02]),
    ("js/math-random-secret", &[326, 330, 338, 1241], &[A02]),
    // SonarQube files this under A05 (2021), but CWE-400 and CWE-770 are in no
    // 2025 category, so the 2021 one is left out to keep the two editions consistent.
    ("js/upload-size-too-large", &[400, 770], &[]),
    ("cdk/bucket-allows-plain-http", &[319], &[]),
    ("cdk/bucket-without-versioning", &[16], &[]),
    ("cdk/bucket-public-access", &[284, 732], &[]),
    ("cdk/bucket-public-access-not-blocked", &[284, 732], &[]),
    ("cdk/volume-not-encrypted", &[311], &[]),
    ("cdk/database-not-encrypted", &[311], &[]),
    ("cdk/search-domain-not-encrypted", &[311], &[]),
    ("cdk/notebook-not-encrypted", &[312], &[]),
    ("cdk/topic-not-encrypted", &[311], &[]),
    ("cdk/queue-not-encrypted", &[311], &[]),
    ("cdk/file-system-not-encrypted", &[311], &[]),
    ("cdk/api-method-without-auth", &[306], &[]),
    ("cdk/publicly-accessible", &[284, 668, 732, 1327], &[]),
    ("cdk/admin-port-open-to-world", &[284], &[A01]),
    ("cdk/policy-grants-everything", &[284, 732], &[]),
    ("cdk/policy-for-everyone", &[284, 732], &[]),
    ("py/no-eval", &[95], &[A03]),
    ("py/subprocess-shell", &[78], &[A03]),
    ("py/pickle-load", &[502], &[A08]),
    ("java/weak-hash", &[1240], &[A02]),
    ("c/no-gets", &[120, 242], &[]),
    ("c/unsafe-string-function", &[120, 676], &[]),
];
