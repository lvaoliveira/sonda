//! CVSS v3.0/v3.1 base scores from their vector strings, by the
//! specification's formula. Advisories carry the vector, not the score.

/// `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` → 7.2. `None` for other
/// versions and malformed vectors.
pub fn base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    if !matches!(parts.next()?, "CVSS:3.0" | "CVSS:3.1") {
        return None;
    }
    let mut metric = |name: &str| -> Option<&str> {
        let (key, value) = parts.next()?.split_once(':')?;
        (key == name).then_some(value)
    };
    let av = match metric("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match metric("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = metric("PR")?;
    let ui = match metric("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let changed = match metric("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let pr = match (pr, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let mut cia = [0.0; 3];
    for (slot, name) in cia.iter_mut().zip(["C", "I", "A"]) {
        *slot = match metric(name)? {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => return None,
        };
    }
    // Temporal and environmental metrics may follow; they don't change the
    // base score.

    let iss = 1.0 - (1.0 - cia[0]) * (1.0 - cia[1]) * (1.0 - cia[2]);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let raw = if changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Some(round_up(raw.min(10.0)))
}

/// CVSS 3.1's Roundup: the smallest one-decimal number not below `x`,
/// computed on integers to avoid floating-point surprises.
fn round_up(x: f64) -> f64 {
    let int = (x * 100_000.0).round() as i64;
    if int % 10_000 == 0 {
        int as f64 / 100_000.0
    } else {
        ((int / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_match_published_ones() {
        // CVE-2021-23337 (lodash), CVE-2020-26235 (time), CVE-2021-44228
        // (log4shell), and a scope-changed XSS.
        for (vector, score) in [
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
            ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 6.2),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ] {
            assert_eq!(base_score(vector), Some(score), "{vector}");
        }
        // With temporal metrics after the base ones.
        assert_eq!(
            base_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H/E:P"),
            Some(7.2)
        );
    }

    #[test]
    fn other_versions_and_malformed_vectors_have_no_score() {
        for v in [
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AC:L",
            "",
        ] {
            assert_eq!(base_score(v), None, "{v}");
        }
    }
}
