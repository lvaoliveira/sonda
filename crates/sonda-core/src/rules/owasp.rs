//! The OWASP Top 10, 2021 and 2025 editions. A rule records its 2021
//! categories (as SonarQube reports them); its 2025 categories follow from
//! its CWE ids and OWASP's own list of the CWEs each 2025 category covers.

/// An edition of the OWASP Top 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Edition {
    Y2021,
    Y2025,
}

impl Edition {
    /// Newest first: the one to show by default.
    pub const ALL: [Edition; 2] = [Edition::Y2025, Edition::Y2021];

    pub fn year(self) -> u16 {
        match self {
            Edition::Y2021 => 2021,
            Edition::Y2025 => 2025,
        }
    }
}

/// One category of one edition, such as A05:2025 Injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Owasp {
    edition: Edition,
    /// 1 to 10.
    rank: u8,
}

const IDS: [&str; 10] = [
    "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10",
];

const TITLES_2021: [&str; 10] = [
    "Broken Access Control",
    "Cryptographic Failures",
    "Injection",
    "Insecure Design",
    "Security Misconfiguration",
    "Vulnerable and Outdated Components",
    "Identification and Authentication Failures",
    "Software and Data Integrity Failures",
    "Security Logging and Monitoring Failures",
    "Server-Side Request Forgery",
];

const TITLES_2025: [&str; 10] = [
    "Broken Access Control",
    "Security Misconfiguration",
    "Software Supply Chain Failures",
    "Cryptographic Failures",
    "Injection",
    "Insecure Design",
    "Authentication Failures",
    "Software or Data Integrity Failures",
    "Security Logging and Alerting Failures",
    "Mishandling of Exceptional Conditions",
];

impl Owasp {
    pub(crate) const fn new(edition: Edition, rank: u8) -> Owasp {
        Owasp { edition, rank }
    }

    /// The edition's ten categories, in order.
    pub fn all(edition: Edition) -> impl Iterator<Item = Owasp> {
        (1..=10).map(move |rank| Owasp::new(edition, rank))
    }

    pub fn edition(self) -> Edition {
        self.edition
    }

    /// `A01` to `A10`.
    pub fn id(self) -> &'static str {
        IDS[usize::from(self.rank - 1)]
    }

    pub fn title(self) -> &'static str {
        let titles = match self.edition {
            Edition::Y2021 => &TITLES_2021,
            Edition::Y2025 => &TITLES_2025,
        };
        titles[usize::from(self.rank - 1)]
    }
}

/// The 2021 categories, for the catalog's standards table.
pub(crate) mod y2021 {
    use super::{Edition, Owasp};

    pub(crate) const A01: Owasp = Owasp::new(Edition::Y2021, 1);
    pub(crate) const A02: Owasp = Owasp::new(Edition::Y2021, 2);
    pub(crate) const A03: Owasp = Owasp::new(Edition::Y2021, 3);
    pub(crate) const A04: Owasp = Owasp::new(Edition::Y2021, 4);
    pub(crate) const A05: Owasp = Owasp::new(Edition::Y2021, 5);
    pub(crate) const A07: Owasp = Owasp::new(Edition::Y2021, 7);
    pub(crate) const A08: Owasp = Owasp::new(Edition::Y2021, 8);
}

/// The CWEs each 2025 category covers, A01 to A10, from each category's
/// "List of Mapped CWEs" in github.com/OWASP/Top10 (2025/docs/en, commit
/// 3a31f35). No CWE is in two categories.
const CWE_2025: [&[u16]; 10] = [
    // A01
    &[
        22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379,
        402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862, 863,
        918, 922, 1275,
    ],
    // A02
    &[
        5, 11, 13, 15, 16, 260, 315, 489, 526, 547, 611, 614, 776, 942, 1004, 1174,
    ],
    // A03
    &[447, 1035, 1104, 1329, 1357, 1395],
    // A04
    &[
        261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335,
        336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241,
    ],
    // A05
    &[
        20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104,
        112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917,
    ],
    // A06
    &[
        73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454,
        472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841,
        1021, 1022, 1125,
    ],
    // A07
    &[
        258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305,
        306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392,
        1393,
    ],
    // A08
    &[
        345, 353, 426, 427, 494, 502, 506, 509, 565, 784, 829, 830, 915, 926,
    ],
    // A09
    &[117, 221, 223, 532, 778],
    // A10
    &[
        209, 215, 234, 235, 248, 252, 274, 280, 369, 390, 391, 394, 396, 397, 460, 476, 478, 484,
        550, 636, 703, 754, 755, 756,
    ],
];

/// The 2025 categories the CWE ids `cwe` fall into, in order.
pub(crate) fn from_cwe_2025(cwe: &[u16]) -> Vec<Owasp> {
    Owasp::all(Edition::Y2025)
        .filter(|o| {
            CWE_2025[usize::from(o.rank - 1)]
                .iter()
                .any(|c| cwe.contains(c))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owasp_2025_lists_are_sorted_and_disjoint() {
        let mut seen = std::collections::HashSet::new();
        for list in CWE_2025 {
            assert!(list.windows(2).all(|w| w[0] < w[1]));
            for c in list {
                assert!(seen.insert(c), "CWE-{c} in two categories");
            }
        }
        // Each category page's own count.
        let counts: Vec<usize> = CWE_2025.iter().map(|l| l.len()).collect();
        assert_eq!(counts, [40, 16, 6, 32, 37, 39, 36, 14, 5, 24]);
    }

    #[test]
    fn categories_from_cwe() {
        let a05 = Owasp::new(Edition::Y2025, 5);
        assert_eq!(from_cwe_2025(&[79, 95]), [a05]);
        assert_eq!((a05.id(), a05.title()), ("A05", "Injection"));
        assert_eq!(from_cwe_2025(&[120, 242]), []);
        assert_eq!(
            Owasp::new(Edition::Y2021, 5).title(),
            "Security Misconfiguration"
        );
    }
}
