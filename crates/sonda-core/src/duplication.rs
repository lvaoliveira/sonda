//! Copy-paste detection over token streams (exact clones).
//!
//! Every window of `min_tokens` consecutive tokens is hashed with a rolling
//! hash. Each repeated window is paired with the first occurrence of that
//! window, then extended token by token into a maximal block.
//!
//! Memory: the tokens, then 16 bytes per window while the windows are
//! sorted by hash, then 8 per window. (A hash map from each window's hash to
//! its first occurrence took over 2 GB on VS Code's 34 million tokens.)
//!
//! Apart from that sort, linear time, even on hostile input: no block starts inside a copy that
//! is already reported, so copy ranges are disjoint and the total extension
//! work is bounded by the number of tokens. (Without that rule, a file
//! repeating one token was quadratic: 80,000 lines took 75 s.)

use crate::analysis::Token;
use rayon::slice::ParallelSliceMut;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Span {
    pub file: usize,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Block {
    pub original: Span,
    pub copy: Span,
}

#[derive(Debug, Default)]
pub struct Duplication {
    /// Duplicated 1-based line numbers, per file index.
    pub lines: Vec<BTreeSet<usize>>,
    pub blocks: Vec<Block>,
}

const BASE: u64 = 0x0000_0100_0000_01b3;

pub fn detect(files: &[&[Token]], min_tokens: usize, min_lines: usize) -> Duplication {
    let w = min_tokens.max(1);
    let first = FirstOccurrences::new(files, w);
    let windows = Windows {
        files,
        first: &first,
        w,
    };

    let mut out = Duplication {
        lines: vec![BTreeSet::new(); files.len()],
        blocks: Vec::new(),
    };
    for fb in 0..files.len() {
        // The token index up to which this file's copies are reported.
        let mut copied_until = 0;
        for pb in 0..first.windows(fb) {
            let Some((block, end)) = windows.copy_at(fb, pb, copied_until) else {
                continue;
            };
            copied_until = end;
            if block.copy.end_line - block.copy.start_line + 1 < min_lines {
                continue;
            }
            for s in [block.original, block.copy] {
                out.lines[s.file].extend(s.start_line..=s.end_line);
            }
            out.blocks.push(block);
        }
    }
    out
}

/// The files' tokens and their windows, each `w` tokens long.
struct Windows<'a> {
    files: &'a [&'a [Token]],
    first: &'a FirstOccurrences,
    w: usize,
}

impl Windows<'_> {
    /// The block whose copy starts at token `pb` of file `fb`, and the token
    /// its copy ends before; `None` when that window starts no new copy:
    /// it's the first of its hash, overlaps it, is inside a copy already
    /// reported (before `copied_until`) or one that started a token earlier,
    /// or only shares its hash.
    fn copy_at(&self, fb: usize, pb: usize, copied_until: usize) -> Option<(Block, usize)> {
        let w = self.w;
        let (a, repeated) = self.first.of(fb, pb);
        if !repeated || a == self.first.index(fb, pb) || pb < copied_until {
            return None;
        }
        let (fa, pa) = self.first.position(a);
        if overlaps(fa, pa, fb, pb, w) || self.first.extends_previous_block((fa, pa), (fb, pb)) {
            return None;
        }
        let (ta, tb) = (self.files[fa], self.files[fb]);
        if !same_tokens(&ta[pa..pa + w], &tb[pb..pb + w]) {
            return None; // hash collision
        }
        let len = match_length(ta, pa, tb, pb, w, fa == fb);
        let span = |file: usize, tokens: &[Token], start: usize| Span {
            file,
            start_line: tokens[start].line,
            end_line: tokens[start + len - 1].line,
        };
        let block = Block {
            original: span(fa, ta, pa),
            copy: span(fb, tb, pb),
        };
        Some((block, pb + len))
    }
}

/// Each window's first occurrence: the earliest window, in file order, with
/// the same hash. Windows are numbered across files, file by file.
struct FirstOccurrences {
    /// The number of each file's first window, then the total.
    starts: Vec<usize>,
    /// Per window: its first occurrence's number, shifted left one bit, with
    /// the low bit set when its hash repeats.
    first: Vec<u64>,
}

impl FirstOccurrences {
    fn new(files: &[&[Token]], w: usize) -> Self {
        let mut starts = Vec::with_capacity(files.len() + 1);
        let mut by_hash: Vec<(u64, u64)> = Vec::new();
        for tokens in files {
            starts.push(by_hash.len());
            let start = by_hash.len() as u64;
            by_hash.extend(window_hashes(tokens, w).into_iter().zip(start..));
        }
        starts.push(by_hash.len());
        // Within a hash, by window number: the first is the first occurrence.
        by_hash.par_sort_unstable();
        let mut first = vec![0u64; by_hash.len()];
        for group in by_hash.chunk_by(|a, b| a.0 == b.0) {
            let packed = group[0].1 << 1 | u64::from(group.len() > 1);
            for &(_, i) in group {
                first[i as usize] = packed;
            }
        }
        Self { starts, first }
    }

    /// How many windows file `f` has.
    fn windows(&self, f: usize) -> usize {
        self.starts[f + 1] - self.starts[f]
    }

    /// The number of window `p` of file `f`.
    fn index(&self, f: usize, p: usize) -> usize {
        self.starts[f] + p
    }

    /// The number of the first occurrence of window `p` of file `f`, and
    /// whether its hash repeats.
    fn of(&self, f: usize, p: usize) -> (usize, bool) {
        let packed = self.first[self.index(f, p)];
        ((packed >> 1) as usize, packed & 1 == 1)
    }

    /// The (file, position) of window number `i`. Files without windows share
    /// their start with the next file; the last of those is the one with it.
    fn position(&self, i: usize) -> (usize, usize) {
        let f = self.starts.partition_point(|&s| s <= i) - 1;
        (f, i - self.starts[f])
    }

    /// Whether the copy at `b` of the window at `a` is covered by a block
    /// that started one token earlier: the window before `b` first occurs
    /// just before `a` (and so has the same hash).
    fn extends_previous_block(&self, (fa, pa): (usize, usize), (fb, pb): (usize, usize)) -> bool {
        pa > 0 && pb > 0 && self.of(fb, pb - 1).0 == self.index(fa, pa - 1)
    }
}

fn same_tokens(a: &[Token], b: &[Token]) -> bool {
    a.iter().zip(b).all(|(x, y)| x.hash == y.hash)
}

/// How far the copy at `tb[pb..]` of `ta[pa..]` goes, from its first `w`
/// tokens on; within one file, the copy never reaches into the original.
fn match_length(
    ta: &[Token],
    pa: usize,
    tb: &[Token],
    pb: usize,
    w: usize,
    same_file: bool,
) -> usize {
    let mut len = w;
    while pa + len < ta.len()
        && pb + len < tb.len()
        && ta[pa + len].hash == tb[pb + len].hash
        && !(same_file && pa + len >= pb)
    {
        len += 1;
    }
    len
}

fn overlaps(fa: usize, pa: usize, fb: usize, pb: usize, w: usize) -> bool {
    fa == fb && pa.abs_diff(pb) < w
}

fn window_hashes(tokens: &[Token], w: usize) -> Vec<u64> {
    if tokens.len() < w {
        return Vec::new();
    }
    let top = BASE.wrapping_pow(w as u32 - 1);
    let mut h = 0u64;
    for t in &tokens[..w] {
        h = h.wrapping_mul(BASE).wrapping_add(t.hash);
    }
    let mut out = Vec::with_capacity(tokens.len() - w + 1);
    out.push(h);
    for i in w..tokens.len() {
        h = h
            .wrapping_sub(tokens[i - w].hash.wrapping_mul(top))
            .wrapping_mul(BASE)
            .wrapping_add(tokens[i].hash);
        out.push(h);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// One token per character, one line per `\n`.
    fn tokens(s: &str) -> Vec<Token> {
        let mut line = 1;
        let mut out = Vec::new();
        for c in s.chars() {
            if c == '\n' {
                line += 1;
            } else {
                out.push(Token {
                    hash: c as u64,
                    line,
                });
            }
        }
        out
    }

    /// Regression: one repeated token made detection quadratic (each window
    /// re-extended a block back to the start); 80,000 lines took 75 s in a
    /// release build. Linear, this takes milliseconds even unoptimized; the
    /// bound is two orders of magnitude above that.
    #[test]
    fn repetitive_input_is_linear() {
        let n = 200_000;
        let same: Vec<Token> = (0..n)
            .map(|i| Token {
                hash: 7,
                line: i + 1,
            })
            .collect();
        let started = std::time::Instant::now();
        let d = detect(&[&same], 100, 10);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        // Still reported: everything after the first window repeats it.
        assert!(d.lines[0].len() > n - 200);
    }

    #[test]
    fn rolling_hash_matches_direct_hash() {
        let t = tokens("abcdefgh");
        let rolled = window_hashes(&t, 3);
        let direct = window_hashes(&t[2..5], 3);
        assert_eq!(rolled[2], direct[0]);
    }

    #[test]
    fn finds_block_across_files_and_extends_it() {
        let a = tokens("xx\nabc\ndef\nghi\nyy");
        let b = tokens("zz\nabc\ndef\nghi\nqq");
        let d = detect(&[&a, &b], 4, 2);
        assert_eq!(d.blocks.len(), 1);
        let blk = d.blocks[0];
        assert_eq!((blk.original.start_line, blk.original.end_line), (2, 4));
        assert_eq!(
            (blk.copy.file, blk.copy.start_line, blk.copy.end_line),
            (1, 2, 4)
        );
        assert_eq!(d.lines[0], BTreeSet::from([2, 3, 4]));
    }

    #[test]
    fn respects_min_lines_and_self_overlap() {
        let a = tokens("abcdef\nabcdef");
        assert_eq!(detect(&[&a], 4, 3).blocks.len(), 0);
        let d = detect(&[&a], 4, 1);
        assert_eq!(d.blocks.len(), 1);
        let repetitive = tokens("aaaaaaaa");
        // Overlapping windows of a run must not be reported as copies of each other.
        assert_eq!(detect(&[&repetitive], 4, 1).blocks.len(), 1);
    }

    /// Token streams from a tiny alphabet, so repeats are common.
    fn token_files() -> impl Strategy<Value = Vec<Vec<Token>>> {
        let file = prop::collection::vec((0u64..3, 0usize..3), 0..300).prop_map(|raw| {
            let mut line = 1;
            raw.into_iter()
                .map(|(hash, newlines)| {
                    line += newlines / 2;
                    Token { hash, line }
                })
                .collect::<Vec<_>>()
        });
        // Empty files too: they have no windows, and share a start.
        prop::collection::vec(prop_oneof![1 => Just(Vec::new()), 4 => file], 1..5)
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn rolling_hash_equals_direct_hash(
            hashes in prop::collection::vec(any::<u64>(), 1..200),
            w in 1usize..20,
        ) {
            let tokens: Vec<Token> = hashes.iter().map(|&hash| Token { hash, line: 1 }).collect();
            let rolled = window_hashes(&tokens, w);
            for (i, h) in rolled.iter().enumerate() {
                prop_assert_eq!(*h, window_hashes(&tokens[i..i + w], w)[0]);
            }
        }

        /// Against the hash map it replaced: for every window, the same
        /// first occurrence and the same answer to whether it repeats.
        #[test]
        fn first_occurrences_match_a_hash_map(
            files in token_files(),
            w in 1usize..6,
        ) {
            let refs: Vec<&[Token]> = files.iter().map(Vec::as_slice).collect();
            let hashes: Vec<Vec<u64>> = refs.iter().map(|t| window_hashes(t, w)).collect();
            let mut expected: std::collections::HashMap<u64, ((usize, usize), bool)> =
                std::collections::HashMap::new();
            for (f, hs) in hashes.iter().enumerate() {
                for (p, &h) in hs.iter().enumerate() {
                    expected.entry(h).and_modify(|e| e.1 = true).or_insert(((f, p), false));
                }
            }
            let first = FirstOccurrences::new(&refs, w);
            for (f, hs) in hashes.iter().enumerate() {
                prop_assert_eq!(first.windows(f), hs.len());
                for (p, h) in hs.iter().enumerate() {
                    let (i, repeated) = first.of(f, p);
                    prop_assert_eq!((first.position(i), repeated), expected[h]);
                    prop_assert_eq!(first.position(first.index(f, p)), (f, p));
                }
            }
        }

        #[test]
        fn blocks_are_real_copies_within_their_files(
            files in token_files(),
            min_tokens in 2usize..12,
            min_lines in 1usize..4,
        ) {
            let refs: Vec<&[Token]> = files.iter().map(Vec::as_slice).collect();
            let d = detect(&refs, min_tokens, min_lines);
            prop_assert_eq!(d.lines.len(), files.len());
            let last_line = |f: usize| files[f].last().map_or(0, |t| t.line);
            for b in &d.blocks {
                for s in [b.original, b.copy] {
                    prop_assert!(s.start_line <= s.end_line && s.end_line <= last_line(s.file));
                }
                prop_assert!(b.copy.end_line - b.copy.start_line + 1 >= min_lines);
            }
            for (f, lines) in d.lines.iter().enumerate() {
                prop_assert!(lines.iter().all(|&l| l >= 1 && l <= last_line(f)));
            }
            // Same input, same output.
            let again = detect(&refs, min_tokens, min_lines);
            prop_assert_eq!(again.blocks, d.blocks);
        }
    }
}
