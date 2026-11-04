//! Copy-paste detection over token streams (exact clones).
//!
//! Every window of `min_tokens` consecutive tokens is hashed with a rolling
//! hash. Each repeated window is paired with the first occurrence of that
//! window, then extended token by token into a maximal block.
//!
//! Linear time, even on hostile input: no block starts inside a copy that
//! is already reported, so copy ranges are disjoint and the total extension
//! work is bounded by the number of tokens. (Without that rule, a file
//! repeating one token was quadratic: 80,000 lines took 75 s.)

use crate::analysis::Token;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

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
    let hashes: Vec<Vec<u64>> = files.iter().map(|t| window_hashes(t, w)).collect();
    let first = first_occurrences(&hashes);
    let windows = Windows {
        files,
        hashes: &hashes,
        first: &first,
        w,
    };

    let mut out = Duplication {
        lines: vec![BTreeSet::new(); files.len()],
        blocks: Vec::new(),
    };
    // Per file, the token index up to which copies are already reported.
    let mut copied_until = vec![0usize; files.len()];
    for (fb, hs) in hashes.iter().enumerate() {
        for pb in 0..hs.len() {
            let Some((block, end)) = windows.copy_at(fb, pb, copied_until[fb]) else {
                continue;
            };
            copied_until[fb] = end;
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

/// The files' tokens with their window hashes, each `w` tokens long.
struct Windows<'a> {
    files: &'a [&'a [Token]],
    hashes: &'a [Vec<u64>],
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
        // Indexing `first` cannot panic: it holds every hash in `hashes`.
        let ((fa, pa), repeated) = self.first[&self.hashes[fb][pb]];
        if !repeated || (fa, pa) == (fb, pb) || overlaps(fa, pa, fb, pb, w) || pb < copied_until {
            return None;
        }
        if extends_previous_block(self.hashes, self.first, (fa, pa), (fb, pb)) {
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

/// Hash -> (file, position) of its first occurrence, and whether it repeats.
type FirstOccurrences = HashMap<u64, ((usize, usize), bool)>;

fn first_occurrences(hashes: &[Vec<u64>]) -> FirstOccurrences {
    let mut first = FirstOccurrences::new();
    for (f, hs) in hashes.iter().enumerate() {
        for (p, &h) in hs.iter().enumerate() {
            first
                .entry(h)
                .and_modify(|e| e.1 = true)
                .or_insert(((f, p), false));
        }
    }
    first
}

/// Whether the copy at `b` of the window at `a` is covered by a block that
/// started one token earlier.
fn extends_previous_block(
    hashes: &[Vec<u64>],
    first: &FirstOccurrences,
    (fa, pa): (usize, usize),
    (fb, pb): (usize, usize),
) -> bool {
    if pa == 0 || pb == 0 {
        return false;
    }
    let prev = hashes[fb][pb - 1];
    hashes[fa][pa - 1] == prev && first[&prev].0 == (fa, pa - 1)
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
        prop::collection::vec(file, 1..4)
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
