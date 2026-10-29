//! Copy-paste detection over token streams (exact clones).
//!
//! Every window of `min_tokens` consecutive tokens is hashed with a rolling
//! hash. Each repeated window is paired with the first occurrence of that
//! window, then extended token by token into a maximal block.

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

    // hash -> (file, position) of its first occurrence, and whether it repeats.
    let mut first: HashMap<u64, ((usize, usize), bool)> = HashMap::new();
    for (f, hs) in hashes.iter().enumerate() {
        for (p, &h) in hs.iter().enumerate() {
            first
                .entry(h)
                .and_modify(|e| e.1 = true)
                .or_insert(((f, p), false));
        }
    }

    let mut out = Duplication {
        lines: vec![BTreeSet::new(); files.len()],
        blocks: Vec::new(),
    };
    // Indexing `first` cannot panic: it holds every hash in `hashes`.
    for (fb, hs) in hashes.iter().enumerate() {
        for (pb, &h) in hs.iter().enumerate() {
            let ((fa, pa), repeated) = first[&h];
            if !repeated || (fa, pa) == (fb, pb) || overlaps(fa, pa, fb, pb, w) {
                continue;
            }
            // Already covered by a block that started one token earlier.
            if pa > 0 && pb > 0 {
                let prev = hashes[fb][pb - 1];
                if hashes[fa][pa - 1] == prev && first[&prev].0 == (fa, pa - 1) {
                    continue;
                }
            }
            let (ta, tb) = (files[fa], files[fb]);
            if ta[pa..pa + w]
                .iter()
                .zip(&tb[pb..pb + w])
                .any(|(x, y)| x.hash != y.hash)
            {
                continue; // hash collision
            }
            let mut len = w;
            while pa + len < ta.len()
                && pb + len < tb.len()
                && ta[pa + len].hash == tb[pb + len].hash
                && !(fa == fb && pa + len >= pb)
            {
                len += 1;
            }
            let span = |file: usize, tokens: &[Token], start: usize| Span {
                file,
                start_line: tokens[start].line,
                end_line: tokens[start + len - 1].line,
            };
            let block = Block {
                original: span(fa, ta, pa),
                copy: span(fb, tb, pb),
            };
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
}
