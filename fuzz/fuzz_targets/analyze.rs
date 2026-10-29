//! Analyzes arbitrary input in every grammar. The first byte picks the
//! language; the rest is the file. Invalid UTF-8 is skipped, as the scanner
//! does.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    if let Ok(src) = std::str::from_utf8(rest) {
        sonda::fuzzing::analyze(selector, src);
    }
});
