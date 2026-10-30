//! Parses arbitrary OSV records and version strings, which come from
//! outside (an advisory import). The first byte picks the ecosystem.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((&selector, rest)) = data.split_first()
        && let Ok(text) = std::str::from_utf8(rest)
    {
        sonda_core::fuzzing::parse_advisory(selector, text);
    }
});
