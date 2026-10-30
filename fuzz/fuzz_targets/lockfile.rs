//! Parses arbitrary lockfile contents, which come from the untrusted
//! repository. The first byte picks the format.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some((&selector, rest)) = data.split_first()
        && let Ok(text) = std::str::from_utf8(rest)
    {
        sonda_core::fuzzing::parse_lockfile(selector, text);
    }
});
