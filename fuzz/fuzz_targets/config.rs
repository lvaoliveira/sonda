//! Parses arbitrary `sonda.toml` contents, which come from the untrusted
//! repository.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        sonda::fuzzing::parse_config(text);
    }
});
