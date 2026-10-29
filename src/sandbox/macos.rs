//! Seatbelt sandbox for analysis workers (ADR-0004).
//!
//! This is the only `unsafe` code in sonda: no maintained crate wraps
//! `sandbox_init`, and the alternative (launching workers through
//! `sandbox-exec`) gives a weaker profile. The API is deprecated but still
//! works on current macOS.

use std::ffi::{CStr, CString, c_char, c_int};

/// Deny everything and allow nothing back. Reads and writes on descriptors
/// that are already open (the worker's pipes) are not mediated.
const PROFILE: &str = "(version 1) (deny default)";

// SAFETY: the declarations match <sandbox.h> in the macOS SDK; both
// functions live in libSystem, which every macOS process links.
unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

pub(super) fn enter() -> Result<(), String> {
    let profile = CString::new(PROFILE).map_err(|e| format!("seatbelt: {e}"))?;
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: `profile` is a NUL-terminated string that outlives the call,
    // and `error` is a valid out-pointer. Flags 0 means `profile` is profile
    // source rather than a named profile.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };
    if rc == 0 {
        return Ok(());
    }
    let message = if error.is_null() {
        format!("sandbox_init returned {rc}")
    } else {
        // SAFETY: a non-null `error` is a NUL-terminated string allocated by
        // sandbox_init. It is copied out, then freed exactly once and never
        // used again.
        let text = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        unsafe { sandbox_free_error(error) };
        text
    };
    Err(format!("seatbelt: {message}"))
}
