//! End-to-end tests of the `sonda` binary.

use std::process::Command;

fn sonda() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sonda"))
}

/// Regression: verbose logs printed a file name's raw escape sequence to
/// the terminal (tracing-subscriber does not escape `%`-formatted values).
#[cfg(unix)]
#[test]
fn logs_escape_control_characters_from_the_repository() {
    let dir = tempfile::tempdir().unwrap();
    // Invalid UTF-8 content makes the file name appear in a debug log.
    std::fs::write(dir.path().join("evil\x1b[2J.py"), b"x = '\xff'\n").unwrap();

    let out = sonda()
        .args(["scan", "--no-gate", "-vv"])
        .arg(dir.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();

    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("evil\\u{1b}[2J.py"), "{stderr}");
    assert!(!stderr.contains('\x1b'), "raw escape in logs");
    assert!(!out.stdout.contains(&0x1b), "raw escape in report");
}
