//! Black-box framing check for the shipped one-shot helper.

use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn shipped_binary_rejects_malformed_framing_without_testimony() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nq-synthetic-cache-result-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"{}\n{}\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid request"));
}
