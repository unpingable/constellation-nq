//! Real parent-death qualification for the child-held invocation fence.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use nq_bedrock_runtime_carrier::{RuntimeBindingV1, RuntimeReleaseV1};
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use serde::Serialize;
use tempfile::TempDir;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::parse(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Sha256Digest {
    let canonical = canonical_json_bytes(value).unwrap();
    let mut preimage = Vec::new();
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&canonical);
    sha256_bytes(&preimage)
}

fn child_of(parent: u32) -> Option<i32> {
    let path = format!("/proc/{parent}/task/{parent}/children");
    fs::read_to_string(path)
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn wait_for_child(parent: u32) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(child) = child_of(parent) {
            return child;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "carrier never spawned slow executable"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_absent(pid: i32) {
    let start = Instant::now();
    while Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "slow executable did not exit"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn surviving_child_holds_fence_after_carrier_sigkill() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let sleep = Path::new("/usr/bin/sleep");
    assert!(sleep.is_file());
    let executable_digest = sha256_bytes(&fs::read(sleep).unwrap());
    let binding = RuntimeBindingV1 {
        schema: "nq.bedrock_runtime_carrier_binding.v1".into(),
        occurrence_id: "parent-death-occurrence".into(),
        coordination_domain_id: "parent-death-domain".into(),
        mechanics_digest: digest(1),
        runtime_recheck_digest: digest(2),
        claim_id: digest(3),
        executable_digest,
        arguments: vec!["30".into()],
    };
    let release = RuntimeReleaseV1 {
        schema: "nq.bedrock_runtime_release.v1".into(),
        binding_id: domain_digest(b"nq.bedrock_runtime_carrier_binding.v1\0", &binding),
        occurrence_id: binding.occurrence_id.clone(),
        coordination_domain_id: binding.coordination_domain_id.clone(),
        mechanics_digest: binding.mechanics_digest.clone(),
        runtime_recheck_digest: binding.runtime_recheck_digest.clone(),
        claim_id: binding.claim_id.clone(),
        release_nonce: "parent-death-release".into(),
    };
    let release_id = domain_digest(b"nq.bedrock_runtime_release.v1\0", &release);
    let binding_path = temp.path().join("binding.json");
    let release_path = temp.path().join("release.json");
    let state_path = temp.path().join("state.sqlite3");
    fs::write(&binding_path, canonical_json_bytes(&binding).unwrap()).unwrap();
    fs::write(&release_path, canonical_json_bytes(&release).unwrap()).unwrap();

    let binary = env!("CARGO_BIN_EXE_nq-bedrock-runtime-carrier");
    let mut carrier = Command::new(binary)
        .args(["--binding", binding_path.to_str().unwrap()])
        .args(["--release", release_path.to_str().unwrap()])
        .args(["--state", state_path.to_str().unwrap()])
        .args(["--executable", sleep.to_str().unwrap()])
        .spawn()
        .unwrap();
    let child_pid = wait_for_child(carrier.id());
    kill(
        Pid::from_raw(i32::try_from(carrier.id()).unwrap()),
        Signal::SIGKILL,
    )
    .unwrap();
    let status = carrier.wait().unwrap();
    assert!(!status.success());
    assert!(Path::new(&format!("/proc/{child_pid}")).exists());

    let evidence = digest(8);
    let while_live = Command::new(binary)
        .args(["--state", state_path.to_str().unwrap()])
        .args(["--reconcile-release-id", release_id.as_str()])
        .args(["--outcome-evidence-digest", evidence.as_str()])
        .arg("--exit-code=0")
        .status()
        .unwrap();
    assert!(
        !while_live.success(),
        "reconciliation crossed a surviving child fence"
    );

    kill(Pid::from_raw(child_pid), Signal::SIGKILL).unwrap();
    wait_absent(child_pid);
    let after_exit = Command::new(binary)
        .args(["--state", state_path.to_str().unwrap()])
        .args(["--reconcile-release-id", release_id.as_str()])
        .args(["--outcome-evidence-digest", evidence.as_str()])
        .arg("--exit-code=0")
        .status()
        .unwrap();
    assert!(after_exit.success());
}
