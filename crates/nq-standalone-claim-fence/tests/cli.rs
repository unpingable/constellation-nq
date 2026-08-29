//! Real process qualification for the standalone claim/fence CLI.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command;

use nq_protocol::{Sha256Digest, canonical_json_bytes};
use nq_standalone_claim_fence::{ClaimRequestV1, TransitionKind, TransitionRequestV1};
use tempfile::TempDir;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::parse(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

#[test]
fn cli_claim_redirect_reopen_and_fence_are_durable() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state = temp.path().join("claims.sqlite3");
    let claim_path = temp.path().join("claim.json");
    let transition_path = temp.path().join("transition.json");
    let claim = ClaimRequestV1 {
        schema: "nq.standalone_claim_request.v1".into(),
        occurrence_id: "cli-occurrence".into(),
        coordination_domain_id: "cli-domain".into(),
        mechanics_digest: digest(1),
        authorization_receipt_digest: digest(2),
        runtime_identity_digest: digest(3),
        claim_nonce: "cli-claim".into(),
    };
    fs::write(&claim_path, canonical_json_bytes(&claim).unwrap()).unwrap();
    let binary = env!("CARGO_BIN_EXE_nq-standalone-claim-fence");
    let invoke_claim = || {
        Command::new(binary)
            .arg("claim")
            .arg(&state)
            .arg(&claim_path)
            .output()
            .unwrap()
    };
    let first = invoke_claim();
    assert!(first.status.success());
    assert_eq!(first.stdout.last(), Some(&b'\n'));
    let first_value: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_value["disposition"], "advanced");
    let replay = invoke_claim();
    assert!(replay.status.success());
    let replay_value: serde_json::Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay_value["disposition"], "exact_replay");

    let transition = TransitionRequestV1 {
        schema: "nq.standalone_claim_transition.v1".into(),
        claim_id: Sha256Digest::parse(first_value["claim_id"].as_str().unwrap().to_owned())
            .unwrap(),
        occurrence_id: claim.occurrence_id,
        coordination_domain_id: claim.coordination_domain_id,
        mechanics_digest: claim.mechanics_digest,
        transition: TransitionKind::Fence,
        transition_nonce: "cli-fence".into(),
        evidence_digest: digest(4),
    };
    fs::write(&transition_path, canonical_json_bytes(&transition).unwrap()).unwrap();
    let fenced = Command::new(binary)
        .arg("transition")
        .arg(&state)
        .arg(&transition_path)
        .output()
        .unwrap();
    assert!(fenced.status.success());
    let fenced_value: serde_json::Value = serde_json::from_slice(&fenced.stdout).unwrap();
    assert_eq!(fenced_value["resulting_state"], "fenced");

    fs::write(
        &transition_path,
        b"{\"schema\":\"nq.standalone_claim_transition.v1\"}",
    )
    .unwrap();
    let malformed = Command::new(binary)
        .arg("transition")
        .arg(&state)
        .arg(&transition_path)
        .output()
        .unwrap();
    assert!(!malformed.status.success());
    assert!(malformed.stdout.is_empty());
}
