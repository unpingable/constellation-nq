use super::*;
use std::sync::{Arc, Barrier};
use tempfile::TempDir;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::parse(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn claim_request(occurrence: &str, domain: &str, nonce: &str) -> ClaimRequestV1 {
    ClaimRequestV1 {
        schema: CLAIM_SCHEMA.into(),
        occurrence_id: occurrence.into(),
        coordination_domain_id: domain.into(),
        mechanics_digest: digest(1),
        authorization_receipt_digest: digest(2),
        runtime_identity_digest: digest(3),
        claim_nonce: nonce.into(),
    }
}

fn transition(claim: &ClaimRequestV1, kind: TransitionKind, nonce: &str) -> TransitionRequestV1 {
    TransitionRequestV1 {
        schema: TRANSITION_SCHEMA.into(),
        claim_id: framed_digest(CLAIM_DOMAIN, claim).unwrap(),
        occurrence_id: claim.occurrence_id.clone(),
        coordination_domain_id: claim.coordination_domain_id.clone(),
        mechanics_digest: claim.mechanics_digest.clone(),
        transition: kind,
        transition_nonce: nonce.into(),
        evidence_digest: digest(4),
    }
}

fn fixture() -> (TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let state = temp.path().join("claims.sqlite3");
    (temp, state)
}

#[test]
fn exact_claim_reopens_and_substitution_refuses() {
    let (_temp, state) = fixture();
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let mut interface = ClaimFence::open(&state).unwrap();
    assert_eq!(
        interface.claim(&claim).unwrap().disposition,
        Disposition::Advanced
    );
    assert_eq!(
        interface.claim(&claim).unwrap().disposition,
        Disposition::ExactReplay
    );
    let mut substituted = claim.clone();
    substituted.claim_nonce = "different".into();
    assert!(interface.claim(&substituted).is_err());
}

#[test]
fn active_domain_is_exclusive_but_terminal_domain_can_advance() {
    let (_temp, state) = fixture();
    let first = claim_request("occurrence-1", "domain-1", "claim-1");
    let second = claim_request("occurrence-2", "domain-1", "claim-2");
    let mut interface = ClaimFence::open(&state).unwrap();
    interface.claim(&first).unwrap();
    assert!(interface.claim(&second).is_err());
    for (kind, nonce) in [
        (TransitionKind::Fence, "fence-1"),
        (TransitionKind::Release, "release-1"),
        (TransitionKind::Complete, "complete-1"),
    ] {
        interface
            .transition(&transition(&first, kind, nonce))
            .unwrap();
    }
    assert_eq!(
        interface.claim(&second).unwrap().disposition,
        Disposition::Advanced
    );
}

#[test]
fn fence_release_and_completion_are_exact_ordered_edges() {
    let (_temp, state) = fixture();
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let mut interface = ClaimFence::open(&state).unwrap();
    interface.claim(&claim).unwrap();
    assert_eq!(
        interface
            .transition(&transition(&claim, TransitionKind::Fence, "fence"))
            .unwrap()
            .resulting_state,
        ClaimState::Fenced
    );
    assert_eq!(
        interface
            .transition(&transition(&claim, TransitionKind::Release, "release"))
            .unwrap()
            .resulting_state,
        ClaimState::Released
    );
    assert_eq!(
        interface
            .transition(&transition(&claim, TransitionKind::Complete, "complete"))
            .unwrap()
            .resulting_state,
        ClaimState::Terminal
    );
}

#[test]
fn alternate_transition_histories_and_identity_substitution_refuse() {
    let (_temp, state) = fixture();
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let mut interface = ClaimFence::open(&state).unwrap();
    interface.claim(&claim).unwrap();
    assert!(
        interface
            .transition(&transition(
                &claim,
                TransitionKind::Release,
                "early-release"
            ))
            .is_err()
    );
    assert!(
        interface
            .transition(&transition(
                &claim,
                TransitionKind::Complete,
                "early-complete"
            ))
            .is_err()
    );
    let mut substituted = transition(&claim, TransitionKind::Fence, "substituted");
    substituted.mechanics_digest = digest(9);
    assert!(interface.transition(&substituted).is_err());
}

#[test]
fn released_occurrence_is_one_use_even_after_terminal() {
    let (_temp, state) = fixture();
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let mut interface = ClaimFence::open(&state).unwrap();
    interface.claim(&claim).unwrap();
    interface
        .transition(&transition(&claim, TransitionKind::Fence, "fence"))
        .unwrap();
    let release = transition(&claim, TransitionKind::Release, "release");
    assert_eq!(
        interface.transition(&release).unwrap().disposition,
        Disposition::Advanced
    );
    assert_eq!(
        interface.transition(&release).unwrap().disposition,
        Disposition::ExactReplay
    );
    interface
        .transition(&transition(&claim, TransitionKind::Complete, "complete"))
        .unwrap();
    assert_eq!(
        interface.transition(&release).unwrap().disposition,
        Disposition::ExactReplay
    );
}

#[test]
fn outcome_unknown_requires_exact_reconciliation() {
    let (_temp, state) = fixture();
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let mut interface = ClaimFence::open(&state).unwrap();
    interface.claim(&claim).unwrap();
    interface
        .transition(&transition(&claim, TransitionKind::Fence, "fence"))
        .unwrap();
    interface
        .transition(&transition(&claim, TransitionKind::Release, "release"))
        .unwrap();
    interface
        .transition(&transition(
            &claim,
            TransitionKind::MarkOutcomeUnknown,
            "unknown",
        ))
        .unwrap();
    assert!(
        interface
            .transition(&transition(
                &claim,
                TransitionKind::Complete,
                "late-complete"
            ))
            .is_err()
    );
    let reconcile = transition(&claim, TransitionKind::Reconcile, "reconcile");
    assert_eq!(
        interface.transition(&reconcile).unwrap().resulting_state,
        ClaimState::Terminal
    );
    let mut alternate = reconcile;
    alternate.evidence_digest = digest(8);
    assert!(interface.transition(&alternate).is_err());
}

#[test]
fn concurrent_release_has_one_append_and_only_exact_replays() {
    let (_temp, state) = fixture();
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let mut setup = ClaimFence::open(&state).unwrap();
    setup.claim(&claim).unwrap();
    setup
        .transition(&transition(&claim, TransitionKind::Fence, "fence"))
        .unwrap();
    drop(setup);
    let request = Arc::new(transition(&claim, TransitionKind::Release, "release"));
    let state = Arc::new(state);
    let barrier = Arc::new(Barrier::new(8));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let request = Arc::clone(&request);
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            let mut interface = ClaimFence::open(&state).unwrap();
            barrier.wait();
            interface.transition(&request).unwrap().disposition
        }));
    }
    let dispositions: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        dispositions
            .iter()
            .filter(|d| **d == Disposition::Advanced)
            .count(),
        1
    );
    assert_eq!(
        dispositions
            .iter()
            .filter(|d| **d == Disposition::ExactReplay)
            .count(),
        7
    );
}

#[test]
fn restart_retains_exact_state_and_nonce_reuse_refuses() {
    let (_temp, state) = fixture();
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let fence = transition(&claim, TransitionKind::Fence, "transition-nonce");
    let mut first = ClaimFence::open(&state).unwrap();
    first.claim(&claim).unwrap();
    first.transition(&fence).unwrap();
    drop(first);
    let mut reopened = ClaimFence::open(&state).unwrap();
    assert_eq!(
        reopened.transition(&fence).unwrap().disposition,
        Disposition::ExactReplay
    );
    let mut reused = transition(&claim, TransitionKind::Release, "transition-nonce");
    reused.evidence_digest = digest(8);
    assert!(reopened.transition(&reused).is_err());
}

#[test]
fn state_symlink_and_nonprivate_parent_refuse() {
    let (temp, state) = fixture();
    let target = temp.path().join("target");
    fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(target, &state).unwrap();
    assert!(ClaimFence::open(&state).is_err());
    fs::remove_file(&state).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(ClaimFence::open(&state).is_err());
}

#[test]
fn canonical_closed_models_refuse_unknown_fields() {
    let claim = claim_request("occurrence-1", "domain-1", "claim-1");
    let mut value = serde_json::to_value(&claim).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<ClaimRequestV1>(value).is_err());
}
