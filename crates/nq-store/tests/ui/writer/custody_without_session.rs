use nq_store::{GovernedCustody, Store};

fn custody_without_session(custody: &mut GovernedCustody, store: &Store) {
    let _ = custody.claim_launch(
        nq_protocol::Sha256Digest::parse("aa".repeat(32)).expect("digest"),
        "2026-07-30T00:00:00Z".to_owned(),
    );
}

fn main() {}
