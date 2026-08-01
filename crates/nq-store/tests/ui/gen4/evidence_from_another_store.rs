use nq_runtime_dependency_authority::{ResolvedControllingActivation, VerificationBrand};
use nq_store::StoreWriterSession;

fn cross_store_evidence<'store, 'session_id, 'evidence_id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'session_id>>,
    evidence_from_another_store: &ResolvedControllingActivation<'evidence_id>,
) {
    let _ = session.establish_runtime_dependency_trust_root(evidence_from_another_store);
}

fn main() {}
