use nq_runtime_dependency_authority::ResolvedControllingActivation;
use nq_store::Store;

fn establish_without_session(store: &mut Store, evidence: &ResolvedControllingActivation<'_>) {
    let _ = store.establish_runtime_dependency_trust_root(evidence);
}

fn main() {}
