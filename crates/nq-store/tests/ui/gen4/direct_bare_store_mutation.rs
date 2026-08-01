use nq_runtime_dependency_authority::ResolvedControllingActivation;
use nq_store::Store;

fn direct_mutation(store: &mut Store, evidence: &ResolvedControllingActivation<'_>) {
    let _ = store.establish_runtime_dependency_trust_root_bare(evidence);
}

fn main() {}
