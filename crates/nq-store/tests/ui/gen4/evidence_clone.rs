use nq_runtime_dependency_authority::ResolvedControllingActivation;

fn clone_evidence<'id>(
    evidence: &ResolvedControllingActivation<'id>,
) -> ResolvedControllingActivation<'id> {
    evidence.clone()
}

fn main() {}
