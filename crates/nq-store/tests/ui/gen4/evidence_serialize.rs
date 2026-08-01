use nq_runtime_dependency_authority::ResolvedControllingActivation;

fn serialize(evidence: &ResolvedControllingActivation<'_>) {
    let _ = serde_json::to_vec(evidence);
}

fn main() {}
