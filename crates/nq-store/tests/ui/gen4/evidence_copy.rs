use nq_runtime_dependency_authority::ResolvedControllingActivation;

fn copy_evidence(evidence: ResolvedControllingActivation<'_>) {
    let _first = evidence;
    let _second = evidence;
}

fn main() {}
