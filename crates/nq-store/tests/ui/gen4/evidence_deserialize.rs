use nq_runtime_dependency_authority::ResolvedControllingActivation;

fn main() {
    let _ = serde_json::from_str::<ResolvedControllingActivation<'static>>("{}");
}
