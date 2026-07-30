use nq_host_role_dependency_custody::AuthenticatedSourceResolution;

fn main() {
    let _ = serde_json::from_str::<AuthenticatedSourceResolution<'static>>("{}");
}
