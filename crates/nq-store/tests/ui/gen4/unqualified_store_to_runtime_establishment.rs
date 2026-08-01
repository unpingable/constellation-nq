use std::path::Path;

use nq_store::{
    Store,
    host_role_runtime::{
        GenesisAuthorityCustody, HostRoleRuntime, RuntimeAuthorityResidentBinding,
        RuntimeDependencies,
    },
};

fn attempt_two_step(
    path: &Path,
    dependencies: &RuntimeDependencies,
    custody: &GenesisAuthorityCustody,
    resident: &RuntimeAuthorityResidentBinding,
) {
    let mut store = Store::initialize_unqualified_storage(path).unwrap();
    let _ = HostRoleRuntime::initialize_from_unqualified_store(
        &mut store,
        dependencies,
        custody,
        resident,
    );
}

fn main() {}
