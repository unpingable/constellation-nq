use nq_store::{
    Store,
    host_role_runtime::{
        GenesisAuthorityCustody, HostRoleRuntime, RuntimeAuthorityResidentBinding,
        RuntimeDependencies,
    },
};

fn attempt_two_step(
    dependencies: &RuntimeDependencies,
    custody: &GenesisAuthorityCustody,
    resident: &RuntimeAuthorityResidentBinding,
) {
    let mut store = Store::initialize_in_memory().unwrap();
    let _ = HostRoleRuntime::initialize_from_unqualified_store(
        &mut store,
        dependencies,
        custody,
        resident,
    );
}

fn main() {}
