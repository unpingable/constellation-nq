//! Explicit compile-time profile registry.

use crate::{
    ProfileKey, ProfileModule, conformance, host, host_filesystem, host_memory, http_endpoint,
    synthetic_cache_executor_result, systemd_unit, systemd_unit_v2,
};

// Adding a compiled profile intentionally requires one visible registry entry.
// There is no runtime scanning, inventory mechanism, or integration enum.
static PROFILES: [&'static dyn ProfileModule; 9] = [
    &conformance::MODULE,
    &host::MODULE,
    &systemd_unit::MODULE,
    &http_endpoint::MODULE,
    &synthetic_cache_executor_result::MODULE,
    &host_filesystem::CAPACITY_MODULE,
    &host_filesystem::INODES_MODULE,
    &host_memory::MODULE,
    &systemd_unit_v2::MODULE,
];

/// Returns all profile modules compiled into this binary.
#[must_use]
pub fn all_profiles() -> &'static [&'static dyn ProfileModule] {
    &PROFILES
}

/// Resolves an exact profile identifier and semantic version.
#[must_use]
pub fn resolve_profile(id: &str, version: u32) -> Option<&'static dyn ProfileModule> {
    PROFILES.iter().copied().find(|module| {
        let key = &module.descriptor().profile;
        key.id == id && key.version == version
    })
}

/// Resolves an exact profile key.
#[must_use]
pub fn resolve_profile_key(key: &ProfileKey) -> Option<&'static dyn ProfileModule> {
    resolve_profile(&key.id, key.version)
}
