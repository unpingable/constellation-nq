//! Explicit compile-time profile registry.

use crate::{ProfileKey, ProfileModule, conformance, host, http_endpoint, systemd_unit};

// Adding a compiled profile intentionally requires one visible registry entry.
// There is no runtime scanning, inventory mechanism, or integration enum.
static PROFILES: [&'static dyn ProfileModule; 4] = [
    &conformance::MODULE,
    &host::MODULE,
    &systemd_unit::MODULE,
    &http_endpoint::MODULE,
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
