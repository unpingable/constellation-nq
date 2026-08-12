//! C2 guarded Store-generation infrastructure.
//!
//! This module is intentionally separate from the generic Gen4 Store API.
//! Its values bind an immutable physical generation and closed root layout;
//! none of them alone grants a writer session or signer standing.

pub mod authority_geometry;
mod candidate_qualification;
pub mod c2_lifecycle;
pub mod currentness;
pub mod install;
pub(crate) mod live_c2;
pub mod lock;
pub mod persistence;
pub mod policy;
pub mod records;
pub mod refusal;
// Superseded model-era ordinary restart pipeline. The production C2 reopen
// path is Store-owned in `live_c2`; retain this only as an archaeological law
// specimen for its local tests.
#[cfg(test)]
pub mod restart;
pub mod restore;
pub mod signer;

pub mod signing;

// Production-root crash/restart specimens live outside `live_c2.rs` so their
// evidence cannot accidentally depend on that module's private model fixtures.
#[cfg(test)]
mod live_c2_bootstrap_crash_tests;
#[cfg(test)]
mod live_c2_hostile_tests;
#[cfg(test)]
pub(crate) mod source_io_crash_test_support {
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone)]
    struct SourceIoCrashObserverV1 {
        selected: Option<&'static str>,
        observed: Rc<RefCell<Vec<&'static str>>>,
    }

    thread_local! {
        static SOURCE_IO_CRASH_OBSERVER_V1: RefCell<Option<SourceIoCrashObserverV1>> =
            const { RefCell::new(None) };
    }

    /// Source-adjacent test/qualification hook for the exact SC-01..SC-70
    /// production I/O census. A selected cut terminates a child test process
    /// immediately after the named I/O succeeds: no Rust or SQLite destructor
    /// may turn the specimen into an orderly rollback.
    pub(crate) fn after_source_io_v1(cut: &'static str) {
        SOURCE_IO_CRASH_OBSERVER_V1.with(|slot| {
            let active = slot.borrow();
            let Some(active) = active.as_ref() else {
                return;
            };
            active.observed.borrow_mut().push(cut);
            if active.selected == Some(cut) {
                std::process::exit(197);
            }
        });
    }

    /// Whether the active child selected an error-only source cut whose
    /// immediate precursor cannot be induced by a valid bounded runtime
    /// input.  This is deliberately narrower than the crash hook: production
    /// builds have no selector and callers cannot inject an I/O result.
    pub(crate) fn selected_precursor_v1(cut: &'static str) -> bool {
        SOURCE_IO_CRASH_OBSERVER_V1.with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|active| active.selected == Some(cut))
        })
    }

    /// Activate observation only around the production operation under test.
    /// Setup and restart verification therefore cannot accidentally consume a
    /// cut that belongs to the consequence-bearing operation.
    pub(crate) fn with_source_io_observer_v1<R>(
        selected: Option<&'static str>,
        operation: impl FnOnce() -> R,
    ) -> (R, Vec<&'static str>) {
        struct Reset;

        impl Drop for Reset {
            fn drop(&mut self) {
                SOURCE_IO_CRASH_OBSERVER_V1.with(|slot| {
                    slot.replace(None);
                });
            }
        }

        let observed = Rc::new(RefCell::new(Vec::new()));
        SOURCE_IO_CRASH_OBSERVER_V1.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "nested source-I/O crash observation is forbidden"
            );
            slot.replace(Some(SourceIoCrashObserverV1 {
                selected,
                observed: observed.clone(),
            }));
        });
        let reset = Reset;
        let result = operation();
        let observed = observed.borrow().clone();
        drop(reset);
        (result, observed)
    }
}

use std::path::Path;

use nq_protocol::{Sha256Digest, semantic_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact fixed file names in a C2 Store root.
pub const C2_SQLITE_FILE_V1: &str = "store.sqlite3";
pub const C2_LOCK_FILE_V1: &str = ".nq-store-generation-lock.v1";
pub const C2_BOOTSTRAP_EXTENT_V1: &str = "bootstrap.b.v1";
pub const C2_GLOBAL_REFUSAL_EXTENT_V1: &str = "global-refusal.g.v1";
pub const C2_LOCK_SCHEMA_V1: &str = "nq.c2_store_generation_lock.v1";
pub const C2_APPEND_EXTENT_LAYOUT_V1: &str = "nq.append_extent_layout.v1";

/// Immutable physical Store-generation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreGenerationIdentityV1 {
    occurrence_id: String,
    policy_digest: Sha256Digest,
    enrollment_digest: Sha256Digest,
    installation_mode: C2InstallationModeV1,
    structural_cut: u64,
    identity: Sha256Digest,
}

/// Only the two authenticated C2 installation modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum C2InstallationModeV1 {
    Fresh,
    RestoreSuccessor,
}

/// Closed, fixed-name physical root layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2StoreRootLayoutV1 {
    sqlite_file: &'static str,
    lock_file: &'static str,
    bootstrap_extent: &'static str,
    global_refusal_extent: &'static str,
    lock_schema: &'static str,
    append_layout: &'static str,
    lock_length: usize,
}

/// Recomputation result; asserted bytes never become authority by themselves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C2StoreGenerationIdentityRecomputationV1 {
    asserted: Sha256Digest,
    recomputed: Sha256Digest,
}

/// Typed root/identity refusal.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum StoreGenerationIdentityRefusalV1 {
    #[error("a required Store-generation coordinate is empty")]
    EmptyCoordinate,
    #[error("the structural cut is outside the exact I-JSON range")]
    UnsafeCut,
    #[error("Store-generation identity canonicalization failed")]
    Canonicalization,
    #[error("the asserted Store-generation identity differs from its exact preimage")]
    IdentityMismatch,
    #[error("the Store root contains a name outside the fixed C2 layout")]
    RootLayoutMismatch,
    #[error("the lock carrier length or canonical zero padding is malformed")]
    LockCarrierMalformed,
}

#[derive(Serialize)]
struct GenerationPreimage<'a> {
    schema: &'static str,
    occurrence_id: &'a str,
    policy_digest: &'a Sha256Digest,
    enrollment_digest: &'a Sha256Digest,
    installation_mode: C2InstallationModeV1,
    structural_cut: u64,
}

/// WU-02 constructs identity only from the immutable authenticated preimage.
pub fn construct_wu_02_immutable_wu_immutable_physical_generation_policy_resolution(
    occurrence_id: String,
    policy_digest: Sha256Digest,
    enrollment_digest: Sha256Digest,
    installation_mode: C2InstallationModeV1,
    structural_cut: u64,
) -> Result<StoreGenerationIdentityV1, StoreGenerationIdentityRefusalV1> {
    if occurrence_id.is_empty() {
        return Err(StoreGenerationIdentityRefusalV1::EmptyCoordinate);
    }
    if structural_cut > 9_007_199_254_740_991 {
        return Err(StoreGenerationIdentityRefusalV1::UnsafeCut);
    }
    let identity = semantic_digest(&GenerationPreimage {
        schema: "nq.c2_store_generation_identity_preimage.v1",
        occurrence_id: &occurrence_id,
        policy_digest: &policy_digest,
        enrollment_digest: &enrollment_digest,
        installation_mode,
        structural_cut,
    })
    .map_err(|_| StoreGenerationIdentityRefusalV1::Canonicalization)?;
    Ok(StoreGenerationIdentityV1 {
        occurrence_id,
        policy_digest,
        enrollment_digest,
        installation_mode,
        structural_cut,
        identity,
    })
}

/// WU-02 rederives rather than trusting a serialized identity field.
pub fn verify_wu_02_immutable_wu_immutable_physical_generation_policy_resolution(
    value: &StoreGenerationIdentityV1,
) -> Result<(), StoreGenerationIdentityRefusalV1> {
    let recomputed = construct_wu_02_immutable_wu_immutable_physical_generation_policy_resolution(
        value.occurrence_id.clone(),
        value.policy_digest.clone(),
        value.enrollment_digest.clone(),
        value.installation_mode,
        value.structural_cut,
    )?;
    if recomputed.identity == value.identity {
        Ok(())
    } else {
        Err(StoreGenerationIdentityRefusalV1::IdentityMismatch)
    }
}

/// N-65 constructs the only supported fixed-name root layout.
pub fn construct_n_65_store_root_has_exactly_fixed_sqlite_lock(
    lock_length: usize,
) -> Result<C2StoreRootLayoutV1, StoreGenerationIdentityRefusalV1> {
    if lock_length == 0 {
        return Err(StoreGenerationIdentityRefusalV1::LockCarrierMalformed);
    }
    Ok(C2StoreRootLayoutV1 {
        sqlite_file: C2_SQLITE_FILE_V1,
        lock_file: C2_LOCK_FILE_V1,
        bootstrap_extent: C2_BOOTSTRAP_EXTENT_V1,
        global_refusal_extent: C2_GLOBAL_REFUSAL_EXTENT_V1,
        lock_schema: C2_LOCK_SCHEMA_V1,
        append_layout: C2_APPEND_EXTENT_LAYOUT_V1,
        lock_length,
    })
}

/// N-65 verifies that a complete root census has no alternate name.
pub fn verify_n_65_store_root_has_exactly_fixed_sqlite_lock(
    layout: &C2StoreRootLayoutV1,
    observed_names: &std::collections::BTreeSet<String>,
) -> Result<(), StoreGenerationIdentityRefusalV1> {
    let expected = [
        layout.sqlite_file,
        layout.lock_file,
        layout.bootstrap_extent,
        layout.global_refusal_extent,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if observed_names == &expected
        && layout.lock_schema == C2_LOCK_SCHEMA_V1
        && layout.append_layout == C2_APPEND_EXTENT_LAYOUT_V1
    {
        Ok(())
    } else {
        Err(StoreGenerationIdentityRefusalV1::RootLayoutMismatch)
    }
}

/// N-66 checks exact lock length and zero-only trailing padding.
pub fn construct_n_66_lock_bytes_are_canonical_byte_record_zero<'a>(
    layout: &C2StoreRootLayoutV1,
    lock_bytes: &'a [u8],
    canonical_record_length: usize,
) -> Result<&'a [u8], StoreGenerationIdentityRefusalV1> {
    verify_n_66_lock_bytes_are_canonical_byte_record_zero(
        layout,
        lock_bytes,
        canonical_record_length,
    )?;
    Ok(lock_bytes)
}

pub fn verify_n_66_lock_bytes_are_canonical_byte_record_zero(
    layout: &C2StoreRootLayoutV1,
    lock_bytes: &[u8],
    canonical_record_length: usize,
) -> Result<(), StoreGenerationIdentityRefusalV1> {
    if canonical_record_length == 0
        || canonical_record_length > layout.lock_length
        || lock_bytes.len() != layout.lock_length
        || lock_bytes[canonical_record_length..]
            .iter()
            .any(|byte| *byte != 0)
    {
        Err(StoreGenerationIdentityRefusalV1::LockCarrierMalformed)
    } else {
        Ok(())
    }
}

/// N-67 is a refusal-only path for an incomplete or substituted layout.
pub fn verify_n_67_refusal(
    layout: &C2StoreRootLayoutV1,
    observed_names: &std::collections::BTreeSet<String>,
) -> Result<(), StoreGenerationIdentityRefusalV1> {
    verify_n_65_store_root_has_exactly_fixed_sqlite_lock(layout, observed_names)
}

/// RR-04 recomputes the physical identity and retains both sides.
pub fn recompute_rr_04_store_generation_identity(
    value: &StoreGenerationIdentityV1,
) -> Result<C2StoreGenerationIdentityRecomputationV1, StoreGenerationIdentityRefusalV1> {
    let recomputed = construct_wu_02_immutable_wu_immutable_physical_generation_policy_resolution(
        value.occurrence_id.clone(),
        value.policy_digest.clone(),
        value.enrollment_digest.clone(),
        value.installation_mode,
        value.structural_cut,
    )?;
    Ok(C2StoreGenerationIdentityRecomputationV1 {
        asserted: value.identity.clone(),
        recomputed: recomputed.identity,
    })
}

pub fn verify_rr_04_asserted_recomputed_identity_equality(
    recomputation: &C2StoreGenerationIdentityRecomputationV1,
) -> Result<(), StoreGenerationIdentityRefusalV1> {
    if recomputation.asserted == recomputation.recomputed {
        Ok(())
    } else {
        Err(StoreGenerationIdentityRefusalV1::IdentityMismatch)
    }
}

/// SEAM-06 accepts the current root only after fixed-name descriptor census.
pub fn construct_seam_06_immutable_seam_root_layout_current_store_opens(
    root_path: &Path,
    lock_length: usize,
) -> Result<C2StoreRootLayoutV1, StoreGenerationIdentityRefusalV1> {
    if !root_path.is_absolute() {
        return Err(StoreGenerationIdentityRefusalV1::RootLayoutMismatch);
    }
    construct_n_65_store_root_has_exactly_fixed_sqlite_lock(lock_length)
}

pub fn verify_seam_06_immutable_seam_root_layout_current_store_opens(
    layout: &C2StoreRootLayoutV1,
    observed_names: &std::collections::BTreeSet<String>,
) -> Result<(), StoreGenerationIdentityRefusalV1> {
    verify_n_65_store_root_has_exactly_fixed_sqlite_lock(layout, observed_names)
}

impl StoreGenerationIdentityV1 {
    #[must_use]
    pub fn identity(&self) -> &Sha256Digest {
        &self.identity
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use nq_protocol::sha256_bytes;

    use super::*;

    #[test]
    fn identity_recomputes_and_root_layout_is_closed() {
        let identity =
            construct_wu_02_immutable_wu_immutable_physical_generation_policy_resolution(
                "occurrence".into(),
                sha256_bytes(b"policy"),
                sha256_bytes(b"enrollment"),
                C2InstallationModeV1::Fresh,
                1,
            )
            .unwrap();
        verify_wu_02_immutable_wu_immutable_physical_generation_policy_resolution(&identity)
            .unwrap();
        verify_rr_04_asserted_recomputed_identity_equality(
            &recompute_rr_04_store_generation_identity(&identity).unwrap(),
        )
        .unwrap();

        let layout = construct_n_65_store_root_has_exactly_fixed_sqlite_lock(512).unwrap();
        let names = [
            C2_SQLITE_FILE_V1,
            C2_LOCK_FILE_V1,
            C2_BOOTSTRAP_EXTENT_V1,
            C2_GLOBAL_REFUSAL_EXTENT_V1,
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        verify_n_65_store_root_has_exactly_fixed_sqlite_lock(&layout, &names).unwrap();
    }

    #[test]
    fn nonzero_lock_padding_refuses() {
        let layout = construct_n_65_store_root_has_exactly_fixed_sqlite_lock(16).unwrap();
        let mut bytes = vec![0; 16];
        bytes[15] = 1;
        assert_eq!(
            verify_n_66_lock_bytes_are_canonical_byte_record_zero(&layout, &bytes, 8),
            Err(StoreGenerationIdentityRefusalV1::LockCarrierMalformed)
        );
    }
}
