//! Semantic identity of the compiled evaluator.
//!
//! A profile's *descriptor* digest identifies its declared vocabulary and limits
//! only (see [`ProfileDescriptor::digest`]). Its *semantic id* additionally binds
//! the evaluator source closure — the compiled law of `nq-profiles` and
//! `nq-protocol` plus the pinned versions of external canonicalization crates —
//! and the protocol semantics label, so a behavior-changing edit rotates the id
//! even when the descriptor is byte-identical. Conservative by design: a cosmetic
//! source edit also rotates it, which is far safer than silent drift.
//!
//! # Identity law
//!
//! `profile_semantic_id` identifies *declared* profile meaning: rule/descriptor
//! data, the source closure of the law-bearing crates, the declared protocol
//! semantics, and locked dependency declarations. It does **not** capture ad-hoc
//! build-invocation effects (e.g. package-qualified `--features` activation),
//! which are not observable from a build script; those are bound separately by the
//! evaluator artifact digest (SHA-256 of the running `nqd` executable) in the
//! admission context.
//!
//! - Matching `profile_semantic_id`s establish equality of the covered *declared*
//!   semantics.
//! - Different ids mean equivalence has *not* been established — conservative
//!   source churn (comments, unrelated lockfile bumps) may rotate the id without
//!   changing behavior; it is **not** proof that behavior changed.
//! - The evaluator artifact digest binds the exact compiled realization, including
//!   undeclared build-invocation effects.
//!
//! **Replay requires both** a matching declared semantic identity **and** a
//! matching evaluator artifact digest.

use serde::{Deserialize, Serialize};

use crate::descriptor::{DescriptorError, ProfileDescriptor};

/// Schema tag for the composite semantic-id preimage.
pub const PROFILE_SEMANTIC_ID_SCHEMA: &str = "nq.profile_semantic_id.v1";

/// Conservative source-closure digest computed at build time over the compiled
/// semantics: every `nq-profiles` and `nq-protocol` source file, this crate's
/// build script, every workspace manifest (which carries enabled Cargo features),
/// the workspace lockfile (pinned dependency versions), and the toolchain file.
///
/// Fail-closed against *omission* — a new source file under either law-bearing
/// crate is auto-included — but deliberately coarse and conservative: it is
/// crate-global (a change to any profile or detector rotates every profile's id)
/// and over-includes (comments, unrelated dependency bumps). "Transitive" here
/// means "the whole source tree of the two law-bearing crates," not
/// dependency-graph transitive; the module/use graph is not parsed.
pub const EVALUATOR_SOURCE_DIGEST: &str = env!("NQ_PROFILES_SOURCE_DIGEST");

/// Composite semantic identity of one compiled profile.
///
/// Binds the descriptor digest, the evaluator source closure, and the protocol
/// semantics label. This is *intended* to pin the meaning under which an admitted
/// report is produced. Production admission records it, and every governed
/// profile/evaluation refusal transports and reopens it alongside the declared
/// profile key so equal key/version values cannot erase implementation drift.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ProfileSemanticId(nq_protocol::Sha256Digest);

impl ProfileSemanticId {
    /// Returns the lowercase `sha256:`-prefixed identity string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Canonical preimage for a profile semantic id. Field names are part of the
/// hashed identity via canonical JSON.
#[derive(Serialize)]
struct SemanticIdPreimage<'a> {
    schema: &'a str,
    protocol_semantics_version: &'a str,
    descriptor_digest: &'a str,
    evaluator_source_digest: &'a str,
}

/// Computes the composite semantic identity of a compiled profile.
///
/// # Errors
///
/// Returns [`DescriptorError`] if the descriptor cannot be canonicalized.
pub fn profile_semantic_id(
    descriptor: &ProfileDescriptor,
) -> Result<ProfileSemanticId, DescriptorError> {
    profile_semantic_id_for_source(
        descriptor,
        nq_protocol::HELPER_PROTOCOL_VERSION,
        EVALUATOR_SOURCE_DIGEST,
    )
}

/// Recompute the semantic identity carried by one historical admission.
///
/// The admission-time protocol and evaluator-source digests are immutable
/// constituents of the admission context. Reopening history must use those
/// exact constituents rather than silently reinterpret the old occurrence
/// under the currently compiled source closure.
///
/// # Errors
///
/// Returns [`DescriptorError`] if the descriptor cannot be canonicalized.
pub fn profile_semantic_id_for_source(
    descriptor: &ProfileDescriptor,
    protocol_semantics_version: &str,
    evaluator_source_digest: &str,
) -> Result<ProfileSemanticId, DescriptorError> {
    let descriptor_digest = descriptor.digest()?;
    compose_semantic_id(
        PROFILE_SEMANTIC_ID_SCHEMA,
        protocol_semantics_version,
        descriptor_digest.as_str(),
        evaluator_source_digest,
    )
}

/// Hashes the four identity components into one semantic id. Kept separate so a
/// test can prove every component actually contributes — that no field can be
/// silently dropped from the preimage.
fn compose_semantic_id(
    schema: &str,
    protocol_semantics_version: &str,
    descriptor_digest: &str,
    evaluator_source_digest: &str,
) -> Result<ProfileSemanticId, DescriptorError> {
    let preimage = SemanticIdPreimage {
        schema,
        protocol_semantics_version,
        descriptor_digest,
        evaluator_source_digest,
    };
    nq_protocol::semantic_digest(&preimage)
        .map(ProfileSemanticId)
        .map_err(|error| DescriptorError::Canonicalization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{compose_semantic_id, profile_semantic_id_for_source};
    use crate::{ProfileModule as _, conformance};

    #[test]
    fn every_preimage_field_contributes_to_the_identity() {
        let base = compose_semantic_id("s", "p", "d", "src").expect("base id");
        // Changing ANY field must change the id, so no field (in particular the
        // source closure or the protocol version) can be silently dropped from
        // the preimage without this test failing.
        assert_ne!(
            base,
            compose_semantic_id("s2", "p", "d", "src").expect("id")
        );
        assert_ne!(
            base,
            compose_semantic_id("s", "p2", "d", "src").expect("id")
        );
        assert_ne!(
            base,
            compose_semantic_id("s", "p", "d2", "src").expect("id")
        );
        assert_ne!(
            base,
            compose_semantic_id("s", "p", "d", "src2").expect("id")
        );
    }

    #[test]
    fn historical_identity_uses_the_admission_time_source_and_protocol() {
        let descriptor = conformance::MODULE.descriptor();
        let historical = profile_semantic_id_for_source(
            descriptor,
            "nq.helper.historical",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .expect("historical semantic id");
        let current = super::profile_semantic_id(descriptor).expect("current semantic id");
        assert_ne!(historical, current);
        assert_eq!(
            historical,
            profile_semantic_id_for_source(
                descriptor,
                "nq.helper.historical",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("same historical semantic id")
        );
    }
}
