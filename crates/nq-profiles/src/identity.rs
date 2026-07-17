//! Semantic identity of the compiled evaluator.
//!
//! A profile's *descriptor* digest identifies its declared vocabulary and limits
//! only (see [`ProfileDescriptor::digest`]). Its *semantic id* additionally binds
//! the evaluator source closure — every law compiled into this crate — and the
//! protocol semantics the canonicalizer obeys, so a behavior-changing edit rotates
//! the id even when the descriptor is byte-identical. Conservative by design: a
//! cosmetic source edit also rotates it, which is far safer than silent drift.

use serde::{Deserialize, Serialize};

use crate::descriptor::{DescriptorError, ProfileDescriptor};

/// Schema tag for the composite semantic-id preimage.
pub const PROFILE_SEMANTIC_ID_SCHEMA: &str = "nq.profile_semantic_id.v1";

/// Fail-closed digest of this crate's compiled source closure, computed at build
/// time over every source file plus the manifest and build script. Any change to
/// a profile law or to shared admission machinery rotates it.
pub const EVALUATOR_SOURCE_DIGEST: &str = env!("NQ_PROFILES_SOURCE_DIGEST");

/// Composite semantic identity of one compiled profile.
///
/// Binds the descriptor digest, the evaluator source closure, and the protocol
/// semantics version. This — not the descriptor digest alone — is what pins the
/// meaning under which an admitted report was produced.
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
    let descriptor_digest = descriptor.digest()?;
    let preimage = SemanticIdPreimage {
        schema: PROFILE_SEMANTIC_ID_SCHEMA,
        protocol_semantics_version: nq_protocol::HELPER_PROTOCOL_VERSION,
        descriptor_digest: descriptor_digest.as_str(),
        evaluator_source_digest: EVALUATOR_SOURCE_DIGEST,
    };
    nq_protocol::semantic_digest(&preimage)
        .map(ProfileSemanticId)
        .map_err(|error| DescriptorError::Canonicalization(error.to_string()))
}
