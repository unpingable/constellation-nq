//! Rebuildable typed projections derived only from admitted reports.

use std::{any::Any, fmt::Debug};

use serde_json::Value;

use crate::{ProfileKey, ProfileRefusal};

/// A profile-owned typed projection erased only at the registry boundary.
///
/// Implementations retain their Rust type through [`Self::as_any`] while the
/// generic store may retain canonical JSON. Projections are rebuildable and
/// never become detector source-of-truth by themselves.
pub trait ProfileProjection: Any + Debug + Send + Sync {
    /// Profile contract that produced this row.
    fn profile(&self) -> &ProfileKey;

    /// Source observation ordinal.
    fn ordinal(&self) -> u32;

    /// Canonical JSON representation for an optional rebuildable projection.
    fn canonical_json(&self) -> Value;

    /// Allows a compiled detector to recover its profile-owned concrete type.
    fn as_any(&self) -> &dyn Any;
}

/// Result of profile-owned projection.
pub type ProjectionResult = Result<Vec<Box<dyn ProfileProjection>>, ProfileRefusal>;
