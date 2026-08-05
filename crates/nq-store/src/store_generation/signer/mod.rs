//! Store-private C2 signer lifecycle implementation.
//!
//! Modules are visible for persisted record types and verification results;
//! authority-bearing constructors and custody remain crate-private.

#![forbid(unsafe_code)]

pub mod authority;
pub mod binding;
pub(crate) mod bootstrap;
pub(crate) mod claims;
pub(crate) mod coordinator;
pub(crate) mod correspondence;
pub(crate) mod crash;
pub(crate) mod custody;
pub(crate) mod external_governance;
pub mod lineage;
pub(crate) mod manifest;
pub(crate) mod messages;
pub(crate) mod records;
pub(crate) mod restart;
pub(crate) mod result;

/// Static SG-WU-01A closed module-registration witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerModuleRegistrationV1;

/// The registration verifier has no dynamic extension point to inspect.
#[must_use]
pub const fn verify_closed_module_registration() -> SignerModuleRegistrationV1 {
    SignerModuleRegistrationV1
}
