#![forbid(unsafe_code)]

//! Public facade for the Store-owned host-role runtime.
//!
//! The implementation lives in `nq-store` so the two governed establishment
//! routes and the Store's branded writer-session factory share one Rust
//! privacy boundary. This crate preserves the established public import path
//! without exporting the Store-private establishment scope.
//!
//! The generic custody append remains deliberately unavailable:
//!
//! ```compile_fail
//! use nq_host_role_runtime::{CustodyAppendRequest, HostRoleRuntime};
//!
//! fn bypass(runtime: &mut HostRoleRuntime, request: &CustodyAppendRequest) {
//!     runtime.append_custody_only(request).unwrap();
//! }
//! ```

pub use nq_store::host_role_runtime::*;
