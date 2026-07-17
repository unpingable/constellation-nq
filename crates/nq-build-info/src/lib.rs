//! Machine-readable build metadata emitted before any configuration is read.

use std::ffi::OsStr;
use std::io::{self, Write};

use serde::Serialize;

/// Stable schema identifier for the executable build probe.
pub const BUILD_INFO_SCHEMA: &str = "nq.build_info.v1";

/// Build-time helper isolation policy represented by one executable.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HelperIsolationPolicy {
    /// Production builds require a helper identity distinct from the daemon.
    ProductionSeparateIdentityRequired,
    /// Debug builds expose the explicit same-identity test-only exception.
    DebugSameIdentityTestExceptionAvailable,
}

/// Exact machine-readable identity and policy for one shipped executable.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BuildInfo<'a> {
    /// Build probe document schema.
    pub schema: &'static str,
    /// Expected package component name.
    pub component: &'a str,
    /// Cargo package version compiled into the executable.
    pub version: &'a str,
    /// Whether Rust debug assertions are compiled in.
    pub debug_assertions: bool,
    /// Helper identity policy selected by this build profile.
    pub helper_isolation_policy: HelperIsolationPolicy,
}

impl<'a> BuildInfo<'a> {
    /// Construct build information from compile-time policy.
    #[must_use]
    pub const fn current(component: &'a str, version: &'a str) -> Self {
        let debug_assertions = cfg!(debug_assertions);
        let helper_isolation_policy = if debug_assertions {
            HelperIsolationPolicy::DebugSameIdentityTestExceptionAvailable
        } else {
            HelperIsolationPolicy::ProductionSeparateIdentityRequired
        };
        Self {
            schema: BUILD_INFO_SCHEMA,
            component,
            version,
            debug_assertions,
            helper_isolation_policy,
        }
    }
}

/// Emit one compact JSON build-information document when `--build-info` is
/// the process's only argument.
///
/// This function consults only compile-time constants and process arguments;
/// callers invoke it before CLI parsing, configuration loading, logging, or a
/// helper protocol read.
///
/// # Errors
///
/// Returns an output error if the machine-readable document cannot be written
/// or flushed to standard output.
pub fn write_if_requested(component: &str, version: &str) -> io::Result<bool> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new("--build-info")) || arguments.next().is_some()
    {
        return Ok(false);
    }
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &BuildInfo::current(component, version))
        .map_err(io::Error::other)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_information_is_strict_and_machine_readable() {
        let information = BuildInfo::current("fixture", "1.2.3");
        let bytes = serde_json::to_vec(&information).expect("serialize build information");
        let decoded: serde_json::Value =
            serde_json::from_slice(&bytes).expect("deserialize build information");
        assert_eq!(decoded["schema"], BUILD_INFO_SCHEMA);
        assert_eq!(decoded["component"], "fixture");
        assert_eq!(decoded["version"], "1.2.3");
        assert_eq!(decoded["debug_assertions"], cfg!(debug_assertions));
    }
}
