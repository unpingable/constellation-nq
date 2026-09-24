//! The helper's typed failure codes are exactly the owning profiles' closed
//! lists: every `CollectionFailure` is built from a profile enum, never from
//! a string literal, so a code cannot exist that the owner did not define.

use nq_profiles::{host_filesystem::FilesystemFailureCode, host_memory::MemoryFailureCode};

const SOURCE: &str = include_str!("../src/lib.rs");

#[test]
fn every_collection_failure_is_built_from_a_profile_enum() {
    let mut sites = 0;
    for (index, _) in SOURCE.match_indices("CollectionFailure::new(") {
        let rest = &SOURCE[index + "CollectionFailure::new(".len()..];
        let first_argument = rest.trim_start();
        assert!(
            first_argument.starts_with("FilesystemFailureCode::")
                || first_argument.starts_with("MemoryFailureCode::"),
            "a CollectionFailure is built from something other than a profile code enum near byte {index}"
        );
        sites += 1;
    }
    assert!(
        sites >= 20,
        "expected the helper's failure sites, found {sites}"
    );
    // The constructor itself is the only place that accepts a bare string.
    assert_eq!(SOURCE.matches("fn new(code: &'static str").count(), 1);
}

#[test]
fn the_closed_lists_are_tokens_and_parse_exactly() {
    for code in FilesystemFailureCode::ALL {
        let text = code.as_str();
        assert!(is_token(text), "{text}");
        assert_eq!(FilesystemFailureCode::parse(text), Some(code));
    }
    for code in MemoryFailureCode::ALL {
        let text = code.as_str();
        assert!(is_token(text), "{text}");
        assert_eq!(MemoryFailureCode::parse(text), Some(code));
    }
    for foreign in [
        "psi_not_provided",
        "boot_clock_unavailable",
        "psi_malformed",
    ] {
        assert_eq!(FilesystemFailureCode::parse(foreign), None, "{foreign}");
    }
    for foreign in [
        "not_a_mountpoint",
        "filesystem_identity_mismatch",
        "statfs_failed",
    ] {
        assert_eq!(MemoryFailureCode::parse(foreign), None, "{foreign}");
    }
    for junk in [
        "",
        "backend_failed",
        "/etc/machine-id",
        "Machine_Identity_Mismatch",
        " psi_malformed",
    ] {
        assert_eq!(FilesystemFailureCode::parse(junk), None, "{junk}");
        assert_eq!(MemoryFailureCode::parse(junk), None, "{junk}");
    }
    // The two shared texts are distinct values of distinct types; equality
    // of text implies nothing about meaning.
    assert_eq!(
        FilesystemFailureCode::MachineIdentityMismatch.as_str(),
        MemoryFailureCode::MachineIdentityMismatch.as_str()
    );
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.as_bytes()[0].is_ascii_lowercase()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
