//! The helper's failure codes are closed by the owning profiles' types: a
//! filesystem failure carries a `FilesystemFailureCode`, a memory failure a
//! `MemoryFailureCode`, and the wire tokens the helper publishes are the
//! modules' own vocabularies. The compile-fail doctests on
//! `CollectionFailure` show that one owner's code cannot be placed in the
//! other owner's failure.

use nq_host_resource_helper::{CollectionFailure, failure_code_vocabularies};
use nq_profiles::{
    ProfileModule, host_filesystem, host_filesystem::FilesystemFailureCode, host_memory,
    host_memory::MemoryFailureCode, systemd_unit_v2, systemd_unit_v2::SystemdUnitFailureCode,
};

#[test]
fn the_helper_publishes_exactly_the_owner_vocabularies() {
    let vocabularies = failure_code_vocabularies();
    let entries = vocabularies.as_array().expect("array");
    assert_eq!(entries.len(), 4);
    for (entry, module, expected) in [
        (
            &entries[0],
            &host_filesystem::CAPACITY_MODULE as &dyn ProfileModule,
            FilesystemFailureCode::tokens(),
        ),
        (
            &entries[1],
            &host_filesystem::INODES_MODULE as &dyn ProfileModule,
            FilesystemFailureCode::tokens(),
        ),
        (
            &entries[2],
            &host_memory::MODULE as &dyn ProfileModule,
            MemoryFailureCode::tokens(),
        ),
        (
            &entries[3],
            &systemd_unit_v2::MODULE as &dyn ProfileModule,
            SystemdUnitFailureCode::tokens(),
        ),
    ] {
        assert_eq!(entry["id"], module.descriptor().profile.id);
        assert_eq!(entry["version"], module.descriptor().profile.version);
        let codes = entry["codes"]
            .as_array()
            .expect("codes")
            .iter()
            .map(|code| code.as_str().expect("token"))
            .collect::<Vec<_>>();
        assert_eq!(codes, expected);
        assert_eq!(module.failure_codes(), expected);
    }
}

#[test]
fn every_owner_token_is_stable_unique_and_parses_back_to_its_own_enum_only() {
    let mut seen = std::collections::BTreeSet::new();
    for code in FilesystemFailureCode::ALL {
        let text = code.as_str();
        assert!(is_token(text), "{text}");
        assert!(seen.insert(("filesystem", text)), "duplicate {text}");
        assert_eq!(FilesystemFailureCode::parse(text), Some(code));
    }
    seen.clear();
    for code in MemoryFailureCode::ALL {
        let text = code.as_str();
        assert!(is_token(text), "{text}");
        assert!(seen.insert(("memory", text)), "duplicate {text}");
        assert_eq!(MemoryFailureCode::parse(text), Some(code));
    }
    seen.clear();
    for code in SystemdUnitFailureCode::ALL {
        let text = code.as_str();
        assert!(is_token(text), "{text}");
        assert!(seen.insert(("systemd_unit", text)), "duplicate {text}");
        assert_eq!(SystemdUnitFailureCode::parse(text), Some(code));
        if code != SystemdUnitFailureCode::MachineIdentityMismatch {
            assert_eq!(FilesystemFailureCode::parse(text), None, "{text}");
            assert_eq!(MemoryFailureCode::parse(text), None, "{text}");
        }
    }
    for foreign in [
        "psi_not_provided",
        "boot_clock_unavailable",
        "psi_malformed",
    ] {
        assert_eq!(FilesystemFailureCode::parse(foreign), None, "{foreign}");
        assert_eq!(SystemdUnitFailureCode::parse(foreign), None, "{foreign}");
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
    ] {
        assert_eq!(FilesystemFailureCode::parse(junk), None, "{junk}");
        assert_eq!(MemoryFailureCode::parse(junk), None, "{junk}");
    }
    // Shared text is not shared meaning: two enums, two values.
    assert_eq!(
        FilesystemFailureCode::MachineIdentityMismatch.as_str(),
        MemoryFailureCode::MachineIdentityMismatch.as_str()
    );
}

#[test]
fn retriable_is_per_occurrence_data_not_a_property_of_the_code() {
    let once = CollectionFailure::owner(MemoryFailureCode::PsiReadFailed, "read", true);
    let again = CollectionFailure::owner(MemoryFailureCode::PsiReadFailed, "bound", false);
    assert_eq!(once.code(), again.code());
    assert_ne!(once.retriable(), again.retriable());
    let typed: CollectionFailure<FilesystemFailureCode> = CollectionFailure::owner(
        FilesystemFailureCode::MountIdentityUnavailable,
        "fdinfo",
        true,
    );
    assert_eq!(typed.code().as_str(), "mount_identity_unavailable");
    assert!(typed.retriable());
    assert_eq!(typed.message(), "fdinfo");
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.as_bytes()[0].is_ascii_lowercase()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
