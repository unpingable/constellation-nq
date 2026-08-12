//! Store-root hostile specimens for live-C2 one-use and reopen boundaries.
//!
//! These tests deliberately use only production Store roots.  Their snapshot
//! compares the complete logical SQLite state plus the exact fixed B/G file
//! contents and custody tree, so a typed refusal cannot hide a durable or
//! carrier-first write.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use nq_protocol::{canonical_json_bytes, sha256_bytes};
use nq_runtime_dependency_authority::test_support::RawAuthorityFixture;
use nq_runtime_dependency_authority::{ControllingActivationSnapshot, resolve_for_restart};
use rusqlite::Connection;
use rusqlite::types::Value as SqlValue;
use serde_json::Value as JsonValue;
use tempfile::tempdir;

use super::live_c2::tests::{
    apply_exact_revocation_for_test, exact_recovery_pair_for_test, exact_restore_pair_for_test,
};
use super::live_c2::{
    C2DiscontinuityRefusalV1, C2HealthySuccessorIntentV1, C2LiveReopenRefusalV1,
    C2LiveSignerRefusalV1, C2LiveTransitionDriverRefusalV1, C2RecoveryPredecessorStatusV1,
    C2RecoveryPreparationIntentV1, StoreC2QualifiedRuntimeEvidenceV1,
};
use super::live_c2_bootstrap_crash_tests::{
    ExactFileSnapshotV1, PreparedBootstrapHarnessV1, complete_bootstrap_installation,
    directory_file_snapshot, fixed_footprint_snapshot, logical_store_snapshot,
    prepare_bootstrap_harness,
};
use super::signer::custody::with_test_production_custody_root_v1;
use super::signer::external_governance::tests::{
    sign_exact_bootstrap_grant_for_test, sign_exact_recovery_grant_for_test,
    sign_exact_restore_authorization_for_test,
};
use super::signer::external_governance::{
    StoreIntegrityBootstrapGrantRequestV1, StoreIntegrityRecoveryRequestV1,
    construct_bootstrap_grant_request, construct_recovery_request,
};
use super::signer::manifest::{
    SignerImplementationManifestDerivationInputV1, StoreIntegritySignerImplementationManifestV1,
    derive_signer_implementation_manifest_v1,
};
use crate::{RuntimeAuthorityRestartSnapshot, Store, StoreError};

#[derive(Debug, Eq, PartialEq)]
struct ExactDurableStateV1 {
    logical_store: String,
    fixed_carriers: BTreeMap<&'static str, Option<ExactFileSnapshotV1>>,
    custody_tree: BTreeMap<PathBuf, ExactFileSnapshotV1>,
}

fn exact_durable_state(store: &Store, database: &Path, custody_root: &Path) -> ExactDurableStateV1 {
    ExactDurableStateV1 {
        logical_store: logical_store_snapshot(store),
        fixed_carriers: fixed_footprint_snapshot(
            database
                .parent()
                .expect("database remains below Store root"),
        ),
        custody_tree: directory_file_snapshot(custody_root),
    }
}

fn exact_durable_state_from_database(database: &Path, custody_root: &Path) -> ExactDurableStateV1 {
    let connection = Connection::open(database).expect("open raw snapshot SQLite connection");
    let logical_store = crate::logical_state_digest(
        &connection,
        b"nq.c2.bootstrap_installation_crash.no_write.v1\0",
    )
    .expect("compute exact raw logical Store snapshot");
    drop(connection);
    ExactDurableStateV1 {
        logical_store,
        fixed_carriers: fixed_footprint_snapshot(
            database
                .parent()
                .expect("database remains below Store root"),
        ),
        custody_tree: directory_file_snapshot(custody_root),
    }
}

fn resolve_runtime_authority_fixture(
    fixture: &RawAuthorityFixture,
    snapshot: &RuntimeAuthorityRestartSnapshot,
) -> Result<ControllingActivationSnapshot, C2LiveSignerRefusalV1> {
    resolve_for_restart(
        &fixture.custody(),
        &snapshot.presented,
        snapshot.migration_receipt.as_ref(),
        &fixture.restart_expectations(),
    )
    .map_err(StoreError::from)
    .map_err(C2LiveSignerRefusalV1::from)
}

#[derive(Clone, Copy)]
struct RawImmutableMutationSpecV1 {
    label: &'static str,
    table: &'static str,
    column: &'static str,
    update_trigger: &'static str,
    row_selector: &'static str,
}

struct RawImmutableCellUndoV1 {
    spec: RawImmutableMutationSpecV1,
    rowid: i64,
    original: SqlValue,
}

/// Test-only corruption primitive for hostile reopen specimens.
///
/// Each invocation removes exactly the named immutable-update trigger inside
/// one raw SQLite transaction, writes one selected cell with foreign-key and
/// CHECK enforcement disabled, and recreates the exact saved trigger before
/// commit.  The returned value is the exact prior SQLite value, so the same
/// primitive can restore the database before the next independent mutation.
fn replace_one_immutable_cell_for_test(
    database: &Path,
    spec: RawImmutableMutationSpecV1,
    replacement: SqlValue,
) -> RawImmutableCellUndoV1 {
    let (rowid, original) =
        replace_immutable_cell_at_rowid_for_test(database, spec, None, replacement);
    RawImmutableCellUndoV1 {
        spec,
        rowid,
        original,
    }
}

fn restore_one_immutable_cell_for_test(database: &Path, undo: RawImmutableCellUndoV1) -> SqlValue {
    let (_, tampered) = replace_immutable_cell_at_rowid_for_test(
        database,
        undo.spec,
        Some(undo.rowid),
        undo.original,
    );
    tampered
}

fn replace_immutable_cell_at_rowid_for_test(
    database: &Path,
    spec: RawImmutableMutationSpecV1,
    exact_rowid: Option<i64>,
    replacement: SqlValue,
) -> (i64, SqlValue) {
    let mut connection = Connection::open(database).expect("open raw hostile SQLite connection");
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .expect("disable foreign keys for one deliberate hostile mutation");
    connection
        .pragma_update(None, "ignore_check_constraints", "ON")
        .expect("disable CHECK constraints for one deliberate hostile mutation");

    let transaction = connection
        .transaction()
        .expect("begin exact hostile mutation transaction");
    let trigger_sql: String = transaction
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [spec.update_trigger],
            |row| row.get(0),
        )
        .unwrap_or_else(|error| {
            panic!(
                "{}: load exact immutable trigger {}: {error}",
                spec.label, spec.update_trigger
            )
        });
    assert!(
        !trigger_sql.is_empty(),
        "{}: immutable trigger SQL is empty",
        spec.label
    );

    let (rowid, original): (i64, SqlValue) = if let Some(rowid) = exact_rowid {
        let select_sql = format!(
            "SELECT rowid, {} FROM {} WHERE rowid = ?1",
            spec.column, spec.table
        );
        transaction
            .query_row(&select_sql, [rowid], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap_or_else(|error| {
                panic!(
                    "{}: select exact hostile rowid {rowid}: {error}",
                    spec.label
                )
            })
    } else {
        let select_sql = format!(
            "SELECT rowid, {} FROM {} WHERE {}",
            spec.column, spec.table, spec.row_selector
        );
        transaction
            .query_row(&select_sql, [], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap_or_else(|error| panic!("{}: select exact hostile target: {error}", spec.label))
    };
    assert_ne!(
        original, replacement,
        "{}: hostile replacement must actually change the selected coordinate",
        spec.label
    );

    transaction
        .execute_batch(&format!("DROP TRIGGER {}", spec.update_trigger))
        .unwrap_or_else(|error| {
            panic!(
                "{}: drop only immutable trigger {}: {error}",
                spec.label, spec.update_trigger
            )
        });
    let update_sql = format!(
        "UPDATE {} SET {} = ?1 WHERE rowid = ?2",
        spec.table, spec.column
    );
    let changed = transaction
        .execute(&update_sql, rusqlite::params![replacement, rowid])
        .unwrap_or_else(|error| panic!("{}: mutate exact hostile target: {error}", spec.label));
    assert_eq!(
        changed, 1,
        "{}: mutation must affect exactly one row",
        spec.label
    );
    transaction
        .execute_batch(&trigger_sql)
        .unwrap_or_else(|error| {
            panic!(
                "{}: recreate exact immutable trigger {}: {error}",
                spec.label, spec.update_trigger
            )
        });
    transaction
        .commit()
        .expect("commit exact hostile mutation and trigger restoration");
    (rowid, original)
}

/// Derive one canonical-record hostile replacement from the exact consumed
/// durable bytes.  This mutates the semantic record itself, rather than a
/// redundant SQL projection that the resolver is not supposed to trust.
fn replace_json_field_bytes_for_test(
    database: &Path,
    table: &str,
    column: &str,
    row_selector: &str,
    field: &str,
    replacement: JsonValue,
) -> Vec<u8> {
    let connection = Connection::open(database).expect("open canonical hostile SQLite connection");
    let select_sql = format!("SELECT {column} FROM {table} WHERE {row_selector}");
    let original: Vec<u8> = connection
        .query_row(&select_sql, [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("load exact canonical hostile target: {error}"));
    let mut value: JsonValue =
        serde_json::from_slice(&original).expect("decode exact canonical hostile target");
    let prior = value
        .as_object_mut()
        .expect("canonical hostile target is an object")
        .insert(field.to_owned(), replacement)
        .unwrap_or_else(|| panic!("canonical hostile field {field} is absent"));
    assert_ne!(
        value.get(field),
        Some(&prior),
        "canonical hostile replacement must change {field}"
    );
    serde_json::to_vec(&value).expect("encode canonical hostile replacement")
}

fn replace_nested_json_field_bytes_for_test(
    database: &Path,
    table: &str,
    column: &str,
    row_selector: &str,
    object_field: &str,
    field: &str,
    replacement: JsonValue,
) -> Vec<u8> {
    let connection = Connection::open(database).expect("open canonical hostile SQLite connection");
    let select_sql = format!("SELECT {column} FROM {table} WHERE {row_selector}");
    let original: Vec<u8> = connection
        .query_row(&select_sql, [], |row| row.get(0))
        .unwrap_or_else(|error| panic!("load exact canonical hostile target: {error}"));
    let mut value: JsonValue =
        serde_json::from_slice(&original).expect("decode exact canonical hostile target");
    let nested = value
        .get_mut(object_field)
        .and_then(JsonValue::as_object_mut)
        .unwrap_or_else(|| panic!("canonical hostile object {object_field} is absent"));
    let prior = nested
        .insert(field.to_owned(), replacement)
        .unwrap_or_else(|| panic!("canonical hostile field {object_field}.{field} is absent"));
    assert_ne!(
        nested.get(field),
        Some(&prior),
        "canonical hostile replacement must change {object_field}.{field}"
    );
    serde_json::to_vec(&value).expect("encode canonical hostile replacement")
}

#[allow(clippy::too_many_arguments)]
fn assert_one_consumed_reopen_coordinate_refuses_without_write(
    store: Store,
    database: &Path,
    custody_root: &Path,
    authority_fixture: &RawAuthorityFixture,
    qualified: &StoreC2QualifiedRuntimeEvidenceV1,
    manifest: &StoreIntegritySignerImplementationManifestV1,
    spec: RawImmutableMutationSpecV1,
    replacement: SqlValue,
    expect_store_open_refusal: bool,
) -> Store {
    let baseline = exact_durable_state(&store, database, custody_root);
    drop(store);
    let undo = replace_one_immutable_cell_for_test(database, spec, replacement);
    let tampered = exact_durable_state_from_database(database, custody_root);
    match Store::open(database) {
        Ok(mut tampered_store) => {
            assert!(
                !expect_store_open_refusal,
                "{} substitution should have failed Store::open integrity validation",
                spec.label
            );
            let callback_entered = Cell::new(false);
            let refusal: Result<(), C2LiveReopenRefusalV1> = tampered_store
                .with_reopened_c2_generation_current_v1(
                    qualified,
                    manifest,
                    |snapshot| resolve_runtime_authority_fixture(authority_fixture, snapshot),
                    |_session| {
                        callback_entered.set(true);
                        Ok(())
                    },
                );
            assert!(
                refusal.is_err(),
                "{} substitution unexpectedly reopened GenerationCurrent",
                spec.label
            );
            assert!(
                !callback_entered.get(),
                "{} substitution entered the live writer callback",
                spec.label
            );
            assert_eq!(
                exact_durable_state(&tampered_store, database, custody_root),
                tampered,
                "{} refusal wrote durable Store/B/G/custody state: {refusal:?}",
                spec.label
            );
        }
        Err(error) => {
            assert!(
                expect_store_open_refusal,
                "{} unexpectedly failed before the production reopen root: {error}",
                spec.label
            );
            assert!(
                matches!(error, StoreError::Integrity(_)),
                "{} failed Store::open with a non-integrity refusal: {error}",
                spec.label
            );
            assert_eq!(
                exact_durable_state_from_database(database, custody_root),
                tampered,
                "{} Store::open integrity refusal wrote durable state",
                spec.label
            );
        }
    }

    let tampered_value = restore_one_immutable_cell_for_test(database, undo);
    assert_ne!(
        tampered_value,
        SqlValue::Null,
        "{} hostile mutation unexpectedly selected NULL",
        spec.label
    );
    let store = Store::open(database)
        .unwrap_or_else(|error| panic!("{}: reopen restored Store: {error}", spec.label));
    assert_eq!(
        exact_durable_state(&store, database, custody_root),
        baseline,
        "{}: exact baseline was not restored",
        spec.label
    );
    store
}

fn assert_consequence_root_refuses_without_write<T: std::fmt::Debug, E: std::fmt::Debug>(
    store: &mut Store,
    database: &Path,
    custody_root: &Path,
    label: &str,
    operation: impl FnOnce(&mut Store) -> Result<T, E>,
) {
    let before = exact_durable_state(store, database, custody_root);
    let refusal = operation(store).expect_err(label);
    assert_eq!(
        exact_durable_state(store, database, custody_root),
        before,
        "{label} wrote durable Store/B/G/custody state: {refusal:?}"
    );
}

fn request_identity_text(domain: &str, value: &JsonValue, identity_field: &str) -> String {
    let mut preimage = value.clone();
    let object = preimage
        .as_object_mut()
        .expect("canonical request remains an object");
    object.remove(identity_field);
    object.remove("signature");
    let canonical = canonical_json_bytes(&preimage).expect("canonicalize request identity body");
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    sha256_bytes(&bytes).into_string()
}

fn mutate_canonical_unsigned_request(
    bytes: &[u8],
    field: &str,
    replacement: JsonValue,
    identity_field: &str,
    identity_domain: &str,
) -> JsonValue {
    let mut value: JsonValue =
        serde_json::from_slice(bytes).expect("decode exact typed request bytes");
    let original = value
        .as_object_mut()
        .expect("typed request remains an object")
        .insert(field.to_owned(), replacement)
        .unwrap_or_else(|| panic!("typed request field {field} is absent"));
    assert_ne!(value.get(field), Some(&original), "{field} must change");
    let identity = request_identity_text(identity_domain, &value, identity_field);
    value
        .as_object_mut()
        .expect("typed request remains an object")
        .insert(identity_field.to_owned(), JsonValue::String(identity));
    value
}

fn mutated_bootstrap_request(
    request: &StoreIntegrityBootstrapGrantRequestV1,
    field: &str,
    replacement: JsonValue,
) -> StoreIntegrityBootstrapGrantRequestV1 {
    construct_bootstrap_grant_request(mutate_canonical_unsigned_request(
        request.canonical_bytes(),
        field,
        replacement,
        "grant_request_identity",
        "nq.c2.store_integrity_bootstrap_grant_request.identity.v1",
    ))
    .unwrap_or_else(|error| panic!("construct one-coordinate bootstrap request: {error}"))
}

fn mutated_recovery_request(
    request: &StoreIntegrityRecoveryRequestV1,
    field: &str,
    replacement: JsonValue,
) -> StoreIntegrityRecoveryRequestV1 {
    construct_recovery_request(mutate_canonical_unsigned_request(
        request.canonical_bytes(),
        field,
        replacement,
        "recovery_request_identity",
        "nq.c2.store_integrity_recovery_request.identity.v1",
    ))
    .unwrap_or_else(|error| panic!("construct one-coordinate recovery request: {error}"))
}

fn request_fields_with_mutation(
    bytes: &[u8],
    field: &str,
    replacement: JsonValue,
) -> BTreeMap<String, JsonValue> {
    let mut value: JsonValue = serde_json::from_slice(bytes).expect("decode exact request fields");
    let original = value
        .as_object_mut()
        .expect("request fields remain an object")
        .insert(field.to_owned(), replacement)
        .unwrap_or_else(|| panic!("request field {field} is absent"));
    assert_ne!(value.get(field), Some(&original), "{field} must change");
    value
        .as_object()
        .expect("request fields remain an object")
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn load_prepared_bootstrap_request(database: &Path) -> StoreIntegrityBootstrapGrantRequestV1 {
    let connection = Connection::open(database).expect("open prepared bootstrap Store");
    let canonical: Vec<u8> = connection
        .query_row(
            "SELECT bootstrap_request_canonical_bytes
             FROM c2_custody_proposal_preparations
             WHERE preparation_lineage = 'initialExternal'",
            [],
            |row| row.get(0),
        )
        .expect("load exact Store-prepared bootstrap request");
    let value =
        serde_json::from_slice(&canonical).expect("decode Store-prepared bootstrap request");
    construct_bootstrap_grant_request(value)
        .expect("reconstruct exact typed Store-prepared bootstrap request")
}

fn substituted_qualified_runtime_variants(
    manifest: &StoreIntegritySignerImplementationManifestV1,
) -> [(String, StoreC2QualifiedRuntimeEvidenceV1); 4] {
    let measured_runtime =
        sha256_bytes(&fs::read("/proc/self/exe").expect("read exact running Linux test image"));
    [
        (
            "qualified candidate substitution".to_owned(),
            StoreC2QualifiedRuntimeEvidenceV1::for_test(
                sha256_bytes(b"hostile-full-root/wrong-candidate"),
                sha256_bytes(b"bootstrap-crash/source-tree"),
                measured_runtime.clone(),
                manifest.manifest_identity().clone(),
            ),
        ),
        (
            "source-tree substitution".to_owned(),
            StoreC2QualifiedRuntimeEvidenceV1::for_test(
                sha256_bytes(b"bootstrap-crash/candidate"),
                sha256_bytes(b"hostile-full-root/wrong-source-tree"),
                measured_runtime.clone(),
                manifest.manifest_identity().clone(),
            ),
        ),
        (
            "runtime-artifact substitution".to_owned(),
            StoreC2QualifiedRuntimeEvidenceV1::for_test(
                sha256_bytes(b"bootstrap-crash/candidate"),
                sha256_bytes(b"bootstrap-crash/source-tree"),
                sha256_bytes(b"hostile-full-root/wrong-runtime-artifact"),
                manifest.manifest_identity().clone(),
            ),
        ),
        (
            "qualified-manifest substitution".to_owned(),
            StoreC2QualifiedRuntimeEvidenceV1::for_test(
                sha256_bytes(b"bootstrap-crash/candidate"),
                sha256_bytes(b"bootstrap-crash/source-tree"),
                measured_runtime,
                sha256_bytes(b"hostile-full-root/wrong-qualified-manifest"),
            ),
        ),
    ]
}

fn substituted_valid_manifest(
    manifest: &StoreIntegritySignerImplementationManifestV1,
) -> StoreIntegritySignerImplementationManifestV1 {
    derive_signer_implementation_manifest_v1(SignerImplementationManifestDerivationInputV1 {
        custody_format_identity: sha256_bytes(b"hostile-full-root/substituted-custody-format"),
        signer_message_contract_identity: manifest.signer_message_contract_identity().clone(),
        source_file_bytes: BTreeMap::from([(
            "crates/nq-store/src/store_generation/live_c2.rs".to_owned(),
            b"hostile-full-root/substituted-live-c2-basis".to_vec(),
        )]),
        cryptographic_backend_identity: sha256_bytes(
            b"hostile-full-root/substituted-cryptographic-backend",
        ),
        toolchain_identity: sha256_bytes(b"hostile-full-root/substituted-toolchain"),
        target_profile_identity: sha256_bytes(b"hostile-full-root/substituted-target"),
        qualification_assumption_identities: BTreeSet::from([sha256_bytes(
            b"hostile-full-root/substituted-assumption",
        )]),
    })
    .expect("derive one different valid implementation manifest")
}

#[test]
fn completed_predecessor_transition_is_nontransitive_and_retry_is_exact_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);

        let a_to_b = C2HealthySuccessorIntentV1::new(
            sha256_bytes(b"hostile-one-use/transition/a-to-b"),
            sha256_bytes(b"hostile-one-use/challenge/b"),
            10_000,
        )
        .expect("construct exact A-to-B intent");
        harness
            .store
            .rotate_c2_live_healthy_successor_v1(
                &harness.qualified,
                &harness.manifest,
                &a_to_b,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("complete exact A-to-B transition");

        let before =
            exact_durable_state(&harness.store, &harness.database, custody_directory.path());
        let refusal = harness
            .store
            .rotate_c2_live_healthy_successor_v1(
                &harness.qualified,
                &harness.manifest,
                &a_to_b,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect_err("completed A-to-B occurrence cannot authorize a B successor");
        let after =
            exact_durable_state(&harness.store, &harness.database, custody_directory.path());
        assert_eq!(
            after, before,
            "nontransitive predecessor refusal wrote durable Store/B/G/custody state: {refusal:?}"
        );

        let b_to_c = C2HealthySuccessorIntentV1::new(
            sha256_bytes(b"hostile-one-use/transition/b-to-c"),
            sha256_bytes(b"hostile-one-use/challenge/c"),
            20_000,
        )
        .expect("construct exact B-to-C intent");
        harness
            .store
            .rotate_c2_live_healthy_successor_v1(
                &harness.qualified,
                &harness.manifest,
                &b_to_c,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("a fresh B current context may authorize exact B-to-C");
    });
}

#[test]
fn restore_consequence_is_one_use_across_restart_and_replay_is_exact_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (request, authorization) = exact_restore_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.authority_fixture,
        );
        harness
            .store
            .restore_c2_live_historical_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("complete exact restore once");

        let PreparedBootstrapHarnessV1 {
            _store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        drop(store);
        let mut reopened = Store::open(&database).expect("reopen restored Store");
        let before = exact_durable_state(&reopened, &database, custody_directory.path());
        let refusal = reopened
            .restore_c2_live_historical_foundation_v1(
                &qualified,
                &manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
            )
            .expect_err("one MSG-13 occurrence cannot restore a second foundation/adoption");
        assert_eq!(
            exact_durable_state(&reopened, &database, custody_directory.path()),
            before,
            "replayed restore consequence wrote durable state: {refusal:?}"
        );
        drop(_store_directory);
    });
}

#[test]
fn recovery_consequence_is_one_use_across_restart_and_replay_is_exact_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (prepared, grant) = exact_recovery_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let request = prepared.request().clone();
        harness
            .store
            .recover_c2_live_new_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("complete exact recovery once");
        drop(prepared);

        let PreparedBootstrapHarnessV1 {
            _store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        drop(store);
        let mut reopened = Store::open(&database).expect("reopen recovered Store");
        let before = exact_durable_state(&reopened, &database, custody_directory.path());
        let refusal = reopened
            .recover_c2_live_new_foundation_v1(
                &qualified,
                &manifest,
                &request,
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
            )
            .expect_err("one MSG-15 occurrence cannot create a second foundation/adoption");
        assert_eq!(
            exact_durable_state(&reopened, &database, custody_directory.path()),
            before,
            "replayed recovery consequence wrote durable state: {refusal:?}"
        );
        drop(_store_directory);
    });
}

#[test]
fn bootstrap_consequence_root_rejects_candidate_tree_runtime_and_manifest_substitution_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        for (label, wrong) in substituted_qualified_runtime_variants(&harness.manifest) {
            let manifest = &harness.manifest;
            let grant = &harness.grant;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                &format!("bootstrap {label}"),
                |store| {
                    store.install_c2_live_from_bootstrap_grant_v1(
                        &wrong,
                        manifest,
                        grant,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
        let substituted_manifest = substituted_valid_manifest(&harness.manifest);
        let qualified = &harness.qualified;
        let grant = &harness.grant;
        let fixture = &harness.authority_fixture;
        assert_consequence_root_refuses_without_write(
            &mut harness.store,
            &harness.database,
            custody_directory.path(),
            "bootstrap implementation-manifest substitution",
            |store| {
                store.install_c2_live_from_bootstrap_grant_v1(
                    qualified,
                    &substituted_manifest,
                    grant,
                    |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                )
            },
        );
        complete_bootstrap_installation(&mut harness);
    });
}

#[test]
fn healthy_consequence_root_rejects_candidate_tree_runtime_and_manifest_substitution_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        let intent = C2HealthySuccessorIntentV1::new(
            sha256_bytes(b"hostile-full-root/healthy-transition"),
            sha256_bytes(b"hostile-full-root/healthy-pop-challenge"),
            10_000,
        )
        .expect("construct exact healthy intent");
        for (label, wrong) in substituted_qualified_runtime_variants(&harness.manifest) {
            let manifest = &harness.manifest;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                &format!("healthy {label}"),
                |store| {
                    store.rotate_c2_live_healthy_successor_v1(
                        &wrong,
                        manifest,
                        &intent,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
        let substituted_manifest = substituted_valid_manifest(&harness.manifest);
        let qualified = &harness.qualified;
        let fixture = &harness.authority_fixture;
        assert_consequence_root_refuses_without_write(
            &mut harness.store,
            &harness.database,
            custody_directory.path(),
            "healthy implementation-manifest substitution",
            |store| {
                store.rotate_c2_live_healthy_successor_v1(
                    qualified,
                    &substituted_manifest,
                    &intent,
                    |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                )
            },
        );
        harness
            .store
            .rotate_c2_live_healthy_successor_v1(
                &harness.qualified,
                &harness.manifest,
                &intent,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("exact healthy coordinates still complete");
    });
}

#[test]
fn restore_consequence_root_rejects_candidate_tree_runtime_and_manifest_substitution_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (request, authorization) = exact_restore_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.authority_fixture,
        );
        for (label, wrong) in substituted_qualified_runtime_variants(&harness.manifest) {
            let manifest = &harness.manifest;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                &format!("restore {label}"),
                |store| {
                    store.restore_c2_live_historical_foundation_v1(
                        &wrong,
                        manifest,
                        &request,
                        &authorization,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
        let substituted_manifest = substituted_valid_manifest(&harness.manifest);
        let qualified = &harness.qualified;
        let fixture = &harness.authority_fixture;
        assert_consequence_root_refuses_without_write(
            &mut harness.store,
            &harness.database,
            custody_directory.path(),
            "restore implementation-manifest substitution",
            |store| {
                store.restore_c2_live_historical_foundation_v1(
                    qualified,
                    &substituted_manifest,
                    &request,
                    &authorization,
                    |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                )
            },
        );
        harness
            .store
            .restore_c2_live_historical_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("exact restore coordinates still complete");
    });
}

#[test]
fn recovery_consequence_root_rejects_candidate_tree_runtime_and_manifest_substitution_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (prepared, grant) = exact_recovery_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let request = prepared.request().clone();
        drop(prepared);
        for (label, wrong) in substituted_qualified_runtime_variants(&harness.manifest) {
            let manifest = &harness.manifest;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                &format!("recovery {label}"),
                |store| {
                    store.recover_c2_live_new_foundation_v1(
                        &wrong,
                        manifest,
                        &request,
                        &grant,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
        let substituted_manifest = substituted_valid_manifest(&harness.manifest);
        let qualified = &harness.qualified;
        let fixture = &harness.authority_fixture;
        assert_consequence_root_refuses_without_write(
            &mut harness.store,
            &harness.database,
            custody_directory.path(),
            "recovery implementation-manifest substitution",
            |store| {
                store.recover_c2_live_new_foundation_v1(
                    qualified,
                    &substituted_manifest,
                    &request,
                    &grant,
                    |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                )
            },
        );
        harness
            .store
            .recover_c2_live_new_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("exact recovery coordinates still complete");
    });
}

#[test]
fn bootstrap_consequence_root_rejects_resigned_wrong_request_coordinates_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        let request = load_prepared_bootstrap_request(&harness.database);
        let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
        let digest =
            |tag: u8| JsonValue::String(format!("sha256:{}", format!("{tag:02x}").repeat(32)));
        let cases = [
            (
                "bootstrap occurrence/Store scope",
                "occurrence_id",
                JsonValue::String("hostile.bootstrap.wrong-occurrence".to_owned()),
            ),
            (
                "bootstrap controlling activation/session",
                "controlling_activation",
                digest(0x71),
            ),
            (
                "bootstrap resident generation",
                "resident_generation",
                JsonValue::from(9_000_001_u64),
            ),
            ("bootstrap proposal", "proposal_identity", digest(0x72)),
            (
                "bootstrap custody",
                "custody_instance_identity",
                digest(0x73),
            ),
            (
                "bootstrap policy",
                "signer_scope_policy_identity",
                digest(0x74),
            ),
            (
                "bootstrap applicability",
                "installed_policy_calculation_identity",
                digest(0x75),
            ),
            (
                "bootstrap transition cut",
                "c2_lifecycle_cut",
                JsonValue::from(9_000_002_u64),
            ),
        ];

        for (label, field, replacement) in cases {
            let wrong_request = mutated_bootstrap_request(&request, field, replacement);
            let wrong_grant = sign_exact_bootstrap_grant_for_test(&wrong_request, &signing_key);
            let qualified = &harness.qualified;
            let manifest = &harness.manifest;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                label,
                |store| {
                    store.install_c2_live_from_bootstrap_grant_v1(
                        qualified,
                        manifest,
                        &wrong_grant,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
        complete_bootstrap_installation(&mut harness);
    });
}

#[test]
fn healthy_consequence_root_rejects_changed_completed_occurrence_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        let transition = sha256_bytes(b"hostile-full-root/healthy-changed/transition");
        let exact = C2HealthySuccessorIntentV1::new(
            transition.clone(),
            sha256_bytes(b"hostile-full-root/healthy-changed/challenge"),
            10_000,
        )
        .expect("construct exact healthy transition");
        harness
            .store
            .rotate_c2_live_healthy_successor_v1(
                &harness.qualified,
                &harness.manifest,
                &exact,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("complete exact healthy transition once");

        let changed_cases = [
            (
                "healthy same transition with changed MSG-07 challenge/content",
                C2HealthySuccessorIntentV1::new(
                    transition.clone(),
                    sha256_bytes(b"hostile-full-root/healthy-changed/other-challenge"),
                    10_000,
                )
                .expect("construct changed challenge collision"),
            ),
            (
                "healthy same transition with changed cut/content",
                C2HealthySuccessorIntentV1::new(
                    transition,
                    sha256_bytes(b"hostile-full-root/healthy-changed/challenge"),
                    10_001,
                )
                .expect("construct changed cut collision"),
            ),
        ];
        for (label, changed) in changed_cases {
            let qualified = &harness.qualified;
            let manifest = &harness.manifest;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                label,
                |store| {
                    store.rotate_c2_live_healthy_successor_v1(
                        qualified,
                        manifest,
                        &changed,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
    });
}

#[test]
fn restore_consequence_root_rejects_resigned_wrong_request_coordinates_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (request, authorization) = exact_restore_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.authority_fixture,
        );
        let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
        let digest =
            |tag: u8| JsonValue::String(format!("sha256:{}", format!("{tag:02x}").repeat(32)));
        let cases = [
            (
                "restore Store generation",
                "physical_store_generation_identity",
                digest(0x81),
                false,
            ),
            (
                "restore lifecycle root",
                "signer_lifecycle_root_identity",
                digest(0x82),
                false,
            ),
            ("restore scope", "scope_identity", digest(0x83), false),
            (
                "restore policy",
                "active_store_policy_identity",
                digest(0x84),
                false,
            ),
            (
                "restore frontier",
                "pre_effect_frontier_identity",
                digest(0x85),
                false,
            ),
            (
                "restore exact-effect request/carrier substitution",
                "desired_effect_projection_identity",
                digest(0x86),
                true,
            ),
            (
                "restore predecessor current signer",
                "predecessor_current_signer_binding_identity",
                digest(0x87),
                false,
            ),
            (
                "restore predecessor key generation",
                "predecessor_generation_commitment_identity",
                digest(0x88),
                false,
            ),
            (
                "restore transition request/carrier substitution",
                "target_restore_proposal_identity",
                digest(0x89),
                true,
            ),
            (
                "restore successor proposal",
                "target_signer_proposal_identity",
                digest(0x8a),
                false,
            ),
            (
                "restore custody",
                "target_custody_binding_identity",
                digest(0x8b),
                false,
            ),
            (
                "restore lineage request/carrier substitution",
                "restore_declaration_identity",
                digest(0x8c),
                true,
            ),
        ];

        for (label, field, replacement, substitute_carrier_only) in cases {
            let (wrong_request, wrong_authorization) = sign_exact_restore_authorization_for_test(
                request_fields_with_mutation(request.canonical_bytes(), field, replacement),
                &signing_key,
            );
            let presented_request = if substitute_carrier_only {
                &request
            } else {
                &wrong_request
            };
            let qualified = &harness.qualified;
            let manifest = &harness.manifest;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                label,
                |store| {
                    store.restore_c2_live_historical_foundation_v1(
                        qualified,
                        manifest,
                        presented_request,
                        &wrong_authorization,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
        harness
            .store
            .restore_c2_live_historical_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("exact restore coordinates still complete");
    });
}

#[test]
fn recovery_consequence_root_rejects_resigned_wrong_request_coordinates_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (prepared, grant) = exact_recovery_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let request = prepared.request().clone();
        let signing_key = SigningKey::from_bytes(&[1_u8; 32]);
        let digest =
            |tag: u8| JsonValue::String(format!("sha256:{}", format!("{tag:02x}").repeat(32)));
        let cases = [
            (
                "recovery Store generation",
                "physical_store_generation_identity",
                digest(0x91),
                false,
            ),
            (
                "recovery lifecycle root",
                "signer_lifecycle_root_identity",
                digest(0x92),
                false,
            ),
            ("recovery scope", "scope_identity", digest(0x93), false),
            (
                "recovery policy",
                "active_store_policy_identity",
                digest(0x94),
                false,
            ),
            (
                "recovery frontier",
                "pre_effect_frontier_identity",
                digest(0x95),
                false,
            ),
            (
                "recovery exact-effect request/carrier substitution",
                "desired_effect_projection_identity",
                digest(0x96),
                true,
            ),
            (
                "recovery predecessor",
                "recovery_predecessor_binding_identity",
                digest(0x97),
                false,
            ),
            (
                "recovery predecessor key generation",
                "predecessor_key_generation",
                JsonValue::from(9_000_003_u64),
                false,
            ),
            (
                "recovery successor proposal",
                "successor_proposal_identity",
                digest(0x98),
                false,
            ),
            (
                "recovery custody",
                "successor_custody_binding_identity",
                digest(0x99),
                false,
            ),
            (
                "recovery PoP challenge request/carrier substitution",
                "successor_pop_challenge_identity",
                digest(0x9a),
                true,
            ),
            (
                "recovery transition request/carrier substitution",
                "recovery_successor_projection_identity",
                digest(0x9b),
                true,
            ),
        ];

        for (label, field, replacement, substitute_carrier_only) in cases {
            let wrong_request = mutated_recovery_request(&request, field, replacement);
            let wrong_grant = sign_exact_recovery_grant_for_test(&wrong_request, &signing_key);
            let presented_request = if substitute_carrier_only {
                &request
            } else {
                &wrong_request
            };
            let qualified = &harness.qualified;
            let manifest = &harness.manifest;
            let fixture = &harness.authority_fixture;
            assert_consequence_root_refuses_without_write(
                &mut harness.store,
                &harness.database,
                custody_directory.path(),
                label,
                |store| {
                    store.recover_c2_live_new_foundation_v1(
                        qualified,
                        manifest,
                        presented_request,
                        &wrong_grant,
                        |snapshot| resolve_runtime_authority_fixture(fixture, snapshot),
                    )
                },
            );
        }
        drop(prepared);
        harness
            .store
            .recover_c2_live_new_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("exact recovery coordinates still complete");
    });
}

#[test]
fn candidate_tree_runtime_and_manifest_reopen_mismatches_are_exact_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        let measured_runtime =
            sha256_bytes(&fs::read("/proc/self/exe").expect("read exact running Linux test image"));
        let manifest_identity = harness.manifest.manifest_identity().clone();
        let variants = [
            (
                "qualified candidate",
                StoreC2QualifiedRuntimeEvidenceV1::for_test(
                    sha256_bytes(b"hostile-reopen/wrong-candidate"),
                    sha256_bytes(b"bootstrap-crash/source-tree"),
                    measured_runtime.clone(),
                    manifest_identity.clone(),
                ),
            ),
            (
                "source tree",
                StoreC2QualifiedRuntimeEvidenceV1::for_test(
                    sha256_bytes(b"bootstrap-crash/candidate"),
                    sha256_bytes(b"hostile-reopen/wrong-source-tree"),
                    measured_runtime.clone(),
                    manifest_identity.clone(),
                ),
            ),
            (
                "runtime artifact",
                StoreC2QualifiedRuntimeEvidenceV1::for_test(
                    sha256_bytes(b"bootstrap-crash/candidate"),
                    sha256_bytes(b"bootstrap-crash/source-tree"),
                    sha256_bytes(b"hostile-reopen/wrong-runtime-artifact"),
                    manifest_identity.clone(),
                ),
            ),
            (
                "qualified manifest",
                StoreC2QualifiedRuntimeEvidenceV1::for_test(
                    sha256_bytes(b"bootstrap-crash/candidate"),
                    sha256_bytes(b"bootstrap-crash/source-tree"),
                    measured_runtime,
                    sha256_bytes(b"hostile-reopen/wrong-manifest"),
                ),
            ),
        ];

        for (coordinate, wrong) in variants {
            let before =
                exact_durable_state(&harness.store, &harness.database, custody_directory.path());
            let callback_entered = Cell::new(false);
            let refusal: Result<(), C2LiveReopenRefusalV1> =
                harness.store.with_reopened_c2_generation_current_v1(
                    &wrong,
                    &harness.manifest,
                    |snapshot| {
                        resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot)
                    },
                    |_session| {
                        callback_entered.set(true);
                        Ok(())
                    },
                );
            assert!(refusal.is_err(), "wrong {coordinate} unexpectedly reopened");
            assert!(
                !callback_entered.get(),
                "wrong {coordinate} reached live writer callback"
            );
            assert_eq!(
                exact_durable_state(&harness.store, &harness.database, custody_directory.path(),),
                before,
                "wrong {coordinate} wrote durable state: {refusal:?}"
            );
        }

        let callback_entered = Cell::new(false);
        harness
            .store
            .with_reopened_c2_generation_current_v1(
                &harness.qualified,
                &harness.manifest,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
                |_session| {
                    callback_entered.set(true);
                    Ok::<_, C2LiveReopenRefusalV1>(())
                },
            )
            .expect("exact coordinates still reopen after all mismatch refusals");
        assert!(callback_entered.get());
    });
}

#[test]
fn durable_generation_current_coordinate_substitution_refuses_reopen_without_writes() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        let a_to_b = C2HealthySuccessorIntentV1::new(
            sha256_bytes(b"hostile-reopen-coordinate/transition/a-to-b"),
            sha256_bytes(b"hostile-reopen-coordinate/challenge/b"),
            10_000,
        )
        .expect("construct exact A-to-B intent");
        harness
            .store
            .rotate_c2_live_healthy_successor_v1(
                &harness.qualified,
                &harness.manifest,
                &a_to_b,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("complete exact A-to-B transition");

        let PreparedBootstrapHarnessV1 {
            _store_directory: store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        let mut store = store;
        let baseline = exact_durable_state(&store, &database, custody_directory.path());

        const TERMINAL_ACCEPTANCE: &str = "signer_enrollment_identity = (SELECT current_enrollment_identity \
             FROM c2_signer_current_binding_projection ORDER BY effective_cut DESC LIMIT 1)";
        const TERMINAL_ADOPTION: &str = "adoption_identity = (SELECT acceptance.foundational_adoption_identity \
             FROM c2_signer_enrollment_acceptances AS acceptance \
             JOIN c2_signer_current_binding_projection AS current \
               ON current.current_enrollment_identity = acceptance.signer_enrollment_identity \
             ORDER BY current.effective_cut DESC LIMIT 1)";
        const TERMINAL_FOUNDATION: &str = "foundation_identity = (SELECT adoption.foundation_identity \
             FROM c2_signer_foundations AS foundation \
             JOIN c2_foundational_enrollment_adoptions AS adoption \
               ON adoption.foundation_identity = foundation.foundation_identity \
             JOIN c2_signer_enrollment_acceptances AS acceptance \
               ON acceptance.foundational_adoption_identity = adoption.adoption_identity \
             JOIN c2_signer_current_binding_projection AS current \
               ON current.current_enrollment_identity = acceptance.signer_enrollment_identity \
             ORDER BY current.effective_cut DESC LIMIT 1)";
        const TERMINAL_CURRENT: &str = "current_binding_identity = (SELECT terminal_binding_identity \
             FROM c2_signer_lineage_completion_projection ORDER BY edge_count DESC LIMIT 1)";
        const TERMINAL_COMPLETION: &str = "lineage_identity = (SELECT lineage_identity \
             FROM c2_signer_lineage_completion_projection ORDER BY edge_count DESC LIMIT 1)";
        const TERMINAL_PREDECESSOR: &str = "current_binding_identity = (SELECT current.predecessor_binding_identity \
             FROM c2_signer_current_binding_projection AS current \
             JOIN c2_signer_lineage_completion_projection AS completion \
               ON completion.terminal_binding_identity = current.current_binding_identity \
             ORDER BY current.effective_cut DESC LIMIT 1)";
        const TERMINAL_SUCCESSION: &str = "successor_binding_identity = (SELECT terminal_binding_identity \
             FROM c2_signer_lineage_completion_projection ORDER BY edge_count DESC LIMIT 1)";
        const TERMINAL_RESOLUTION: &str = "effect_receipt_identity = (SELECT current.persisted_resolution_identity \
             FROM c2_signer_current_binding_projection AS current \
             JOIN c2_signer_lineage_completion_projection AS completion \
               ON completion.terminal_binding_identity = current.current_binding_identity \
             ORDER BY current.effective_cut DESC LIMIT 1)";

        let substituted_foundation_custody = replace_json_field_bytes_for_test(
            &database,
            "c2_signer_foundations",
            "foundation_canonical_bytes",
            TERMINAL_FOUNDATION,
            "custody_evidence_identity",
            JsonValue::String(format!("sha256:{}", "c1".repeat(32))),
        );
        let substituted_adoption_store = replace_json_field_bytes_for_test(
            &database,
            "c2_foundational_enrollment_adoptions",
            "adoption_canonical_bytes",
            TERMINAL_ADOPTION,
            "store_identity",
            JsonValue::String(format!("sha256:{}", "c2".repeat(32))),
        );
        let substituted_adoption_applicability = replace_json_field_bytes_for_test(
            &database,
            "c2_foundational_enrollment_adoptions",
            "adoption_canonical_bytes",
            TERMINAL_ADOPTION,
            "applicability_basis_identity",
            JsonValue::String(format!("sha256:{}", "c3".repeat(32))),
        );
        let substituted_adoption_candidate = replace_json_field_bytes_for_test(
            &database,
            "c2_foundational_enrollment_adoptions",
            "adoption_canonical_bytes",
            TERMINAL_ADOPTION,
            "candidate_identity",
            JsonValue::String(format!("sha256:{}", "c4".repeat(32))),
        );
        let substituted_terminal_transaction = replace_nested_json_field_bytes_for_test(
            &database,
            "c2_signer_message_appends",
            "canonical_message",
            TERMINAL_RESOLUTION,
            "coordinates",
            "transaction_intent_identity",
            JsonValue::String(format!("sha256:{}", "c5".repeat(32))),
        );

        let cases = [
            (
                RawImmutableMutationSpecV1 {
                    label: "stable foundation identity",
                    table: "c2_signer_foundations",
                    column: "foundation_identity",
                    update_trigger: "immutable_c2_signer_foundations_update",
                    row_selector: TERMINAL_FOUNDATION,
                },
                SqlValue::Text(format!("sha256:{}", "a1".repeat(32))),
                true,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "adoption identity",
                    table: "c2_foundational_enrollment_adoptions",
                    column: "adoption_identity",
                    update_trigger: "immutable_c2_foundational_enrollment_adoptions_update",
                    row_selector: TERMINAL_ADOPTION,
                },
                SqlValue::Text(format!("sha256:{}", "a2".repeat(32))),
                true,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "acceptance identity",
                    table: "c2_signer_enrollment_acceptances",
                    column: "signer_enrollment_identity",
                    update_trigger: "immutable_c2_signer_enrollment_acceptances_update",
                    row_selector: TERMINAL_ACCEPTANCE,
                },
                SqlValue::Text(format!("sha256:{}", "a3".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "physical generation",
                    table: "c2_signer_current_binding_projection",
                    column: "physical_store_generation_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "a4".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "lifecycle root",
                    table: "c2_signer_current_binding_projection",
                    column: "signer_lifecycle_root_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "a5".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "signer scope",
                    table: "c2_signer_current_binding_projection",
                    column: "scope_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "a6".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "current signer binding",
                    table: "c2_signer_current_binding_projection",
                    column: "current_binding_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "a7".repeat(32))),
                true,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "current signer enrollment",
                    table: "c2_signer_current_binding_projection",
                    column: "current_enrollment_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "a8".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "current signer standing",
                    table: "c2_signer_current_binding_projection",
                    column: "current_standing_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "a9".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "predecessor binding",
                    table: "c2_signer_current_binding_projection",
                    column: "predecessor_binding_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "aa".repeat(32))),
                true,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "predecessor key generation",
                    table: "c2_signer_current_binding_projection",
                    column: "current_key_generation",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_PREDECESSOR,
                },
                SqlValue::Integer(9_000_000),
                true,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "terminal binding",
                    table: "c2_signer_lineage_completion_projection",
                    column: "terminal_binding_identity",
                    update_trigger: "immutable_c2_signer_lineage_completion_update",
                    row_selector: TERMINAL_COMPLETION,
                },
                SqlValue::Text(format!("sha256:{}", "ab".repeat(32))),
                true,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "transition",
                    table: "c2_signer_current_binding_projection",
                    column: "transition_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "ac".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "MSG-06 predecessor continuity",
                    table: "c2_signer_current_binding_projection",
                    column: "continuity_authorization_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "b0".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "active policy",
                    table: "c2_signer_current_binding_projection",
                    column: "current_policy_identity",
                    update_trigger: "immutable_c2_signer_current_binding_update",
                    row_selector: TERMINAL_CURRENT,
                },
                SqlValue::Text(format!("sha256:{}", "ad".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "successor proposal",
                    table: "c2_signer_succession_projection",
                    column: "proposal_identity",
                    update_trigger: "immutable_c2_signer_succession_update",
                    row_selector: TERMINAL_SUCCESSION,
                },
                SqlValue::Text(format!("sha256:{}", "ae".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "successor proof of possession",
                    table: "c2_signer_succession_projection",
                    column: "successor_pop_identity",
                    update_trigger: "immutable_c2_signer_succession_update",
                    row_selector: TERMINAL_SUCCESSION,
                },
                SqlValue::Text(format!("sha256:{}", "af".repeat(32))),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "foundation custody",
                    table: "c2_signer_foundations",
                    column: "foundation_canonical_bytes",
                    update_trigger: "immutable_c2_signer_foundations_update",
                    row_selector: TERMINAL_FOUNDATION,
                },
                SqlValue::Blob(substituted_foundation_custody),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "adoption Store",
                    table: "c2_foundational_enrollment_adoptions",
                    column: "adoption_canonical_bytes",
                    update_trigger: "immutable_c2_foundational_enrollment_adoptions_update",
                    row_selector: TERMINAL_ADOPTION,
                },
                SqlValue::Blob(substituted_adoption_store),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "adoption applicability",
                    table: "c2_foundational_enrollment_adoptions",
                    column: "adoption_canonical_bytes",
                    update_trigger: "immutable_c2_foundational_enrollment_adoptions_update",
                    row_selector: TERMINAL_ADOPTION,
                },
                SqlValue::Blob(substituted_adoption_applicability),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "adoption candidate",
                    table: "c2_foundational_enrollment_adoptions",
                    column: "adoption_canonical_bytes",
                    update_trigger: "immutable_c2_foundational_enrollment_adoptions_update",
                    row_selector: TERMINAL_ADOPTION,
                },
                SqlValue::Blob(substituted_adoption_candidate),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "frontier",
                    table: "c2_signer_message_appends",
                    column: "resulting_frontier_identity",
                    update_trigger: "immutable_c2_signer_message_appends_update",
                    row_selector: TERMINAL_RESOLUTION,
                },
                SqlValue::Blob(vec![0xf1; 32]),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "route",
                    table: "c2_signer_message_appends",
                    column: "route",
                    update_trigger: "immutable_c2_signer_message_appends_update",
                    row_selector: TERMINAL_RESOLUTION,
                },
                SqlValue::Text("msg08_global_refusal".to_owned()),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "identity domain",
                    table: "c2_signer_message_appends",
                    column: "identity_domain",
                    update_trigger: "immutable_c2_signer_message_appends_update",
                    row_selector: TERMINAL_RESOLUTION,
                },
                SqlValue::Text("nq.c2.hostile.substituted.identity.v1".to_owned()),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "signature domain",
                    table: "c2_signer_message_appends",
                    column: "signature_domain",
                    update_trigger: "immutable_c2_signer_message_appends_update",
                    row_selector: TERMINAL_RESOLUTION,
                },
                SqlValue::Text("nq.c2.hostile.substituted.signature.v1".to_owned()),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "transaction",
                    table: "c2_signer_message_appends",
                    column: "canonical_message",
                    update_trigger: "immutable_c2_signer_message_appends_update",
                    row_selector: TERMINAL_RESOLUTION,
                },
                SqlValue::Blob(substituted_terminal_transaction),
                false,
            ),
            (
                RawImmutableMutationSpecV1 {
                    label: "exact content",
                    table: "c2_signer_message_appends",
                    column: "exact_content_identity",
                    update_trigger: "immutable_c2_signer_message_appends_update",
                    row_selector: TERMINAL_RESOLUTION,
                },
                SqlValue::Blob(vec![0xec; 32]),
                false,
            ),
        ];

        for (spec, replacement, expect_store_open_refusal) in cases {
            drop(store);
            let undo = replace_one_immutable_cell_for_test(&database, spec, replacement);
            let tampered = exact_durable_state_from_database(&database, custody_directory.path());
            match Store::open(&database) {
                Ok(mut tampered_store) => {
                    assert!(
                        !expect_store_open_refusal,
                        "{} substitution should have failed Store::open integrity validation",
                        spec.label
                    );
                    let callback_entered = Cell::new(false);
                    let refusal: Result<(), C2LiveReopenRefusalV1> = tampered_store
                        .with_reopened_c2_generation_current_v1(
                            &qualified,
                            &manifest,
                            |snapshot| {
                                resolve_runtime_authority_fixture(&authority_fixture, snapshot)
                            },
                            |_session| {
                                callback_entered.set(true);
                                Ok(())
                            },
                        );
                    assert!(
                        refusal.is_err(),
                        "{} substitution unexpectedly reopened GenerationCurrent",
                        spec.label
                    );
                    assert!(
                        !callback_entered.get(),
                        "{} substitution entered the live writer callback",
                        spec.label
                    );
                    assert_eq!(
                        exact_durable_state(&tampered_store, &database, custody_directory.path(),),
                        tampered,
                        "{} refusal wrote durable Store/B/G/custody state: {refusal:?}",
                        spec.label
                    );
                }
                Err(error) => {
                    assert!(
                        expect_store_open_refusal,
                        "{} unexpectedly failed before the production reopen root: {error}",
                        spec.label
                    );
                    assert!(
                        matches!(error, StoreError::Integrity(_)),
                        "{} failed Store::open with a non-integrity refusal: {error}",
                        spec.label
                    );
                    assert_eq!(
                        exact_durable_state_from_database(&database, custody_directory.path(),),
                        tampered,
                        "{} Store::open integrity refusal wrote durable state",
                        spec.label
                    );
                }
            }

            let tampered_value = restore_one_immutable_cell_for_test(&database, undo);
            assert_ne!(
                tampered_value,
                SqlValue::Null,
                "{} hostile mutation unexpectedly selected NULL",
                spec.label
            );
            store = Store::open(&database)
                .unwrap_or_else(|error| panic!("{}: reopen restored Store: {error}", spec.label));
            assert_eq!(
                exact_durable_state(&store, &database, custody_directory.path()),
                baseline,
                "{}: exact baseline was not restored before the next mutation",
                spec.label
            );
        }

        let callback_entered = Cell::new(false);
        store
            .with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                |_session| {
                    callback_entered.set(true);
                    Ok::<_, C2LiveReopenRefusalV1>(())
                },
            )
            .expect("exact restored GenerationCurrent still reopens");
        assert!(callback_entered.get());
        drop(store_directory);
    });
}

#[test]
fn bootstrap_consumed_request_substitution_refuses_reopen_without_writes() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        const BOOTSTRAP_REQUEST: &str = "route = 'msg01_bootstrap_grant'";
        let substituted_request = replace_json_field_bytes_for_test(
            &harness.database,
            "c2_external_carrier_ingress",
            "canonical_request",
            BOOTSTRAP_REQUEST,
            "occurrence_id",
            JsonValue::String("hostile-substituted-occurrence".to_owned()),
        );
        let PreparedBootstrapHarnessV1 {
            _store_directory: store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        let mut store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "bootstrap MSG-01 request occurrence",
                table: "c2_external_carrier_ingress",
                column: "canonical_request",
                update_trigger: "immutable_c2_external_carrier_ingress_update",
                row_selector: BOOTSTRAP_REQUEST,
            },
            SqlValue::Blob(substituted_request),
            false,
        );
        store
            .with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                |_session| Ok::<_, C2LiveReopenRefusalV1>(()),
            )
            .expect("restored exact bootstrap terminal reopens");
        drop(store_directory);
    });
}

#[test]
fn restore_consumed_request_authority_and_historical_foundation_substitutions_refuse_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (request, authorization) = exact_restore_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.authority_fixture,
        );
        harness
            .store
            .restore_c2_live_historical_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("complete exact restore");

        const RESTORE_REQUEST: &str = "route = 'msg13_restore_authorization'";
        const TERMINAL_CURRENT: &str = "current_binding_identity = (SELECT terminal_binding_identity \
             FROM c2_signer_lineage_completion_projection ORDER BY edge_count DESC LIMIT 1)";
        let substituted_request = replace_json_field_bytes_for_test(
            &harness.database,
            "c2_external_carrier_ingress",
            "canonical_request",
            RESTORE_REQUEST,
            "target_signer_proposal_identity",
            JsonValue::String(format!("sha256:{}", "d1".repeat(32))),
        );
        let PreparedBootstrapHarnessV1 {
            _store_directory: store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        let store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "restore MSG-13 request proposal",
                table: "c2_external_carrier_ingress",
                column: "canonical_request",
                update_trigger: "immutable_c2_external_carrier_ingress_update",
                row_selector: RESTORE_REQUEST,
            },
            SqlValue::Blob(substituted_request),
            false,
        );
        let store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "restore entry authority",
                table: "c2_signer_current_binding_projection",
                column: "restore_authority_identity",
                update_trigger: "immutable_c2_signer_current_binding_update",
                row_selector: TERMINAL_CURRENT,
            },
            SqlValue::Text(format!("sha256:{}", "d2".repeat(32))),
            false,
        );
        let mut store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "restore historical stable foundation",
                table: "c2_signer_current_binding_projection",
                column: "historical_foundation_identity",
                update_trigger: "immutable_c2_signer_current_binding_update",
                row_selector: TERMINAL_CURRENT,
            },
            SqlValue::Text(format!("sha256:{}", "d3".repeat(32))),
            false,
        );
        store
            .with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                |_session| Ok::<_, C2LiveReopenRefusalV1>(()),
            )
            .expect("restored exact restore terminal reopens");
        drop(store_directory);
    });
}

#[test]
fn recovery_consumed_request_condition_authority_and_grant_substitutions_refuse_no_write() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);
        apply_exact_revocation_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let (prepared, grant) = exact_recovery_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.manifest,
            &harness.authority_fixture,
        );
        let request = prepared.request().clone();
        harness
            .store
            .recover_c2_live_new_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &grant,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect("complete exact recovery");
        drop(prepared);

        const RECOVERY_REQUEST: &str = "route = 'msg15_recovery_grant'";
        const TERMINAL_CURRENT: &str = "current_binding_identity = (SELECT terminal_binding_identity \
             FROM c2_signer_lineage_completion_projection ORDER BY edge_count DESC LIMIT 1)";
        let substituted_request = replace_json_field_bytes_for_test(
            &harness.database,
            "c2_external_carrier_ingress",
            "canonical_request",
            RECOVERY_REQUEST,
            "successor_proposal_identity",
            JsonValue::String(format!("sha256:{}", "e1".repeat(32))),
        );
        let PreparedBootstrapHarnessV1 {
            _store_directory: store_directory,
            database,
            store,
            authority_fixture,
            qualified,
            manifest,
            grant: _,
        } = harness;
        let store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "recovery MSG-15 request proposal",
                table: "c2_external_carrier_ingress",
                column: "canonical_request",
                update_trigger: "immutable_c2_external_carrier_ingress_update",
                row_selector: RECOVERY_REQUEST,
            },
            SqlValue::Blob(substituted_request),
            false,
        );
        let store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "recovery discontinuity condition",
                table: "c2_signer_current_binding_projection",
                column: "recovery_condition_identity",
                update_trigger: "immutable_c2_signer_current_binding_update",
                row_selector: TERMINAL_CURRENT,
            },
            SqlValue::Text(format!("sha256:{}", "e2".repeat(32))),
            false,
        );
        let store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "recovery entry authority",
                table: "c2_signer_current_binding_projection",
                column: "recovery_authority_identity",
                update_trigger: "immutable_c2_signer_current_binding_update",
                row_selector: TERMINAL_CURRENT,
            },
            SqlValue::Text(format!("sha256:{}", "e3".repeat(32))),
            false,
        );
        let mut store = assert_one_consumed_reopen_coordinate_refuses_without_write(
            store,
            &database,
            custody_directory.path(),
            &authority_fixture,
            &qualified,
            &manifest,
            RawImmutableMutationSpecV1 {
                label: "recovery MSG-15 grant",
                table: "c2_signer_current_binding_projection",
                column: "recovery_grant_identity",
                update_trigger: "immutable_c2_signer_current_binding_update",
                row_selector: TERMINAL_CURRENT,
            },
            SqlValue::Text(format!("sha256:{}", "e4".repeat(32))),
            false,
        );
        store
            .with_reopened_c2_generation_current_v1(
                &qualified,
                &manifest,
                |snapshot| resolve_runtime_authority_fixture(&authority_fixture, snapshot),
                |_session| Ok::<_, C2LiveReopenRefusalV1>(()),
            )
            .expect("restored exact recovery terminal reopens");
        drop(store_directory);
    });
}

#[test]
fn discontinuity_routes_cannot_bypass_available_ordinary_continuity_and_write_nothing() {
    let custody_directory = tempdir().expect("create test custody root");
    fs::set_permissions(custody_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("seal test custody root permissions");

    with_test_production_custody_root_v1(custody_directory.path(), || {
        let mut harness = prepare_bootstrap_harness();
        complete_bootstrap_installation(&mut harness);

        let before_restore =
            exact_durable_state(&harness.store, &harness.database, custody_directory.path());
        let (request, authorization) = exact_restore_pair_for_test(
            &mut harness.store,
            &harness.qualified,
            &harness.authority_fixture,
        );
        let restore_refusal = harness
            .store
            .restore_c2_live_historical_foundation_v1(
                &harness.qualified,
                &harness.manifest,
                &request,
                &authorization,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect_err("MSG-13 must not bypass available ordinary continuity");
        assert!(matches!(
            restore_refusal,
            C2LiveTransitionDriverRefusalV1::Discontinuity(
                C2DiscontinuityRefusalV1::RestoreEligibilityAbsent
            )
        ));
        assert_eq!(
            exact_durable_state(&harness.store, &harness.database, custody_directory.path(),),
            before_restore,
            "refused restore wrote durable Store/B/G/custody state"
        );

        let recovery_intent = C2RecoveryPreparationIntentV1::new(
            C2RecoveryPredecessorStatusV1::InactiveRevoked,
            sha256_bytes(b"hostile-discontinuity-bypass/recovery-transition"),
            sha256_bytes(b"hostile-discontinuity-bypass/recovery-pop-challenge"),
        )
        .expect("construct exact inert recovery intent");
        let before_recovery =
            exact_durable_state(&harness.store, &harness.database, custody_directory.path());
        let recovery_refusal = harness
            .store
            .prepare_c2_live_recovery_v1(
                &harness.qualified,
                &harness.manifest,
                &recovery_intent,
                |snapshot| resolve_runtime_authority_fixture(&harness.authority_fixture, snapshot),
            )
            .expect_err("MSG-15 preparation must not bypass available ordinary continuity");
        assert!(matches!(
            recovery_refusal,
            C2LiveTransitionDriverRefusalV1::Discontinuity(
                C2DiscontinuityRefusalV1::RecoveryEligibilityAbsent
            )
        ));
        assert_eq!(
            exact_durable_state(&harness.store, &harness.database, custody_directory.path(),),
            before_recovery,
            "refused recovery preparation wrote durable Store/B/G/custody state"
        );
    });
}
