//! Actual helper-to-governed-V2 effect-path qualification.
//!
//! These tests use the opt-in host-role runtime fixture support only to build
//! authenticated contract inputs. The opaque prepared token still comes from
//! the production native-deadline preparation path, and provider bytes still
//! come through the actual admission and `StdioRunner` paths.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nq_host_role_contract::{RecordRef, Token};
use nq_host_role_runtime::{
    HostRoleRuntime,
    test_support::{
        NativeEngineFixtureBinding, NativeEvaluatorFixtureBinding, NativeProfileFixtureBinding,
        native_engine_fixture,
    },
};
use nq_store::{
    DiagnosticArtifactByteState, DiagnosticArtifactLookup, DiagnosticArtifactSchemaSupport,
    GovernedCustodyInventoryEntry, GovernedCustodyRecoveryClass, GovernedProjectionRecovery,
    GovernedProjectionVerificationDisposition, GovernedProtectedFailureAccess,
};
use tempfile::TempDir;

use super::*;

const PROFILE_FUNCTION: &str = "def profile_outcome(request: dict[str, Any]) -> dict[str, Any]:\n";

#[derive(Clone, Copy)]
enum HelperMode {
    Complete,
    RefuseGoverned,
}

struct EffectFixture {
    _directory: TempDir,
    config: NqConfig,
    watcher: WatcherConfig,
    prepared: PreparedGovernedInvocation,
    reservation_record_id: Sha256Digest,
    marker: PathBuf,
}

fn helper_source(mode: HelperMode) -> String {
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../helpers/python-conformance/nq_conformance_helper.py");
    let source = fs::read_to_string(source_path).expect("Python conformance helper");
    let refusal = match mode {
        HelperMode::Complete => "",
        HelperMode::RefuseGoverned => {
            r#"    if request["request_id"].startswith("nq-provider-"):
        return refusal(
            request,
            "collection",
            "collection_failed",
            "the governed effect-path fixture refused this exact request",
            details={"fixture": "engine-governed-effect"},
        )
"#
        }
    };
    let replacement = format!(
        r#"{PROFILE_FUNCTION}    marker = os.environ.get("NQ_TEST_SPAWN_MARKER")
    if marker:
        with open(marker, "a", encoding="utf-8") as stream:
            stream.write(request["request_id"] + "\n")
{refusal}"#
    );
    let instrumented = source.replacen(PROFILE_FUNCTION, &replacement, 1);
    assert_ne!(instrumented, source, "helper hook inserted");
    instrumented
}

fn effect_config(root: &Path, helper_path: &Path, marker: &Path) -> NqConfig {
    NqConfig::from_toml(&format!(
        r#"schema = "nq.config.v2"
database_path = "{}"
socket_path = "{}"
admissions_dir = "{}"
helper_runtime_dir = "{}"

[[watchers]]
instance_id = "governed.effect"
subject = "conformance:governed-effect"
scope = {{ kind = "fixture", value = {{ id = "governed-effect", nonce = "exact-v2" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = []

[watchers.command]
executable = "{}"
env = {{ NQ_TEST_SPAWN_MARKER = "{}" }}
execution_account = "{}"
allow_same_identity_in_debug = true
working_directory = "{}"

[watchers.profile]
id = "nq.conformance"
version = 1

[watchers.invocation]
deadline_ms = 30000

[watchers.resources]
max_response_bytes = 1048576
max_stderr_bytes = 65536
max_observations = 4
max_address_space_bytes = 536870912
max_cpu_seconds = 60
max_processes = 32
max_open_files = 128
max_file_bytes = 67108864
"#,
        root.join("nq.db").display(),
        root.join("nqd.sock").display(),
        root.join("admissions").display(),
        root.join("helpers").display(),
        helper_path.display(),
        marker.display(),
        nix::unistd::geteuid().as_raw(),
        root.display(),
    ))
    .expect("effect-path configuration")
}

fn apparmor_denied(error: &EngineError) -> bool {
    error.to_string().contains("spawn_failed")
        && fs::read_to_string("/proc/self/attr/current")
            .is_ok_and(|profile| profile.contains("unpriv_bwrap"))
}

#[allow(clippy::too_many_lines)]
fn admitted_effect_fixture(mode: HelperMode, maximum_execution_ms: u64) -> Option<EffectFixture> {
    admitted_effect_fixture_with_profile(
        mode,
        maximum_execution_ms,
        nq_profiles::conformance::PROFILE_ID,
        u64::from(nq_profiles::conformance::PROFILE_VERSION),
    )
}

#[allow(clippy::too_many_lines)]
fn admitted_effect_fixture_with_profile(
    mode: HelperMode,
    maximum_execution_ms: u64,
    production_profile_id: &str,
    production_profile_version: u64,
) -> Option<EffectFixture> {
    let directory = tempfile::tempdir().expect("effect-path directory");
    let root = directory.path();
    let helper_path = root.join("governed_conformance.py");
    let marker = root.join("spawn-marker");
    fs::write(&helper_path, helper_source(mode)).expect("write helper");
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o755))
        .expect("helper executable mode");
    fs::create_dir(root.join("admissions")).expect("admissions directory");
    fs::set_permissions(root.join("admissions"), fs::Permissions::from_mode(0o700))
        .expect("admissions mode");
    fs::create_dir(root.join("helpers")).expect("helper runtime directory");
    fs::set_permissions(root.join("helpers"), fs::Permissions::from_mode(0o711))
        .expect("helper runtime mode");

    let config = effect_config(root, &helper_path, &marker);
    let profile: &'static dyn ProfileModule = &nq_profiles::conformance::MODULE;
    let mut store = Store::initialize(&config.database_path).expect("initialize store");
    append_profile_descriptor(&mut store, profile).expect("append profile descriptor");
    drop(store);

    let watcher = config
        .watcher("governed.effect")
        .expect("configured watcher")
        .clone();
    let mut admission_engine = CollectionEngine::open(&config).expect("admission engine");
    let evaluator = admission_engine
        .require_evaluator_identity()
        .expect("evaluator identity")
        .clone();
    let admission = match admission_engine.watcher_action(&watcher, "admit") {
        Ok(outcome) => outcome,
        Err(error) if apparmor_denied(&error) => {
            eprintln!(
                "skipping governed helper execution: sandbox AppArmor denies executable memfds"
            );
            return None;
        }
        Err(error) => panic!("actual helper admission failed: {error}"),
    };
    let WatcherActionOutcome::Activated { admission_id, .. } = admission else {
        panic!("first actual admission must activate");
    };
    let provider = admission_engine
        .store
        .provider_admission_for_source(&admission_id)
        .expect("provider admission lookup")
        .expect("provider admission");
    let provider_digest = Sha256Digest::parse(provider.provider_admission_id.clone())
        .expect("provider admission identity");
    let provider_admission = RecordRef {
        schema: Token::parse("nq.local_provider_admission.v1").expect("provider schema"),
        record_id: provider_digest.clone(),
        bytes_digest: provider_digest,
    };
    let descriptor = profile.descriptor();
    let descriptor_digest = descriptor.digest().expect("profile descriptor identity");
    let semantic_identity = profile_semantic_id(descriptor).expect("profile semantic identity");
    let detector_closure = nq_store::detector_suite_identity_digest(Vec::<String>::new())
        .expect("zero-detector closure");
    let fixture = native_engine_fixture(&NativeEngineFixtureBinding {
        provider_admission,
        provider_admission_bytes: provider.contract_json,
        production_profile_id: production_profile_id.to_owned(),
        production_profile_version,
        native_profile: NativeProfileFixtureBinding {
            descriptor_schema: nq_profiles::PROFILE_DESCRIPTOR_SCHEMA.to_owned(),
            profile_id: descriptor.profile.id.clone(),
            profile_version: u64::from(descriptor.profile.version),
            descriptor_digest: Sha256Digest::parse(descriptor_digest.as_str().to_owned())
                .expect("typed profile descriptor identity"),
            semantic_identity_schema: nq_profiles::PROFILE_SEMANTIC_ID_SCHEMA.to_owned(),
            semantic_identity_digest: Sha256Digest::parse(semantic_identity.as_str().to_owned())
                .expect("typed profile semantic identity"),
            evaluator_source_digest: Sha256Digest::parse(EVALUATOR_SOURCE_DIGEST.to_owned())
                .expect("evaluator source identity"),
            helper_protocol_version: nq_protocol::HELPER_PROTOCOL_VERSION.to_owned(),
            detector_closure_identity_digest: detector_closure,
            detector_count: 0,
        },
        native_evaluator: NativeEvaluatorFixtureBinding {
            artifact_digest: evaluator.artifact_digest().clone(),
            artifact_identity_method: evaluator.artifact_identity_method().to_owned(),
            target_triple: evaluator.target_triple().to_owned(),
        },
        maximum_execution_ms,
    });
    drop(admission_engine);
    if marker.exists() {
        fs::remove_file(&marker).expect("clear admission spawn marker");
    }

    let mut store = Store::open(&config.database_path).expect("reopen store for runtime");
    store
        .establish_runtime_dependency_trust_root(&fixture.dependency_anchor_id)
        .expect("establish fixture trust root");
    let mut runtime =
        HostRoleRuntime::from_store(store, fixture.dependencies).expect("host-role runtime");
    let prepared = runtime
        .prepare_native_deadline_invocation(fixture.request)
        .expect("production native-deadline preparation");
    let reservation_record_id = prepared
        .custody_reservation_spec()
        .reservation_record_id
        .clone();
    drop(runtime);
    Some(EffectFixture {
        _directory: directory,
        config,
        watcher,
        prepared,
        reservation_record_id,
        marker,
    })
}

fn assert_exact_run_scoped_status(
    store: &Store,
    run_id: &str,
    watcher_instance_id: &str,
    expected_code: &str,
) -> (String, String) {
    let statuses = store
        .status_history_bounded(64, None)
        .expect("governed status history");
    let run_statuses = statuses
        .iter()
        .filter(|status| status.run_id.as_deref() == Some(run_id))
        .collect::<Vec<_>>();
    let [status] = run_statuses.as_slice() else {
        panic!(
            "governed run {run_id} has {} status events rather than exactly one",
            run_statuses.len()
        );
    };
    assert_eq!(status.component_kind, "diagnostic_execution");
    assert_eq!(status.component_id, run_id);
    assert_eq!(status.state, "unknown");
    assert_eq!(status.code, expected_code);
    assert!(
        statuses.iter().all(|candidate| {
            candidate.component_kind != "instance" || candidate.component_id != watcher_instance_id
        }),
        "governed execution created watcher-instance health"
    );
    assert!(
        store
            .status_snapshots()
            .expect("governed status projection")
            .iter()
            .all(|candidate| {
                candidate.component_kind != "instance"
                    || candidate.component_id != watcher_instance_id
            }),
        "governed execution advanced watcher-instance health"
    );
    (status.status_event_id.clone(), status.observed_at.clone())
}

#[test]
fn actual_helper_complete_persists_reopens_and_indexes_exact_v2() {
    let Some(fixture) = admitted_effect_fixture(HelperMode::Complete, 30_000) else {
        return;
    };
    let mut engine = CollectionEngine::open(&fixture.config).expect("execution engine");
    let artifact = engine
        .execute_prepared_governed_conformance(fixture.prepared)
        .expect("actual governed execution");
    assert_eq!(artifact.schema, DiagnosticExecutionSchemaV2::V2);
    let canonical_bytes = artifact.canonical_bytes().expect("canonical V2");
    let artifact_id = artifact.artifact_id.as_digest().clone();
    let run_id = artifact.run_id.as_str().to_owned();
    drop(engine);

    let store = Store::open(&fixture.config.database_path).expect("reopen exact store");
    let status_identity = assert_exact_run_scoped_status(
        &store,
        &run_id,
        &fixture.watcher.instance_id,
        "diagnostic_execution_completed",
    );
    let DiagnosticArtifactLookup::Found(access) = store
        .diagnostic_artifact(&artifact_id, &[DIAGNOSTIC_EXECUTION_V2_SCHEMA])
        .expect("artifact lookup")
    else {
        panic!("actual governed V2 artifact was not committed");
    };
    assert_eq!(
        access.schema_support,
        DiagnosticArtifactSchemaSupport::Supported
    );
    let DiagnosticArtifactByteState::VerifiedAvailable {
        canonical_bytes: reopened,
    } = access.byte_state
    else {
        panic!("actual governed V2 bytes were not verified available");
    };
    assert_eq!(reopened.as_bytes(), canonical_bytes);
    let projection = store
        .verify_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
        .expect("reverify governed projection");
    assert_eq!(
        projection.disposition,
        GovernedProjectionVerificationDisposition::AlreadyIndexed
    );
    assert_eq!(projection.diagnostic_artifact_id, artifact_id);
    assert!(
        store
            .governed_custody_inventory()
            .expect("custody inventory")
            .iter()
            .any(|entry| matches!(
                entry,
                GovernedCustodyInventoryEntry::Verified(inspection)
                    if inspection.reservation_record_id == fixture.reservation_record_id
                        && inspection.recovery_class == GovernedCustodyRecoveryClass::Indexed
            ))
    );
    drop(store);

    let mut mutation_engine =
        CollectionEngine::open(&fixture.config).expect("topology-mutation engine");
    mutation_engine
        .revoke_binding(&fixture.watcher)
        .expect("retire current helper binding");
    drop(mutation_engine);
    let store = Store::open(&fixture.config.database_path).expect("store after topology mutation");
    assert_eq!(
        assert_exact_run_scoped_status(
            &store,
            &run_id,
            &fixture.watcher.instance_id,
            "diagnostic_execution_completed",
        ),
        status_identity,
        "topology mutation changed the immutable status identity or time"
    );
    let DiagnosticArtifactLookup::Found(after_mutation) = store
        .diagnostic_artifact(&artifact_id, &[DIAGNOSTIC_EXECUTION_V2_SCHEMA])
        .expect("historical artifact after topology mutation")
    else {
        panic!("topology mutation removed the historical artifact");
    };
    let DiagnosticArtifactByteState::VerifiedAvailable {
        canonical_bytes: after_mutation,
    } = after_mutation.byte_state
    else {
        panic!("topology mutation changed historical artifact availability");
    };
    assert_eq!(after_mutation.as_bytes(), canonical_bytes);
}

fn assert_recovery_failpoint(failpoint: GovernedProjectionFailpoint) {
    let Some(fixture) = admitted_effect_fixture(HelperMode::Complete, 30_000) else {
        return;
    };
    let mut engine = CollectionEngine::open(&fixture.config).expect("failpoint engine");
    let error = engine
        .execute_prepared_governed_conformance_with_failpoint(fixture.prepared, failpoint)
        .expect_err("projection failpoint interrupts before index mark");
    assert!(matches!(
        error,
        EngineError::Invariant(ref message) if message.contains("test failpoint")
    ));
    drop(engine);

    let store = Store::open(&fixture.config.database_path).expect("read-only restart inventory");
    let before = store
        .governed_custody_inventory()
        .expect("pending inventory");
    assert!(before.iter().any(|entry| matches!(
        entry,
        GovernedCustodyInventoryEntry::Verified(inspection)
            if inspection.reservation_record_id == fixture.reservation_record_id
                && inspection.recovery_class
                    == GovernedCustodyRecoveryClass::FinalClosureAwaitingProjection
    )));
    drop(store);
    let recovered =
        CollectionEngine::open(&fixture.config).expect("execution-runtime startup recovery");
    let [first] = recovered.startup_projection_recovery() else {
        panic!("startup did not report exactly one pending projection recovery");
    };
    let verification = match first {
        GovernedProjectionRecovery::Recovered(verification) => verification.clone(),
        other => panic!("unexpected first recovery result: {other:?}"),
    };
    assert_eq!(
        verification.disposition,
        GovernedProjectionVerificationDisposition::Indexed
    );
    drop(recovered);
    let mut store = Store::open(&fixture.config.database_path).expect("post-recovery inspection");
    let status_count = store
        .status_history_bounded(10, None)
        .expect("recovered status history")
        .len();
    assert_eq!(status_count, 1, "recovery duplicated the run status");
    let second = store
        .recover_governed_projection_and_mark_indexed(&fixture.reservation_record_id)
        .expect("idempotent exact capsule recovery");
    assert!(matches!(
        second,
        GovernedProjectionRecovery::AlreadyIndexed(ref replay)
            if replay.closure_id == verification.closure_id
                && replay.diagnostic_artifact_id == verification.diagnostic_artifact_id
    ));
    assert_eq!(
        store
            .status_history_bounded(10, None)
            .expect("idempotent status history")
            .len(),
        status_count,
        "idempotent recovery appended a duplicate result"
    );
}

#[test]
fn restart_recovers_exact_projection_after_final_seal_before_sql() {
    assert_recovery_failpoint(GovernedProjectionFailpoint::AfterFinalSealBeforeSql);
}

#[test]
fn restart_recovers_exact_projection_after_sql_before_index_mark() {
    assert_recovery_failpoint(GovernedProjectionFailpoint::AfterSqlBeforeIndexMark);
}

#[test]
fn recovery_refuses_coherent_sql_publication_substitution() {
    let Some(fixture) = admitted_effect_fixture(HelperMode::Complete, 30_000) else {
        return;
    };
    let EffectFixture {
        _directory,
        config,
        prepared,
        reservation_record_id,
        ..
    } = fixture;
    let mut engine = CollectionEngine::open(&config).expect("SQL-hostile engine");
    let failpoint_error = engine
        .execute_prepared_governed_conformance_with_failpoint(
            prepared,
            GovernedProjectionFailpoint::AfterSqlBeforeIndexMark,
        )
        .expect_err("SQL-hostile fixture stops after commit");
    assert!(
        matches!(failpoint_error, EngineError::Invariant(ref message)
            if message.contains("test failpoint: after SQL projection before index mark")),
        "unexpected initial failpoint: {failpoint_error}"
    );
    drop(engine);

    let hostile = rusqlite::Connection::open(&config.database_path).expect("hostile SQL writer");
    // Preserve the exact trigger bytes: schema fingerprinting must see an
    // unchanged schema so the intended projection-capsule comparison is the
    // first integrity boundary reached by startup recovery.
    let trigger_sql: String = hostile
        .query_row(
            "SELECT sql FROM sqlite_schema
             WHERE type = 'trigger' AND name = 'immutable_status_events_update'",
            [],
            |row| row.get(0),
        )
        .expect("exact immutable_status_events_update trigger SQL");
    hostile
        .execute_batch("DROP TRIGGER immutable_status_events_update;")
        .expect("drop trigger before substitution");
    hostile
        .execute(
            "UPDATE status_events SET observed_at = '2026-07-29T00:00:01Z'",
            [],
        )
        .expect("substitute one coherent status publication field");
    hostile
        .execute_batch(&trigger_sql)
        .expect("recreate the exact trigger SQL verbatim");
    drop(hostile);

    let Err(error) = CollectionEngine::open(&config) else {
        panic!("substituted SQL publication must refuse startup recovery");
    };
    assert!(
        error
            .to_string()
            .contains("existing SQL publication differs from the sealed capsule"),
        "unexpected recovery refusal: {error}"
    );
    let store = Store::open(&config.database_path).expect("inspect refused SQL substitution");
    assert!(
        store
            .governed_custody_inventory()
            .expect("pending substituted-SQL inventory")
            .iter()
            .any(|entry| matches!(
                entry,
                GovernedCustodyInventoryEntry::Verified(inspection)
                    if inspection.reservation_record_id == reservation_record_id
                        && inspection.recovery_class
                            == GovernedCustodyRecoveryClass::FinalClosureAwaitingProjection
            ))
    );
}

#[test]
fn actual_helper_refusal_remains_exact_and_durable() {
    let Some(fixture) = admitted_effect_fixture(HelperMode::RefuseGoverned, 30_000) else {
        return;
    };
    let mut engine = CollectionEngine::open(&fixture.config).expect("execution engine");
    let artifact = engine
        .execute_prepared_governed_conformance(fixture.prepared)
        .expect("helper refusal is a terminal diagnostic artifact");
    assert_eq!(artifact.outcome.derivation, DiagnosticDerivationV1::Refused);
    assert_eq!(artifact.outcome.refusals.len(), 1);
    let GovernedRefusalOrigin::Helper(refusal) = &artifact.outcome.refusals[0].origin else {
        panic!("helper refusal changed origin");
    };
    assert_eq!(refusal.code, nq_protocol::RefusalCode::CollectionFailed);
    assert_eq!(
        refusal.message,
        "the governed effect-path fixture refused this exact request"
    );
    let canonical_bytes = artifact.canonical_bytes().expect("canonical refused V2");
    let artifact_id = artifact.artifact_id.as_digest().clone();
    let run_id = artifact.run_id.as_str().to_owned();
    drop(engine);

    let store = Store::open(&fixture.config.database_path).expect("reopen refusal store");
    let status_identity = assert_exact_run_scoped_status(
        &store,
        &run_id,
        &fixture.watcher.instance_id,
        "diagnostic_execution_refused",
    );
    let DiagnosticArtifactLookup::Found(access) = store
        .diagnostic_artifact(&artifact_id, &[DIAGNOSTIC_EXECUTION_V2_SCHEMA])
        .expect("refusal artifact lookup")
    else {
        panic!("actual helper refusal was not committed");
    };
    let DiagnosticArtifactByteState::VerifiedAvailable {
        canonical_bytes: reopened,
    } = access.byte_state
    else {
        panic!("actual helper refusal bytes were not verified available");
    };
    assert_eq!(reopened.as_bytes(), canonical_bytes);
    drop(store);
    let store = Store::open(&fixture.config.database_path).expect("reopen refusal status");
    assert_eq!(
        assert_exact_run_scoped_status(
            &store,
            &run_id,
            &fixture.watcher.instance_id,
            "diagnostic_execution_refused",
        ),
        status_identity,
        "restart changed the immutable refusal status identity or time"
    );
}

fn assert_pre_effect_terminal(fixture: EffectFixture, expected_code: GovernedExecutionRefusalCode) {
    assert!(
        !fixture.marker.exists(),
        "admission marker must be clear before governed execution"
    );
    let mut engine = CollectionEngine::open(&fixture.config).expect("pre-effect engine");
    let error = engine
        .execute_prepared_governed_conformance(fixture.prepared)
        .expect_err("pre-effect mismatch must refuse");
    assert!(matches!(
        error,
        EngineError::GovernedExecutionRefused { code, .. } if code == expected_code
    ));
    assert!(
        !fixture.marker.exists(),
        "a pre-effect refusal spawned the provider"
    );
    drop(engine);

    let store = Store::open(&fixture.config.database_path).expect("terminalized store");
    assert!(matches!(
        store
            .governed_protected_failure(&fixture.reservation_record_id)
            .expect("protected failure"),
        GovernedProtectedFailureAccess::VerifiedAvailable(_)
    ));
    assert!(
        store
            .governed_custody_inventory()
            .expect("terminal custody inventory")
            .iter()
            .any(|entry| matches!(
                entry,
                GovernedCustodyInventoryEntry::Verified(inspection)
                    if inspection.reservation_record_id == fixture.reservation_record_id
                        && inspection.recovery_class
                            == GovernedCustodyRecoveryClass::ProtectedFailure
            ))
    );
}

#[test]
fn stale_generation_profile_and_clock_refuse_before_spawn_and_terminalize() {
    let Some(stale) = admitted_effect_fixture(HelperMode::Complete, 30_000) else {
        return;
    };
    let mut mutation_engine =
        CollectionEngine::open(&stale.config).expect("stale-generation mutation engine");
    mutation_engine
        .revoke_binding(&stale.watcher)
        .expect("revoke current generation");
    drop(mutation_engine);
    assert_pre_effect_terminal(stale, GovernedExecutionRefusalCode::WatcherResolutionFailed);

    let Some(profile) = admitted_effect_fixture_with_profile(
        HelperMode::Complete,
        30_000,
        "nq.conformance-incompatible",
        1,
    ) else {
        return;
    };
    assert_pre_effect_terminal(
        profile,
        GovernedExecutionRefusalCode::NativeProfileCorrespondenceUnavailable,
    );

    let Some(clock) = admitted_effect_fixture(HelperMode::Complete, 1) else {
        return;
    };
    std::thread::sleep(StdDuration::from_millis(10));
    assert_pre_effect_terminal(clock, GovernedExecutionRefusalCode::DeadlineExpired);
}
