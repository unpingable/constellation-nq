//! Real executable boundary tests for passive sampling and replay.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};

use nq_passive_load_helper::{ObserverConfigV1, ProviderConfigV1};
use nq_profiles::{ProfileModule as _, host};
use nq_protocol::{
    Capability, HelperRequest, InstanceId, MonotonicClock, MonotonicDeadline,
    PassiveHostLoadSampleSelectionV1, ProfileBinding, ProfileId, ProfileVersion, RequestId,
    ResponseOutcome, ScopeBinding, ScopeKind, Sha256Digest, SubjectBinding, SubjectId,
    VantageBinding, VantageKind, encode_ndjson, parse_response, sha256_bytes,
};
use serde_json::{Value, json};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_nq-passive-load-helper")
}

#[test]
#[allow(clippy::too_many_lines)]
fn real_process_selects_and_replays_without_sampling() {
    let root = tempfile::tempdir().unwrap();
    let store = root.path().join("samples");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).unwrap();
    let key = root.path().join("sample.key");
    let keygen = Command::new(binary())
        .args([
            "keygen",
            key.to_str().unwrap(),
            "fixture.process-observer",
            "process-key-1",
        ])
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "{}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let key_receipt: Value = serde_json::from_slice(&keygen.stdout).unwrap();

    let context = Command::new(binary())
        .arg("inspect-capacity-context")
        .output()
        .unwrap();
    assert!(context.status.success());
    let context: Value = serde_json::from_slice(&context.stdout).unwrap();
    let capacity_context_id =
        Sha256Digest::parse(context["capacity_context_id"].as_str().unwrap().to_owned()).unwrap();
    let binding = SubjectBinding {
        subject: SubjectId::new("host:process-boundary").unwrap(),
        scope: ScopeBinding {
            kind: ScopeKind::new("host").unwrap(),
            value: json!({"id": "process-boundary"}),
        },
        vantage: VantageBinding {
            kind: VantageKind::new("local").unwrap(),
            value: json!({}),
        },
    };
    let observer = ObserverConfigV1 {
        schema: "nq.passive_load_observer_config.v1".into(),
        sample_store: store.clone(),
        binding: binding.clone(),
        sample_interval_ms: 1_000,
        max_samples: 3,
        max_store_bytes: 262_144,
        expires_at: None,
        private_key_path: key,
        producer_issuer: "fixture.process-observer".into(),
        producer_key_id: "process-key-1".into(),
        capacity_context_id: capacity_context_id.clone(),
    };
    let observer_bytes = toml::to_string(&observer).unwrap().into_bytes();
    let observer_path = root.path().join("observer.toml");
    fs::write(&observer_path, &observer_bytes).unwrap();
    let sampled = Command::new(binary())
        .args(["sample-once", observer_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        sampled.status.success(),
        "{}",
        String::from_utf8_lossy(&sampled.stderr)
    );

    let artifact = sha256_bytes(&fs::read(binary()).unwrap());
    let provider = ProviderConfigV1 {
        schema: "nq.passive_load_provider_config.v1".into(),
        sample_store: store.clone(),
        max_sample_age_ms: 60_000,
        observer_profile: "nq.host_load_passive_sampler.v1".into(),
        observer_artifact_digest: artifact.clone(),
        observer_config_digest: sha256_bytes(&observer_bytes),
        producer_issuer: "fixture.process-observer".into(),
        producer_key_id: "process-key-1".into(),
        producer_public_key_hex: key_receipt["public_key_hex"].as_str().unwrap().into(),
        capacity_context_id: capacity_context_id.clone(),
    };
    let provider_path = root.path().join("provider.toml");
    fs::write(&provider_path, toml::to_string(&provider).unwrap()).unwrap();
    let descriptor = host::MODULE.descriptor();
    let request = HelperRequest::builder(
        RequestId::new("process-boundary-request").unwrap(),
        InstanceId::new("passive.process-boundary").unwrap(),
        ProfileBinding {
            id: ProfileId::new(host::PROFILE_ID).unwrap(),
            version: ProfileVersion::new(host::PROFILE_VERSION.to_string()).unwrap(),
            digest: Sha256Digest::parse(descriptor.digest().unwrap().as_str().to_owned()).unwrap(),
        },
        binding,
        MonotonicDeadline {
            clock: MonotonicClock::LinuxBoottime,
            expires_at_ns: 1,
        },
    )
    .capabilities(vec![
        Capability::new("read_procfs").unwrap(),
        Capability::new("read_system_info").unwrap(),
    ])
    .passive_host_load_sample(PassiveHostLoadSampleSelectionV1 {
        schema: nq_protocol::PASSIVE_HOST_LOAD_SELECTION_SCHEMA_V1.into(),
        cutoff_at: chrono::Utc::now(),
        max_age_ms: 60_000,
        observer_profile: "nq.host_load_passive_sampler.v1".into(),
        observer_artifact_digest: artifact,
        observer_config_digest: sha256_bytes(&observer_bytes),
        producer_issuer: "fixture.process-observer".into(),
        producer_key_id: "process-key-1".into(),
        producer_public_key_digest: Sha256Digest::parse(
            key_receipt["public_key_digest"]
                .as_str()
                .unwrap()
                .to_owned(),
        )
        .unwrap(),
        capacity_context_id,
    })
    .build()
    .unwrap();
    let frame = encode_ndjson(&request).unwrap();
    let exchange = || {
        let mut child = Command::new(binary())
            .args(["serve-stdio", provider_path.to_str().unwrap()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(&frame).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    let first = exchange();
    let second = exchange();
    assert_eq!(first, second);
    assert_eq!(
        fs::read_dir(&store)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.file_name() != ".observer.lock")
            })
            .count(),
        1
    );
    let response = parse_response(&request, &first).unwrap();
    assert!(matches!(response.outcome, ResponseOutcome::Report { .. }));
}

#[test]
fn build_info_is_machine_readable_and_production_bounded() {
    let output = Command::new(binary()).arg("--build-info").output().unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["component"], "nq-passive-load-helper");
    assert!(value["debug_assertions"].is_boolean());
}

#[test]
#[allow(clippy::too_many_lines)]
fn operational_generation_cli_is_finite_restart_safe_and_read_only_on_status() {
    let root = tempfile::tempdir().unwrap();
    let store = root.path().join("generation-store");
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).unwrap();
    let key = root.path().join("generation.key");
    let keygen = Command::new(binary())
        .args([
            "keygen",
            key.to_str().unwrap(),
            "fixture.operational-observer",
            "fixture-operational-key-1",
        ])
        .output()
        .unwrap();
    assert!(keygen.status.success());
    let key_receipt: Value = serde_json::from_slice(&keygen.stdout).unwrap();
    let context = Command::new(binary())
        .arg("inspect-capacity-context")
        .output()
        .unwrap();
    assert!(context.status.success());
    let context: Value = serde_json::from_slice(&context.stdout).unwrap();

    let now = chrono::Utc::now().timestamp_millis();
    let policy_path = root.path().join("policy.json");
    fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&json!({
            "schema": "nq.passive_load_operational_policy.v1",
            "deployment_profile_ref": "fixture.operational-policy:v1",
            "min_sampling_interval_ms": 100,
            "max_sampling_interval_ms": 60_000,
            "min_timer_granularity_ms": 10,
            "max_scheduling_jitter_ms": 100,
            "max_generation_duration_ms": 120_000,
            "max_generation_samples": 4,
            "max_active_store_bytes": 1_048_576,
            "min_required_free_bytes": 1,
            "max_consecutive_sample_failures": 3,
            "max_sample_eligibility_age_ms": 120_000,
            "max_key_overlap_ms": 1_000,
            "allowed_startup_policies": [
                "sample_current_slot",
                "wait_for_next_sample_slot"
            ],
            "allowed_retention_modes": ["retain_all"]
        }))
        .unwrap(),
    )
    .unwrap();
    let generation_spec_path = root.path().join("generation-spec.json");
    fs::write(
        &generation_spec_path,
        serde_json::to_vec_pretty(&json!({
            "schema": "nq.passive_load_observer_generation_spec.v1",
            "operator_occurrence_id": "fixture:prepare-generation-1",
            "previous_generation_id": null,
            "sample_store": store,
            "binding": {
                "subject": "host:process-operational",
                "scope": {"kind": "host", "value": {"id": "process-operational"}},
                "vantage": {"kind": "local", "value": {}}
            },
            "sampling_anchor_unix_ms": now,
            "sample_interval_ms": 60_000,
            "startup_policy": "sample_current_slot",
            "created_at_unix_ms": now,
            "not_before_unix_ms": now,
            "expires_at_unix_ms": now + 90_000,
            "max_samples": 2,
            "max_store_bytes": 1_048_576,
            "min_free_bytes": 1,
            "failure_pause_threshold": 2,
            "retention_mode": "retain_all",
            "max_sample_eligibility_age_ms": 120_000,
            "private_key_path": key,
            "producer_issuer": "fixture.operational-observer",
            "producer_key_id": "fixture-operational-key-1",
            "producer_public_key_hex": key_receipt["public_key_hex"],
            "key_not_before_unix_ms": now,
            "key_retire_at_unix_ms": now + 91_000,
            "capacity_context_id": context["capacity_context_id"]
        }))
        .unwrap(),
    )
    .unwrap();
    let generation_path = root.path().join("generation.json");
    let prepared = Command::new(binary())
        .args([
            "prepare-generation",
            policy_path.to_str().unwrap(),
            generation_spec_path.to_str().unwrap(),
            generation_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        prepared.status.success(),
        "{}",
        String::from_utf8_lossy(&prepared.stderr)
    );
    let prepared_receipt: Value = serde_json::from_slice(&prepared.stdout).unwrap();
    assert_eq!(
        prepared_receipt["schema"],
        "nq.passive_load_observer_generation_materialization.v1"
    );

    let sample = Command::new(binary())
        .args([
            "sample-once-generation",
            policy_path.to_str().unwrap(),
            generation_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(sample.status.success());
    let sample: Value = serde_json::from_slice(&sample.stdout).unwrap();
    assert_eq!(sample["outcome"], "sampled");
    let replayed_tick = Command::new(binary())
        .args([
            "sample-once-generation",
            policy_path.to_str().unwrap(),
            generation_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(replayed_tick.status.success());
    let replayed_tick: Value = serde_json::from_slice(&replayed_tick.stdout).unwrap();
    assert_eq!(replayed_tick["outcome"], "already_sampled");

    let status = Command::new(binary())
        .args([
            "generation-status",
            policy_path.to_str().unwrap(),
            generation_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(status.status.success());
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["samples_produced"], 1);
    assert_eq!(status["remaining_samples"], 1);
    assert_eq!(status["state"], "active");

    let retired = Command::new(binary())
        .args([
            "retire-generation",
            generation_path.to_str().unwrap(),
            "fixture:retire-generation-1",
            "bounded process qualification complete",
        ])
        .output()
        .unwrap();
    assert!(retired.status.success());
    let after_retirement = Command::new(binary())
        .args([
            "sample-once-generation",
            policy_path.to_str().unwrap(),
            generation_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(after_retirement.status.success());
    let after_retirement: Value = serde_json::from_slice(&after_retirement.stdout).unwrap();
    assert_eq!(after_retirement["outcome"], "paused");
    assert_eq!(
        fs::read_dir(&store)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_name().to_str().is_some_and(|name| {
                    std::path::Path::new(name)
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                        && !name.starts_with('.')
                })
            })
            .count(),
        1
    );
}
