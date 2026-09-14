//! Bounded notification-delivery custody. It owns no attention or admission.

use anyhow::{Context, Result, bail};
use nq_core::config::{
    CommandConfig, NotificationRouteConfig, NotificationTransportKind, NqConfig, ResourceLimits,
};
use nq_core::identity::VerifiedLaunch;
use nq_core::runner::{AcquisitionOutcome, StdioRunner};
use nq_store::{
    CanonicalDocument, NotificationDeliveryEventInput, NotificationDeliveryIntentInput,
    NotificationDeliveryRetention, NotificationInput, Store,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::time::Duration;

const MAX_INTENT_BYTES: usize = 32_768;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    attention_kind: String,
    stable_event_id: String,
    attention_receipt_digest: Option<String>,
    attention_policy_id: String,
    attention_policy_digest: String,
    transition_id: String,
    route_reference: String,
    destination_identity: String,
    summary: String,
    inspection_reference: String,
    owner_receipt: Option<Value>,
}

fn bounded(label: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        bail!("notification {label} must be 1..={maximum} non-control bytes");
    }
    Ok(())
}

fn required_json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("Nightshift {field} is missing"))
}

fn read_intent(path: &std::path::Path) -> Result<(Intent, CanonicalDocument)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open notification intent {}", path.display()))?;
    let metadata = file.metadata().context("inspect notification intent")?;
    if !metadata.file_type().is_file() {
        bail!("notification intent must be a regular file");
    }
    if metadata.len() > MAX_INTENT_BYTES as u64 {
        bail!("notification intent exceeds {MAX_INTENT_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    file.take((MAX_INTENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read notification intent")?;
    if bytes.len() > MAX_INTENT_BYTES {
        bail!("notification intent exceeds {MAX_INTENT_BYTES} bytes");
    }
    let value: Value = serde_json::from_slice(&bytes).context("notification intent is not JSON")?;
    let document = CanonicalDocument::from_serializable(&value)?;
    if document.as_bytes() != bytes {
        bail!("notification intent must be canonical JSON");
    }
    let intent: Intent = serde_json::from_value(value)?;
    if intent.schema != "nq.notification_delivery_intent.v1" {
        bail!("unsupported notification intent schema");
    }
    for (name, value, maximum) in [
        ("stable_event_id", intent.stable_event_id.as_str(), 256),
        (
            "attention_policy_id",
            intent.attention_policy_id.as_str(),
            256,
        ),
        ("transition_id", intent.transition_id.as_str(), 256),
        ("route_reference", intent.route_reference.as_str(), 256),
        (
            "destination_identity",
            intent.destination_identity.as_str(),
            256,
        ),
        ("summary", intent.summary.as_str(), 512),
        (
            "inspection_reference",
            intent.inspection_reference.as_str(),
            1024,
        ),
    ] {
        bounded(name, value, maximum)?;
    }
    match intent.attention_kind.as_str() {
        "operator_assertion"
            if intent.attention_receipt_digest.is_none() && intent.owner_receipt.is_none() => {}
        "nightshift_receipt"
            if intent.attention_receipt_digest.is_some() && intent.owner_receipt.is_some() => {}
        _ => bail!("unsupported or ambiguous notification attention kind"),
    }
    Ok((intent, document))
}

fn replay_nightshift(route: &NotificationRouteConfig, intent: &Intent) -> Result<()> {
    if intent.attention_kind != "nightshift_receipt" {
        return Ok(());
    }
    let replay = route
        .nightshift_attention_replay
        .as_ref()
        .context("Nightshift replay is not configured for this route")?;
    let bundle = intent
        .owner_receipt
        .as_ref()
        .context("Nightshift replay bundle is missing")?;
    let policy = bundle
        .get("policy")
        .context("Nightshift bundle policy is missing")?;
    let receipt = bundle
        .get("receipt")
        .context("Nightshift bundle receipt is missing")?;
    if required_json_string(bundle, "schema")?
        != "nightshift.project-predicate-attention-replay-bundle/v1"
        || required_json_string(policy, "schema")?
            != "nightshift.project-predicate-attention-policy/v1"
        || required_json_string(receipt, "schema")? != "nightshift.project-predicate-attention/v1"
        || required_json_string(policy, "policy_digest")? != replay.approved_policy_digest
        || required_json_string(receipt, "policy_digest")? != replay.approved_policy_digest
        || intent.attention_policy_digest != replay.approved_policy_digest
        || required_json_string(receipt, "policy_id")? != intent.attention_policy_id
        || required_json_string(receipt, "receipt_digest")?
            != intent
                .attention_receipt_digest
                .as_deref()
                .context("attention receipt digest is missing")?
        || required_json_string(receipt, "disposition")? != "ATTENTION_REQUIRED"
    {
        bail!("Nightshift attention bundle does not match the approved policy and intent binding");
    }
    let receipt_digest = required_json_string(receipt, "receipt_digest")?;
    if intent.stable_event_id != receipt_digest || intent.transition_id != receipt_digest {
        bail!(
            "Nightshift delivery event and transition identities must equal the exact attention receipt digest"
        );
    }
    if bundle.get("history").and_then(Value::as_array).is_none() {
        bail!("Nightshift attention bundle history is missing");
    }

    let directory = tempfile::Builder::new()
        .prefix("nq-nightshift-replay-")
        .tempdir()?;
    let document = CanonicalDocument::from_serializable(bundle)?;
    let account =
        nq_helper_sandbox::resolve_account(&replay.execution_account, cfg!(debug_assertions))
            .context("resolve Nightshift replay execution account")?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o710))?;
    nix::unistd::chown(
        directory.path(),
        None,
        Some(nix::unistd::Gid::from_raw(account.gid)),
    )
    .context("assign private Nightshift replay directory")?;
    let command = CommandConfig {
        executable: replay.executable.clone(),
        args: vec![
            "--store".into(),
            replay.store_locator.to_string_lossy().into_owned(),
            "attention".into(),
            "replay".into(),
            "--bundle-stdin".into(),
        ],
        env: BTreeMap::new(),
        execution_account: replay.execution_account.clone(),
        allow_same_identity_in_debug: cfg!(debug_assertions),
        working_directory: directory.path().to_owned(),
    };
    let launch =
        VerifiedLaunch::open(&command).context("open exact Nightshift replay executable")?;
    if launch.identity().sha256 != replay.executable_sha256 {
        bail!("Nightshift replay executable digest does not match route configuration");
    }
    let limits = ResourceLimits {
        max_response_bytes: 16_384,
        max_stderr_bytes: 16_384,
        max_observations: 1,
        max_address_space_bytes: 256 * 1024 * 1024,
        max_cpu_seconds: 15,
        max_processes: 8,
        max_open_files: 32,
        max_file_bytes: 0,
    };
    // Nightshift's pathname reader intentionally refuses symlinks, including
    // sealed /proc/self/fd argument paths. The explicit stdin contract carries
    // these already-canonical bytes without weakening either pathname boundary.
    let capture = StdioRunner.run_verified(
        &launch,
        document.as_bytes(),
        Duration::from_millis(route.timeout_ms.min(15_000)),
        &limits,
    );
    if capture.outcome != AcquisitionOutcome::Response {
        let class = match capture.outcome {
            AcquisitionOutcome::Timeout => "timeout",
            AcquisitionOutcome::OutputTooLarge => "stdout_limit",
            AcquisitionOutcome::StderrTooLarge => "stderr_limit",
            AcquisitionOutcome::ExitNonzero { .. } => "nonzero_exit",
            AcquisitionOutcome::Eof => "empty_stdout",
            AcquisitionOutcome::MalformedFraming { .. } => "malformed_framing",
            AcquisitionOutcome::MalformedJson { .. } => "malformed_json",
            AcquisitionOutcome::SpawnFailed { .. } => "spawn_failed",
            AcquisitionOutcome::IoFailed { .. } => "io_failed",
            AcquisitionOutcome::RequestWriteFailed { .. } => "request_write_failed",
            AcquisitionOutcome::ExchangeTimeout { .. }
            | AcquisitionOutcome::HelperExited { .. }
            | AcquisitionOutcome::Disconnect { .. }
            | AcquisitionOutcome::CarrierStartupFailed { .. }
            | AcquisitionOutcome::NotRunning => "unsupported_carrier_outcome",
            AcquisitionOutcome::Response => unreachable!(),
        };
        bail!("bounded Nightshift attention replay failed: {class}");
    }
    let result: Value = serde_json::from_slice(
        capture
            .response_frame()
            .context("Nightshift replay response frame is missing")?,
    )?;
    let expected = intent
        .attention_receipt_digest
        .as_deref()
        .expect("checked above");
    if required_json_string(&result, "schema")?
        != "nightshift.project-predicate-attention-replay/v1"
        || result.get("matches").and_then(Value::as_bool) != Some(true)
        || required_json_string(&result, "expected_receipt_digest")? != expected
        || required_json_string(&result, "recomputed_receipt_digest")? != expected
    {
        bail!("Nightshift replay did not reproduce the exact attention receipt");
    }
    Ok(())
}

fn render(route: &NotificationRouteConfig, intent: &Intent) -> Result<CanonicalDocument> {
    let text = format!(
        "Attention required: {}\nInspect: {}",
        intent.summary, intent.inspection_reference
    );
    let payload = match route.transport {
        NotificationTransportKind::Slack => json!({"text": text}),
        NotificationTransportKind::Discord => json!({"content": text}),
    };
    Ok(CanonicalDocument::from_serializable(&payload)?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransportResult {
    Accepted(u16),
    Failed(u16),
    Unknown,
}

async fn submit_with_dispatch<R, P, F, Fut>(
    config: &NqConfig,
    intent_path: &std::path::Path,
    route_ref: &str,
    enable_network: bool,
    resolve_endpoint: R,
    prepare_dispatch: P,
) -> Result<Value>
where
    R: FnOnce(&str) -> Result<String>,
    P: FnOnce(u64) -> Result<F>,
    F: FnOnce(String, Vec<u8>, u64) -> Fut,
    Fut: Future<Output = Result<TransportResult>>,
{
    let (intent, intent_document) = read_intent(intent_path)?;
    if intent.route_reference != route_ref {
        bail!("CLI route does not match intent route reference");
    }
    let route = config
        .notification_routes
        .iter()
        .find(|r| r.reference == route_ref)
        .context("route reference is not configured")?;
    replay_nightshift(route, &intent)?;
    let payload = render(route, &intent)?;
    let mut store = Store::open(&config.database_path)?;
    let notification_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let notification = NotificationInput {
        notification_id: notification_id.clone(),
        idempotency_key: format!("{}:{}", intent.stable_event_id, intent.destination_identity),
        finding_event_id: None,
        destination_kind: match route.transport {
            NotificationTransportKind::Slack => "slack".into(),
            NotificationTransportKind::Discord => "discord".into(),
        },
        payload: payload.clone(),
        available_at: now.clone(),
        max_attempts: 1,
        created_at: now.clone(),
    };
    let delivery_intent = NotificationDeliveryIntentInput {
        notification_id: notification_id.clone(),
        stable_event_id: intent.stable_event_id,
        attention_kind: intent.attention_kind,
        attention_receipt_digest: intent.attention_receipt_digest,
        attention_policy_id: intent.attention_policy_id,
        attention_policy_digest: intent.attention_policy_digest,
        transition_id: intent.transition_id,
        route_reference: intent.route_reference,
        destination_identity: intent.destination_identity,
        content_digest: payload.digest().to_owned(),
        intent: intent_document,
        created_at: now.clone(),
    };
    match store.retain_notification_delivery(&notification, &delivery_intent)? {
        NotificationDeliveryRetention::Inserted => {}
        NotificationDeliveryRetention::Existing(existing) => {
            return Ok(json!({
                "notification_id": existing.notification_id,
                "delivery_state": existing.delivery_state,
            }));
        }
    }
    if !enable_network {
        store.append_notification_delivery_event(&NotificationDeliveryEventInput {
            notification_id: notification_id.clone(),
            event_number: 1,
            occurred_at: now,
            outcome: "refused".into(),
            detail: CanonicalDocument::from_serializable(
                &json!({"reason":"network_dispatch_not_explicitly_enabled"}),
            )?,
        })?;
        return Ok(json!({"notification_id": notification_id, "delivery_state":"refused"}));
    }
    let endpoint = match resolve_endpoint(&route.endpoint_secret_locator) {
        Ok(endpoint) => endpoint,
        Err(_) => {
            store.append_notification_delivery_event(&NotificationDeliveryEventInput {
                notification_id: notification_id.clone(),
                event_number: 1,
                occurred_at: now,
                outcome: "refused".into(),
                detail: CanonicalDocument::from_serializable(
                    &json!({"reason":"endpoint_resolution_unavailable"}),
                )?,
            })?;
            return Ok(json!({"notification_id": notification_id, "delivery_state":"refused"}));
        }
    };
    let dispatch = match prepare_dispatch(route.timeout_ms) {
        Ok(dispatch) => dispatch,
        Err(_) => {
            store.append_notification_delivery_event(&NotificationDeliveryEventInput {
                notification_id: notification_id.clone(),
                event_number: 1,
                occurred_at: now,
                outcome: "refused".into(),
                detail: CanonicalDocument::from_serializable(
                    &json!({"reason":"transport_client_unavailable"}),
                )?,
            })?;
            return Ok(json!({"notification_id": notification_id, "delivery_state":"refused"}));
        }
    };
    store.append_notification_delivery_event(&NotificationDeliveryEventInput {
        notification_id: notification_id.clone(),
        event_number: 1,
        occurred_at: now.clone(),
        outcome: "claimed".into(),
        detail: CanonicalDocument::from_serializable(
            &json!({"route_reference":route.reference,"transport":"https"}),
        )?,
    })?;
    let (outcome, detail) =
        match dispatch(endpoint, payload.as_bytes().to_vec(), route.timeout_ms).await? {
            TransportResult::Accepted(status) => ("accepted", json!({"http_status":status})),
            TransportResult::Failed(status) => ("failed", json!({"http_status":status})),
            TransportResult::Unknown => (
                "unknown",
                json!({"reason":"transport_error_or_response_loss"}),
            ),
        };
    store.append_notification_delivery_event(&NotificationDeliveryEventInput {
        notification_id: notification_id.clone(),
        event_number: 2,
        occurred_at: chrono::Utc::now().to_rfc3339(),
        outcome: outcome.into(),
        detail: CanonicalDocument::from_serializable(&detail)?,
    })?;
    Ok(json!({"notification_id": notification_id, "delivery_state":outcome}))
}

pub(crate) async fn submit(
    config: &NqConfig,
    intent_path: &std::path::Path,
    route_ref: &str,
    enable_network: bool,
) -> Result<Value> {
    submit_with_dispatch(
        config,
        intent_path,
        route_ref,
        enable_network,
        |locator| {
            std::env::var(locator).context("configured endpoint secret locator is unavailable")
        },
        |timeout_ms| {
            let client = reqwest::Client::builder()
                .https_only(true)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(std::time::Duration::from_millis(timeout_ms))
                .build()?;
            Ok(move |endpoint, body, _| async move {
                match client
                    .post(endpoint)
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(body)
                    .send()
                    .await
                {
                    Ok(response) if response.status().is_success() => {
                        Ok(TransportResult::Accepted(response.status().as_u16()))
                    }
                    Ok(response) => Ok(TransportResult::Failed(response.status().as_u16())),
                    Err(_) => Ok(TransportResult::Unknown),
                }
            })
        },
    )
    .await
}

pub(crate) fn inspect(config: &NqConfig, id: Option<&str>) -> Result<Value> {
    Ok(serde_json::to_value(
        Store::open_read_only(&config.database_path)?.notification_delivery_status(id)?,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_core::config::CONFIG_SCHEMA;
    use rusqlite::Connection;
    use sha2::{Digest as _, Sha256};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempfile::TempDir;

    fn route(transport: NotificationTransportKind) -> NotificationRouteConfig {
        NotificationRouteConfig {
            reference: "ops.primary".into(),
            transport,
            endpoint_secret_locator: "NQ_TEST_URL".into(),
            // Replay includes descriptor custody, account/sandbox setup, and
            // process launch. Keep the explicit timeout qualification below at
            // 100 ms; ordinary positive fixtures use a realistic local bound.
            timeout_ms: 2_000,
            max_response_bytes: 1024,
            nightshift_attention_replay: None,
        }
    }

    fn config(root: &TempDir) -> NqConfig {
        let config = NqConfig {
            schema: CONFIG_SCHEMA.into(),
            database_path: root.path().join("notification.db"),
            socket_path: root.path().join("nqd.sock"),
            admissions_dir: root.path().join("admissions"),
            helper_runtime_dir: root.path().join("helpers"),
            watchers: Vec::new(),
            notification_routes: vec![route(NotificationTransportKind::Slack)],
        };
        Store::initialize(&config.database_path).expect("initialize notification fixture store");
        config
    }

    fn intent(summary: &str, attention_kind: &str, owner_receipt: Option<Value>) -> Value {
        let event_identity = if attention_kind == "nightshift_receipt" {
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            "event-1"
        };
        json!({
            "schema":"nq.notification_delivery_intent.v1",
            "attention_kind":attention_kind,
            "stable_event_id":event_identity,
            "attention_receipt_digest": if attention_kind == "nightshift_receipt" { json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") } else { Value::Null },
            "attention_policy_id":"policy-1",
            "attention_policy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "transition_id": if attention_kind == "nightshift_receipt" { event_identity } else { "transition-1" },
            "route_reference":"ops.primary",
            "destination_identity":"destination-1",
            "summary":summary,
            "inspection_reference":"record:1",
            "owner_receipt":owner_receipt,
        })
    }

    fn write_intent(root: &TempDir, value: Value) -> std::path::PathBuf {
        let path = root.path().join("intent.json");
        let document = CanonicalDocument::from_serializable(&value).expect("canonical fixture");
        fs::write(&path, document.as_bytes()).expect("write fixture intent");
        path
    }

    #[test]
    fn intent_fifo_is_opened_nonblocking_and_refused_as_non_regular() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("intent.fifo");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
        let error = read_intent(&path).unwrap_err().to_string();
        assert!(error.contains("regular file"));
    }

    fn endpoint(_: &str) -> Result<String> {
        Ok("https://fixture.invalid/notification".into())
    }

    fn replay_bundle() -> Value {
        json!({
            "schema":"nightshift.project-predicate-attention-replay-bundle/v1",
            "policy":{"schema":"nightshift.project-predicate-attention-policy/v1","policy_id":"policy-1","policy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
            "history":[],
            "receipt":{"schema":"nightshift.project-predicate-attention/v1","policy_id":"policy-1","policy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","disposition":"ATTENTION_REQUIRED"}
        })
    }

    fn configure_replay(root: &TempDir, route: &mut NotificationRouteConfig, body: &str) {
        let executable = root.path().join("nightshift-fixture");
        fs::write(&executable, body).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(fs::read(&executable).unwrap()))
        );
        route.nightshift_attention_replay = Some(
            nq_core::config::NightshiftAttentionReplayConfig {
                executable,
                executable_sha256: digest,
                store_locator: root.path().join("nightshift.db"),
                approved_policy_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                execution_account: nix::unistd::Uid::current().as_raw().to_string(),
            },
        );
    }

    #[test]
    fn renders_only_the_minimal_transport_projection() {
        let intent = Intent {
            schema: "nq.notification_delivery_intent.v1".into(),
            attention_kind: "operator_assertion".into(),
            stable_event_id: "event-1".into(),
            attention_receipt_digest: None,
            attention_policy_id: "policy-1".into(),
            attention_policy_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            transition_id: "transition-1".into(),
            route_reference: "ops.primary".into(),
            destination_identity: "destination-1".into(),
            summary: "check storage".into(),
            inspection_reference: "record:1".into(),
            owner_receipt: None,
        };
        let slack: Value = serde_json::from_slice(
            render(&route(NotificationTransportKind::Slack), &intent)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let discord: Value = serde_json::from_slice(
            render(&route(NotificationTransportKind::Discord), &intent)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(
            slack,
            json!({"text":"Attention required: check storage\nInspect: record:1"})
        );
        assert_eq!(
            discord,
            json!({"content":"Attention required: check storage\nInspect: record:1"})
        );
    }

    #[tokio::test]
    async fn network_disabled_submission_is_retained_as_a_refusal_without_endpoint_resolution() {
        let root = TempDir::new().expect("temporary notification root");
        let config = config(&root);
        let path = write_intent(&root, intent("check storage", "operator_assertion", None));
        let result = submit_with_dispatch(
            &config,
            &path,
            "ops.primary",
            false,
            |_| bail!("endpoint resolution must not occur"),
            |_| Ok(|_, _, _| async { panic!("dispatch must not occur") }),
        )
        .await
        .expect("network-disabled submission is retained");
        assert_eq!(result["delivery_state"], "refused");
        let status = inspect(&config, result["notification_id"].as_str()).expect("inspect refusal");
        assert_eq!(status[0]["event_count"], 1);
        assert_eq!(status[0]["delivery_state"], "refused");
    }

    #[tokio::test]
    async fn injected_transport_maps_accepted_failed_and_unknown_without_outbound_io() {
        for (outcome, expected) in [
            (TransportResult::Accepted(204), "accepted"),
            (TransportResult::Failed(503), "failed"),
            (TransportResult::Unknown, "unknown"),
        ] {
            let root = TempDir::new().expect("temporary notification root");
            let config = config(&root);
            let path = write_intent(&root, intent("check storage", "operator_assertion", None));
            let result =
                submit_with_dispatch(&config, &path, "ops.primary", true, endpoint, |_| {
                    Ok(move |endpoint, payload, timeout| async move {
                        assert_eq!(endpoint, "https://fixture.invalid/notification");
                        assert_eq!(timeout, 2_000);
                        assert!(
                            String::from_utf8(payload)
                                .expect("payload UTF-8")
                                .contains("check storage")
                        );
                        Ok(outcome)
                    })
                })
                .await
                .expect("fake transport result retained");
            assert_eq!(result["delivery_state"], expected);
            let status =
                inspect(&config, result["notification_id"].as_str()).expect("inspect result");
            assert_eq!(status[0]["event_count"], 2);
            assert_eq!(status[0]["delivery_state"], expected);
            assert!(
                !status
                    .to_string()
                    .contains("https://fixture.invalid/notification"),
                "endpoint values are never retained in delivery custody"
            );
        }
    }

    #[tokio::test]
    async fn unknown_terminal_result_is_not_automatically_retried_and_exact_duplicate_converges() {
        let root = TempDir::new().expect("temporary notification root");
        let config = config(&root);
        let path = write_intent(&root, intent("check storage", "operator_assertion", None));
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::clone(&calls);
        let first = submit_with_dispatch(&config, &path, "ops.primary", true, endpoint, |_| {
            Ok(move |_, _, _| {
                first_calls.fetch_add(1, Ordering::SeqCst);
                async { Ok(TransportResult::Unknown) }
            })
        })
        .await
        .expect("unknown retained");
        let second_calls = Arc::clone(&calls);
        let second = submit_with_dispatch(&config, &path, "ops.primary", true, endpoint, |_| {
            Ok(move |_, _, _| {
                second_calls.fetch_add(1, Ordering::SeqCst);
                async { Ok(TransportResult::Accepted(200)) }
            })
        })
        .await
        .expect("exact duplicate converges");
        assert_eq!(first, second);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let status = inspect(&config, None).expect("ordered replay inspection");
        assert_eq!(status.as_array().expect("status array").len(), 1);
        assert_eq!(status[0]["event_count"], 2);
        assert_eq!(status[0]["delivery_state"], "unknown");
    }

    #[tokio::test]
    async fn material_duplicate_mismatch_and_invalid_routes_are_refused_before_dispatch() {
        let root = TempDir::new().expect("temporary notification root");
        let config = config(&root);
        let path = write_intent(&root, intent("check storage", "operator_assertion", None));
        submit_with_dispatch(&config, &path, "ops.primary", false, endpoint, |_| {
            Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
        })
        .await
        .expect("initial refusal retained");
        let mismatch = write_intent(
            &root,
            intent("different material", "operator_assertion", None),
        );
        let error =
            submit_with_dispatch(&config, &mismatch, "ops.primary", false, endpoint, |_| {
                Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
            })
            .await
            .expect_err("content change must not retarget identity");
        assert!(error.to_string().contains("different canonical intent"));
        let route_error =
            submit_with_dispatch(&config, &path, "missing.route", false, endpoint, |_| {
                Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
            })
            .await
            .expect_err("missing route rejected");
        assert!(route_error.to_string().contains("does not match"));
        let mut missing_config = config.clone();
        missing_config.notification_routes[0].reference = "other.route".into();
        let missing_error = submit_with_dispatch(
            &missing_config,
            &path,
            "ops.primary",
            false,
            endpoint,
            |_| Ok(|_, _, _| async { Ok(TransportResult::Unknown) }),
        )
        .await
        .expect_err("unconfigured matching route is rejected");
        assert!(missing_error.to_string().contains("not configured"));
    }

    #[tokio::test]
    async fn endpoint_or_client_prelaunch_failure_is_a_secret_free_refusal() {
        for prepare in [false, true] {
            let root = TempDir::new().expect("temporary notification root");
            let config = config(&root);
            let path = write_intent(&root, intent("check storage", "operator_assertion", None));
            let result = if prepare {
                submit_with_dispatch(
                    &config,
                    &path,
                    "ops.primary",
                    true,
                    endpoint,
                    |_| -> Result<
                        fn(String, Vec<u8>, u64) -> std::future::Ready<Result<TransportResult>>,
                    > { bail!("fixture client construction failed") },
                )
                .await
            } else {
                submit_with_dispatch(
                    &config,
                    &path,
                    "ops.primary",
                    true,
                    |_| bail!("https://secret.invalid/value"),
                    |_| Ok(|_, _, _| async { Ok(TransportResult::Accepted(200)) }),
                )
                .await
            }
            .expect("prelaunch condition is retained, not returned");
            assert_eq!(result["delivery_state"], "refused");
            let custody = inspect(&config, result["notification_id"].as_str())
                .expect("inspect refusal")
                .to_string();
            assert!(!custody.contains("secret.invalid"));
            let detail: Vec<u8> = Connection::open(&config.database_path)
                .expect("open fixture database")
                .query_row(
                    "SELECT detail_json FROM notification_delivery_events WHERE notification_id = ?1",
                    [result["notification_id"].as_str().expect("notification id")],
                    |row| row.get(0),
                )
                .expect("retained refusal detail");
            let detail = String::from_utf8(detail).expect("canonical JSON detail");
            assert!(!detail.contains("secret.invalid"));
            assert!(detail.contains(if prepare {
                "transport_client_unavailable"
            } else {
                "endpoint_resolution_unavailable"
            }));
        }
    }

    #[tokio::test]
    async fn changed_policy_binding_is_not_an_exact_duplicate() {
        let root = TempDir::new().expect("temporary notification root");
        let config = config(&root);
        let path = write_intent(&root, intent("check storage", "operator_assertion", None));
        submit_with_dispatch(&config, &path, "ops.primary", false, endpoint, |_| {
            Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
        })
        .await
        .expect("initial retention");
        let mut changed = intent("check storage", "operator_assertion", None);
        changed["attention_policy_digest"] =
            json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let changed_path = write_intent(&root, changed);
        let error = submit_with_dispatch(
            &config,
            &changed_path,
            "ops.primary",
            false,
            endpoint,
            |_| Ok(|_, _, _| async { Ok(TransportResult::Unknown) }),
        )
        .await
        .expect_err("policy change rejected");
        assert!(error.to_string().contains("different canonical intent"));
    }

    #[test]
    fn concurrent_delivery_retention_has_one_insert_and_one_exact_reopen() {
        let root = TempDir::new().expect("temporary notification root");
        let database = root.path().join("notification.db");
        Store::initialize(&database).expect("initialize notification store");
        let source = intent("check storage", "operator_assertion", None);
        let document = CanonicalDocument::from_serializable(&source).expect("canonical intent");
        let payload = CanonicalDocument::from_serializable(&json!({"text":"fixture"}))
            .expect("canonical payload");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut workers = Vec::new();
        for ordinal in 0..2 {
            let database = database.clone();
            let barrier = Arc::clone(&barrier);
            let document = document.clone();
            let payload = payload.clone();
            workers.push(std::thread::spawn(move || {
                let notification_id = format!("notification-{ordinal}");
                let notification = NotificationInput {
                    notification_id: notification_id.clone(),
                    idempotency_key: "event-1:destination-1".into(),
                    finding_event_id: None,
                    destination_kind: "slack".into(),
                    payload,
                    available_at: "2026-01-01T00:00:00Z".into(),
                    max_attempts: 1,
                    created_at: "2026-01-01T00:00:00Z".into(),
                };
                let delivery = NotificationDeliveryIntentInput {
                    notification_id,
                    stable_event_id: "event-1".into(),
                    attention_kind: "operator_assertion".into(),
                    attention_receipt_digest: None,
                    attention_policy_id: "policy-1".into(),
                    attention_policy_digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .into(),
                    transition_id: "transition-1".into(),
                    route_reference: "ops.primary".into(),
                    destination_identity: "destination-1".into(),
                    content_digest: notification.payload.digest().into(),
                    intent: document,
                    created_at: "2026-01-01T00:00:00Z".into(),
                };
                barrier.wait();
                Store::open(&database)
                    .expect("open concurrent store")
                    .retain_notification_delivery(&notification, &delivery)
                    .expect("one retained identity")
            }));
        }
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker joins"))
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, NotificationDeliveryRetention::Inserted))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, NotificationDeliveryRetention::Existing(_)))
                .count(),
            1
        );
        let mut reopened = Store::open(&database).unwrap();
        let retained = reopened
            .notification_delivery_by_identity("event-1", "destination-1")
            .unwrap()
            .unwrap();
        assert_eq!(retained.delivery_state, "pending");
        reopened
            .append_notification_delivery_event(&NotificationDeliveryEventInput {
                notification_id: retained.notification_id.clone(),
                event_number: 1,
                occurred_at: "2026-01-01T00:00:01Z".into(),
                outcome: "claimed".into(),
                detail: CanonicalDocument::from_serializable(&json!({"phase":"before_transport"}))
                    .unwrap(),
            })
            .unwrap();
        drop(reopened);
        let recovered = Store::open(&database).unwrap();
        assert_eq!(
            recovered
                .notification_delivery_status(Some(&retained.notification_id))
                .unwrap()[0]
                .delivery_state,
            "unknown"
        );
        assert_eq!(
            recovered
                .notification_delivery_by_identity("event-1", "destination-1")
                .unwrap()
                .unwrap()
                .delivery_state,
            "unknown"
        );
    }

    #[tokio::test]
    async fn nightshift_replay_bundle_is_refused_without_a_verified_replay_adapter() {
        let root = TempDir::new().expect("temporary notification root");
        let path = write_intent(
            &root,
            intent(
                "check storage",
                "nightshift_receipt",
                Some(json!({
                    "schema":"nightshift.project-predicate-attention-replay-bundle/v1",
                    "receipt_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                })),
            ),
        );
        let config = config(&root);
        let error = submit_with_dispatch(&config, &path, "ops.primary", false, endpoint, |_| {
            Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
        })
        .await
        .expect_err("substituted owner receipt is rejected");
        assert!(error.to_string().contains("replay is not configured"));
    }

    #[tokio::test]
    async fn exact_nightshift_bundle_replays_before_any_delivery_boundary() {
        let root = TempDir::new().unwrap();
        let mut config = config(&root);
        configure_replay(
            &root,
            &mut config.notification_routes[0],
            "#!/bin/sh\ntest \"$5\" = --bundle-stdin || exit 91\nIFS= read -r bundle || exit 92\ncase \"$bundle\" in *nightshift.project-predicate-attention-replay-bundle/v1*) ;; *) exit 93;; esac\nprintf '%s\\n' '{\"schema\":\"nightshift.project-predicate-attention-replay/v1\",\"matches\":true,\"expected_receipt_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"recomputed_receipt_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}'\n",
        );
        let path = write_intent(
            &root,
            intent("check storage", "nightshift_receipt", Some(replay_bundle())),
        );
        let result = submit_with_dispatch(
            &config,
            &path,
            "ops.primary",
            false,
            |_| panic!("endpoint resolution must follow the explicit network boundary"),
            |_| Ok(|_, _, _| async { panic!("transport must not run") }),
        )
        .await
        .expect("exact canonical replay accepted before no-network refusal");
        assert_eq!(result["delivery_state"], "refused");
    }

    #[test]
    fn nightshift_mismatch_changed_binary_and_timeout_fail_closed() {
        let root = TempDir::new().unwrap();
        let parsed: Intent = serde_json::from_value(intent(
            "check storage",
            "nightshift_receipt",
            Some(replay_bundle()),
        ))
        .unwrap();

        let mut mismatch = route(NotificationTransportKind::Slack);
        configure_replay(
            &root,
            &mut mismatch,
            "#!/bin/sh\nIFS= read -r bundle || exit 92\nprintf '%s\\n' '{\"schema\":\"nightshift.project-predicate-attention-replay/v1\",\"matches\":false,\"expected_receipt_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"recomputed_receipt_digest\":\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}'\n",
        );
        assert!(
            replay_nightshift(&mismatch, &parsed)
                .unwrap_err()
                .to_string()
                .contains("did not reproduce")
        );

        let executable = mismatch
            .nightshift_attention_replay
            .as_ref()
            .unwrap()
            .executable
            .clone();
        fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
        assert!(
            replay_nightshift(&mismatch, &parsed)
                .unwrap_err()
                .to_string()
                .contains("digest does not match")
        );

        let mut timeout = route(NotificationTransportKind::Slack);
        timeout.timeout_ms = 100;
        configure_replay(&root, &mut timeout, "#!/bin/sh\nsleep 2\n");
        assert!(
            replay_nightshift(&timeout, &parsed)
                .unwrap_err()
                .to_string()
                .contains("failed: timeout")
        );
    }

    #[test]
    fn nightshift_policy_receipt_and_disposition_bindings_are_exact() {
        for pointer in ["policy", "receipt", "disposition"] {
            let root = TempDir::new().unwrap();
            let mut route = route(NotificationTransportKind::Slack);
            configure_replay(&root, &mut route, "#!/bin/sh\nexit 99\n");
            let mut bundle = replay_bundle();
            match pointer {
                "policy" => {
                    bundle["policy"]["policy_digest"] = json!(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    )
                }
                "receipt" => {
                    bundle["receipt"]["receipt_digest"] = json!(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    )
                }
                _ => bundle["receipt"]["disposition"] = json!("NO_ATTENTION"),
            }
            let parsed: Intent =
                serde_json::from_value(intent("check storage", "nightshift_receipt", Some(bundle)))
                    .unwrap();
            assert!(
                replay_nightshift(&route, &parsed)
                    .unwrap_err()
                    .to_string()
                    .contains("does not match")
            );
        }

        for field in [
            "attention_policy_digest",
            "stable_event_id",
            "transition_id",
        ] {
            let root = TempDir::new().unwrap();
            let mut route = route(NotificationTransportKind::Slack);
            configure_replay(&root, &mut route, "#!/bin/sh\nexit 99\n");
            let mut value = intent("check storage", "nightshift_receipt", Some(replay_bundle()));
            value[field] =
                json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
            let parsed: Intent = serde_json::from_value(value).unwrap();
            let error = replay_nightshift(&route, &parsed).unwrap_err().to_string();
            if field == "attention_policy_digest" {
                assert!(error.contains("approved policy and intent binding"));
            } else {
                assert!(error.contains("event and transition identities"));
            }
        }
    }
}
