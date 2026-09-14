//! Bounded notification-delivery custody. It owns no attention or admission.

use anyhow::{Context, Result, bail};
use nq_core::config::{
    CommandConfig, NotificationRouteConfig, NotificationTransportKind, NqConfig, ResourceLimits,
};
use nq_core::identity::VerifiedLaunch;
use nq_core::runner::{AcquisitionOutcome, StdioRunner};
use nq_helper_sandbox::open_runtime_root;
use nq_protocol::sha256_bytes;
use nq_store::{
    CanonicalDocument, NotificationDeliveryEventInput, NotificationDeliveryIntentInput,
    NotificationDeliveryRetention, NotificationInput, Store,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

const MAX_INTENT_BYTES: usize = 32_768;
const LOCAL_INBOX_FILE_MAX_BYTES: usize = 4_096;

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
    // These are two closed owner contracts, not interchangeable evidence or
    // arbitrary verifier commands. The enrolled executable and policy still
    // bind the caller's exact route; SQLite's owner kind remains unchanged.
    let saved_check = match required_json_string(bundle, "schema")? {
        "nightshift.project-predicate-attention-replay-bundle/v1" => false,
        "nightshift.saved-check-attention-replay-bundle/v1" => true,
        _ => bail!("unsupported Nightshift attention replay bundle schema"),
    };
    let (policy_schema, receipt_schema, replay_schema) = if saved_check {
        (
            "nightshift.saved-check-attention-policy/v1",
            "nightshift.saved-check-attention-receipt/v1",
            "nightshift.saved-check-attention-replay/v1",
        )
    } else {
        (
            "nightshift.project-predicate-attention-policy/v1",
            "nightshift.project-predicate-attention/v1",
            "nightshift.project-predicate-attention-replay/v1",
        )
    };
    let disposition = required_json_string(receipt, "disposition")?;
    let eligible = if saved_check {
        matches!(disposition, "ATTENTION_REQUIRED" | "LOSS_OF_ASSURANCE")
            && receipt.get("delivery_eligible").and_then(Value::as_bool) == Some(true)
            && required_json_string(receipt, "authority")? == "none"
            && required_json_string(receipt, "inspection_reference")? == intent.inspection_reference
    } else {
        disposition == "ATTENTION_REQUIRED"
    };
    if !eligible
        || required_json_string(policy, "schema")? != policy_schema
        || required_json_string(receipt, "schema")? != receipt_schema
        || required_json_string(policy, "policy_digest")? != replay.approved_policy_digest
        || required_json_string(receipt, "policy_digest")? != replay.approved_policy_digest
        || intent.attention_policy_digest != replay.approved_policy_digest
        || required_json_string(receipt, "policy_id")? != intent.attention_policy_id
        || required_json_string(receipt, "receipt_digest")?
            != intent
                .attention_receipt_digest
                .as_deref()
                .context("attention receipt digest is missing")?
    {
        bail!("Nightshift attention bundle does not match the approved policy and intent binding");
    }
    let receipt_digest = required_json_string(receipt, "receipt_digest")?;
    if intent.stable_event_id != receipt_digest || intent.transition_id != receipt_digest {
        bail!(
            "Nightshift delivery event and transition identities must equal the exact attention receipt digest"
        );
    }
    if !saved_check && bundle.get("history").and_then(Value::as_array).is_none() {
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
    let args = if saved_check {
        vec![
            "--store".into(),
            replay.store_locator.to_string_lossy().into_owned(),
            "saved-check".into(),
            "attention-replay".into(),
            "--bundle-stdin".into(),
        ]
    } else {
        vec![
            "--store".into(),
            replay.store_locator.to_string_lossy().into_owned(),
            "attention".into(),
            "replay".into(),
            "--bundle-stdin".into(),
        ]
    };
    let command = CommandConfig {
        executable: replay.executable.clone(),
        args,
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
    if required_json_string(&result, "schema")? != replay_schema
        || result.get("matches").and_then(Value::as_bool) != Some(true)
        || required_json_string(&result, "expected_receipt_digest")? != expected
        || required_json_string(&result, "recomputed_receipt_digest")? != expected
    {
        bail!("Nightshift replay did not reproduce the exact attention receipt");
    }
    Ok(())
}

/// Replay establishes a past owner decision, not freshness at delivery. Check
/// the fixed event window with the delivery process's clock, without replacing
/// the older source-observation time or extending a duplicate's eligibility.
fn saved_check_delivery_is_current(
    owner: Option<&Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    let Some(bundle) = owner else {
        return Ok(true);
    };
    if bundle.get("schema").and_then(Value::as_str)
        != Some("nightshift.saved-check-attention-replay-bundle/v1")
    {
        return Ok(true);
    }
    let receipt = bundle
        .get("receipt")
        .context("saved-check receipt missing")?;
    let parse = |field| -> Result<chrono::DateTime<chrono::FixedOffset>> {
        Ok(chrono::DateTime::parse_from_rfc3339(required_json_string(
            receipt, field,
        )?)?)
    };
    let projected = parse("projection_at")?;
    let evaluated = parse("evaluated_at")?;
    let until = parse("event_current_until")?;
    Ok(projected <= evaluated
        && evaluated <= now
        && now <= until
        && until.signed_duration_since(projected) <= chrono::Duration::seconds(300))
}

fn refuse_expired_saved_check(store: &mut Store, id: &str, owner: Option<&Value>) -> Result<bool> {
    let now = chrono::Utc::now();
    let reason = match saved_check_delivery_is_current(owner, now) {
        Ok(true) => return Ok(false),
        Ok(false) => "saved_check_attention_event_not_current",
        Err(_) => "saved_check_attention_event_time_invalid",
    };
    store.append_notification_delivery_event(&NotificationDeliveryEventInput {
        notification_id: id.to_owned(),
        event_number: 1,
        occurred_at: now.to_rfc3339(),
        outcome: "refused".into(),
        detail: CanonicalDocument::from_serializable(&json!({"reason":reason}))?,
    })?;
    Ok(true)
}

/// A duplicate is a read of old custody, not a second replay or delivery. The
/// exact submitted bytes must match; for local inboxes the configured pathname
/// must still name the same enrolled route. Its current existence/contents and
/// the replay executable's availability cannot establish the past outcome.
fn retained_duplicate(
    config: &NqConfig,
    route: &NotificationRouteConfig,
    intent: &Intent,
    document: &CanonicalDocument,
) -> Result<Option<Value>> {
    let store = Store::open_read_only(&config.database_path)?;
    let Some(retained) = store.notification_delivery_intent_by_identity(
        &intent.stable_event_id,
        &intent.destination_identity,
    )?
    else {
        return Ok(None);
    };
    let retained: Value = serde_json::from_slice(retained.as_bytes())?;
    let submitted: Value = serde_json::from_slice(document.as_bytes())?;
    if route.transport == NotificationTransportKind::LocalFile {
        let path = route
            .local_inbox_directory
            .as_ref()
            .context("local inbox directory absent")?;
        let path_digest = sha256_bytes(path.as_os_str().as_bytes());
        if retained.get("schema").and_then(Value::as_str)
            != Some("nq.local-inbox-delivery-intent/v1")
            || retained.get("intent") != Some(&submitted)
            || retained
                .pointer("/directory_binding/path_sha256")
                .and_then(Value::as_str)
                != Some(path_digest.as_str())
        {
            bail!(
                "notification identity is already retained with different canonical intent or local route"
            );
        }
    } else if retained != submitted {
        bail!("notification identity is already retained with different canonical intent");
    }
    if intent.attention_kind == "nightshift_receipt" {
        let replay = route
            .nightshift_attention_replay
            .as_ref()
            .context("Nightshift replay is not configured for this route")?;
        if replay.approved_policy_digest != intent.attention_policy_digest {
            bail!("retained notification differs from the route's approved policy");
        }
    }
    let status = store
        .notification_delivery_by_identity(&intent.stable_event_id, &intent.destination_identity)?
        .context("retained notification custody is incomplete")?;
    Ok(Some(
        json!({"notification_id":status.notification_id,"delivery_state":status.delivery_state}),
    ))
}

fn render(route: &NotificationRouteConfig, intent: &Intent) -> Result<CanonicalDocument> {
    let text = format!(
        "Attention required: {}\nInspect: {}",
        intent.summary, intent.inspection_reference
    );
    let payload = match route.transport {
        NotificationTransportKind::Slack => json!({"text": text}),
        NotificationTransportKind::Discord => json!({"content": text}),
        NotificationTransportKind::LocalFile => {
            bail!("local inbox uses its own bounded message envelope")
        }
    };
    Ok(CanonicalDocument::from_serializable(&payload)?)
}

fn local_inbox_binding(
    route: &NotificationRouteConfig,
) -> Result<(nq_helper_sandbox::ValidatedRuntimeRoot, CanonicalDocument)> {
    let configured = route
        .local_inbox_directory
        .as_ref()
        .context("local_file route has no inbox directory")?;
    let root = open_runtime_root(configured).context("validate local inbox directory")?;
    let metadata = fs::metadata(root.descriptor_path()).context("inspect local inbox directory")?;
    let binding = CanonicalDocument::from_serializable(&json!({
        "schema":"nq.local-inbox-directory-binding/v1",
        "path_sha256":sha256_bytes(root.canonical_path().as_os_str().as_bytes()).as_str(),
        "device":metadata.dev(),
        "inode":metadata.ino(),
        "mode":metadata.mode() & 0o7777
    }))?;
    Ok((root, binding))
}

fn render_local_inbox(intent: &Intent, binding: &CanonicalDocument) -> Result<CanonicalDocument> {
    Ok(CanonicalDocument::from_serializable(&json!({
        "schema":"nq.local-inbox-message/v1",
        "stable_event_id":intent.stable_event_id,
        "summary":intent.summary,
        "inspection_reference":intent.inspection_reference,
        "route_reference":intent.route_reference,
        "destination_identity":intent.destination_identity,
        "destination_binding_digest":binding.digest(),
        "delivery_statement":"local file retained; human receipt is not established"
    }))?)
}

fn validate_local_inbox_payload(payload: &CanonicalDocument) -> Result<()> {
    if payload.as_bytes().len() > LOCAL_INBOX_FILE_MAX_BYTES {
        bail!(
            "local inbox message exceeds {LOCAL_INBOX_FILE_MAX_BYTES} bytes before delivery custody"
        );
    }
    Ok(())
}

enum LocalWriteFailure {
    BeforeCreate,
    AfterCreate,
}

trait LocalInboxWriteOperation {
    fn write_and_sync(&self, file: &mut fs::File, bytes: &[u8]) -> std::io::Result<()>;
    fn sync_directory(&self, root: &nq_helper_sandbox::ValidatedRuntimeRoot)
    -> std::io::Result<()>;
}

struct SystemLocalInboxWriteOperation;

impl LocalInboxWriteOperation for SystemLocalInboxWriteOperation {
    fn write_and_sync(&self, file: &mut fs::File, bytes: &[u8]) -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn sync_directory(
        &self,
        root: &nq_helper_sandbox::ValidatedRuntimeRoot,
    ) -> std::io::Result<()> {
        fs::File::open(root.descriptor_path())?.sync_all()
    }
}

fn write_local_inbox_with<O: LocalInboxWriteOperation>(
    root: &nq_helper_sandbox::ValidatedRuntimeRoot,
    filename: &str,
    bytes: &[u8],
    operation: &O,
) -> Result<(), LocalWriteFailure> {
    if root.revalidate().is_err()
        || bytes.len() > LOCAL_INBOX_FILE_MAX_BYTES
        || filename.is_empty()
        || filename.len() > 128
        || filename.contains('/')
        || filename.contains('\0')
    {
        return Err(LocalWriteFailure::BeforeCreate);
    }
    let path = root.descriptor_path().join(filename);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| LocalWriteFailure::BeforeCreate)?;
    operation
        .write_and_sync(&mut file, bytes)
        .map_err(|_| LocalWriteFailure::AfterCreate)?;
    root.revalidate()
        .and_then(|()| operation.sync_directory(root))
        .map_err(|_| LocalWriteFailure::AfterCreate)
}

#[cfg(test)]
fn write_local_inbox(
    root: &nq_helper_sandbox::ValidatedRuntimeRoot,
    filename: &str,
    bytes: &[u8],
) -> Result<(), LocalWriteFailure> {
    write_local_inbox_with(root, filename, bytes, &SystemLocalInboxWriteOperation)
}

/// Deliver one exact attention intent to a descriptor-bound local inbox.
/// This creates a factual local file only; it does not establish human receipt.
pub(crate) fn deliver_local(
    config: &NqConfig,
    intent_path: &std::path::Path,
    route_ref: &str,
) -> Result<Value> {
    deliver_local_with(
        config,
        intent_path,
        route_ref,
        &SystemLocalInboxWriteOperation,
    )
}

fn deliver_local_with<O: LocalInboxWriteOperation>(
    config: &NqConfig,
    intent_path: &std::path::Path,
    route_ref: &str,
    operation: &O,
) -> Result<Value> {
    let (intent, intent_document) = read_intent(intent_path)?;
    if intent.route_reference != route_ref {
        bail!("CLI route does not match intent route reference");
    }
    let route = config
        .notification_routes
        .iter()
        .find(|route| route.reference == route_ref)
        .context("route reference is not configured")?;
    if route.transport != NotificationTransportKind::LocalFile {
        bail!("notification deliver-local requires a local_file route");
    }
    let expected_destination = format!("local-inbox:{}", route.reference);
    if intent.destination_identity != expected_destination {
        bail!("local inbox intent destination identity does not match its configured route");
    }
    if let Some(existing) = retained_duplicate(config, route, &intent, &intent_document)? {
        return Ok(existing);
    }
    replay_nightshift(route, &intent)?;
    let owner_receipt = intent.owner_receipt.clone();
    let (root, directory_binding) = local_inbox_binding(route)?;
    let payload = render_local_inbox(&intent, &directory_binding)?;
    validate_local_inbox_payload(&payload)?;
    let original_intent: Value = serde_json::from_slice(intent_document.as_bytes())?;
    let retained_intent = CanonicalDocument::from_serializable(&json!({
        "schema":"nq.local-inbox-delivery-intent/v1",
        "intent":original_intent,
        "directory_binding":serde_json::from_slice::<Value>(directory_binding.as_bytes())?
    }))?;
    let mut store = Store::open(&config.database_path)?;
    let notification_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let notification = NotificationInput {
        notification_id: notification_id.clone(),
        idempotency_key: format!("{}:{}", intent.stable_event_id, expected_destination),
        finding_event_id: None,
        destination_kind: "local_file".into(),
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
        destination_identity: expected_destination,
        content_digest: payload.digest().to_owned(),
        intent: retained_intent,
        created_at: now.clone(),
    };
    match store.retain_notification_delivery(&notification, &delivery_intent)? {
        NotificationDeliveryRetention::Inserted => {}
        NotificationDeliveryRetention::Existing(existing) => {
            return Ok(
                json!({"notification_id":existing.notification_id,"delivery_state":existing.delivery_state}),
            );
        }
    }
    if refuse_expired_saved_check(&mut store, &notification_id, owner_receipt.as_ref())? {
        return Ok(json!({"notification_id":notification_id,"delivery_state":"refused"}));
    }
    store.append_notification_delivery_event(&NotificationDeliveryEventInput {
        notification_id: notification_id.clone(),
        event_number: 1,
        occurred_at: now.clone(),
        outcome: "claimed".into(),
        detail: CanonicalDocument::from_serializable(&json!({
            "route_reference":route.reference,
            "transport":"local_file",
            "directory_binding_digest":directory_binding.digest()
        }))?,
    })?;
    let filename = format!("{notification_id}.json");
    let (outcome, detail) =
        match write_local_inbox_with(&root, &filename, payload.as_bytes(), operation) {
            Ok(()) => (
                "accepted",
                json!({"filename":filename,"message_digest":payload.digest()}),
            ),
            Err(LocalWriteFailure::BeforeCreate) => {
                ("failed", json!({"reason":"local_inbox_create_unavailable"}))
            }
            Err(LocalWriteFailure::AfterCreate) => (
                "unknown",
                json!({"reason":"local_inbox_post_create_state_uncertain"}),
            ),
        };
    store.append_notification_delivery_event(&NotificationDeliveryEventInput {
        notification_id: notification_id.clone(),
        event_number: 2,
        occurred_at: chrono::Utc::now().to_rfc3339(),
        outcome: outcome.into(),
        detail: CanonicalDocument::from_serializable(&detail)?,
    })?;
    Ok(
        json!({"notification_id":notification_id,"delivery_state":outcome,"human_receipt":"not_established"}),
    )
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
    if route.transport == NotificationTransportKind::LocalFile {
        bail!("local_file routes require notification deliver-local");
    }
    if let Some(existing) = retained_duplicate(config, route, &intent, &intent_document)? {
        return Ok(existing);
    }
    replay_nightshift(route, &intent)?;
    let owner_receipt = intent.owner_receipt.clone();
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
            NotificationTransportKind::LocalFile => {
                unreachable!("local routes use notification deliver-local")
            }
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
    if refuse_expired_saved_check(&mut store, &notification_id, owner_receipt.as_ref())? {
        return Ok(json!({"notification_id":notification_id,"delivery_state":"refused"}));
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
    let endpoint_locator = route
        .endpoint_secret_locator
        .as_deref()
        .context("HTTPS route has no endpoint secret locator")?;
    let endpoint = match resolve_endpoint(endpoint_locator) {
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
            endpoint_secret_locator: Some("NQ_TEST_URL".into()),
            local_inbox_directory: None,
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

    fn local_config(root: &TempDir) -> NqConfig {
        let inbox = root.path().join("inbox");
        fs::create_dir(&inbox).expect("create inbox");
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o711)).expect("protect inbox");
        let config = NqConfig {
            schema: CONFIG_SCHEMA.into(),
            database_path: root.path().join("notification.db"),
            socket_path: root.path().join("nqd.sock"),
            admissions_dir: root.path().join("admissions"),
            helper_runtime_dir: root.path().join("helpers"),
            watchers: Vec::new(),
            notification_routes: vec![NotificationRouteConfig {
                reference: "local.ops".into(),
                transport: NotificationTransportKind::LocalFile,
                endpoint_secret_locator: None,
                local_inbox_directory: Some(inbox),
                timeout_ms: 10_000,
                max_response_bytes: 1024,
                nightshift_attention_replay: None,
            }],
        };
        Store::initialize(&config.database_path).expect("initialize local inbox Store");
        config
    }

    fn local_intent() -> Value {
        let mut value = intent("check storage", "operator_assertion", None);
        value["route_reference"] = Value::String("local.ops".into());
        value["destination_identity"] = Value::String("local-inbox:local.ops".into());
        value
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

    fn saved_check_bundle(at: chrono::DateTime<chrono::Utc>) -> Value {
        let mut bundle = replay_bundle();
        bundle["schema"] = json!("nightshift.saved-check-attention-replay-bundle/v1");
        bundle["policy"]["schema"] = json!("nightshift.saved-check-attention-policy/v1");
        bundle["receipt"]["schema"] = json!("nightshift.saved-check-attention-receipt/v1");
        bundle["receipt"]["delivery_eligible"] = json!(true);
        bundle["receipt"]["authority"] = json!("none");
        bundle["receipt"]["inspection_reference"] = json!("record:1");
        bundle["receipt"]["projection_at"] = json!(at.to_rfc3339());
        bundle["receipt"]["evaluated_at"] = json!(at.to_rfc3339());
        bundle["receipt"]["event_current_until"] =
            json!((at + chrono::Duration::seconds(300)).to_rfc3339());
        bundle
    }

    // The deterministic transport checks NQ's command selection and refusal
    // ordering only; actual Nightshift receipt replay is a separate integration
    // check. This fixture does not establish an owner-minted decision.
    const SAVED_CHECK_REPLAY_FIXTURE: &str = "#!/bin/sh\ntest \"$3\" = saved-check || exit 90\ntest \"$4\" = attention-replay || exit 91\ntest \"$5\" = --bundle-stdin || exit 92\nIFS= read -r bundle || exit 93\nprintf '%s\\n' '{\"schema\":\"nightshift.saved-check-attention-replay/v1\",\"matches\":true,\"expected_receipt_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"recomputed_receipt_digest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}'\n";

    #[test]
    fn saved_check_freshness_is_delivery_time_not_source_or_replay_time() {
        let at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let bundle = saved_check_bundle(at);
        for (delta, expected) in [(-1, false), (0, true), (300, true), (301, false)] {
            assert_eq!(
                saved_check_delivery_is_current(
                    Some(&bundle),
                    at + chrono::Duration::seconds(delta)
                )
                .unwrap(),
                expected
            );
        }
        let mut invalid = bundle.clone();
        invalid["receipt"]["evaluated_at"] =
            json!((at - chrono::Duration::seconds(1)).to_rfc3339());
        assert!(!saved_check_delivery_is_current(Some(&invalid), at).unwrap());
        invalid["receipt"]["projection_at"] = json!("not-a-time");
        assert!(saved_check_delivery_is_current(Some(&invalid), at).is_err());
        let mut fractional = bundle.clone();
        fractional["receipt"]["event_current_until"] =
            json!((at + chrono::Duration::milliseconds(300_001)).to_rfc3339());
        assert!(!saved_check_delivery_is_current(Some(&fractional), at).unwrap());
        assert!(saved_check_delivery_is_current(Some(&replay_bundle()), at).unwrap());
    }

    #[test]
    fn saved_check_union_preserves_local_delivery_replay_and_expiry() {
        for expired in [false, true] {
            let root = TempDir::new().unwrap();
            let mut config = local_config(&root);
            configure_replay(
                &root,
                &mut config.notification_routes[0],
                SAVED_CHECK_REPLAY_FIXTURE,
            );
            let at = chrono::Utc::now() - chrono::Duration::seconds(if expired { 600 } else { 1 });
            let mut bundle = saved_check_bundle(at);
            bundle["receipt"]["disposition"] = json!("LOSS_OF_ASSURANCE");
            let mut value = intent(
                "check result unavailable; inspect retained record",
                "nightshift_receipt",
                Some(bundle),
            );
            value["route_reference"] = json!("local.ops");
            value["destination_identity"] = json!("local-inbox:local.ops");
            let path = write_intent(&root, value);
            let first = deliver_local(&config, &path, "local.ops").unwrap();
            assert_eq!(
                first["delivery_state"],
                if expired { "refused" } else { "accepted" }
            );
            let duplicate = deliver_local(&config, &path, "local.ops").unwrap();
            assert_eq!(first["notification_id"], duplicate["notification_id"]);
            assert_eq!(first["delivery_state"], duplicate["delivery_state"]);
            assert_eq!(
                fs::read_dir(root.path().join("inbox")).unwrap().count(),
                if expired { 0 } else { 1 }
            );
        }
    }

    #[test]
    fn saved_check_union_rejects_ineligible_or_mismatched_material_before_replay() {
        for field in [
            "delivery_eligible",
            "authority",
            "inspection_reference",
            "disposition",
            "schema",
        ] {
            let root = TempDir::new().unwrap();
            let mut route = route(NotificationTransportKind::Slack);
            configure_replay(&root, &mut route, "#!/bin/sh\nexit 99\n");
            let mut bundle = saved_check_bundle(chrono::Utc::now());
            bundle["receipt"][field] = if field == "delivery_eligible" {
                json!(false)
            } else {
                json!("unsupported")
            };
            let parsed: Intent = serde_json::from_value(intent(
                "inspect condition",
                "nightshift_receipt",
                Some(bundle),
            ))
            .unwrap();
            assert!(
                replay_nightshift(&route, &parsed)
                    .unwrap_err()
                    .to_string()
                    .contains("does not match")
            );
        }
    }

    #[test]
    fn malformed_saved_check_times_end_in_retained_refusal_not_pending_custody() {
        for field in ["projection_at", "evaluated_at", "event_current_until"] {
            let root = TempDir::new().unwrap();
            let mut config = local_config(&root);
            configure_replay(
                &root,
                &mut config.notification_routes[0],
                SAVED_CHECK_REPLAY_FIXTURE,
            );
            let mut bundle = saved_check_bundle(chrono::Utc::now());
            bundle["receipt"][field] = Value::Null;
            let mut value = intent(
                "inspect unavailable check",
                "nightshift_receipt",
                Some(bundle),
            );
            value["route_reference"] = json!("local.ops");
            value["destination_identity"] = json!("local-inbox:local.ops");
            let path = write_intent(&root, value);
            let first = deliver_local(&config, &path, "local.ops").unwrap();
            assert_eq!(first["delivery_state"], "refused");
            assert_eq!(deliver_local(&config, &path, "local.ops").unwrap(), first);
            let status = inspect(&config, first["notification_id"].as_str()).unwrap();
            assert_eq!(status[0]["event_count"], 1);
            assert_eq!(fs::read_dir(root.path().join("inbox")).unwrap().count(), 0);
        }
    }

    #[test]
    fn exact_duplicate_needs_neither_replay_executable_nor_live_inbox() {
        let root = TempDir::new().unwrap();
        let mut config = local_config(&root);
        configure_replay(
            &root,
            &mut config.notification_routes[0],
            SAVED_CHECK_REPLAY_FIXTURE,
        );
        let mut value = intent(
            "inspect failed check",
            "nightshift_receipt",
            Some(saved_check_bundle(
                chrono::Utc::now() - chrono::Duration::seconds(1),
            )),
        );
        value["route_reference"] = json!("local.ops");
        value["destination_identity"] = json!("local-inbox:local.ops");
        let path = write_intent(&root, value.clone());
        let first = deliver_local(&config, &path, "local.ops").unwrap();
        assert_eq!(first["delivery_state"], "accepted");
        fs::rename(
            root.path().join("nightshift-fixture"),
            root.path().join("retained-verifier"),
        )
        .unwrap();
        fs::rename(
            root.path().join("inbox"),
            root.path().join("retained-inbox"),
        )
        .unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let duplicate =
            deliver_local_with(&config, &path, "local.ops", &CountingWrite(writes.clone()))
                .unwrap();
        assert_eq!(duplicate["notification_id"], first["notification_id"]);
        assert_eq!(duplicate["delivery_state"], first["delivery_state"]);
        assert_eq!(writes.load(Ordering::SeqCst), 0);
        value["summary"] = json!("different material with same identity");
        write_intent(&root, value);
        assert!(deliver_local(&config, &path, "local.ops").is_err());
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

    #[test]
    fn local_inbox_writes_one_exact_file_and_duplicate_reopens_custody() {
        let root = TempDir::new().expect("temporary root");
        let config = local_config(&root);
        let path = write_intent(&root, local_intent());
        let first = deliver_local(&config, &path, "local.ops").expect("write local inbox");
        assert_eq!(first["delivery_state"], "accepted");
        assert_eq!(first["human_receipt"], "not_established");
        let notification_id = first["notification_id"].as_str().expect("notification id");
        let message: Value = serde_json::from_slice(
            &fs::read(
                config.notification_routes[0]
                    .local_inbox_directory
                    .as_ref()
                    .expect("inbox")
                    .join(format!("{notification_id}.json")),
            )
            .expect("read local inbox file"),
        )
        .expect("message JSON");
        assert_eq!(message["schema"], "nq.local-inbox-message/v1");
        assert_eq!(message["stable_event_id"], "event-1");
        assert_eq!(
            message["delivery_statement"],
            "local file retained; human receipt is not established"
        );
        assert_eq!(
            fs::metadata(
                config.notification_routes[0]
                    .local_inbox_directory
                    .as_ref()
                    .expect("inbox")
                    .join(format!("{notification_id}.json")),
            )
            .expect("inbox metadata")
            .mode()
                & 0o777,
            0o600
        );
        let duplicate = deliver_local(&config, &path, "local.ops").expect("reopen duplicate");
        assert_eq!(duplicate["notification_id"], first["notification_id"]);
        assert_eq!(
            fs::read_dir(
                config.notification_routes[0]
                    .local_inbox_directory
                    .as_ref()
                    .expect("inbox")
            )
            .expect("list inbox")
            .count(),
            1
        );
    }

    #[test]
    fn local_inbox_oversized_render_refuses_before_custody_or_file_creation() {
        let root = TempDir::new().expect("temporary root");
        let mut config = local_config(&root);
        // The local destination includes the route reference, so keep both
        // source fields within their independently validated 256-byte limits.
        let route_reference = "r".repeat(244);
        config.notification_routes[0].reference = route_reference.clone();
        let mut value = local_intent();
        value["route_reference"] = Value::String(route_reference.clone());
        value["destination_identity"] = Value::String(format!("local-inbox:{route_reference}"));
        // These are valid non-control intent strings. Canonical JSON escapes
        // each quote, making the bounded local projection exceed 4 KiB.
        value["stable_event_id"] = Value::String("\"".repeat(256));
        value["summary"] = Value::String("\"".repeat(512));
        value["inspection_reference"] = Value::String("\"".repeat(1024));
        let path = write_intent(&root, value);

        let error = deliver_local(&config, &path, &route_reference)
            .expect_err("oversized local projection must refuse before custody")
            .to_string();
        assert!(error.contains("local inbox message exceeds 4096 bytes before delivery custody"));
        assert_eq!(
            inspect(&config, None).expect("inspect empty custody"),
            json!([])
        );
        assert_eq!(
            fs::read_dir(
                config.notification_routes[0]
                    .local_inbox_directory
                    .as_ref()
                    .expect("inbox"),
            )
            .expect("list inbox")
            .count(),
            0
        );
    }

    #[test]
    fn local_inbox_precreated_name_refuses_before_any_file_mutation() {
        let root = TempDir::new().expect("temporary root");
        let inbox = root.path().join("inbox");
        fs::create_dir(&inbox).expect("create inbox");
        fs::set_permissions(&inbox, fs::Permissions::from_mode(0o711)).expect("protect inbox");
        let root = open_runtime_root(&inbox).expect("open protected inbox");
        let existing = root.descriptor_path().join("known.json");
        fs::write(&existing, b"existing").expect("precreate inbox entry");
        assert!(matches!(
            write_local_inbox(&root, "known.json", b"replacement"),
            Err(LocalWriteFailure::BeforeCreate)
        ));
        assert_eq!(fs::read(existing).expect("reopen existing"), b"existing");
        assert!(matches!(
            write_local_inbox(&root, "../outside", b"ignored"),
            Err(LocalWriteFailure::BeforeCreate)
        ));
    }

    struct FailingWrite;

    impl LocalInboxWriteOperation for FailingWrite {
        fn write_and_sync(&self, _file: &mut fs::File, _bytes: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("deterministic post-create failure"))
        }

        fn sync_directory(
            &self,
            _root: &nq_helper_sandbox::ValidatedRuntimeRoot,
        ) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct CountingWrite(Arc<AtomicUsize>);

    impl LocalInboxWriteOperation for CountingWrite {
        fn write_and_sync(&self, file: &mut fs::File, bytes: &[u8]) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            file.write_all(bytes)?;
            file.sync_all()
        }

        fn sync_directory(
            &self,
            root: &nq_helper_sandbox::ValidatedRuntimeRoot,
        ) -> std::io::Result<()> {
            fs::File::open(root.descriptor_path())?.sync_all()
        }
    }

    #[test]
    fn local_inbox_post_create_failure_is_unknown_and_duplicate_does_not_write_again() {
        let root = TempDir::new().expect("temporary root");
        let config = local_config(&root);
        let path = write_intent(&root, local_intent());
        let first = deliver_local_with(&config, &path, "local.ops", &FailingWrite)
            .expect("retain uncertain local write");
        assert_eq!(first["delivery_state"], "unknown");
        let writes = Arc::new(AtomicUsize::new(0));
        let duplicate = deliver_local_with(
            &config,
            &path,
            "local.ops",
            &CountingWrite(Arc::clone(&writes)),
        )
        .expect("reopen uncertain custody");
        assert_eq!(duplicate["notification_id"], first["notification_id"]);
        assert_eq!(duplicate["delivery_state"], "unknown");
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn local_inbox_changed_directory_for_same_event_refuses_retargeting() {
        let root = TempDir::new().expect("temporary root");
        let mut config = local_config(&root);
        let path = write_intent(&root, local_intent());
        deliver_local(&config, &path, "local.ops").expect("first local delivery");
        let replacement = root.path().join("replacement-inbox");
        fs::create_dir(&replacement).expect("create replacement inbox");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o711))
            .expect("protect replacement inbox");
        config.notification_routes[0].local_inbox_directory = Some(replacement);
        assert!(deliver_local(&config, &path, "local.ops").is_err());
    }

    #[test]
    fn local_inbox_alias_refuses_before_first_custody() {
        let root = TempDir::new().unwrap();
        let mut config = local_config(&root);
        fs::create_dir(root.path().join("neighbor")).unwrap();
        config.notification_routes[0].local_inbox_directory =
            Some(root.path().join("neighbor/../inbox"));
        let path = write_intent(&root, local_intent());
        assert!(deliver_local(&config, &path, "local.ops").is_err());
        assert_eq!(inspect(&config, None).unwrap(), json!([]));
    }

    #[tokio::test]
    async fn https_command_refuses_local_route_before_new_or_duplicate_custody() {
        let root = TempDir::new().unwrap();
        let config = local_config(&root);
        let path = write_intent(&root, local_intent());
        for existing in [false, true] {
            if existing {
                deliver_local(&config, &path, "local.ops").unwrap();
            }
            let result = submit_with_dispatch(
                &config,
                &path,
                "local.ops",
                false,
                |_| panic!("wrong surface must not resolve a destination"),
                |_| Ok(|_, _, _| async { panic!("wrong surface must not dispatch") }),
            )
            .await;
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("require notification deliver-local")
            );
        }
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
