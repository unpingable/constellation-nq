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
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::Duration;

const MAX_INTENT_BYTES: usize = 32_768;
const LOCAL_INBOX_FILE_MAX_BYTES: usize = 4_096;
const INTENT_V1: &str = "nq.notification_delivery_intent.v1";
const INTENT_V2: &str = "nq.notification_delivery_intent.v2";
const PAGERDUTY_ENQUEUE_URL: &str = "https://events.pagerduty.com/v2/enqueue";
const PAGERDUTY_DETAILS_MAX_BYTES: usize = 4_096;
const PAGERDUTY_COMPONENTS: [&str; 6] = [
    "nq",
    "host_posture",
    "nightshift",
    "docket",
    "ag",
    "service",
];
/// The rule anchors of the beta alert registry (page and warn), excluding the
/// retired `docket-not-ready` anchor.
const PAGERDUTY_RULES: [&str; 17] = [
    "nq-no-fresh-acquisition",
    "host-posture-unknown",
    "nightshift-recurrence-missing",
    "docket-unsettled",
    "ag-executor-unavailable",
    "service-down",
    "host-disk",
    "nq-latency-near-bound",
    "nq-open-cost-growing",
    "nq-pending-acquisition",
    "host-posture-refusals",
    "host-posture-retention",
    "nightshift-evidence-stale",
    "nightshift-cycle-slow",
    "docket-reconciliation-lag",
    "ag-repeated-refusals",
    "build-identity",
];
const V2_FIELDS: [&str; 5] = ["action", "condition", "severity", "runbook_url", "details"];
/// The closed response classes an evaluator assigns. Only `page` may reach an
/// interruption channel; NQ never derives the class from any other field.
const RESPONSE_CLASSES: [&str; 3] = ["informational", "attention", "page"];
/// The retained refusal for an intent on a `PagerDuty` route whose
/// `response_class` is not `page`, including a legacy v2 intent without one.
const RESPONSE_CLASS_NOT_PAGE: &str = "response_class_not_page";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Intent {
    pub(crate) schema: String,
    pub(crate) attention_kind: String,
    pub(crate) stable_event_id: String,
    pub(crate) attention_receipt_digest: Option<String>,
    pub(crate) attention_policy_id: String,
    pub(crate) attention_policy_digest: String,
    pub(crate) transition_id: String,
    pub(crate) route_reference: String,
    pub(crate) destination_identity: String,
    summary: String,
    inspection_reference: String,
    owner_receipt: Option<Value>,
    /// Absent in v1 means `attention`. Absent in v2 is a pre-0.2.2 legacy
    /// record: readable, never sent.
    response_class: Option<String>,
}

impl Intent {
    fn response_class(&self) -> &str {
        self.response_class.as_deref().unwrap_or("attention")
    }

    fn is_page(&self) -> bool {
        self.response_class.as_deref() == Some("page")
    }
}

/// The stable condition a `PagerDuty` alert is about. It deliberately excludes
/// event, evidence and time identities so that trigger, repeat and resolve of
/// the same condition share one derived dedup key.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Condition {
    site: String,
    component: String,
    rule: String,
    target_class: Option<String>,
}

/// The fields `nq.notification_delivery_intent.v2` adds to the v1 intent.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PagerDutyFields {
    action: String,
    condition: Condition,
    severity: String,
    runbook_url: Option<String>,
    details: Option<Value>,
}

/// Derive the `PagerDuty` dedup key. It is never supplied by the caller.
fn dedup_key(condition: &Condition) -> String {
    let mut key = format!(
        "constellation:{}:{}:{}",
        condition.site, condition.component, condition.rule
    );
    if let Some(target_class) = &condition.target_class {
        key.push(':');
        key.push_str(target_class);
    }
    key
}

/// Name the per-event identity a condition value appears to carry, if any.
fn per_event_identity(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    if lower.contains("sha256") {
        return Some("a digest");
    }
    let uuid = |window: &[u8]| {
        window.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    };
    if bytes.windows(36).any(uuid) {
        return Some("a UUID");
    }
    let date = |window: &[u8]| {
        window.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 4 | 7) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit()
            }
        })
    };
    if bytes.windows(10).any(date) {
        return Some("a date");
    }
    let mut hex_run = 0usize;
    let mut digit_run = 0usize;
    for byte in bytes {
        hex_run = if byte.is_ascii_hexdigit() {
            hex_run + 1
        } else {
            0
        };
        digit_run = if byte.is_ascii_digit() {
            digit_run + 1
        } else {
            0
        };
        if hex_run >= 32 {
            return Some("a hexadecimal identifier");
        }
        if digit_run >= 8 {
            return Some("a numeric timestamp or identifier");
        }
    }
    if bytes.iter().all(u8::is_ascii_digit) {
        return Some("a numeric identifier");
    }
    None
}

/// Submission applies the current closed registry and the per-event and
/// credential heuristics. Reopening retained history checks structure only, so
/// a later registry or heuristic change cannot make append-only custody
/// unreadable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Validation {
    Submission,
    Retained,
}

fn condition_token(label: &str, value: &str, maximum: usize, validation: Validation) -> Result<()> {
    if validation == Validation::Submission
        && let Some(kind) = per_event_identity(value)
    {
        bail!(
            "notification condition {label} is refused: it looks like {kind}; a condition names a stable class, not an event"
        );
    }
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > maximum
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        bail!("notification condition {label} must be 1..={maximum} characters of [a-z0-9._-]");
    }
    Ok(())
}

fn secret_like_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "routing_key",
        "token",
        "secret",
        "password",
        "api_key",
        "authorization",
        "credential",
    ]
    .iter()
    .any(|name| key.contains(name))
}

fn reject_secret_like_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if secret_like_key(key) {
                    bail!("notification details must not carry credential-like field {key:?}");
                }
                reject_secret_like_keys(nested)?;
            }
        }
        Value::Array(items) => {
            for nested in items {
                reject_secret_like_keys(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_pagerduty_fields(fields: &PagerDutyFields, validation: Validation) -> Result<()> {
    if !matches!(fields.action.as_str(), "trigger" | "resolve") {
        bail!("notification action must be trigger or resolve");
    }
    if !matches!(
        fields.severity.as_str(),
        "critical" | "error" | "warning" | "info"
    ) {
        bail!("notification severity must be critical, error, warning or info");
    }
    let condition = &fields.condition;
    condition_token("site", &condition.site, 64, validation)?;
    condition_token("component", &condition.component, 64, validation)?;
    condition_token("rule", &condition.rule, 64, validation)?;
    if validation == Validation::Submission
        && !PAGERDUTY_COMPONENTS.contains(&condition.component.as_str())
    {
        bail!("notification condition component is not in the closed component set");
    }
    if validation == Validation::Submission && !PAGERDUTY_RULES.contains(&condition.rule.as_str()) {
        bail!("notification condition rule is not a beta alert registry anchor");
    }
    if let Some(target_class) = &condition.target_class {
        condition_token("target_class", target_class, 48, validation)?;
    }
    if let Some(url) = &fields.runbook_url
        && (!url.starts_with("https://")
            || url.len() > 1024
            || url.chars().any(|c| c.is_control() || c.is_whitespace()))
    {
        bail!("notification runbook_url must be an https URL of at most 1024 bytes");
    }
    if let Some(details) = &fields.details {
        let Some(map) = details.as_object() else {
            bail!("notification details must be a JSON object");
        };
        if map.contains_key("constellation") {
            bail!("notification details must not use the reserved constellation key");
        }
        if CanonicalDocument::from_serializable(details)?
            .as_bytes()
            .len()
            > PAGERDUTY_DETAILS_MAX_BYTES
        {
            bail!("notification details exceed {PAGERDUTY_DETAILS_MAX_BYTES} bytes");
        }
        if validation == Validation::Submission {
            reject_secret_like_keys(details)?;
        }
    }
    Ok(())
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

fn read_intent(
    path: &std::path::Path,
) -> Result<(Intent, Option<PagerDutyFields>, CanonicalDocument)> {
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
    let (intent, pager) = parse_submitted(value)?;
    Ok((intent, pager, document))
}

fn parse_retained_intent(value: Value) -> Result<Intent> {
    parse_intent_value(value, Validation::Retained).map(|(intent, _)| intent)
}

fn parse_submitted(value: Value) -> Result<(Intent, Option<PagerDutyFields>)> {
    parse_intent_value(value, Validation::Submission)
}

fn parse_retained(value: Value) -> Result<(Intent, Option<PagerDutyFields>)> {
    parse_intent_value(value, Validation::Retained)
}

/// Parse a v1 intent, or a v2 intent as its v1 fields plus the `PagerDuty`
/// fields. Both keep closed field sets.
fn parse_intent_value(
    value: Value,
    validation: Validation,
) -> Result<(Intent, Option<PagerDutyFields>)> {
    match value.get("schema").and_then(Value::as_str) {
        Some(INTENT_V1) => Ok((parse_intent_fields(value, 512)?, None)),
        Some(INTENT_V2) => {
            let mut common = value
                .as_object()
                .context("notification intent is not an object")?
                .clone();
            let mut added = Map::new();
            for field in V2_FIELDS {
                if let Some(value) = common.remove(field) {
                    added.insert(field.to_owned(), value);
                }
            }
            let pager: PagerDutyFields = serde_json::from_value(Value::Object(added))?;
            validate_pagerduty_fields(&pager, validation)?;
            Ok((
                parse_intent_fields(Value::Object(common), 1024)?,
                Some(pager),
            ))
        }
        _ => bail!("unsupported notification intent schema"),
    }
}

fn parse_intent_fields(value: Value, summary_maximum: usize) -> Result<Intent> {
    let intent: Intent = serde_json::from_value(value)?;
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
        ("summary", intent.summary.as_str(), summary_maximum),
        (
            "inspection_reference",
            intent.inspection_reference.as_str(),
            1024,
        ),
    ] {
        bounded(name, value, maximum)?;
    }
    if let Some(class) = &intent.response_class
        && !RESPONSE_CLASSES.contains(&class.as_str())
    {
        bail!("notification response_class must be informational, attention or page");
    }
    match intent.attention_kind.as_str() {
        "operator_assertion"
            if intent.attention_receipt_digest.is_none() && intent.owner_receipt.is_none() => {}
        "nightshift_receipt"
            if intent.attention_receipt_digest.is_some() && intent.owner_receipt.is_some() => {}
        _ => bail!("unsupported or ambiguous notification attention kind"),
    }
    Ok(intent)
}

/// Reopen a retained intent without consulting a configured route or delivery target.
/// Local-inbox custody wraps the submitted intent with a directory binding; the
/// wrapper remains historical custody and is not replayed here.
pub(crate) fn reopen_retained_intent(document: &CanonicalDocument) -> Result<Intent> {
    let value: Value = serde_json::from_slice(document.as_bytes())
        .context("retained notification intent is not JSON")?;
    if value.get("schema").and_then(Value::as_str) == Some("nq.local-inbox-delivery-intent/v1") {
        let wrapper = value
            .as_object()
            .context("retained local inbox intent is not an object")?;
        if wrapper.len() != 3
            || !wrapper.contains_key("schema")
            || !wrapper.contains_key("intent")
            || !wrapper.contains_key("directory_binding")
        {
            bail!("retained local inbox intent has an unsupported wrapper shape");
        }
        let inner = value
            .get("intent")
            .cloned()
            .context("retained local inbox intent is missing submitted intent")?;
        let binding = value
            .get("directory_binding")
            .and_then(Value::as_object)
            .context("retained local inbox intent has no directory binding")?;
        if binding.len() != 5
            || binding.get("schema").and_then(Value::as_str)
                != Some("nq.local-inbox-directory-binding/v1")
            || binding
                .get("path_sha256")
                .and_then(Value::as_str)
                .and_then(|value| nq_protocol::Sha256Digest::parse(value.to_owned()).ok())
                .is_none()
            || binding.get("device").and_then(Value::as_u64).is_none()
            || binding.get("inode").and_then(Value::as_u64).is_none()
            || binding.get("mode").and_then(Value::as_u64).is_none()
        {
            bail!("retained local inbox directory binding is invalid");
        }
        return parse_retained_intent(inner);
    }
    parse_retained_intent(value)
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
        "[{}] Attention required: {}\nInspect: {}",
        intent.response_class(),
        intent.summary,
        intent.inspection_reference
    );
    let payload = match route.transport {
        NotificationTransportKind::Slack => json!({"text": text}),
        NotificationTransportKind::Discord => json!({"content": text}),
        NotificationTransportKind::LocalFile => {
            bail!("local inbox uses its own bounded message envelope")
        }
        NotificationTransportKind::PagerDuty => {
            bail!("pagerduty uses its own event envelope")
        }
    };
    Ok(CanonicalDocument::from_serializable(&payload)?)
}

/// Render the retained `PagerDuty` event. The routing key is never part of
/// these bytes; it is added only to the request body at dispatch.
fn render_pagerduty(
    intent: &Intent,
    pager: &PagerDutyFields,
    intent_document: &CanonicalDocument,
) -> Result<CanonicalDocument> {
    let key = dedup_key(&pager.condition);
    let event = if pager.action == "resolve" {
        json!({"event_action":"resolve","dedup_key":key})
    } else {
        let mut custom_details = match &pager.details {
            Some(Value::Object(details)) => details.clone(),
            _ => Map::new(),
        };
        custom_details.insert(
            "constellation".into(),
            json!({
                "schema":intent.schema,
                "stable_event_id":intent.stable_event_id,
                "transition_id":intent.transition_id,
                "intent_digest":intent_document.digest(),
                "inspection_reference":intent.inspection_reference,
            }),
        );
        let mut payload = json!({
            "summary":intent.summary,
            "source":pager.condition.site,
            "severity":pager.severity,
            "component":pager.condition.component,
            "group":pager.condition.rule,
            "custom_details":custom_details,
        });
        if let Some(target_class) = &pager.condition.target_class {
            payload["class"] = json!(target_class);
        }
        let mut event = json!({"event_action":"trigger","dedup_key":key,"payload":payload});
        if let Some(url) = &pager.runbook_url {
            event["links"] = json!([{"href":url,"text":"Runbook"}]);
        }
        event
    };
    Ok(CanonicalDocument::from_serializable(&event)?)
}

fn valid_routing_key(key: &str) -> bool {
    key.len() == 32 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Add the routing key to the request bytes only.
fn inject_routing_key(retained: &[u8], routing_key: &str) -> Result<Vec<u8>> {
    let mut event: Map<String, Value> =
        serde_json::from_slice(retained).context("retained PagerDuty event is not an object")?;
    event.insert("routing_key".into(), Value::String(routing_key.to_owned()));
    Ok(serde_json::to_vec(&event)?)
}

/// Bound destination text and mask the routing key or any key-shaped run.
fn redact_destination_text(text: &str, routing_key: &str) -> String {
    let replaced = if routing_key.is_empty() {
        text.to_owned()
    } else {
        text.replace(routing_key, "<redacted>")
    };
    let mut output = String::new();
    let mut run = String::new();
    let flush = |run: &mut String, output: &mut String| {
        if run.len() >= 32 {
            output.push_str("<redacted>");
        } else {
            output.push_str(run);
        }
        run.clear();
    };
    for character in replaced.chars().filter(|c| !c.is_control()) {
        if character.is_ascii_alphanumeric() {
            run.push(character);
        } else {
            flush(&mut run, &mut output);
            output.push(character);
        }
    }
    flush(&mut run, &mut output);
    output.chars().take(256).collect()
}

async fn read_bounded_body(mut response: reqwest::Response, maximum: usize) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len() + chunk.len() > maximum {
                    return None;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Some(body),
            Err(_) => return None,
        }
    }
}

fn reported(outcome: &'static str, detail: Value) -> TransportResult {
    TransportResult::Reported { outcome, detail }
}

/// One Events API v2 request. HTTP 202 with `status: success` is accepted;
/// 429/5xx and refused connections are retryable failures; other 4xx are
/// permanent failures; a timeout or loss after dispatch is unknown. Nothing
/// here retries.
async fn pagerduty_post(
    client: &reqwest::Client,
    url: &str,
    routing_key: &str,
    retained: &[u8],
    max_response_bytes: usize,
) -> Result<TransportResult> {
    let body = inject_routing_key(retained, routing_key)?;
    let response = match client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_connect() => {
            return Ok(reported(
                "failed",
                json!({"reason":"connect_failed","retry_class":"retryable"}),
            ));
        }
        Err(error) if error.is_timeout() => {
            return Ok(reported(
                "unknown",
                json!({"reason":"timeout_after_dispatch","retry_class":"resubmit_safe"}),
            ));
        }
        Err(_) => {
            return Ok(reported(
                "unknown",
                json!({"reason":"transport_error_or_response_loss","retry_class":"resubmit_safe"}),
            ));
        }
    };
    let status = response.status().as_u16();
    let parsed = read_bounded_body(response, max_response_bytes)
        .await
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let mut detail = Map::new();
    detail.insert("http_status".into(), json!(status));
    let pagerduty_status = parsed
        .as_ref()
        .and_then(|body| body.get("status"))
        .and_then(Value::as_str);
    if let Some(body) = &parsed {
        if let Some(text) = pagerduty_status {
            detail.insert(
                "pagerduty_status".into(),
                json!(redact_destination_text(text, routing_key)),
            );
        }
        if let Some(message) = body.get("message").and_then(Value::as_str) {
            detail.insert(
                "pagerduty_message".into(),
                json!(redact_destination_text(message, routing_key)),
            );
        }
        if let Some(errors) = body.get("errors").and_then(Value::as_array) {
            let errors: Vec<String> = errors
                .iter()
                .filter_map(Value::as_str)
                .take(5)
                .map(|error| redact_destination_text(error, routing_key))
                .collect();
            detail.insert("pagerduty_errors".into(), json!(errors));
        }
    } else {
        detail.insert("response_body".into(), json!("unparsed_or_over_limit"));
    }
    let (outcome, reason, retry_class) = match status {
        202 if pagerduty_status == Some("success") => ("accepted", None, None),
        200..=299 => (
            "unknown",
            Some("success_not_confirmed"),
            Some("resubmit_safe"),
        ),
        429 => ("failed", Some("rate_limited"), Some("retryable")),
        500..=599 => ("failed", Some("server_error"), Some("retryable")),
        400..=499 => ("failed", Some("rejected"), Some("permanent")),
        _ => ("failed", Some("unexpected_status"), Some("permanent")),
    };
    if let Some(reason) = reason {
        detail.insert("reason".into(), json!(reason));
    }
    if let Some(retry_class) = retry_class {
        detail.insert("retry_class".into(), json!(retry_class));
    }
    Ok(reported(outcome, Value::Object(detail)))
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
        "summary":format!("[{}] {}", intent.response_class(), intent.summary),
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
    let (intent, pager, intent_document) = read_intent(intent_path)?;
    if pager.is_some() {
        bail!("nq.notification_delivery_intent.v2 is accepted only by pagerduty routes");
    }
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

#[derive(Clone, Debug, PartialEq, Eq)]
enum TransportResult {
    Accepted(u16),
    Failed(u16),
    Unknown,
    /// A transport that classifies its own bounded, secret-free result.
    Reported {
        outcome: &'static str,
        detail: Value,
    },
}

fn retain_refusal(
    store: &mut Store,
    notification_id: &str,
    at: String,
    reason: &str,
) -> Result<Value> {
    store.append_notification_delivery_event(&NotificationDeliveryEventInput {
        notification_id: notification_id.to_owned(),
        event_number: 1,
        occurred_at: at,
        outcome: "refused".into(),
        detail: CanonicalDocument::from_serializable(&json!({"reason":reason}))?,
    })?;
    Ok(json!({"notification_id": notification_id, "delivery_state":"refused"}))
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
    let (intent, pager, intent_document) = read_intent(intent_path)?;
    submit_parsed_with_dispatch(
        config,
        intent,
        pager,
        intent_document,
        route_ref,
        enable_network,
        resolve_endpoint,
        prepare_dispatch,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    reason = "One custody path shared by file submission and resubmission"
)]
async fn submit_parsed_with_dispatch<R, P, F, Fut>(
    config: &NqConfig,
    intent: Intent,
    pager: Option<PagerDutyFields>,
    intent_document: CanonicalDocument,
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
    let key = pager.as_ref().map(|pager| dedup_key(&pager.condition));
    let mut result = submit_custody(
        config,
        intent,
        pager.as_ref(),
        intent_document,
        route_ref,
        enable_network,
        resolve_endpoint,
        prepare_dispatch,
    )
    .await?;
    if let Some(key) = key {
        result["dedup_key"] = json!(key);
    }
    Ok(result)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "Keep the ordered custody, refusal and dispatch boundary in one place"
)]
async fn submit_custody<R, P, F, Fut>(
    config: &NqConfig,
    intent: Intent,
    pager: Option<&PagerDutyFields>,
    intent_document: CanonicalDocument,
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
    let pagerduty = route.transport == NotificationTransportKind::PagerDuty;
    if pagerduty != pager.is_some() {
        bail!(
            "pagerduty routes accept only nq.notification_delivery_intent.v2, which other routes refuse"
        );
    }
    if let Some(existing) = retained_duplicate(config, route, &intent, &intent_document)? {
        return Ok(existing);
    }
    // Page eligibility is the evaluator's explicit decision. It is not
    // inferred from action, severity or condition, and a resolve is page-class.
    // A non-page intent is refused whatever its owner receipt would replay to,
    // so replay runs only for intents that could be sent.
    let not_page = pagerduty && !intent.is_page();
    if !not_page {
        replay_nightshift(route, &intent)?;
    }
    let owner_receipt = intent.owner_receipt.clone();
    let payload = match pager {
        Some(pager) => render_pagerduty(&intent, pager, &intent_document)?,
        None => render(route, &intent)?,
    };
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
            NotificationTransportKind::PagerDuty => "pagerduty".into(),
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
    if not_page {
        return retain_refusal(&mut store, &notification_id, now, RESPONSE_CLASS_NOT_PAGE);
    }
    if refuse_expired_saved_check(&mut store, &notification_id, owner_receipt.as_ref())? {
        return Ok(json!({"notification_id":notification_id,"delivery_state":"refused"}));
    }
    if !enable_network {
        return retain_refusal(
            &mut store,
            &notification_id,
            now,
            "network_dispatch_not_explicitly_enabled",
        );
    }
    let locator = if pagerduty {
        route
            .routing_key_env
            .as_deref()
            .context("pagerduty route has no routing key locator")?
    } else {
        route
            .endpoint_secret_locator
            .as_deref()
            .context("HTTPS route has no endpoint secret locator")?
    };
    // The resolved value is a secret: it is never retained, digested, printed
    // or included in an error; only a fixed reason is kept.
    let secret = match resolve_endpoint(locator) {
        Ok(secret) if !pagerduty || valid_routing_key(&secret) => secret,
        Ok(_) => {
            return retain_refusal(&mut store, &notification_id, now, "routing_key_malformed");
        }
        Err(_) => {
            let reason = if pagerduty {
                "routing_key_unavailable"
            } else {
                "endpoint_resolution_unavailable"
            };
            return retain_refusal(&mut store, &notification_id, now, reason);
        }
    };
    let Ok(dispatch) = prepare_dispatch(route.timeout_ms) else {
        return retain_refusal(
            &mut store,
            &notification_id,
            now,
            "transport_client_unavailable",
        );
    };
    store.append_notification_delivery_event(&NotificationDeliveryEventInput {
        notification_id: notification_id.clone(),
        event_number: 1,
        occurred_at: now.clone(),
        outcome: "claimed".into(),
        detail: CanonicalDocument::from_serializable(&json!({
            "route_reference":route.reference,
            "transport": if pagerduty { "pagerduty" } else { "https" }
        }))?,
    })?;
    let (outcome, detail) =
        match dispatch(secret, payload.as_bytes().to_vec(), route.timeout_ms).await? {
            TransportResult::Accepted(status) => ("accepted", json!({"http_status":status})),
            TransportResult::Failed(status) => ("failed", json!({"http_status":status})),
            TransportResult::Unknown => (
                "unknown",
                json!({"reason":"transport_error_or_response_loss"}),
            ),
            TransportResult::Reported { outcome, detail } => (outcome, detail),
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
    let (intent, pager, document) = read_intent(intent_path)?;
    submit_parsed(config, intent, pager, document, route_ref, enable_network).await
}

async fn submit_parsed(
    config: &NqConfig,
    intent: Intent,
    pager: Option<PagerDutyFields>,
    document: CanonicalDocument,
    route_ref: &str,
    enable_network: bool,
) -> Result<Value> {
    let route = config
        .notification_routes
        .iter()
        .find(|route| route.reference == route_ref);
    let pagerduty =
        route.is_some_and(|route| route.transport == NotificationTransportKind::PagerDuty);
    let max_response_bytes = route.map_or(1, |route| route.max_response_bytes);
    submit_parsed_with_dispatch(
        config,
        intent,
        pager,
        document,
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
            Ok(move |endpoint: String, body: Vec<u8>, _| async move {
                if pagerduty {
                    return pagerduty_post(
                        &client,
                        PAGERDUTY_ENQUEUE_URL,
                        &endpoint,
                        &body,
                        max_response_bytes,
                    )
                    .await;
                }
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

/// Re-derive a v2 intent from a retained, not-accepted record with a new
/// event identity. The condition, and therefore the dedup key, is unchanged.
fn prepare_resubmission(
    config: &NqConfig,
    notification_id: &str,
    stable_event_id: &str,
) -> Result<(Intent, Option<PagerDutyFields>, CanonicalDocument)> {
    bounded("stable_event_id", stable_event_id, 256)?;
    let store = Store::open_read_only(&config.database_path)?;
    let retained = store
        .notification_delivery_intent_by_id(notification_id)?
        .context("notification is not retained")?;
    let status = store
        .notification_delivery_status(Some(notification_id))?
        .pop()
        .context("retained notification custody is incomplete")?;
    let mut value: Value = serde_json::from_slice(retained.as_bytes())?;
    if value.get("schema").and_then(Value::as_str) != Some(INTENT_V2) {
        bail!(
            "resubmit is defined only for nq.notification_delivery_intent.v2 (pagerduty) records"
        );
    }
    if status.delivery_state == "accepted" {
        bail!("notification was accepted by its destination; resubmit is refused");
    }
    // Only the newest record for a condition may be resent: an older trigger
    // would reopen a resolved alert, and an older resolve would close a newer one.
    if let Some(newer) = store.notification_delivery_newer_same_condition(notification_id)? {
        bail!(
            "notification {newer} is a later record for the same condition on this route; only the newest record for a condition may be resubmitted"
        );
    }
    if value.get("stable_event_id").and_then(Value::as_str) == Some(stable_event_id) {
        bail!("resubmit requires a new stable_event_id");
    }
    value["stable_event_id"] = json!(stable_event_id);
    let document = CanonicalDocument::from_serializable(&value)?;
    if document.as_bytes().len() > MAX_INTENT_BYTES {
        bail!("notification intent exceeds {MAX_INTENT_BYTES} bytes");
    }
    let (intent, pager) = parse_submitted(value)?;
    Ok((intent, pager, document))
}

/// Submit a new record for the same `PagerDuty` condition. The original record
/// keeps its retained outcome; `PagerDuty` deduplicates on the shared key.
pub(crate) async fn resubmit(
    config: &NqConfig,
    notification_id: &str,
    stable_event_id: &str,
    enable_network: bool,
) -> Result<Value> {
    let (intent, pager, document) = prepare_resubmission(config, notification_id, stable_event_id)?;
    let route = intent.route_reference.clone();
    let mut result = submit_parsed(config, intent, pager, document, &route, enable_network).await?;
    result["resubmitted_from"] = json!(notification_id);
    Ok(result)
}

pub(crate) fn inspect(config: &NqConfig, id: Option<&str>) -> Result<Value> {
    let store = Store::open_read_only(&config.database_path)?;
    let statuses = store.notification_delivery_status(id)?;
    let mut value = serde_json::to_value(&statuses)?;
    for (index, status) in statuses.iter().enumerate() {
        let Some(retained) = store.notification_delivery_intent_by_id(&status.notification_id)?
        else {
            continue;
        };
        let intent: Value = serde_json::from_slice(retained.as_bytes())?;
        if intent.get("schema").and_then(Value::as_str) != Some(INTENT_V2) {
            continue;
        }
        let (intent, Some(pager)) = parse_retained(intent)? else {
            continue;
        };
        let last_event = store
            .notification_delivery_events_bounded(
                &status.notification_id,
                nq_store::MAX_PUBLIC_QUERY_ROWS,
                None,
            )?
            .pop()
            .map(|event| -> Result<Value> {
                Ok(json!({
                    "event_number":event.event_number,
                    "outcome":event.outcome,
                    "occurred_at":event.occurred_at,
                    "detail":serde_json::from_slice::<Value>(&event.detail_json)?,
                }))
            })
            .transpose()?;
        value[index]["pagerduty"] = json!({
            "action":pager.action,
            "response_class":intent.response_class,
            "dedup_key":dedup_key(&pager.condition),
            "last_event":last_event,
        });
    }
    Ok(value)
}

/// A retained v2 intent that current submission validation would refuse (a
/// retired rule anchor and a credential-like details key), for history tests.
#[cfg(test)]
pub(crate) fn historical_pagerduty_intent(route: &str, stable_event_id: &str) -> Value {
    json!({
        "schema":INTENT_V2,
        "attention_kind":"operator_assertion",
        "stable_event_id":stable_event_id,
        "attention_policy_id":"policy-1",
        "attention_policy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "transition_id":"transition-1",
        "route_reference":route,
        "destination_identity":format!("pagerduty:{route}"),
        "summary":"historical condition",
        "inspection_reference":"record:1",
        "action":"trigger",
        "condition":{"site":"crow-lab","component":"docket","rule":"docket-not-ready","target_class":"batch-20261002"},
        "severity":"critical",
        "details":{"api_token_name":"historical"},
    })
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
            routing_key_env: None,
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
            retention: Default::default(),
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
            retention: Default::default(),
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
                routing_key_env: None,
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
            response_class: None,
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
            json!({"text":"[attention] Attention required: check storage\nInspect: record:1"})
        );
        assert_eq!(
            discord,
            json!({"content":"[attention] Attention required: check storage\nInspect: record:1"})
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
        assert_eq!(message["summary"], "[attention] check storage");
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

    // PagerDuty Events API v2 sink.

    const ROUTING_KEY: &str = "0123456789abcdef0123456789abcdef";

    fn pagerduty_route() -> NotificationRouteConfig {
        NotificationRouteConfig {
            reference: "pd.ops".into(),
            transport: NotificationTransportKind::PagerDuty,
            endpoint_secret_locator: None,
            routing_key_env: Some("NQ_PD_OPS_ROUTING_KEY".into()),
            local_inbox_directory: None,
            timeout_ms: 2_000,
            max_response_bytes: 1024,
            nightshift_attention_replay: None,
        }
    }

    fn pagerduty_config(root: &TempDir) -> NqConfig {
        let mut config = config(root);
        config.notification_routes.push(pagerduty_route());
        config
    }

    fn pagerduty_intent(action: &str, stable_event_id: &str, summary: &str) -> Value {
        json!({
            "schema":"nq.notification_delivery_intent.v2",
            "attention_kind":"operator_assertion",
            "stable_event_id":stable_event_id,
            "attention_policy_id":"policy-1",
            "attention_policy_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "transition_id":"transition-1",
            "route_reference":"pd.ops",
            "destination_identity":"pagerduty:pd.ops",
            "summary":summary,
            "inspection_reference":"record:1",
            "action":action,
            "condition":{"site":"crow-lab","component":"nq","rule":"nq-no-fresh-acquisition","target_class":"demo"},
            "response_class":"page",
            "severity":"critical",
            "runbook_url":"https://runbooks.example/beta#nq-no-fresh-acquisition",
            "details":{"newest_artifact_age_seconds":900},
        })
    }

    const DEDUP: &str = "constellation:crow-lab:nq:nq-no-fresh-acquisition:demo";

    #[allow(
        clippy::unnecessary_wraps,
        reason = "Matches the secret resolver signature"
    )]
    fn routing_key(_: &str) -> Result<String> {
        Ok(ROUTING_KEY.into())
    }

    /// Every retained byte (database and WAL), inspection and status export.
    fn assert_routing_key_absent(config: &NqConfig) {
        let mut retained = Vec::new();
        for suffix in ["", "-wal", "-journal"] {
            let mut path = config.database_path.clone().into_os_string();
            path.push(suffix);
            if let Ok(bytes) = fs::read(&path) {
                retained.extend(bytes);
            }
        }
        assert!(!retained.is_empty());
        let key = ROUTING_KEY.as_bytes();
        assert!(
            !retained.windows(key.len()).any(|window| window == key),
            "routing key reached retained database bytes"
        );
        assert!(
            !retained
                .windows(b"routing_key\"".len())
                .any(|window| window == b"routing_key\""),
            "a routing_key field reached retained bytes"
        );
        assert!(
            !inspect(config, None)
                .unwrap()
                .to_string()
                .contains(ROUTING_KEY)
        );
        let store = Store::open_read_only(&config.database_path).unwrap();
        let status = nq_core::engine::status_snapshot_v3(&store).unwrap();
        assert!(
            !serde_json::to_string(&status)
                .unwrap()
                .contains(ROUTING_KEY)
        );
    }

    /// Serve exactly one HTTP response on loopback and return the request bytes.
    fn serve_once(
        status_line: &'static str,
        body: String,
    ) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v2/enqueue", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "request ended before headers");
                request.extend_from_slice(&buffer[..read]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
            let length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map_or(0, |value| value.trim().parse().unwrap());
            while request.len() < header_end + length {
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0, "request ended before body");
                request.extend_from_slice(&buffer[..read]);
            }
            let response = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        (url, handle)
    }

    fn loopback_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn request_body(request: &[u8]) -> Value {
        let end = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        serde_json::from_slice(&request[end..]).unwrap()
    }

    #[test]
    fn pagerduty_dedup_key_derivation_vectors() {
        let condition = |site: &str, component: &str, rule: &str, target: Option<&str>| Condition {
            site: site.into(),
            component: component.into(),
            rule: rule.into(),
            target_class: target.map(Into::into),
        };
        for (value, expected) in [
            (
                condition("crow-lab", "nq", "nq-no-fresh-acquisition", Some("demo")),
                "constellation:crow-lab:nq:nq-no-fresh-acquisition:demo",
            ),
            (
                condition(
                    "labelwatch-host",
                    "host_posture",
                    "host-posture-unknown",
                    None,
                ),
                "constellation:labelwatch-host:host_posture:host-posture-unknown",
            ),
            (
                condition("site.a_1", "service", "service-down", Some("nqd.service")),
                "constellation:site.a_1:service:service-down:nqd.service",
            ),
        ] {
            assert_eq!(dedup_key(&value), expected);
        }
    }

    #[test]
    fn v2_intent_refuses_hostile_or_open_condition_values() {
        let hostile = [
            ("site", json!("sha256:aaaa")),
            ("site", json!("host-0123456789abcdef0123456789abcdef")),
            ("site", json!("123e4567-e89b-12d3-a456-426614174000")),
            ("site", json!("1727900000")),
            ("site", json!("4242")),
            ("target_class", json!("run-2026-10-02")),
            ("target_class", json!("batch-20261002")),
            ("target_class", json!("x0123456789ABCDEF0123456789abcdef0")),
        ];
        for (field, value) in hostile {
            let mut intent = pagerduty_intent("trigger", "event-1", "inspect");
            intent["condition"][field] = value.clone();
            let error = parse_submitted(intent).unwrap_err().to_string();
            assert!(error.contains("is refused"), "{field}={value}: {error}");
        }
        let invalid = [
            ("/condition/target_class", json!("a".repeat(49))),
            ("/condition/target_class", json!("Demo")),
            ("/condition/site", json!("crow lab")),
            ("/condition/component", json!("kernel")),
            ("/condition/rule", json!("docket-not-ready")),
            ("/condition/rule", json!("made-up-rule")),
            ("/action", json!("acknowledge")),
            ("/severity", json!("page")),
            ("/runbook_url", json!("http://runbooks.example/x")),
            ("/details", json!(["not", "an", "object"])),
            ("/details", json!({"constellation":"reserved"})),
            ("/details", json!({"nested":{"PagerDuty_Routing_Key":"x"}})),
            ("/details", json!({"blob":"x".repeat(4100)})),
            ("/summary", json!("s".repeat(1025))),
        ];
        for (pointer, value) in invalid {
            let mut intent = pagerduty_intent("trigger", "event-1", "inspect");
            *intent.pointer_mut(pointer).unwrap() = value;
            assert!(parse_submitted(intent).is_err(), "{pointer}");
        }
        let mut extra = pagerduty_intent("trigger", "event-1", "inspect");
        extra["condition"]["instance"] = json!("x");
        assert!(parse_submitted(extra).is_err());
        let mut extra = pagerduty_intent("trigger", "event-1", "inspect");
        extra["dedup_key"] = json!("caller-supplied");
        assert!(parse_submitted(extra).is_err());
        let mut v1_with_action = intent("check storage", "operator_assertion", None);
        v1_with_action["action"] = json!("trigger");
        assert!(parse_submitted(v1_with_action).is_err());
        let mut long_summary = pagerduty_intent("trigger", "event-1", &"s".repeat(1024));
        assert!(parse_submitted(long_summary.clone()).is_ok());
        long_summary["schema"] = json!("nq.notification_delivery_intent.v1");
        assert!(parse_submitted(long_summary).is_err());
        assert!(parse_submitted(pagerduty_intent("resolve", "event-1", "inspect")).is_ok());
    }

    #[tokio::test]
    async fn hostile_condition_is_refused_before_custody_or_dispatch() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let mut value = pagerduty_intent("trigger", "event-1", "inspect");
        value["condition"]["target_class"] = json!("123e4567-e89b-12d3-a456-426614174000");
        let path = write_intent(&root, value);
        let error = submit_with_dispatch(
            &config,
            &path,
            "pd.ops",
            true,
            |_| panic!("no secret resolution for a refused intent"),
            |_| Ok(|_, _, _| async { panic!("no dispatch for a refused intent") }),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("looks like a UUID"));
        assert_eq!(inspect(&config, None).unwrap(), json!([]));
    }

    #[test]
    fn pagerduty_trigger_and_resolve_render_without_routing_key() {
        let trigger = pagerduty_intent("trigger", "event-1", "no fresh NQ acquisition");
        let document = CanonicalDocument::from_serializable(&trigger).unwrap();
        let (intent, pager) = parse_submitted(trigger).unwrap();
        let rendered = render_pagerduty(&intent, pager.as_ref().unwrap(), &document).unwrap();
        let expected = format!(
            concat!(
                r#"{{"dedup_key":"constellation:crow-lab:nq:nq-no-fresh-acquisition:demo","event_action":"trigger","#,
                r#""links":[{{"href":"https://runbooks.example/beta#nq-no-fresh-acquisition","text":"Runbook"}}],"#,
                r#""payload":{{"class":"demo","component":"nq","custom_details":{{"constellation":{{"inspection_reference":"record:1","intent_digest":"{}","#,
                r#""schema":"nq.notification_delivery_intent.v2","stable_event_id":"event-1","transition_id":"transition-1"}},"#,
                r#""newest_artifact_age_seconds":900}},"group":"nq-no-fresh-acquisition","severity":"critical","#,
                r#""source":"crow-lab","summary":"no fresh NQ acquisition"}}}}"#
            ),
            document.digest()
        );
        assert_eq!(
            String::from_utf8(rendered.as_bytes().to_vec()).unwrap(),
            expected
        );

        let resolve = pagerduty_intent("resolve", "event-2", "condition cleared");
        let document = CanonicalDocument::from_serializable(&resolve).unwrap();
        let (intent, pager) = parse_submitted(resolve).unwrap();
        let rendered = render_pagerduty(&intent, pager.as_ref().unwrap(), &document).unwrap();
        assert_eq!(
            rendered.as_bytes(),
            br#"{"dedup_key":"constellation:crow-lab:nq:nq-no-fresh-acquisition:demo","event_action":"resolve"}"#
        );

        let request: Value =
            serde_json::from_slice(&inject_routing_key(rendered.as_bytes(), ROUTING_KEY).unwrap())
                .unwrap();
        assert_eq!(
            request,
            json!({"routing_key":ROUTING_KEY,"event_action":"resolve","dedup_key":DEDUP})
        );
    }

    #[tokio::test]
    async fn pagerduty_http_outcomes_are_classified_from_a_loopback_server() {
        let cases = [
            (
                "202 Accepted",
                json!({"status":"success","message":"Event processed","dedup_key":DEDUP}),
                "accepted",
                None,
                None,
            ),
            (
                "202 Accepted",
                json!({"status":"queued"}),
                "unknown",
                Some("success_not_confirmed"),
                Some("resubmit_safe"),
            ),
            (
                "429 Too Many Requests",
                json!({"status":"throttle event","message":"Requests for this service are arriving too quickly"}),
                "failed",
                Some("rate_limited"),
                Some("retryable"),
            ),
            (
                "500 Internal Server Error",
                json!({}),
                "failed",
                Some("server_error"),
                Some("retryable"),
            ),
            (
                "400 Bad Request",
                json!({"status":"invalid event","message":"Event object is invalid","errors":[format!("routing_key {ROUTING_KEY} is incorrect")]}),
                "failed",
                Some("rejected"),
                Some("permanent"),
            ),
        ];
        let client = loopback_client();
        for (status_line, body, outcome, reason, retry_class) in cases {
            let (url, server) = serve_once(status_line, body.to_string());
            let retained = br#"{"dedup_key":"constellation:crow-lab:nq:nq-no-fresh-acquisition:demo","event_action":"resolve"}"#;
            let result = pagerduty_post(&client, &url, ROUTING_KEY, retained, 1024)
                .await
                .unwrap();
            let request = server.join().unwrap();
            assert_eq!(
                request_body(&request),
                json!({"routing_key":ROUTING_KEY,"event_action":"resolve","dedup_key":DEDUP})
            );
            let TransportResult::Reported {
                outcome: actual,
                detail,
            } = result
            else {
                panic!("pagerduty reports its own classification")
            };
            assert_eq!(actual, outcome, "{status_line}");
            assert_eq!(detail.get("reason").and_then(Value::as_str), reason);
            assert_eq!(
                detail.get("retry_class").and_then(Value::as_str),
                retry_class
            );
            assert!(detail["http_status"].is_u64());
            assert!(!detail.to_string().contains(ROUTING_KEY), "{detail}");
            if status_line.starts_with("400") {
                assert_eq!(detail["pagerduty_message"], "Event object is invalid");
                assert_eq!(
                    detail["pagerduty_errors"],
                    json!(["routing_key <redacted> is incorrect"])
                );
            }
        }

        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v2/enqueue", closed.local_addr().unwrap());
        drop(closed);
        assert_eq!(
            pagerduty_post(&client, &url, ROUTING_KEY, b"{}", 1024)
                .await
                .unwrap(),
            reported(
                "failed",
                json!({"reason":"connect_failed","retry_class":"retryable"})
            )
        );
    }

    #[tokio::test]
    async fn pagerduty_submission_injects_the_routing_key_only_into_request_bytes() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let path = write_intent(
            &root,
            pagerduty_intent("trigger", "event-1", "no fresh acquisition"),
        );
        let (url, server) = serve_once(
            "202 Accepted",
            json!({"status":"success","message":"Event processed","dedup_key":DEDUP}).to_string(),
        );
        let result = submit_with_dispatch(
            &config,
            &path,
            "pd.ops",
            true,
            |locator| {
                assert_eq!(locator, "NQ_PD_OPS_ROUTING_KEY");
                Ok(ROUTING_KEY.into())
            },
            |timeout| {
                assert_eq!(timeout, 2_000);
                let client = loopback_client();
                Ok(move |key: String, body: Vec<u8>, _| async move {
                    pagerduty_post(&client, &url, &key, &body, 1024).await
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(result["delivery_state"], "accepted");
        assert_eq!(result["dedup_key"], DEDUP);
        let request = request_body(&server.join().unwrap());
        assert_eq!(request["routing_key"], ROUTING_KEY);
        assert_eq!(request["dedup_key"], DEDUP);
        assert_eq!(request["payload"]["source"], "crow-lab");

        let id = result["notification_id"].as_str().unwrap();
        let status = inspect(&config, Some(id)).unwrap();
        assert_eq!(status[0]["delivery_state"], "accepted");
        assert_eq!(status[0]["pagerduty"]["dedup_key"], DEDUP);
        assert_eq!(status[0]["pagerduty"]["action"], "trigger");
        assert_eq!(
            status[0]["pagerduty"]["last_event"]["detail"]["http_status"],
            202
        );
        let payload: Vec<u8> = Connection::open(&config.database_path)
            .unwrap()
            .query_row(
                "SELECT payload_json FROM notification_outbox WHERE notification_id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["dedup_key"], DEDUP);
        assert!(payload.get("routing_key").is_none());
        let mut expected_request = payload;
        expected_request["routing_key"] = json!(ROUTING_KEY);
        assert_eq!(request, expected_request);
        assert_routing_key_absent(&config);
    }

    #[tokio::test]
    async fn malformed_or_missing_routing_key_is_a_secret_free_retained_refusal() {
        let malformed = &ROUTING_KEY[..31];
        for (resolved, reason) in [
            (Some(malformed), "routing_key_malformed"),
            (
                Some("0123456789abcdef0123456789abcdeg"),
                "routing_key_malformed",
            ),
            (None, "routing_key_unavailable"),
        ] {
            let root = TempDir::new().unwrap();
            let config = pagerduty_config(&root);
            let path = write_intent(&root, pagerduty_intent("trigger", "event-1", "inspect"));
            let result = submit_with_dispatch(
                &config,
                &path,
                "pd.ops",
                true,
                |_| match resolved {
                    Some(value) => Ok(value.to_owned()),
                    None => bail!("locator {ROUTING_KEY} unavailable"),
                },
                |_| Ok(|_, _, _| async { panic!("no dispatch after a refused key") }),
            )
            .await
            .unwrap();
            assert_eq!(result["delivery_state"], "refused");
            let status = inspect(&config, result["notification_id"].as_str()).unwrap();
            assert_eq!(
                status[0]["pagerduty"]["last_event"]["detail"]["reason"],
                reason
            );
            assert!(!status.to_string().contains(malformed));
            assert_routing_key_absent(&config);
        }
    }

    #[tokio::test]
    async fn v2_and_pagerduty_routes_are_mutually_exclusive_and_slack_is_unchanged() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let mut v2_on_slack = pagerduty_intent("trigger", "event-1", "inspect");
        v2_on_slack["route_reference"] = json!("ops.primary");
        let path = write_intent(&root, v2_on_slack);
        let error = submit_with_dispatch(&config, &path, "ops.primary", false, endpoint, |_| {
            Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("pagerduty routes accept only"));
        let mut v1_on_pagerduty = intent("check storage", "operator_assertion", None);
        v1_on_pagerduty["route_reference"] = json!("pd.ops");
        let path = write_intent(&root, v1_on_pagerduty);
        assert!(
            submit_with_dispatch(&config, &path, "pd.ops", false, routing_key, |_| {
                Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
            })
            .await
            .is_err()
        );
        assert_eq!(inspect(&config, None).unwrap(), json!([]));
    }

    #[tokio::test]
    async fn duplicate_pagerduty_intent_converges_without_a_second_send() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let path = write_intent(&root, pagerduty_intent("trigger", "event-1", "inspect"));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut results = Vec::new();
        for _ in 0..2 {
            let calls = Arc::clone(&calls);
            results.push(
                submit_with_dispatch(&config, &path, "pd.ops", true, routing_key, |_| {
                    Ok(move |_, _, _| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        async { Ok(reported("failed", json!({"reason":"server_error"}))) }
                    })
                })
                .await
                .unwrap(),
            );
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[0]["dedup_key"], DEDUP);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        write_intent(&root, pagerduty_intent("trigger", "event-1", "changed"));
        assert!(
            submit_with_dispatch(&config, &path, "pd.ops", true, routing_key, |_| {
                Ok(|_, _, _| async { panic!("changed material must not dispatch") })
            })
            .await
            .unwrap_err()
            .to_string()
            .contains("different canonical intent")
        );
    }

    #[tokio::test]
    async fn repeat_trigger_and_resolve_share_one_dedup_key_across_new_records() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let mut ids = BTreeMap::new();
        for (action, event, summary) in [
            ("trigger", "event-1", "no fresh acquisition"),
            ("trigger", "event-2", "no fresh acquisition"),
            ("trigger", "event-3", "no fresh acquisition for 20 minutes"),
            ("resolve", "event-4", "acquisition resumed"),
        ] {
            let path = write_intent(&root, pagerduty_intent(action, event, summary));
            let sent = Arc::clone(&sent);
            let result = submit_with_dispatch(&config, &path, "pd.ops", true, routing_key, |_| {
                Ok(move |key: String, body: Vec<u8>, _| {
                    let request = inject_routing_key(&body, &key).unwrap();
                    sent.lock()
                        .unwrap()
                        .push(serde_json::from_slice(&request).unwrap());
                    async { Ok(reported("accepted", json!({"http_status":202}))) }
                })
            })
            .await
            .unwrap();
            assert_eq!(result["dedup_key"], DEDUP);
            ids.insert(
                result["notification_id"].as_str().unwrap().to_owned(),
                event,
            );
        }
        assert_eq!(ids.len(), 4, "each event identity is a new record");
        let sent = sent.lock().unwrap();
        assert!(sent.iter().all(|request| request["dedup_key"] == DEDUP));
        assert_eq!(
            sent[2]["payload"]["summary"],
            "no fresh acquisition for 20 minutes"
        );
        assert_eq!(
            sent[3],
            json!({"routing_key":ROUTING_KEY,"event_action":"resolve","dedup_key":DEDUP})
        );
        assert_routing_key_absent(&config);
    }

    #[tokio::test]
    async fn claimed_without_terminal_stays_unknown_and_resubmit_sends_the_same_condition() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let path = write_intent(&root, pagerduty_intent("trigger", "event-1", "inspect"));
        // A dispatch that never returns a terminal result models a crash
        // after the claim was committed.
        assert!(
            submit_with_dispatch(&config, &path, "pd.ops", true, routing_key, |_| {
                Ok(|_, _, _| async { bail!("process ended after claim") })
            })
            .await
            .is_err()
        );
        let original = inspect(&config, None).unwrap()[0].clone();
        let original_id = original["notification_id"].as_str().unwrap().to_owned();
        assert_eq!(original["delivery_state"], "unknown");
        assert_eq!(original["event_count"], 1);

        // The exact duplicate converges on the unknown record without a send.
        let duplicate = submit_with_dispatch(&config, &path, "pd.ops", true, routing_key, |_| {
            Ok(|_, _, _| async { panic!("duplicate must not send") })
        })
        .await
        .unwrap();
        assert_eq!(duplicate["delivery_state"], "unknown");

        assert!(prepare_resubmission(&config, &original_id, "event-1").is_err());
        let (resubmission, pager, document) =
            prepare_resubmission(&config, &original_id, "event-1-resubmit-1").unwrap();
        let sent = Arc::new(std::sync::Mutex::new(None::<Value>));
        let captured = Arc::clone(&sent);
        let resubmitted = submit_parsed_with_dispatch(
            &config,
            resubmission,
            pager,
            document,
            "pd.ops",
            true,
            routing_key,
            |_| {
                Ok(move |_key: String, body: Vec<u8>, _| {
                    *captured.lock().unwrap() = Some(serde_json::from_slice(&body).unwrap());
                    async { Ok(reported("accepted", json!({"http_status":202}))) }
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(resubmitted["delivery_state"], "accepted");
        assert_eq!(resubmitted["dedup_key"], DEDUP);
        assert_ne!(resubmitted["notification_id"], original["notification_id"]);
        let body = sent.lock().unwrap().clone().unwrap();
        assert_eq!(body["dedup_key"], DEDUP);
        assert_eq!(
            body["payload"]["custom_details"]["constellation"]["stable_event_id"],
            "event-1-resubmit-1"
        );
        let after = inspect(&config, Some(&original_id)).unwrap();
        assert_eq!(after[0]["delivery_state"], "unknown");
        assert_eq!(after[0]["event_count"], 1);

        let accepted_id = resubmitted["notification_id"].as_str().unwrap();
        assert!(
            prepare_resubmission(&config, accepted_id, "event-1-resubmit-2")
                .unwrap_err()
                .to_string()
                .contains("accepted")
        );
        let slack_path = write_intent(&root, intent("check storage", "operator_assertion", None));
        let slack =
            submit_with_dispatch(&config, &slack_path, "ops.primary", false, endpoint, |_| {
                Ok(|_, _, _| async { Ok(TransportResult::Unknown) })
            })
            .await
            .unwrap();
        assert!(
            prepare_resubmission(
                &config,
                slack["notification_id"].as_str().unwrap(),
                "event-9"
            )
            .unwrap_err()
            .to_string()
            .contains("only for nq.notification_delivery_intent.v2")
        );
        assert_routing_key_absent(&config);
    }

    fn notification_component(config: &NqConfig) -> nq_core::public::ComponentStatusV3 {
        let store = Store::open_read_only(&config.database_path).unwrap();
        nq_core::engine::status_snapshot_v3(&store)
            .unwrap()
            .components
            .into_iter()
            .find(|component| {
                component.kind == nq_core::public::ComponentKind::Notification
                    && component.id == "outbox"
            })
            .unwrap()
    }

    fn notification_detail(config: &NqConfig) -> (nq_core::public::ComponentStatusV3, Value) {
        let component = notification_component(config);
        let nq_core::public::ComponentStatusDetailV3::Diagnostic { value } = &component.detail
        else {
            panic!("notification status is a diagnostic")
        };
        let value = value.clone();
        (component, value)
    }

    async fn submit_pd(
        config: &NqConfig,
        root: &TempDir,
        intent: Value,
        enable_network: bool,
        result: TransportResult,
    ) -> Value {
        let path = write_intent(root, intent);
        submit_with_dispatch(config, &path, "pd.ops", enable_network, routing_key, |_| {
            Ok(move |_, _, _| async move { Ok(result) })
        })
        .await
        .unwrap()
    }

    fn rate_limited() -> TransportResult {
        reported(
            "failed",
            json!({"http_status":429,"reason":"rate_limited","retry_class":"retryable","pagerduty_message":"Requests are arriving too quickly"}),
        )
    }

    fn accepted() -> TransportResult {
        reported("accepted", json!({"http_status":202}))
    }

    #[tokio::test]
    async fn status_export_reflects_retained_delivery_outcomes() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let mut store = Store::open(&config.database_path).unwrap();
        nq_core::engine::record_component_status(
            &mut store,
            "notification",
            "outbox",
            "healthy",
            "outbox_empty",
            &json!({"delivery_enabled": false}),
        )
        .unwrap();
        drop(store);
        assert_eq!(notification_component(&config).code, "outbox_empty");

        // A deliberate network-disabled refusal is not a failure.
        submit_pd(
            &config,
            &root,
            pagerduty_intent("trigger", "event-0", "inspect"),
            false,
            accepted(),
        )
        .await;
        assert_eq!(
            notification_component(&config).code,
            "delivery_custody_current"
        );

        submit_pd(
            &config,
            &root,
            pagerduty_intent("trigger", "event-1", "inspect"),
            true,
            rate_limited(),
        )
        .await;
        let (component, value) = notification_detail(&config);
        assert_eq!(component.state, nq_core::public::HealthState::Degraded);
        assert_eq!(component.code, "delivery_failure_unresolved");
        let route = &value["routes"]["pd.ops"];
        assert_eq!(
            route["counts"],
            json!({"pending":0,"claimed_without_outcome":0,"refused":1,"failed":1,"unknown":0,"accepted":0})
        );
        let failure = &route["unresolved_failures"][0];
        assert_eq!(failure["reason"], "rate_limited");
        assert_eq!(failure["http_status"], 429);
        assert_eq!(
            failure["condition"],
            "crow-lab:nq:nq-no-fresh-acquisition:demo"
        );
        assert!(failure.get("pagerduty_message").is_none());

        // An accepted delivery on another route or for another condition does
        // not hide the failed trigger.
        let slack_path = write_intent(&root, intent("check storage", "operator_assertion", None));
        submit_with_dispatch(&config, &slack_path, "ops.primary", true, endpoint, |_| {
            Ok(|_, _, _| async { Ok(TransportResult::Accepted(200)) })
        })
        .await
        .unwrap();
        let mut other = pagerduty_intent("trigger", "event-2", "inspect");
        other["condition"]["target_class"] = json!("other");
        submit_pd(&config, &root, other, true, accepted()).await;
        let (component, value) = notification_detail(&config);
        assert_eq!(component.code, "delivery_failure_unresolved");
        assert_eq!(value["unresolved_failure_count"], 1);
        assert_eq!(
            value["routes"]["ops.primary"]["unresolved_failure_count"],
            0
        );

        // A later acceptance for the same condition resolves it.
        submit_pd(
            &config,
            &root,
            pagerduty_intent("trigger", "event-3", "inspect"),
            true,
            accepted(),
        )
        .await;
        let (component, value) = notification_detail(&config);
        assert_eq!(component.state, nq_core::public::HealthState::Healthy);
        assert_eq!(component.code, "delivery_custody_current");
        assert_eq!(value["routes"]["pd.ops"]["counts"]["accepted"], 2);
        assert!(value["routes"]["pd.ops"]["newest_accepted_at"].is_string());
        assert_routing_key_absent(&config);
    }

    #[tokio::test]
    async fn status_export_degrades_on_key_refusal_and_not_on_an_in_flight_claim() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let path = write_intent(&root, pagerduty_intent("trigger", "event-1", "inspect"));
        submit_with_dispatch(
            &config,
            &path,
            "pd.ops",
            true,
            |_| bail!("unset"),
            |_| Ok(|_, _, _| async { panic!("refused before dispatch") }),
        )
        .await
        .unwrap();
        let (component, value) = notification_detail(&config);
        assert_eq!(component.code, "delivery_failure_unresolved");
        assert_eq!(
            value["routes"]["pd.ops"]["unresolved_failures"][0]["reason"],
            "routing_key_unavailable"
        );

        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let path = write_intent(&root, pagerduty_intent("trigger", "event-1", "inspect"));
        assert!(
            submit_with_dispatch(&config, &path, "pd.ops", true, routing_key, |_| {
                Ok(|_, _, _| async { bail!("still in flight") })
            })
            .await
            .is_err()
        );
        let (component, value) = notification_detail(&config);
        assert_eq!(component.state, nq_core::public::HealthState::Healthy);
        assert_eq!(component.code, "delivery_in_flight");
        assert_eq!(
            value["routes"]["pd.ops"]["counts"]["claimed_without_outcome"],
            1
        );
    }

    #[tokio::test]
    async fn resubmit_refuses_an_older_trigger_after_an_accepted_resolve() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let trigger = submit_pd(
            &config,
            &root,
            pagerduty_intent("trigger", "event-1", "inspect"),
            true,
            reported("unknown", json!({"reason":"timeout_after_dispatch"})),
        )
        .await;
        let resolve = submit_pd(
            &config,
            &root,
            pagerduty_intent("resolve", "event-2", "cleared"),
            true,
            accepted(),
        )
        .await;
        let error = prepare_resubmission(
            &config,
            trigger["notification_id"].as_str().unwrap(),
            "event-1-r1",
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains(resolve["notification_id"].as_str().unwrap()),
            "{error}"
        );
        assert!(error.contains("only the newest record"));
    }

    #[tokio::test]
    async fn resubmit_refuses_an_older_resolve_after_an_accepted_trigger() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let resolve = submit_pd(
            &config,
            &root,
            pagerduty_intent("resolve", "event-1", "cleared"),
            true,
            reported("failed", json!({"reason":"connect_failed"})),
        )
        .await;
        // A different condition on the same route does not block resubmission.
        let mut other = pagerduty_intent("trigger", "event-2", "inspect");
        other["condition"]["target_class"] = json!("other");
        submit_pd(&config, &root, other, true, accepted()).await;
        let resolve_id = resolve["notification_id"].as_str().unwrap();
        assert!(prepare_resubmission(&config, resolve_id, "event-1-r1").is_ok());
        let trigger = submit_pd(
            &config,
            &root,
            pagerduty_intent("trigger", "event-3", "recurred"),
            true,
            accepted(),
        )
        .await;
        let error = prepare_resubmission(&config, resolve_id, "event-1-r2")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(trigger["notification_id"].as_str().unwrap()),
            "{error}"
        );
    }

    #[test]
    fn v1_response_class_is_closed_optional_and_rendered_as_a_prefix() {
        for (class, prefix) in [
            (None, "attention"),
            (Some("informational"), "informational"),
            (Some("attention"), "attention"),
            (Some("page"), "page"),
        ] {
            let mut value = intent("check storage", "operator_assertion", None);
            if let Some(class) = class {
                value["response_class"] = json!(class);
            }
            let (intent, pager) = parse_submitted(value).unwrap();
            assert!(pager.is_none());
            for (transport, field) in [
                (NotificationTransportKind::Slack, "text"),
                (NotificationTransportKind::Discord, "content"),
            ] {
                let rendered: Value =
                    serde_json::from_slice(render(&route(transport), &intent).unwrap().as_bytes())
                        .unwrap();
                assert_eq!(
                    rendered[field],
                    format!("[{prefix}] Attention required: check storage\nInspect: record:1")
                );
            }
            let binding = CanonicalDocument::from_serializable(&json!({})).unwrap();
            let local: Value =
                serde_json::from_slice(render_local_inbox(&intent, &binding).unwrap().as_bytes())
                    .unwrap();
            assert_eq!(local["summary"], format!("[{prefix}] check storage"));
        }
    }

    #[tokio::test]
    async fn invalid_response_class_is_refused_before_custody() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let mut v1 = intent("check storage", "operator_assertion", None);
        v1["response_class"] = json!("urgent");
        let mut v2 = pagerduty_intent("trigger", "event-1", "inspect");
        v2["response_class"] = json!("Page");
        for (value, route) in [(v1, "ops.primary"), (v2, "pd.ops")] {
            let path = write_intent(&root, value);
            let error = submit_with_dispatch(
                &config,
                &path,
                route,
                true,
                |_| panic!("no secret resolution for a malformed intent"),
                |_| Ok(|_, _, _| async { panic!("no dispatch for a malformed intent") }),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("response_class must be"));
        }
        assert_eq!(inspect(&config, None).unwrap(), json!([]));
    }

    #[tokio::test]
    async fn pagerduty_refuses_non_page_intents_as_retained_refusals() {
        let mut cases = Vec::new();
        for action in ["trigger", "resolve"] {
            for class in [None, Some("informational"), Some("attention")] {
                cases.push((action, class));
            }
        }
        for (action, class) in cases {
            let root = TempDir::new().unwrap();
            let config = pagerduty_config(&root);
            let mut value = pagerduty_intent(action, "event-1", "inspect");
            match class {
                Some(class) => value["response_class"] = json!(class),
                None => {
                    value.as_object_mut().unwrap().remove("response_class");
                }
            }
            let path = write_intent(&root, value);
            let result = submit_with_dispatch(
                &config,
                &path,
                "pd.ops",
                true,
                |_| panic!("no routing key resolution for a non-page intent"),
                |_| Ok(|_, _, _| async { panic!("no network call for a non-page intent") }),
            )
            .await
            .unwrap();
            assert_eq!(result["delivery_state"], "refused", "{action} {class:?}");
            let status = inspect(&config, result["notification_id"].as_str()).unwrap();
            assert_eq!(
                status[0]["pagerduty"]["last_event"]["detail"]["reason"],
                RESPONSE_CLASS_NOT_PAGE
            );
            assert_eq!(status[0]["pagerduty"]["response_class"], json!(class));
            assert_eq!(status[0]["event_count"], 1);

            let (component, detail) = notification_detail(&config);
            assert_eq!(component.code, "delivery_failure_unresolved");
            assert_eq!(detail["routes"]["pd.ops"]["counts"]["refused"], 1);
            assert_eq!(
                detail["routes"]["pd.ops"]["unresolved_failures"][0]["reason"],
                RESPONSE_CLASS_NOT_PAGE
            );
            assert_routing_key_absent(&config);
        }
    }

    #[tokio::test]
    async fn non_page_refusal_precedes_nightshift_replay() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut value = pagerduty_intent("trigger", digest, "inspect");
        value["attention_kind"] = json!("nightshift_receipt");
        value["attention_receipt_digest"] = json!(digest);
        value["transition_id"] = json!(digest);
        value["owner_receipt"] = replay_bundle();
        // The route enrolls no verifier, so any replay attempt fails.
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let path = write_intent(&root, value.clone());
        let error = submit_with_dispatch(
            &config,
            &path,
            "pd.ops",
            true,
            |_| panic!("no secret resolution when replay fails"),
            |_| Ok(|_, _, _| async { panic!("no dispatch when replay fails") }),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Nightshift replay is not configured")
        );
        assert_eq!(inspect(&config, None).unwrap(), json!([]));

        value["response_class"] = json!("attention");
        let path = write_intent(&root, value);
        let result = submit_with_dispatch(
            &config,
            &path,
            "pd.ops",
            true,
            |_| panic!("no secret resolution for a non-page intent"),
            |_| Ok(|_, _, _| async { panic!("no dispatch for a non-page intent") }),
        )
        .await
        .unwrap();
        assert_eq!(result["delivery_state"], "refused");
        let status = inspect(&config, result["notification_id"].as_str()).unwrap();
        assert_eq!(
            status[0]["pagerduty"]["last_event"]["detail"]["reason"],
            RESPONSE_CLASS_NOT_PAGE
        );
    }

    #[tokio::test]
    async fn legacy_v2_record_is_inspectable_and_its_resubmit_is_refused() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let mut legacy = pagerduty_intent("trigger", "event-1", "inspect");
        legacy.as_object_mut().unwrap().remove("response_class");
        let document = CanonicalDocument::from_serializable(&legacy).unwrap();
        assert!(reopen_retained_intent(&document).is_ok());
        let first = submit_pd(&config, &root, legacy, true, accepted()).await;
        let id = first["notification_id"].as_str().unwrap();
        let resubmitted = resubmit(&config, id, "event-1-r1", true).await.unwrap();
        assert_eq!(resubmitted["delivery_state"], "refused");
        assert_eq!(resubmitted["resubmitted_from"], id);
        let status = inspect(&config, resubmitted["notification_id"].as_str()).unwrap();
        assert_eq!(
            status[0]["pagerduty"]["last_event"]["detail"]["reason"],
            RESPONSE_CLASS_NOT_PAGE
        );
        assert_eq!(status[0]["pagerduty"]["response_class"], Value::Null);
    }

    #[test]
    fn retained_v2_history_reopens_outside_the_current_registry() {
        let value = historical_pagerduty_intent("pd.ops", "event-1");
        assert!(parse_submitted(value.clone()).is_err());
        let document = CanonicalDocument::from_serializable(&value).unwrap();
        assert_eq!(
            reopen_retained_intent(&document).unwrap().stable_event_id,
            "event-1"
        );
        let mut malformed = value;
        malformed["condition"]["site"] = json!("Not A Token");
        let document = CanonicalDocument::from_serializable(&malformed).unwrap();
        assert!(reopen_retained_intent(&document).is_err());
    }

    #[tokio::test]
    async fn stale_claim_is_an_unresolved_unknown_and_failures_list_newest_first() {
        let root = TempDir::new().unwrap();
        let config = pagerduty_config(&root);
        let value = pagerduty_intent("trigger", "event-stale", "inspect");
        let document = CanonicalDocument::from_serializable(&value).unwrap();
        let (intent, pager) = parse_submitted(value).unwrap();
        let payload = render_pagerduty(&intent, pager.as_ref().unwrap(), &document).unwrap();
        let mut store = Store::open(&config.database_path).unwrap();
        store
            .retain_notification_delivery(
                &NotificationInput {
                    notification_id: "stale-claim".into(),
                    idempotency_key: "event-stale:pagerduty:pd.ops".into(),
                    finding_event_id: None,
                    destination_kind: "pagerduty".into(),
                    payload: payload.clone(),
                    available_at: "2026-01-01T00:00:00+00:00".into(),
                    max_attempts: 1,
                    created_at: "2026-01-01T00:00:00+00:00".into(),
                },
                &NotificationDeliveryIntentInput {
                    notification_id: "stale-claim".into(),
                    stable_event_id: intent.stable_event_id.clone(),
                    attention_kind: intent.attention_kind.clone(),
                    attention_receipt_digest: None,
                    attention_policy_id: intent.attention_policy_id.clone(),
                    attention_policy_digest: intent.attention_policy_digest.clone(),
                    transition_id: intent.transition_id.clone(),
                    route_reference: intent.route_reference.clone(),
                    destination_identity: intent.destination_identity.clone(),
                    content_digest: payload.digest().to_owned(),
                    intent: document,
                    created_at: "2026-01-01T00:00:00+00:00".into(),
                },
            )
            .unwrap();
        store
            .append_notification_delivery_event(&NotificationDeliveryEventInput {
                notification_id: "stale-claim".into(),
                event_number: 1,
                occurred_at: "2026-01-01T00:00:01+00:00".into(),
                outcome: "claimed".into(),
                detail: CanonicalDocument::from_serializable(
                    &json!({"route_reference":"pd.ops","transport":"pagerduty"}),
                )
                .unwrap(),
            })
            .unwrap();
        drop(store);
        assert_eq!(
            inspect(&config, Some("stale-claim")).unwrap()[0]["delivery_state"],
            "unknown"
        );
        let (component, value) = notification_detail(&config);
        assert_eq!(component.state, nq_core::public::HealthState::Degraded);
        assert_eq!(component.code, "delivery_failure_unresolved");
        let route = &value["routes"]["pd.ops"];
        assert_eq!(route["counts"]["unknown"], 1);
        assert_eq!(route["counts"]["claimed_without_outcome"], 0);
        assert_eq!(route["unresolved_failures"][0]["reason"], "claim_stale");
        assert_eq!(route["unresolved_failures"][0]["outcome"], "unknown");

        // Eleven more failed conditions, submitted in reverse alphabetical
        // order: the listed ten are the newest, newest first.
        for class in ["k", "j", "i", "h", "g", "f", "e", "d", "c", "b", "a"] {
            let mut failed = pagerduty_intent("trigger", &format!("event-{class}"), "inspect");
            failed["condition"]["target_class"] = json!(class);
            submit_pd(&config, &root, failed, true, rate_limited()).await;
        }
        let (_, value) = notification_detail(&config);
        let route = &value["routes"]["pd.ops"];
        assert_eq!(route["unresolved_failure_count"], 12);
        let listed = route["unresolved_failures"].as_array().unwrap();
        assert_eq!(listed.len(), 10);
        assert_eq!(
            listed[0]["condition"],
            "crow-lab:nq:nq-no-fresh-acquisition:a"
        );
        assert_eq!(
            listed[9]["condition"],
            "crow-lab:nq:nq-no-fresh-acquisition:j"
        );
    }
}
