//! Provider-independent escalation authorization, before transport effects.

use anyhow::{Context, Result, bail, ensure};
use nq_core::config::{NotificationRouteConfig, NotificationTransportKind, NqConfig};
use nq_protocol::{Sha256Digest, sha256_bytes};
use nq_store::CanonicalDocument;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

pub(crate) const MAX_POLICY_BYTES: usize = 131_072;
pub(crate) const POLICY_MISSING: &str = "escalation_policy_missing: missing escalation policy document; install and pin [escalation_policy]";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "String")]
enum Schema {
    #[serde(rename = "nq.escalation_policy.v1")]
    V1,
}

impl TryFrom<String> for Schema {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "nq.escalation_policy.v1" => Ok(Self::V1),
            _ => Err("unsupported escalation policy schema"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case", try_from = "String")]
enum ResponseClass {
    Informational,
    Attention,
    Page,
}

impl TryFrom<String> for ResponseClass {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "informational" => Ok(Self::Informational),
            "attention" => Ok(Self::Attention),
            "page" => Ok(Self::Page),
            _ => Err("response_class must be informational, attention or page"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    rule: String,
    components: Vec<String>,
    response_classes: Vec<ResponseClass>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Handler {
    Slack {
        timeout_ms: u64,
        max_response_bytes: usize,
    },
    Discord {
        timeout_ms: u64,
        max_response_bytes: usize,
    },
    #[serde(rename = "pagerduty")]
    PagerDuty {
        timeout_ms: u64,
        max_response_bytes: usize,
        max_details_bytes: usize,
    },
    LocalFile {
        max_message_bytes: usize,
    },
}

impl Handler {
    #[cfg(test)]
    fn for_route(route: &NotificationRouteConfig) -> Self {
        let timeout_ms = route.timeout_ms;
        let max_response_bytes = route.max_response_bytes;
        match route.transport {
            NotificationTransportKind::Slack => Self::Slack {
                timeout_ms,
                max_response_bytes,
            },
            NotificationTransportKind::Discord => Self::Discord {
                timeout_ms,
                max_response_bytes,
            },
            NotificationTransportKind::PagerDuty => Self::PagerDuty {
                timeout_ms,
                max_response_bytes,
                max_details_bytes: 4096,
            },
            NotificationTransportKind::LocalFile => Self::LocalFile {
                max_message_bytes: 4096,
            },
        }
    }

    fn validate(&self, route: &NotificationRouteConfig) -> Result<()> {
        let (kind, network) = match self {
            Self::Slack {
                timeout_ms,
                max_response_bytes,
            } => (
                NotificationTransportKind::Slack,
                Some((*timeout_ms, *max_response_bytes)),
            ),
            Self::Discord {
                timeout_ms,
                max_response_bytes,
            } => (
                NotificationTransportKind::Discord,
                Some((*timeout_ms, *max_response_bytes)),
            ),
            Self::PagerDuty {
                timeout_ms,
                max_response_bytes,
                max_details_bytes,
            } => {
                ensure!(
                    (1..=4096).contains(max_details_bytes),
                    "policy PagerDuty details bound must be 1..=4096"
                );
                (
                    NotificationTransportKind::PagerDuty,
                    Some((*timeout_ms, *max_response_bytes)),
                )
            }
            Self::LocalFile { max_message_bytes } => {
                ensure!(
                    (1..=4096).contains(max_message_bytes),
                    "policy local message bound must be 1..=4096"
                );
                (NotificationTransportKind::LocalFile, None)
            }
        };
        ensure!(
            kind == route.transport,
            "policy handler does not match configured route {}",
            route.reference
        );
        if let Some((timeout, response)) = network {
            ensure!(
                (100..=60_000).contains(&timeout),
                "policy timeout bound must be 100..=60000"
            );
            ensure!(
                (1..=32_768).contains(&response),
                "policy response bound must be 1..=32768"
            );
            ensure!(
                route.timeout_ms <= timeout && route.max_response_bytes <= response,
                "configured route {} exceeds policy handler bounds",
                route.reference
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Route {
    reference: String,
    anchors: Vec<String>,
    response_classes: Vec<ResponseClass>,
    handler: Handler,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: Schema,
    anchors: Vec<Anchor>,
    routes: Vec<Route>,
}

fn unique_nonempty<T: Ord>(values: &[T], maximum: usize, label: &str) -> Result<()> {
    ensure!(
        !values.is_empty() && values.len() <= maximum,
        "policy {label} must have 1..={maximum} entries"
    );
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "policy {label} has duplicate entries"
    );
    Ok(())
}

fn validate_anchors(anchors: &[Anchor]) -> Result<()> {
    unique_nonempty(
        &anchors
            .iter()
            .map(|anchor| &anchor.rule)
            .collect::<Vec<_>>(),
        256,
        "anchors",
    )?;
    for anchor in anchors {
        // Reuse the submission token checks, including stable-class heuristics.
        super::notification::policy_token("rule", &anchor.rule)?;
        unique_nonempty(&anchor.components, 32, "components")?;
        unique_nonempty(&anchor.response_classes, 3, "response_classes")?;
        for component in &anchor.components {
            super::notification::policy_token("component", component)?;
        }
    }
    Ok(())
}

impl Document {
    fn validate(&self, configured: &[NotificationRouteConfig]) -> Result<()> {
        validate_anchors(&self.anchors)?;
        ensure!(self.routes.len() <= 64, "policy accepts at most 64 routes");
        let references: BTreeSet<_> = self.routes.iter().map(|route| &route.reference).collect();
        ensure!(
            references.len() == self.routes.len(),
            "policy has duplicate routes"
        );
        ensure!(
            self.routes.len() == configured.len(),
            "policy routes must exactly cover configured routes"
        );
        for route in &self.routes {
            let configured = configured
                .iter()
                .find(|entry| entry.reference == route.reference)
                .context("policy route is not configured")?;
            unique_nonempty(&route.anchors, 256, "route anchors")?;
            for rule in &route.anchors {
                ensure!(
                    self.anchors.iter().any(|anchor| &anchor.rule == rule),
                    "policy route names an unknown anchor"
                );
            }
            unique_nonempty(&route.response_classes, 3, "route response_classes")?;
            if matches!(route.handler, Handler::PagerDuty { .. }) {
                ensure!(
                    route.response_classes == [ResponseClass::Page],
                    "policy PagerDuty route must allow only page"
                );
            }
            route.handler.validate(configured)?;
        }
        Ok(())
    }
}

/// Validated snapshot. No provider receives unvalidated policy bytes.
#[derive(Debug)]
pub(crate) struct Policy {
    document: Document,
    digest: Option<String>,
}

impl Policy {
    // Test fixtures explicitly install these bytes; production never loads examples.
    #[cfg(test)]
    pub(crate) fn example(routes: &[NotificationRouteConfig]) -> Result<Self> {
        let bytes = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/escalation-policy.example.json"),
        )?;
        let mut document: Document = serde_json::from_slice(&bytes)?;
        document.routes = routes
            .iter()
            .map(|route| Route {
                reference: route.reference.clone(),
                anchors: document
                    .anchors
                    .iter()
                    .map(|anchor| anchor.rule.clone())
                    .collect(),
                response_classes: if route.transport == NotificationTransportKind::PagerDuty {
                    vec![ResponseClass::Page]
                } else {
                    vec![
                        ResponseClass::Informational,
                        ResponseClass::Attention,
                        ResponseClass::Page,
                    ]
                },
                handler: Handler::for_route(route),
            })
            .collect();
        document.validate(routes)?;
        let digest = sha256_bytes(&serde_json::to_vec(&document)?).into_string();
        Ok(Self {
            document,
            digest: Some(digest),
        })
    }

    pub(crate) fn is_missing(&self) -> bool {
        self.digest.is_none()
    }

    pub(crate) fn require_installed(&self) -> Result<()> {
        ensure!(!self.is_missing(), POLICY_MISSING);
        Ok(())
    }

    pub(crate) fn status(&self) -> Value {
        if self.is_missing() {
            json!({"state":"missing", "diagnostic":POLICY_MISSING,
                "page_admission":"refused", "notice_admission":"routes_config"})
        } else {
            json!({"state":"healthy", "digest":self.digest})
        }
    }

    pub(crate) fn load(config: &NqConfig) -> Result<Self> {
        let Some(binding) = &config.escalation_policy else {
            return Ok(Self {
                document: Document {
                    schema: Schema::V1,
                    anchors: Vec::new(),
                    routes: Vec::new(),
                },
                digest: None,
            });
        };
        ensure!(
            binding.path.is_absolute(),
            "escalation policy path must be absolute"
        );
        Sha256Digest::parse(binding.sha256.clone()).context("invalid escalation policy pin")?;
        let bytes =
            super::bounded_input::read(&binding.path, MAX_POLICY_BYTES).with_context(|| {
                format!("read escalation policy document {}", binding.path.display())
            })?;
        let digest = sha256_bytes(&bytes).into_string();
        ensure!(
            digest == binding.sha256,
            "escalation policy digest mismatch"
        );
        let document: Document =
            serde_json::from_slice(&bytes).context("invalid escalation policy document")?;
        document.validate(&config.notification_routes)?;
        Ok(Self {
            document,
            digest: Some(digest),
        })
    }

    fn anchor(&self, rule: &str, component: &str) -> Result<&Anchor> {
        self.require_installed()?;
        if !self
            .document
            .anchors
            .iter()
            .any(|anchor| anchor.components.iter().any(|entry| entry == component))
        {
            bail!("notification condition component is not in the closed component set");
        }
        let anchor = self
            .document
            .anchors
            .iter()
            .find(|anchor| anchor.rule == rule)
            .context("notification condition rule is not a beta alert registry anchor")?;
        ensure!(
            anchor.components.iter().any(|entry| entry == component),
            "notification component is not authorized for this anchor"
        );
        Ok(anchor)
    }

    pub(crate) fn validate_condition(&self, rule: &str, component: &str) -> Result<()> {
        // Missing-policy submissions still undergo protocol validation so the
        // refusal can be retained. No condition is authorized by this branch.
        if self.is_missing() {
            return Ok(());
        }
        self.anchor(rule, component).map(|_| ())
    }

    pub(crate) fn authorize(
        &self,
        route: &str,
        class: &str,
        condition: Option<(&str, &str)>,
    ) -> Result<()> {
        let class: ResponseClass = serde_json::from_value(json!(class))?;
        if self.is_missing() {
            ensure!(class != ResponseClass::Page, POLICY_MISSING);
            return Ok(());
        }
        let route = self
            .document
            .routes
            .iter()
            .find(|entry| entry.reference == route)
            .context("notification route is not authorized by escalation policy")?;
        ensure!(
            route.response_classes.contains(&class),
            "notification response_class is not authorized on this route"
        );
        if let Some((rule, component)) = condition {
            let anchor = self.anchor(rule, component)?;
            ensure!(
                anchor.response_classes.contains(&class),
                "notification response_class is not authorized for this anchor"
            );
            ensure!(
                route.anchors.iter().any(|entry| entry == rule),
                "notification anchor is not authorized on this route"
            );
        }
        Ok(())
    }

    pub(crate) fn validate_payload(
        &self,
        route: &str,
        details: Option<&Value>,
        local_bytes: Option<usize>,
    ) -> Result<()> {
        if self.is_missing() {
            return Ok(());
        }
        let route = self
            .document
            .routes
            .iter()
            .find(|entry| entry.reference == route)
            .context("notification route is not authorized by escalation policy")?;
        match route.handler {
            Handler::PagerDuty {
                max_details_bytes, ..
            } => {
                if let Some(details) = details {
                    ensure!(
                        CanonicalDocument::from_serializable(details)?
                            .as_bytes()
                            .len()
                            <= max_details_bytes,
                        "notification details exceed escalation policy bound"
                    );
                }
            }
            Handler::LocalFile { max_message_bytes } => {
                ensure!(
                    local_bytes.is_some_and(|bytes| bytes <= max_message_bytes),
                    "local inbox message exceeds escalation policy bound"
                );
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn inspect(&self) -> Value {
        if self.is_missing() {
            return json!({"source":"missing", "status":self.status()});
        }
        json!({"source":"installed", "digest":self.digest, "policy":self.document})
    }

    pub(crate) fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    pub(crate) fn check_registry(&self, path: &Path, selected_route: Option<&str>) -> Result<()> {
        self.require_installed()?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Registry {
            schema: String,
            anchors: Vec<Anchor>,
        }
        let bytes = super::bounded_input::read(path, MAX_POLICY_BYTES)?;
        let registry: Registry = serde_json::from_slice(&bytes)?;
        ensure!(
            registry.schema == "nq.escalation_registry.v1",
            "unsupported escalation registry schema"
        );
        validate_anchors(&registry.anchors)?;
        if let Some(reference) = selected_route {
            ensure!(
                self.document
                    .routes
                    .iter()
                    .any(|route| route.reference == reference),
                "registry check route is not authorized by escalation policy"
            );
        }
        for anchor in registry.anchors {
            for component in &anchor.components {
                let permitted = self.anchor(&anchor.rule, component)?;
                ensure!(
                    anchor
                        .response_classes
                        .iter()
                        .all(|class| permitted.response_classes.contains(class)),
                    "attention registry class is not authorized for {}",
                    anchor.rule
                );
                if anchor.response_classes.contains(&ResponseClass::Page) {
                    ensure!(
                        self.document.routes.iter().any(|route| {
                            selected_route.is_none_or(|reference| route.reference == reference)
                                // Only PagerDuty currently accepts condition-bearing v2 pages.
                                && matches!(route.handler, Handler::PagerDuty { .. })
                                && route.anchors.contains(&anchor.rule)
                                && route.response_classes.contains(&ResponseClass::Page)
                        }),
                        "attention registry page for {} has no authorized delivery route",
                        anchor.rule
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nq_core::config::EscalationPolicyConfig;
    use std::fs;
    use tempfile::TempDir;

    fn config(root: &TempDir) -> NqConfig {
        NqConfig::from_toml(&format!(
            r#"
            schema = "nq.config.v1"
            database_path = "{0}/absent.db"
            socket_path = "{0}/absent.sock"
            admissions_dir = "{0}/absent-admissions"
            [[notification_routes]]
            reference = "pagerduty-ops"
            transport = "pagerduty"
            routing_key_env = "NQ_FIXTURE_ROUTING_KEY"
            max_response_bytes = 4096
        "#,
            root.path().display()
        ))
        .unwrap()
    }

    fn install(config: &mut NqConfig, root: &TempDir, bytes: &[u8]) {
        let path = root.path().join("policy.json");
        fs::write(&path, bytes).unwrap();
        config.escalation_policy = Some(EscalationPolicyConfig {
            path,
            sha256: sha256_bytes(bytes).into_string(),
        });
    }

    #[test]
    fn no_binding_has_no_document_or_digest_and_cannot_authorize_pages() {
        let root = TempDir::new().unwrap();
        let policy = Policy::load(&config(&root)).unwrap();
        assert!(policy.is_missing());
        assert_eq!(policy.digest(), None);
        assert!(
            policy
                .require_installed()
                .unwrap_err()
                .to_string()
                .contains(POLICY_MISSING)
        );
        assert!(
            policy
                .authorize("pagerduty-ops", "page", Some(("service-down", "service")))
                .is_err()
        );
        policy.authorize("operations", "attention", None).unwrap();
        assert_eq!(policy.inspect()["source"], "missing");
    }

    #[test]
    fn exact_bytes_are_pinned_and_error_never_selects_an_example() {
        let root = TempDir::new().unwrap();
        let mut config = config(&root);
        let example = Policy::example(&config.notification_routes).unwrap();
        let bytes = serde_json::to_vec_pretty(&example.document).unwrap();
        install(&mut config, &root, &bytes);
        let loaded = Policy::load(&config).unwrap();
        assert!(!loaded.is_missing());
        assert_eq!(loaded.digest(), Some(sha256_bytes(&bytes).as_str()));
        let binding = config.escalation_policy.as_ref().unwrap();
        let mut changed = bytes;
        changed.push(b'\n');
        fs::write(&binding.path, &changed).unwrap();
        assert!(
            Policy::load(&config)
                .unwrap_err()
                .to_string()
                .contains("digest mismatch")
        );
        fs::remove_file(&binding.path).unwrap();
        assert!(Policy::load(&config).is_err());
        config.escalation_policy = None;
        assert!(Policy::load(&config).unwrap().is_missing());
        assert!(!config.database_path.exists());
    }

    #[test]
    fn load_refuses_oversize_nonregular_and_missing_approval() {
        let root = TempDir::new().unwrap();
        let mut config = config(&root);
        install(&mut config, &root, &vec![b' '; MAX_POLICY_BYTES + 1]);
        assert!(format!("{:#}", Policy::load(&config).unwrap_err()).contains("byte bound"));
        let binding = config.escalation_policy.as_mut().unwrap();
        binding.sha256 = "sha256:unapproved".into();
        assert!(
            Policy::load(&config)
                .unwrap_err()
                .to_string()
                .contains("invalid escalation policy pin")
        );
        binding_reset(&mut config);
        let path = config.escalation_policy.as_ref().unwrap().path.clone();
        fs::remove_file(&path).unwrap();
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert!(format!("{:#}", Policy::load(&config).unwrap_err()).contains("regular file"));
        fs::remove_file(&path).unwrap();
        let target = root.path().join("real-policy");
        fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(format!("{:#}", Policy::load(&config).unwrap_err()).contains("regular file"));
    }

    fn binding_reset(config: &mut NqConfig) {
        config.escalation_policy.as_mut().unwrap().sha256 = sha256_bytes(b"{}").into_string();
    }

    #[test]
    fn load_refuses_unknown_enums_fields_duplicates_and_unbounded_permissions() {
        let root = TempDir::new().unwrap();
        let mut config = config(&root);
        let base = Policy::example(&config.notification_routes)
            .unwrap()
            .inspect()["policy"]
            .clone();
        let invalid = [
            ("/schema", json!("nq.escalation_policy.v2")),
            ("/schema", json!({"nq.escalation_policy.v1":null})),
            ("/anchors/0/response_classes/0", json!("urgent")),
            ("/anchors/0/response_classes/0", json!({"page":null})),
            ("/routes/0/response_classes/0", json!({"page":null})),
            ("/routes/0/handler/kind", json!("webex")),
            ("/routes/0/handler/kind", json!({"pagerduty":null})),
            (
                "/routes/0/handler",
                json!({"kind":"local_file","max_message_bytes":4096}),
            ),
            ("/routes/0/handler/timeout_ms", json!(60_001)),
            ("/routes/0/handler/timeout_ms", json!(9999)),
            ("/routes/0/handler/max_response_bytes", json!(4095)),
            ("/routes/0/handler/max_response_bytes", json!(32_769)),
            ("/routes/0/handler/max_details_bytes", json!(4097)),
            ("/routes/0/handler/max_details_bytes", json!(0)),
            ("/routes/0/response_classes", json!(["attention"])),
            ("/routes/0/response_classes", json!(["page", "page"])),
            ("/routes/0/anchors", json!(["unlisted"])),
            ("/routes/0/anchors", json!(["service-down", "service-down"])),
            ("/routes/0/reference", json!("pagerduty-test")),
            ("/routes", json!([])),
            ("/anchors/0/rule", json!("*")),
            ("/anchors/0/components", json!([])),
            ("/anchors/0/components", json!(["nq", "nq"])),
            ("/anchors/0/components", json!(["host-20261022"])),
            ("/anchors/0/response_classes", json!([])),
            ("/anchors/0/response_classes", json!(["page", "page"])),
        ];
        for (pointer, value) in invalid {
            let mut document = base.clone();
            *document.pointer_mut(pointer).unwrap() = value;
            install(&mut config, &root, &serde_json::to_vec(&document).unwrap());
            assert!(Policy::load(&config).is_err(), "{pointer}");
        }
        for pointer in ["", "/anchors/0", "/routes/0", "/routes/0/handler"] {
            let mut document = base.clone();
            document.pointer_mut(pointer).unwrap()["unknown"] = json!(true);
            install(&mut config, &root, &serde_json::to_vec(&document).unwrap());
            assert!(Policy::load(&config).is_err(), "{pointer}");
        }
        for field in ["anchors", "routes"] {
            let mut document = base.clone();
            let first = document[field][0].clone();
            document[field].as_array_mut().unwrap().push(first);
            install(&mut config, &root, &serde_json::to_vec(&document).unwrap());
            assert!(Policy::load(&config).is_err(), "duplicate {field}");
        }
        let mut too_many = base.clone();
        too_many["anchors"] = json!((0..257).map(|i| json!({
            "rule":format!("rule-{i}"), "components":["service"], "response_classes":["page"]
        })).collect::<Vec<_>>());
        install(&mut config, &root, &serde_json::to_vec(&too_many).unwrap());
        assert!(
            Policy::load(&config)
                .unwrap_err()
                .to_string()
                .contains("1..=256")
        );
        let mut too_many_components = base;
        too_many_components["anchors"][0]["components"] = json!(
            (0..33)
                .map(|i| format!("component-{i}"))
                .collect::<Vec<_>>()
        );
        install(
            &mut config,
            &root,
            &serde_json::to_vec(&too_many_components).unwrap(),
        );
        assert!(
            Policy::load(&config)
                .unwrap_err()
                .to_string()
                .contains("1..=32")
        );
    }

    #[test]
    fn registry_pages_need_a_capable_route_and_honor_the_selected_route() {
        let root = TempDir::new().unwrap();
        let mut config = config(&root);
        let mut other = config.notification_routes[0].clone();
        other.reference = "pagerduty-other".into();
        config.notification_routes.push(other);
        let mut notice = config.notification_routes[0].clone();
        notice.reference = "operations".into();
        notice.transport = NotificationTransportKind::Slack;
        config.notification_routes.push(notice);
        let mut policy = Policy::example(&config.notification_routes).unwrap();
        let rule = policy.document.anchors[0].rule.clone();
        let component = policy.document.anchors[0].components[0].clone();
        for route in &mut policy.document.routes[..2] {
            route.anchors.retain(|anchor| anchor != &rule);
        }
        let path = root.path().join("registry.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "schema": "nq.escalation_registry.v1",
                "anchors": [{"rule": rule, "components": [component], "response_classes": ["page"]}]
            }))
            .unwrap(),
        )
        .unwrap();
        // Slack carrying the anchor/class is insufficient: it cannot accept v2.
        assert!(policy.check_registry(&path, None).is_err());
        assert!(policy.check_registry(&path, Some("operations")).is_err());
        policy.document.routes[0].anchors.push(rule);
        policy.check_registry(&path, None).unwrap();
        policy.check_registry(&path, Some("pagerduty-ops")).unwrap();
        assert!(
            policy
                .check_registry(&path, Some("pagerduty-other"))
                .is_err()
        );
    }

    #[test]
    fn attention_mirror_must_fit_the_same_pinned_document() {
        let root = TempDir::new().unwrap();
        let mut config = config(&root);
        let mut document = Policy::example(&config.notification_routes).unwrap();
        let path = root.path().join("registry.json");
        let mut mirror = json!({"schema":"nq.escalation_registry.v1", "anchors":[{
            "rule":"remediation-journal-critical", "components":["service"], "response_classes":["page"]
        }]});
        fs::write(&path, serde_json::to_vec(&mirror).unwrap()).unwrap();
        assert!(document.check_registry(&path, None).is_err());
        document
            .document
            .anchors
            .push(serde_json::from_value(mirror["anchors"][0].clone()).unwrap());
        install(
            &mut config,
            &root,
            &serde_json::to_vec(&document.document).unwrap(),
        );
        let loaded = Policy::load(&config).unwrap();
        assert!(
            loaded
                .check_registry(&path, None)
                .unwrap_err()
                .to_string()
                .contains("no authorized delivery route")
        );
        document.document.routes[0]
            .anchors
            .push("remediation-journal-critical".into());
        install(
            &mut config,
            &root,
            &serde_json::to_vec(&document.document).unwrap(),
        );
        let loaded = Policy::load(&config).unwrap();
        loaded.check_registry(&path, None).unwrap();
        loaded.check_registry(&path, Some("pagerduty-ops")).unwrap();
        assert!(loaded.check_registry(&path, Some("missing")).is_err());
        mirror["anchors"][0]["response_classes"] = json!(["attention"]);
        fs::write(&path, serde_json::to_vec(&mirror).unwrap()).unwrap();
        assert!(loaded.check_registry(&path, None).is_err());
        mirror["anchors"][0]["response_classes"] = json!(["page"]);
        mirror["anchors"][0]["components"] = json!(["nq"]);
        fs::write(&path, serde_json::to_vec(&mirror).unwrap()).unwrap();
        assert!(loaded.check_registry(&path, None).is_err());
    }
}
