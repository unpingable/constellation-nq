//! Closed NQ claim profile for the SILICON-ORCHARD open ECAD corpus.

use chrono::{DateTime, TimeZone as _, Utc};
use nq_protocol::{Sha256Digest, canonical_json_bytes, semantic_digest, sha256_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AcceptedProducerIdentityV1, FIELD_CLOCK_MONITOR_RESULT_HEAD, OperationalClaimRuleV1,
    OperationalQualificationProfileV1,
};

/// Exact Monitor fixture-generator checkpoint.
pub const SILICON_MONITOR_FIXTURE_HEAD: &str = "bb75c4325f903f2c544e9758b5ea8d30c8bbc773";
/// Exact byte identity of the accepted Monitor fixture bundle.
pub const SILICON_MONITOR_BUNDLE_DIGEST: &str =
    "sha256:fa51387ed569064281f63576e46de44628e2833bfbec2955fc7d990209ae173f";
/// Exact DISTANT-BELL result used by the retained traversal fixture.
pub const SILICON_DISTANT_RESULT_HEAD: &str = "8a1adaae27a5da70398b445c152cd4e7548b0289";
/// Closed SILICON ECAD NQ profile identity.
pub const SILICON_ECAD_PROFILE_ID: &str = "profile:silicon-orchard-ecad-stage:v1";
/// Exact Monitor ECAD payload schema admitted by the profile.
pub const SILICON_ECAD_PAYLOAD_SCHEMA: &str = "monitor.ecad-stage-observation/v1";

fn claim(
    claim_id: &str,
    coverage_dimension: &str,
    pointer: &str,
    proposition: &str,
) -> OperationalClaimRuleV1 {
    OperationalClaimRuleV1 {
        claim_id: claim_id.into(),
        coverage_dimension: coverage_dimension.into(),
        payload_json_pointer: pointer.into(),
        proposition: proposition.into(),
    }
}

/// Return the exact profile for the checked-in open ECAD fixture identities.
///
/// The profile supports individual values only. It has no job-result,
/// aggregate-health, remediation, or target-effect claim.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn silicon_orchard_ecad_profile() -> OperationalQualificationProfileV1 {
    OperationalQualificationProfileV1 {
        profile_id: SILICON_ECAD_PROFILE_ID.into(),
        monitor_contract_head: FIELD_CLOCK_MONITOR_RESULT_HEAD.into(),
        accepted_subject_identity_digests: [
            "sha256:0de604d1a6b4b606d8753b1106c8c1bf95027b5c19ecf5d4287b2734250733ca",
            "sha256:117dcc2332cb243a919503d815e95b5406a061b1f3f4f0f83665c17ecb36b7e9",
            "sha256:22608157b5a8a535cad1abf1bffd17980a2a4de225126ab8b705bcfe02e5fbee",
            "sha256:2964f2e50aa7134d82dbfb55a608370098b582e0701769c27b953877168c60a1",
            "sha256:3f7ccaad2ba1503ef6f71aac90a1682a3383ab0f672a5c0b8e98079c41437882",
            "sha256:5e1990110d8ddec3d70e99f2dcdf8909c695a78baaa912a06c2dbe9dae28727b",
            "sha256:685aa649b2e95ec91dc6149315803ee10f4d626e11c8adfd2f0e7486fd50e628",
            "sha256:798940b4ce34d78b0bc3fefa74b25461c83f6a62b03d08393d8d01e7d3165741",
            "sha256:7e7040ead4320585d40a35947ad85d27903729f5c589c510eac6744128e49e4f",
            "sha256:919aef93f266c571cac2fdb766b3ee22c5e8a5ec4ed605c1c2b55b1bb20a9ebb",
            "sha256:9a29016cdccc13b47c88ffb7e508c646bfbf18dac4e13712d8d81a97dd3e5f5a",
            "sha256:b189d8cdde834f7ee20f288a63169b883a35bb779604a48dc3f67c69de8ff1df",
            "sha256:c75ce342b99b32d1731bb02b70cc169690c98b2ecc1f1817c246031df3498e91",
            "sha256:ee770dd947948627c2aaaf74a9f53b67f6be02b1a92dc9f19532a969047db0c9",
            "sha256:f4f24b5d869622878e9efcc09e628156507be3fd1debafc03dc54adb69551ce2",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        accepted_producer_identities: [
            (
                "producer:silicon:agent_worker",
                "sha256:cc8c8bb5f206c917911e06db6d57a59f0c5e3fd1f09687dd8a62e40e7129a865",
                "sha256:85daede4351d4f0f0b2e952c602b82665e73b759632d6a4ea343ef206a56cdc4",
            ),
            (
                "producer:silicon:artifact_monitor",
                "sha256:d23a4830cf73009eb8b5d088f54b4df4568210fdd8f0c081d9e6718503c249b6",
                "sha256:a43e32521f7c5c650378f6ad829221cf7b4481d1dc0151d30fa201b2647c485b",
            ),
            (
                "producer:silicon:license_monitor",
                "sha256:3043d6609a616422262f66aca29cac02d60257a85ac3c2fb3562594840e72285",
                "sha256:6c791c32ca5ac1d1af8574c0c5bb2da52ddc58aec690dcdad8400dfe8dee6a95",
            ),
            (
                "producer:silicon:repository_monitor",
                "sha256:2b1739cd369053860e35b1e94561705abdd0ad76ace255f17c1e8011e5218bef",
                "sha256:151704051f09c42063fb8e3795d69f18eb602f492c452fd574945b07ced93b66",
            ),
            (
                "producer:silicon:result_checker",
                "sha256:abbbbcf9fb9fc7c538cf733076c89bd9fbb9fdbe3f28ee344387a34a2b81e216",
                "sha256:9b11ca401fbaf31ca81b008b9291ee216de6bd6ca8f80eb836eb641af1e96b41",
            ),
            (
                "producer:silicon:scheduler_monitor",
                "sha256:cde6225beab4f9c955ca5c74420bb2e499d71aa892ae5aedf896374815ebcea2",
                "sha256:65b1acff4d30ad6f53a1f29cdc42420cfda4119f54b4f50dcd2a6aa437f8ce61",
            ),
            (
                "producer:silicon:tool_environment_monitor",
                "sha256:0fb616e6ee4967346b45a33da18a9ffe05f53acf19f221ee88447fe21daf4a64",
                "sha256:72da124d521032453f18490030979e97809454a6e62c8705d85b10dd1293144a",
            ),
            (
                "producer:silicon:worker_monitor",
                "sha256:acdb74da07750a6023717b3462112212231c711914db3a44498e68f0ef7c194c",
                "sha256:04f76626a217cae5ca3293e482d094329177bde164535437a79466bba57a1045",
            ),
        ]
        .into_iter()
        .map(
            |(principal_id, producer_identity_digest, public_key_digest)| {
                AcceptedProducerIdentityV1 {
                    principal_id: principal_id.into(),
                    producer_identity_digest: producer_identity_digest.into(),
                    public_key_digest: public_key_digest.into(),
                }
            },
        )
        .collect(),
        accepted_payload_schemas: vec![SILICON_ECAD_PAYLOAD_SCHEMA.into()],
        claims: vec![
            claim(
                "ecad:design-revision",
                "design_revision",
                "/identities/design_revision",
                "exact ECAD design revision identity",
            ),
            claim(
                "ecad:observed-design-revision",
                "design_revision",
                "/observed_design_revision",
                "exact observed ECAD design revision identity",
            ),
            claim(
                "ecad:design-revision-match",
                "design_revision",
                "/design_revision_matches",
                "design revision comparison observation",
            ),
            claim(
                "ecad:input-artifact",
                "input_artifact",
                "/identities/input_artifact_set",
                "exact input artifact-set identity",
            ),
            claim(
                "ecad:license",
                "license",
                "/license_observation",
                "observed license response",
            ),
            claim(
                "ecad:license-identity",
                "license",
                "/identities/license_entitlement",
                "exact license entitlement identity",
            ),
            claim(
                "ecad:output-artifact",
                "output_artifact",
                "/identities/output_artifact_set",
                "exact output artifact-set identity",
            ),
            claim(
                "ecad:observed-output-artifact",
                "output_artifact",
                "/observed_output_artifact_set",
                "exact observed output artifact-set identity or absence",
            ),
            claim(
                "ecad:output-present",
                "output_artifact",
                "/output_present",
                "output presence observation",
            ),
            claim(
                "ecad:output-digest-match",
                "output_artifact",
                "/output_digest_matches",
                "output digest comparison observation",
            ),
            claim(
                "ecad:pdk-identity",
                "pdk",
                "/identities/pdk",
                "exact PDK identity",
            ),
            claim(
                "ecad:observed-pdk-identity",
                "pdk",
                "/observed_pdk",
                "exact observed PDK identity",
            ),
            claim(
                "ecad:pdk-match",
                "pdk",
                "/pdk_matches",
                "PDK comparison observation",
            ),
            claim(
                "ecad:repository-revision",
                "repository_revision",
                "/identities/repository_revision",
                "exact repository revision identity",
            ),
            claim(
                "ecad:observed-repository-revision",
                "repository_revision",
                "/observed_repository_revision",
                "exact observed repository revision identity",
            ),
            claim(
                "ecad:repository-revision-match",
                "repository_revision",
                "/repository_revision_matches",
                "repository revision comparison observation",
            ),
            claim(
                "ecad:scheduler-job",
                "scheduler",
                "/identities/scheduler_job",
                "exact scheduler-job occurrence identity",
            ),
            claim(
                "ecad:scheduler-observation",
                "scheduler",
                "/scheduler_observation",
                "scheduler observation",
            ),
            claim(
                "ecad:stage-occurrence",
                "stage",
                "/identities/stage_occurrence",
                "exact stage occurrence identity",
            ),
            claim(
                "ecad:stage-name",
                "stage",
                "/stage_name",
                "stage name observation",
            ),
            claim(
                "ecad:toolchain-identity",
                "toolchain",
                "/identities/toolchain",
                "exact toolchain identity",
            ),
            claim(
                "ecad:observed-toolchain-identity",
                "toolchain",
                "/observed_toolchain",
                "exact observed toolchain identity",
            ),
            claim(
                "ecad:toolchain-match",
                "toolchain",
                "/toolchain_matches",
                "toolchain comparison observation",
            ),
            claim(
                "ecad:worker-identity",
                "worker",
                "/identities/worker",
                "exact worker identity",
            ),
            claim(
                "ecad:worker-observation",
                "worker",
                "/worker_observation",
                "worker observation",
            ),
            claim(
                "ecad:artifact-observed-at",
                "output_artifact",
                "/artifact_observed_at",
                "artifact observation time",
            ),
            claim(
                "ecad:process-exit-code",
                "stage",
                "/process_exit_code",
                "process exit code as mechanics only",
            ),
        ],
    }
}

/// Versioned SILICON claim-deck schema.
pub const SILICON_ECAD_CLAIM_DECK_SCHEMA_V1: &str = "nq.ecad-claim-deck/v1";
/// Machine-readable SILICON profile schema.
pub const SILICON_ECAD_PROFILE_JSON_SCHEMA_V1: &str = include_str!(
    "../../../operational-contract/schemas/nq.ecad-qualification-profile.v1.schema.json"
);
/// Machine-readable SILICON deck schema.
pub const SILICON_ECAD_DECK_JSON_SCHEMA_V1: &str =
    include_str!("../../../operational-contract/schemas/nq.ecad-claim-deck.v1.schema.json");
/// Versioned SILICON evidence-eligibility schema.
pub const SILICON_ECAD_ELIGIBILITY_SCHEMA_V1: &str = "nq.ecad-evidence-eligibility/v1";
/// Exact closed SILICON claim-deck identity.
pub const SILICON_ECAD_DECK_ID: &str = "deck:silicon-orchard-open-counter:v1";
/// Exact closed SILICON checker identity.
pub const SILICON_ECAD_CHECKER_ID: &str = "checker:silicon-orchard-exact-evidence:v1";
/// Exact JCS identity of the immutable 27-claim deck.
pub const SILICON_ECAD_DECK_DIGEST: &str =
    "sha256:7f9ba67910df6962e4e02cb2e1fa75562a59889e16cef3c9133c90aa090cea0d";

#[allow(missing_docs)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcadRequiredClaimV1 {
    pub claim_id: String,
    pub expected_value_digest: Sha256Digest,
}

#[allow(missing_docs)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcadClaimDeckV1 {
    pub schema: String,
    pub deck_id: String,
    pub checker_id: String,
    pub profile_id: String,
    pub required_claims: Vec<EcadRequiredClaimV1>,
    pub requires_full_evidence: bool,
    pub process_exit_alone_is_sufficient: bool,
    pub grants_authority: bool,
}

#[allow(missing_docs)]
impl EcadClaimDeckV1 {
    /// Validate exact deck identity and claim domain.
    ///
    /// # Errors
    /// Returns an error when any closed deck invariant differs.
    pub fn validate(&self) -> Result<(), String> {
        let exact = silicon_orchard_claim_deck();
        if self.schema != exact.schema
            || self.deck_id != exact.deck_id
            || self.checker_id != exact.checker_id
            || self.profile_id != exact.profile_id
            || self.requires_full_evidence != exact.requires_full_evidence
            || self.process_exit_alone_is_sufficient != exact.process_exit_alone_is_sufficient
            || self.grants_authority != exact.grants_authority
        {
            return Err("ecad_claim_deck_identity_invalid".into());
        }
        if self
            .required_claims
            .iter()
            .map(|claim| &claim.claim_id)
            .ne(exact.required_claims.iter().map(|claim| &claim.claim_id))
        {
            return Err("ecad_claim_deck_domain_invalid".into());
        }
        if self.required_claims != exact.required_claims {
            return Err("ecad_claim_deck_content_invalid".into());
        }
        Ok(())
    }

    /// Compute the canonical semantic deck digest.
    ///
    /// # Errors
    /// Returns an error when deck validation or canonicalization fails.
    pub fn deck_digest(&self) -> Result<Sha256Digest, String> {
        self.validate()?;
        let digest = semantic_digest(self).map_err(|value| value.to_string())?;
        if digest.as_str() != SILICON_ECAD_DECK_DIGEST {
            return Err("ecad_claim_deck_digest_invalid".into());
        }
        Ok(digest)
    }
}

#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EcadEligibilityDispositionV1 {
    EvidenceEligible,
    EvidenceNotEstablished,
    Refused,
    Contradictory,
}

#[allow(missing_docs)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EcadEligibilityCheckV1 {
    pub schema: String,
    pub checker_id: String,
    pub deck_id: String,
    pub deck_digest: Sha256Digest,
    pub qualification_artifact_digest: Sha256Digest,
    pub input_id: String,
    pub disposition: EcadEligibilityDispositionV1,
    pub reasons: Vec<String>,
    pub process_exit_was_not_treated_as_result: bool,
    pub grants_authority: bool,
}

/// Return the exact closed SILICON evidence deck.
#[must_use]
#[allow(clippy::missing_panics_doc, clippy::too_many_lines)]
pub fn silicon_orchard_claim_deck() -> EcadClaimDeckV1 {
    let required = [
        (
            "ecad:design-revision",
            "sha256:da1497dac6f872ea70ee4260c1cee22089d03f80295e1935dfe964d885d0014d",
        ),
        (
            "ecad:observed-design-revision",
            "sha256:da1497dac6f872ea70ee4260c1cee22089d03f80295e1935dfe964d885d0014d",
        ),
        (
            "ecad:design-revision-match",
            "sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
        ),
        (
            "ecad:input-artifact",
            "sha256:3b06decef940c7d43bd2c0b3043c0678486ad8798745fe2e28ed2d50d18ed22b",
        ),
        (
            "ecad:license",
            "sha256:8b7092cc4b053d88fdfb7df09c11c9242c36aba5d07e422786913868eda34bfc",
        ),
        (
            "ecad:license-identity",
            "sha256:39b085a4293ef08852bad17c60d5b48c3dc60d3455ec2eef379bc68a1f18249c",
        ),
        (
            "ecad:output-artifact",
            "sha256:856181e9b02a4d668b8bb8ce323ea87478432cbb9c21bc36039053808a230650",
        ),
        (
            "ecad:observed-output-artifact",
            "sha256:856181e9b02a4d668b8bb8ce323ea87478432cbb9c21bc36039053808a230650",
        ),
        (
            "ecad:output-present",
            "sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
        ),
        (
            "ecad:output-digest-match",
            "sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
        ),
        (
            "ecad:pdk-identity",
            "sha256:30610d97535a1f1250d9bde93fc6283c6180a68bff23a8867ac884b2411aa884",
        ),
        (
            "ecad:observed-pdk-identity",
            "sha256:30610d97535a1f1250d9bde93fc6283c6180a68bff23a8867ac884b2411aa884",
        ),
        (
            "ecad:pdk-match",
            "sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
        ),
        (
            "ecad:repository-revision",
            "sha256:1b87225ddb369ca045389f1e35c0261c9da37a0f2a5349cfae9c5cf757b41c31",
        ),
        (
            "ecad:observed-repository-revision",
            "sha256:1b87225ddb369ca045389f1e35c0261c9da37a0f2a5349cfae9c5cf757b41c31",
        ),
        (
            "ecad:repository-revision-match",
            "sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
        ),
        (
            "ecad:scheduler-job",
            "sha256:6e04d52b8f3e9ff40a9df85f7210c7e545034f07fd200fe1f017615a7484597c",
        ),
        (
            "ecad:scheduler-observation",
            "sha256:7093fda846e50b267da144f7b3683ee1dd8838506939f6052b7370dd01fa2ad0",
        ),
        (
            "ecad:stage-occurrence",
            "sha256:f8f7b8d15ae41d676d2b061fe412e526baf55d2350842a739583634586209731",
        ),
        (
            "ecad:stage-name",
            "sha256:2ad47ffa2c44e63f601770d25d4ca879bf9edef3a1ead64bcf60f905f33496f0",
        ),
        (
            "ecad:toolchain-identity",
            "sha256:d0e6563db1ad19ac1aae7fcc67cebeacf33967f7e5b2077d8b63c3a105ab96c9",
        ),
        (
            "ecad:observed-toolchain-identity",
            "sha256:d0e6563db1ad19ac1aae7fcc67cebeacf33967f7e5b2077d8b63c3a105ab96c9",
        ),
        (
            "ecad:toolchain-match",
            "sha256:b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b",
        ),
        (
            "ecad:worker-identity",
            "sha256:0b2c20c7c0d81961ad9f7d31b55dfc5dbd73ed8f3a095e29e0f9d56fd9f964ad",
        ),
        (
            "ecad:worker-observation",
            "sha256:94332144d941eb1212c9af7f968e215a7042bf94925c9c10b21de97a2f0cea06",
        ),
        (
            "ecad:artifact-observed-at",
            "sha256:19466be86fa2441746800c7b345c30db23b919850d8e6d5b57edbd9618570f86",
        ),
        (
            "ecad:process-exit-code",
            "sha256:5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9",
        ),
    ];
    EcadClaimDeckV1 {
        schema: SILICON_ECAD_CLAIM_DECK_SCHEMA_V1.into(),
        deck_id: SILICON_ECAD_DECK_ID.into(),
        checker_id: SILICON_ECAD_CHECKER_ID.into(),
        profile_id: SILICON_ECAD_PROFILE_ID.into(),
        required_claims: required
            .into_iter()
            .map(|(claim_id, expected_value_digest)| EcadRequiredClaimV1 {
                claim_id: claim_id.into(),
                expected_value_digest: Sha256Digest::parse(expected_value_digest)
                    .expect("fixed digest"),
            })
            .collect(),
        requires_full_evidence: true,
        process_exit_alone_is_sufficient: false,
        grants_authority: false,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiliconMonitorBundleV1 {
    schema: String,
    monitor_result_head: String,
    distant_result_head: String,
    entries: Vec<SiliconMonitorEntryV1>,
    distant_traversal: Value,
    nonclaims: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiliconMonitorEntryV1 {
    scenario: String,
    subject_identity_digest: String,
    producer_identity_digest: String,
    signed_monitor_record: Value,
    signed_monitor_record_json: String,
    exact_payload: Option<Value>,
    exact_payload_json: Option<String>,
}

const SILICON_SCENARIOS: [&str; 20] = [
    "nominal",
    "exit-zero-missing-output",
    "digest-mismatch",
    "wrong-design-revision",
    "wrong-revision",
    "wrong-tool",
    "wrong-pdk",
    "license-unavailable-before-start",
    "license-no-response",
    "healthy-wrong-subject",
    "worker-loss",
    "repository-custody-historical",
    "repository-custody-successor",
    "scheduler-running-source",
    "worker-absent-source",
    "scheduler-contradiction-a",
    "scheduler-contradiction-b",
    "stale-artifact",
    "delayed-duplicate-delivery",
    "agent-contradiction",
];

fn exact_value_keys(value: &Value, expected: &[&str]) -> Result<(), String> {
    let actual = value
        .as_object()
        .ok_or_else(|| "silicon_custody_object_invalid".to_owned())?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err("silicon_custody_fields_invalid".into());
    }
    Ok(())
}

fn retained_object(reference: &Value, domain: &str) -> Result<Value, String> {
    exact_value_keys(reference, &["digest", "byte_length", "bytes_hex"])?;
    let bytes = hex::decode(
        reference
            .get("bytes_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| "silicon_retained_bytes_invalid".to_owned())?,
    )
    .map_err(|_| "silicon_retained_bytes_invalid".to_owned())?;
    if reference.get("byte_length").and_then(Value::as_u64) != Some(bytes.len() as u64)
        || reference.get("digest").and_then(Value::as_str)
            != Some(crate::operational_qualification::monitor_digest(domain, &[&bytes]).as_str())
    {
        return Err("silicon_retained_content_binding_invalid".into());
    }
    let parsed: Value =
        serde_json::from_slice(&bytes).map_err(|_| "silicon_retained_json_invalid".to_owned())?;
    if canonical_json_bytes(&parsed).map_err(|_| "silicon_retained_json_invalid".to_owned())?
        != bytes
    {
        return Err("silicon_retained_json_noncanonical".into());
    }
    Ok(parsed)
}

struct DistantIntakeV1 {
    observation: Vec<u8>,
    payload: Vec<u8>,
    received_at: DateTime<Utc>,
}

#[allow(clippy::too_many_lines)]
fn validate_distant_custody(
    traversal: &Value,
    delayed: &SiliconMonitorEntryV1,
) -> Result<DistantIntakeV1, String> {
    exact_value_keys(
        traversal,
        &[
            "schema",
            "source_scenario",
            "message",
            "receiver_policy",
            "partition_attempt_record",
            "first_custody_attempt_record",
            "retry_custody_attempt_record",
            "first_custody_receipt",
            "replayed_custody_receipt",
            "retained_receiver_inbox",
            "retained_receiver_receipt",
            "retained_receiver_lineage",
            "retained_sender_attempts",
            "retained_sender_delivered",
            "sender_pending_ids_after_reopen",
            "duplicate_converged",
            "grants_authority",
        ],
    )?;
    if traversal["schema"] != "monitor.ecad-distant-traversal-evidence/v1"
        || traversal["source_scenario"] != "delayed-duplicate-delivery"
        || traversal["duplicate_converged"] != true
        || traversal["grants_authority"] != false
        || traversal["sender_pending_ids_after_reopen"]
            .as_array()
            .is_none_or(|values| !values.is_empty())
    {
        return Err("silicon_distant_disposition_invalid".into());
    }
    let message = &traversal["message"];
    let observation = hex::decode(
        message["body"]["observation"]["bytes_hex"]
            .as_str()
            .ok_or_else(|| "silicon_distant_observation_invalid".to_owned())?,
    )
    .map_err(|_| "silicon_distant_observation_invalid".to_owned())?;
    let payload = hex::decode(
        message["body"]["payload"]["bytes_hex"]
            .as_str()
            .ok_or_else(|| "silicon_distant_payload_invalid".to_owned())?,
    )
    .map_err(|_| "silicon_distant_payload_invalid".to_owned())?;
    if observation != delayed.signed_monitor_record_json.as_bytes()
        || payload
            != delayed
                .exact_payload_json
                .as_deref()
                .ok_or_else(|| "silicon_distant_payload_missing".to_owned())?
                .as_bytes()
        || message["body"]["observation"]["byte_length"].as_u64() != Some(observation.len() as u64)
        || message["body"]["observation"]["digest"].as_str()
            != Some(
                crate::operational_qualification::monitor_digest(
                    "store-forward.observation-bytes.v1",
                    &[&observation],
                )
                .as_str(),
            )
        || message["body"]["payload"]["byte_length"].as_u64() != Some(payload.len() as u64)
        || message["body"]["payload"]["digest"].as_str()
            != Some(
                crate::operational_qualification::monitor_digest(
                    "operational.content.v1",
                    &[&payload],
                )
                .as_str(),
            )
    {
        return Err("silicon_distant_source_binding_invalid".into());
    }
    let first_receipt = &traversal["first_custody_receipt"];
    let replayed_receipt = &traversal["replayed_custody_receipt"];
    if first_receipt != replayed_receipt
        || first_receipt["body"]["message_id"] != message["message_id"]
        || first_receipt["body"]["source_observation_id"]
            != message["body"]["source_observation_id"]
        || first_receipt["body"]["source_observation_bytes_digest"]
            != message["body"]["observation"]["digest"]
        || first_receipt["body"]["signed_message_digest"]
            != "sha256:0dee02721577328d5669805d4595dfd72836a937938a5e0f2d0667c4a55f7be1"
        || first_receipt["body"]["admission_policy_digest"]
            != "sha256:c1025968b89b56f397681fb99e5bdff48cc24557a1a8a956d3df49161adae818"
        || first_receipt["body"]["scope"] != "transport_custody_only"
    {
        return Err("silicon_distant_receipt_binding_invalid".into());
    }
    let partition = &traversal["partition_attempt_record"];
    let first = &traversal["first_custody_attempt_record"];
    let retry = &traversal["retry_custody_attempt_record"];
    if partition["delivery"]["message"] != *message
        || first["delivery"]["message"] != *message
        || retry["delivery"]["message"] != *message
        || partition["outcome"] != "partition"
        || !partition["receipt"].is_null()
        || first["outcome"] != "custody_confirmed"
        || first["receipt"] != *first_receipt
        || retry["outcome"] != "custody_confirmed"
        || retry["receipt"] != *replayed_receipt
    {
        return Err("silicon_distant_attempt_binding_invalid".into());
    }
    let inbox = retained_object(
        &traversal["retained_receiver_inbox"],
        "ecad.retained-receiver-inbox.v1",
    )?;
    let receipt = retained_object(
        &traversal["retained_receiver_receipt"],
        "ecad.retained-receiver-receipt.v1",
    )?;
    let lineage = retained_object(
        &traversal["retained_receiver_lineage"],
        "ecad.retained-receiver-lineage.v1",
    )?;
    let delivered = retained_object(
        &traversal["retained_sender_delivered"],
        "ecad.retained-sender-delivered.v1",
    )?;
    if inbox["message"] != *message
        || inbox["first_attempt_id"] != "attempt:silicon-wire:first-custody"
        || inbox["first_received_at"] != first_receipt["body"]["received_at"]
        || receipt != *first_receipt
        || delivered != *first_receipt
        || lineage["claim"]["message_id"] != message["message_id"]
        || lineage["custody_receipt"] != *first_receipt
    {
        return Err("silicon_distant_retained_graph_invalid".into());
    }
    let retained_attempts = traversal["retained_sender_attempts"]
        .as_array()
        .ok_or_else(|| "silicon_distant_attempt_tree_invalid".to_owned())?;
    if retained_attempts.len() != 3 {
        return Err("silicon_distant_attempt_tree_invalid".into());
    }
    let retained_attempts = retained_attempts
        .iter()
        .map(|retained| retained_object(retained, "ecad.retained-sender-attempt.v1"))
        .collect::<Result<Vec<_>, _>>()?;
    if [partition, first, retry]
        .iter()
        .any(|expected| !retained_attempts.contains(expected))
    {
        return Err("silicon_distant_attempt_tree_invalid".into());
    }
    let received_at = DateTime::parse_from_rfc3339(
        first_receipt["body"]["received_at"]
            .as_str()
            .ok_or_else(|| "silicon_distant_receipt_time_invalid".to_owned())?,
    )
    .map_err(|_| "silicon_distant_receipt_time_invalid".to_owned())?
    .with_timezone(&Utc);
    Ok(DistantIntakeV1 {
        observation,
        payload,
        received_at,
    })
}

fn exact_silicon_bundle(
    monitor_fixture_head: &str,
    exact_bundle_bytes: &[u8],
) -> Result<SiliconMonitorBundleV1, String> {
    if monitor_fixture_head != SILICON_MONITOR_FIXTURE_HEAD {
        return Err("silicon_monitor_fixture_head_mismatch".into());
    }
    if exact_bundle_bytes.len() > 1024 * 1024
        || sha256_bytes(exact_bundle_bytes).as_str() != SILICON_MONITOR_BUNDLE_DIGEST
    {
        return Err("silicon_monitor_bundle_digest_mismatch".into());
    }
    let bundle: SiliconMonitorBundleV1 = serde_json::from_slice(exact_bundle_bytes)
        .map_err(|_| "silicon_monitor_bundle_malformed".to_owned())?;
    let scenarios = bundle
        .entries
        .iter()
        .map(|entry| entry.scenario.as_str())
        .collect::<Vec<_>>();
    if bundle.schema != "monitor.ecad-golden-fixture/v1"
        || bundle.monitor_result_head != FIELD_CLOCK_MONITOR_RESULT_HEAD
        || bundle.distant_result_head != SILICON_DISTANT_RESULT_HEAD
        || scenarios != SILICON_SCENARIOS
        || bundle.nonclaims
            != [
                "process exit is not an ECAD result",
                "transport custody is not claim support or currentness",
                "fixture testimony grants no remediation or target-effect authority",
            ]
    {
        return Err("silicon_monitor_bundle_contract_mismatch".into());
    }
    let delayed = bundle
        .entries
        .iter()
        .find(|entry| entry.scenario == "delayed-duplicate-delivery")
        .ok_or_else(|| "silicon_delayed_input_missing".to_owned())?;
    validate_distant_custody(&bundle.distant_traversal, delayed)?;
    for entry in &bundle.entries {
        let record: Value = serde_json::from_str(&entry.signed_monitor_record_json)
            .map_err(|_| "silicon_monitor_entry_record_invalid".to_owned())?;
        let payload = entry
            .exact_payload_json
            .as_deref()
            .map(serde_json::from_str::<Value>)
            .transpose()
            .map_err(|_| "silicon_monitor_entry_payload_invalid".to_owned())?;
        if record != entry.signed_monitor_record || payload != entry.exact_payload {
            return Err("silicon_monitor_entry_raw_binding_invalid".into());
        }
        let input = silicon_input(&bundle, &entry.scenario)?;
        let qualified = crate::qualify_operational_observations(
            &silicon_orchard_ecad_profile(),
            &[input],
            Utc.with_ymd_and_hms(2026, 8, 30, 16, 40, 0)
                .single()
                .expect("fixed NQ qualification time"),
        )
        .map_err(|error| error.to_string())?;
        let reopened = &qualified.inputs[0];
        if reopened.subject_identity_digest.as_deref() != Some(&entry.subject_identity_digest)
            || reopened.producer_identity_digest.as_deref() != Some(&entry.producer_identity_digest)
        {
            return Err("silicon_monitor_entry_provenance_invalid".into());
        }
    }
    Ok(bundle)
}

fn silicon_group(scenario: &str) -> Result<Vec<&'static str>, String> {
    match scenario {
        "scheduler-running-source" | "worker-absent-source" => {
            Ok(vec!["scheduler-running-source", "worker-absent-source"])
        }
        "scheduler-contradiction-a" | "scheduler-contradiction-b" | "agent-contradiction" => {
            Ok(vec![
                "scheduler-contradiction-a",
                "scheduler-contradiction-b",
                "agent-contradiction",
            ])
        }
        value if SILICON_SCENARIOS.contains(&value) => Ok(vec![
            SILICON_SCENARIOS
                .iter()
                .copied()
                .find(|candidate| *candidate == value)
                .expect("closed scenario"),
        ]),
        _ => Err("ecad_checker_input_missing".into()),
    }
}

fn silicon_input(
    bundle: &SiliconMonitorBundleV1,
    scenario: &str,
) -> Result<crate::OperationalEvidenceInputV1, String> {
    let entry = bundle
        .entries
        .iter()
        .find(|entry| entry.scenario == scenario)
        .ok_or_else(|| "ecad_checker_input_missing".to_owned())?;
    let (signed_monitor_record, payload_bytes, receiver_custody_at) =
        if scenario == "delayed-duplicate-delivery" {
            let intake = validate_distant_custody(&bundle.distant_traversal, entry)?;
            (intake.observation, Some(intake.payload), intake.received_at)
        } else {
            (
                entry.signed_monitor_record_json.as_bytes().to_vec(),
                entry
                    .exact_payload_json
                    .as_ref()
                    .map(|payload| payload.as_bytes().to_vec()),
                Utc.with_ymd_and_hms(2026, 8, 30, 16, 30, 0)
                    .single()
                    .expect("fixed NQ custody time"),
            )
        };
    Ok(crate::OperationalEvidenceInputV1 {
        input_id: format!("silicon:{scenario}"),
        signed_monitor_record,
        payload_bytes,
        receiver_custody_at,
    })
}

fn recompute_silicon_qualification(
    bundle: &SiliconMonitorBundleV1,
    input_id: &str,
) -> Result<crate::OperationalQualificationArtifactV1, String> {
    let scenario = input_id
        .strip_prefix("silicon:")
        .ok_or_else(|| "ecad_checker_input_missing".to_owned())?;
    let inputs = silicon_group(scenario)?
        .into_iter()
        .map(|member| silicon_input(bundle, member))
        .collect::<Result<Vec<_>, _>>()?;
    crate::qualify_operational_observations(
        &silicon_orchard_ecad_profile(),
        &inputs,
        Utc.with_ymd_and_hms(2026, 8, 30, 16, 40, 0)
            .single()
            .expect("fixed NQ qualification time"),
    )
    .map_err(|error| error.to_string())
}

/// Check one qualified input against the exact closed deck.
///
/// # Errors
/// Returns an error when deck, profile, or input identity is invalid.
pub fn check_silicon_orchard_eligibility(
    monitor_fixture_head: &str,
    exact_monitor_bundle_bytes: &[u8],
    deck: &EcadClaimDeckV1,
    artifact: &crate::OperationalQualificationArtifactV1,
    input_id: &str,
) -> Result<EcadEligibilityCheckV1, String> {
    deck.validate()?;
    silicon_orchard_ecad_profile()
        .validate()
        .map_err(|error| error.to_string())?;
    let bundle = exact_silicon_bundle(monitor_fixture_head, exact_monitor_bundle_bytes)?;
    let recomputed = recompute_silicon_qualification(&bundle, input_id)?;
    if artifact != &recomputed {
        return Err("ecad_checker_qualification_artifact_mismatch".into());
    }
    if artifact.profile_id != deck.profile_id {
        return Err("ecad_checker_profile_mismatch".into());
    }
    let input = artifact
        .inputs
        .iter()
        .find(|value| value.input_id == input_id)
        .ok_or_else(|| "ecad_checker_input_missing".to_owned())?;
    let has_contradiction = artifact
        .contradictions
        .iter()
        .any(|value| value.first_input_id == input_id || value.second_input_id == input_id);
    let expected: BTreeMap<_, _> = deck
        .required_claims
        .iter()
        .map(|value| (&value.claim_id, &value.expected_value_digest))
        .collect();
    let actual: BTreeMap<_, _> = input
        .claim_support
        .iter()
        .map(|value| (&value.claim_id, &value.value_digest))
        .collect();
    let actual_domain: BTreeSet<_> = actual.keys().copied().collect();
    let expected_domain: BTreeSet<_> = expected.keys().copied().collect();
    let (disposition, reasons) = if !input.refusals.is_empty() {
        (
            EcadEligibilityDispositionV1::Refused,
            vec!["nq input was refused".into()],
        )
    } else if has_contradiction {
        (
            EcadEligibilityDispositionV1::Contradictory,
            vec!["qualified inputs retain an unresolved contradiction".into()],
        )
    } else if !input.cannot_testify.is_empty() {
        (
            EcadEligibilityDispositionV1::EvidenceNotEstablished,
            vec!["NQ cannot testify to the complete claim deck".into()],
        )
    } else if actual_domain != expected_domain {
        (
            EcadEligibilityDispositionV1::EvidenceNotEstablished,
            vec!["qualified claim domain is incomplete or widened".into()],
        )
    } else if expected
        .iter()
        .any(|(claim_id, digest)| actual.get(claim_id) != Some(digest))
    {
        (
            EcadEligibilityDispositionV1::EvidenceNotEstablished,
            vec!["one or more exact claim values differ from the deck".into()],
        )
    } else {
        (EcadEligibilityDispositionV1::EvidenceEligible, vec![])
    };
    Ok(EcadEligibilityCheckV1 {
        schema: SILICON_ECAD_ELIGIBILITY_SCHEMA_V1.into(),
        checker_id: deck.checker_id.clone(),
        deck_id: deck.deck_id.clone(),
        deck_digest: deck.deck_digest()?,
        qualification_artifact_digest: artifact
            .artifact_digest()
            .map_err(|value| value.to_string())?,
        input_id: input_id.into(),
        disposition,
        reasons,
        process_exit_was_not_treated_as_result: true,
        grants_authority: false,
    })
}
