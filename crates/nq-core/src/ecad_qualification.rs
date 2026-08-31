//! Closed NQ claim profile for the SILICON-ORCHARD open ECAD corpus.

use crate::{
    AcceptedProducerIdentityV1, FIELD_CLOCK_MONITOR_RESULT_HEAD, OperationalClaimRuleV1,
    OperationalQualificationProfileV1,
};

/// Exact Monitor fixture-generator checkpoint.
pub const SILICON_MONITOR_FIXTURE_HEAD: &str = "f7172835e1ed67df27ac0e8df4789342f0082394";
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
            "sha256:2964f2e50aa7134d82dbfb55a608370098b582e0701769c27b953877168c60a1",
            "sha256:2ae08e42382e6d7b9a3e36da695c4bc2f01bbd08e41b869dcfafd4c073f940dd",
            "sha256:5e1990110d8ddec3d70e99f2dcdf8909c695a78baaa912a06c2dbe9dae28727b",
            "sha256:685aa649b2e95ec91dc6149315803ee10f4d626e11c8adfd2f0e7486fd50e628",
            "sha256:7e7040ead4320585d40a35947ad85d27903729f5c589c510eac6744128e49e4f",
            "sha256:919aef93f266c571cac2fdb766b3ee22c5e8a5ec4ed605c1c2b55b1bb20a9ebb",
            "sha256:9a29016cdccc13b47c88ffb7e508c646bfbf18dac4e13712d8d81a97dd3e5f5a",
            "sha256:ee770dd947948627c2aaaf74a9f53b67f6be02b1a92dc9f19532a969047db0c9",
            "sha256:f4f24b5d869622878e9efcc09e628156507be3fd1debafc03dc54adb69551ce2",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        accepted_producer_identities: [
            "sha256:62632d93d8a1cb13ab7cc4d610a90e36288b67f4e7de111681bf5d6c1dc7524a",
            "sha256:ccb20e5849f69961e1a905a3af160383ffbbadeb80cd93d248bb932f10aca819",
        ]
        .into_iter()
        .map(|producer_identity_digest| AcceptedProducerIdentityV1 {
            principal_id: "producer:silicon-orchard".into(),
            producer_identity_digest: producer_identity_digest.into(),
            public_key_digest:
                "sha256:23d536e9bc640cfdc8856a8662c1ac3fc45e3c6fd3980e96c6ad95cf26a79c2f".into(),
        })
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
