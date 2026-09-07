//! Exact campaign-owned service-subject reopening for operator-beta profiles.

use nq_protocol::Sha256Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub(crate) const SCHEMA: &str = "constellation.operator_beta.service_subject.v1";
pub(crate) const CAMPAIGN_ID: &str = "constellation-operator-beta-2026";
pub(crate) const UNIT_NAME: &str = "constellation-beta-http-fixture.service";
const DIGEST_DOMAIN: &str = "constellation/operator-beta/service-subject/v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceSubject {
    pub(crate) schema: String,
    pub(crate) campaign_id: String,
    pub(crate) fixture_run_id: String,
    pub(crate) target_machine_identity: String,
    pub(crate) unit_name: String,
    pub(crate) unit_file_sha256: Sha256Digest,
}

impl ServiceSubject {
    pub(crate) fn parse(value: &Value) -> Result<Self, String> {
        let subject: Self = serde_json::from_value(value.clone())
            .map_err(|error| format!("invalid operator-beta service subject: {error}"))?;
        if subject.schema != SCHEMA
            || subject.campaign_id != CAMPAIGN_ID
            || subject.fixture_run_id.is_empty()
            || subject.fixture_run_id.len() > 255
            || subject.target_machine_identity.is_empty()
            || subject.target_machine_identity.len() > 512
            || subject.unit_name != UNIT_NAME
        {
            return Err(
                "operator-beta service subject violates its closed identity or bounds".into(),
            );
        }
        Ok(subject)
    }

    pub(crate) fn identity(&self) -> Result<String, String> {
        let bytes = nq_protocol::canonical_json_bytes(self).map_err(|error| error.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(b"ag-ng\0digest\0v1\0");
        hasher.update((DIGEST_DOMAIN.len() as u128).to_be_bytes());
        hasher.update(DIGEST_DOMAIN.as_bytes());
        hasher.update((bytes.len() as u128).to_be_bytes());
        hasher.update(bytes);
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }
}
