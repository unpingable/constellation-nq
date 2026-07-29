//! Test-only exact transport checks for the retired raw collection surface.
//!
//! The shipped application no longer exposes raw collection or daemon
//! invocation. These checks retain the serialization/refusal qualification
//! that guarded the former surface without keeping that surface reachable in
//! production.

use anyhow::{Result, bail};
use nq_core::{CollectionOutcome, decode_collection_outcome_ndjson};

/// One canonical collection-result frame reopened before use.
#[derive(Debug)]
pub(crate) struct CollectionOutcomeFrame {
    wire: Vec<u8>,
    reopened: CollectionOutcome,
}

impl CollectionOutcomeFrame {
    fn encode(outcome: &CollectionOutcome) -> Result<Self> {
        outcome.validate()?;
        let wire = nq_protocol::encode_ndjson(outcome)?;
        let max_frame_bytes = nq_store::MAX_STORED_JSON_BYTES
            .checked_add(1)
            .expect("stored JSON bound leaves room for one framing byte");
        let reopened = decode_collection_outcome_ndjson(&wire, max_frame_bytes)?;
        if &reopened != outcome {
            bail!("strictly reopened collection-result frame differs from its source object");
        }
        Ok(Self { wire, reopened })
    }

    fn wire(&self) -> &[u8] {
        &self.wire
    }

    fn reopened(&self) -> &CollectionOutcome {
        &self.reopened
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_v2_outbound_frame_is_exactly_reopenable() {
        let outcome = CollectionOutcome::admitted(
            "transport.instance".to_owned(),
            "run-transport".to_owned(),
            "report-transport".to_owned(),
            "complete".to_owned(),
            nq_protocol::sha256_bytes(b"transport-report").into_string(),
            Vec::new(),
        );

        let frame = CollectionOutcomeFrame::encode(&outcome).expect("encode and reopen V2");
        assert_eq!(frame.reopened(), &outcome);
        assert_eq!(
            frame.wire(),
            nq_protocol::encode_ndjson(&outcome)
                .expect("independent canonical frame")
                .as_slice()
        );
        assert_eq!(frame.wire().last(), Some(&b'\n'));
        assert!(!frame.wire()[..frame.wire().len() - 1].contains(&b'\n'));
    }

    #[test]
    fn invalid_outbound_result_is_refused_before_serialization() {
        let mut outcome = CollectionOutcome::admitted(
            "transport.instance".to_owned(),
            "run-transport".to_owned(),
            "report-transport".to_owned(),
            "complete".to_owned(),
            nq_protocol::sha256_bytes(b"transport-report").into_string(),
            Vec::new(),
        );
        outcome.run_id = None;

        let error = CollectionOutcomeFrame::encode(&outcome)
            .expect_err("invalid result must not cross the boundary");
        assert!(error.to_string().contains("requires a run identity"));
    }
}
