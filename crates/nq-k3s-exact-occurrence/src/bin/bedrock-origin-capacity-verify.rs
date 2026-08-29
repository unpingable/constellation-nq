//! Independent BEDROCK Stage-A origin/capacity verification executable.

use std::io::{self, Read, Write};

use ed25519_dalek::VerifyingKey;
use nq_k3s_exact_occurrence::node_observation::{
    DeferredRuntimeCapacityV1, NodeObservationBasisV1, NodeObservationContractV1,
    QualifiedPreRuntimeContextV1, SignedNodeObservationV1,
};
use nq_protocol::canonical_json_bytes;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationInputV1 {
    schema: String,
    contract: NodeObservationContractV1,
    basis: NodeObservationBasisV1,
    signed_observation: SignedNodeObservationV1,
    observer_public_key_hex: String,
    verify_at_unix_ms: u64,
}

#[derive(Serialize)]
struct VerificationOutputV1 {
    schema: &'static str,
    pre_runtime: QualifiedPreRuntimeContextV1,
    deferred_runtime: DeferredRuntimeCapacityV1,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("BEDROCK origin/capacity verification refused: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() != 1 {
        return Err("no arguments are accepted".into());
    }
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let input: VerificationInputV1 = serde_json::from_slice(&bytes)?;
    if input.schema != "nq.bedrock_origin_capacity_verification_input.v1" {
        return Err("closed input schema mismatch".into());
    }
    if canonical_json_bytes(&input)? != bytes {
        return Err("input is not exact canonical JCS".into());
    }
    let key_bytes: [u8; 32] = hex::decode(&input.observer_public_key_hex)?
        .try_into()
        .map_err(|_| "observer public key length")?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    let (pre_runtime, deferred_runtime) = input.signed_observation.verify_pre_runtime(
        &input.basis,
        &input.contract,
        &key,
        input.verify_at_unix_ms,
    )?;
    let output = VerificationOutputV1 {
        schema: "nq.bedrock_origin_capacity_verification_output.v1",
        pre_runtime,
        deferred_runtime,
    };
    io::stdout().write_all(&canonical_json_bytes(&output)?)?;
    Ok(())
}
