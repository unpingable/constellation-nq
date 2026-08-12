//! Pass control: inert public evidence remains usable and serializable.
//!
//! Successful compilation demonstrates that the negative cases fail at the
//! live authority boundary, not because byte arrays, digests, detached
//! signatures, or serialization are generally unavailable.

use nq_protocol::sha256_bytes;
use nq_store::store_generation::records::Ed25519SignatureBytesV1;

fn main() {
    let manifest_digest = sha256_bytes(b"caller-observed manifest evidence");
    let raw_frontier = 7_u64;
    let raw_custody_proof = vec![0_u8; 64];
    let detached_signature =
        Ed25519SignatureBytesV1::from_lower_hex("00".repeat(64)).expect("structural signature");
    let serialized = serde_json::to_vec(&(
        manifest_digest,
        raw_frontier,
        raw_custody_proof,
        detached_signature,
    ))
    .expect("serialize inert evidence");
    assert!(!serialized.is_empty());
}
