use nq_protocol::Sha256Digest;
use nq_store::Store;

fn inject(store: &Store, reservation: &Sha256Digest, forged_resolution: ()) {
    let _ = store.verify_governed_projection_and_mark_indexed(reservation, forged_resolution);
}

fn main() {}
