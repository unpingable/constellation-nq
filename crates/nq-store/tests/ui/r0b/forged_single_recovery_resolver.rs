use nq_protocol::Sha256Digest;
use nq_store::Store;

fn inject(store: &mut Store, reservation: &Sha256Digest, forged_resolution: ()) {
    let _ = store
        .begin_writer_session()
        .expect("writer session")
        .recover_governed_projection_and_mark_indexed(reservation, forged_resolution);
}

fn main() {}
