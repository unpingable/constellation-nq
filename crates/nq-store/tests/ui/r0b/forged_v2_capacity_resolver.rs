use nq_protocol::Sha256Digest;
use nq_store::{GovernedCustodyReservation, Store};

fn inject(
    store: &Store,
    reservation: &GovernedCustodyReservation,
    launch: &Sha256Digest,
    forged_resolution: (),
) {
    let _ = store.verify_governed_execution_custody_closure_v2_capacity(
        reservation,
        launch,
        forged_resolution,
    );
}

fn main() {}
