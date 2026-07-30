use nq_host_role_dependency_custody::{Ed25519TrustAnchor, SignedAdmissionReceiptSet};

fn main() {
    let _ = SignedAdmissionReceiptSet::fixture_signed;
    let _ = Ed25519TrustAnchor::fixture;
}
