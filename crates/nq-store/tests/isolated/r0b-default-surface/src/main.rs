use nq_host_role_dependency_custody::{
    SignedAdmissionReceiptSet, test_support::authenticated_runtime_fixture,
};

fn main() {
    let _ = authenticated_runtime_fixture;
    let _ = SignedAdmissionReceiptSet::fixture_signed;
}
