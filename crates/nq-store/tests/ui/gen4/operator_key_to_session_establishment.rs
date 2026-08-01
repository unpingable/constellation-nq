use ed25519_dalek::SigningKey;
use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::StoreWriterSession;

fn establish_from_operator_key<'store, 'id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
    operator_key: &SigningKey,
) {
    let _ = session.establish_runtime_dependency_trust_root(operator_key);
}

fn main() {}
