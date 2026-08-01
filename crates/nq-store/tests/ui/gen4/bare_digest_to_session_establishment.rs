use nq_protocol::Sha256Digest;
use nq_runtime_dependency_authority::VerificationBrand;
use nq_store::StoreWriterSession;

fn establish_from_digest<'store, 'id>(
    session: &mut StoreWriterSession<'store, VerificationBrand<'id>>,
    digest: &Sha256Digest,
) {
    let _ = session.establish_runtime_dependency_trust_root(digest);
}

fn main() {}
