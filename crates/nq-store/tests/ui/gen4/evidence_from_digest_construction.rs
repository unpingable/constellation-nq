use nq_protocol::Sha256Digest;
use nq_runtime_dependency_authority::ResolvedControllingActivation;

fn construct(digest: Sha256Digest) {
    let _: ResolvedControllingActivation<'static> =
        ResolvedControllingActivation::from_digest(digest);
}

fn main() {}
