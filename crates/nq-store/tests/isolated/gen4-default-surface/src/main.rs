use nq_runtime_dependency_authority::test_support::RawAuthorityFixture;
use nq_store::Store;

fn main() {
    let _ = RawAuthorityFixture::fresh_genesis();
    let _ = Store::initialize("default-surface.db");
}
