use nq_store::Store;

fn main() {
    let _ = Store::initialize_runtime_authority_candidate("ungoverned.db");
}
