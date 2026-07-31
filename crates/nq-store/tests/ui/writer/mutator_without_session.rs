use nq_store::{CollectionInput, Store};

fn bypass(store: &mut Store, collection: &CollectionInput) {
    let _ = store.commit_collection(collection);
}

fn main() {}
