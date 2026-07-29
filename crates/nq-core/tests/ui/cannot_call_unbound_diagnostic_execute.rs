//! A downstream caller cannot emit an unbound diagnostic from configuration
//! alone. Production execution requires an opaque governed runtime grant.

use nq_core::{CollectionEngine, WatcherConfig};

#[allow(dead_code)]
fn forge(engine: &mut CollectionEngine, watcher: &WatcherConfig) {
    let _ = CollectionEngine::diagnostic_execute(engine, watcher);
}

fn main() {}
