//! A downstream caller cannot launch a provider through the raw collection
//! seam. That helper remains available only to nq-core's internal tests.

use nq_core::{CollectionEngine, WatcherConfig};

#[allow(dead_code)]
fn forge(engine: &mut CollectionEngine, watcher: &WatcherConfig) {
    let _ = CollectionEngine::collect(engine, watcher);
}

fn main() {}
