//! A downstream caller cannot supply caller-selected production identity and a
//! raw binding callback. Only the opaque governed-grant bridge may execute.

use nq_core::{CollectionEngine, WatcherConfig};

#[allow(dead_code)]
fn forge(engine: &mut CollectionEngine, watcher: &WatcherConfig) {
    let _ = CollectionEngine::diagnostic_execute_bound(engine, watcher);
}

fn main() {}
