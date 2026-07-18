//! The only identity-injection seam is `#[cfg(test)]` and crate-private, so an
//! external caller cannot open an engine with a supplied (fabricated) identity;
//! production identity comes solely from the platform provider inside `open`.

use nq_core::CollectionEngine;

fn main() {
    let _engine = CollectionEngine::open_with_evaluator_identity(todo!(), todo!());
}
