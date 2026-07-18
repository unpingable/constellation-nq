//! The fixture constructor is `#[cfg(test)]` and crate-private, so it does not
//! exist for any external caller — test-only fixtures cannot leak into
//! production code paths.

use nq_core::EvaluatorRuntimeIdentity;

fn main() {
    let _fixture = EvaluatorRuntimeIdentity::for_test(todo!());
}
