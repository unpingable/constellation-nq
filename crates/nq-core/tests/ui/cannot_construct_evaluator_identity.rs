//! An external caller must not be able to hand-build a "trusted" evaluator
//! identity from a struct literal: the fields are private.

use nq_core::EvaluatorRuntimeIdentity;

fn main() {
    let _forged = EvaluatorRuntimeIdentity {
        artifact_digest: todo!(),
        target_triple: String::new(),
        artifact_identity_method: String::from("fixture"),
        platform_runtime_version: String::new(),
    };
}
