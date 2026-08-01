#![allow(unreachable_code)]

use nq_runtime_dependency_authority::{ResolvedControllingActivation, VerificationBrand};

fn construct<'id>(brand: &VerificationBrand<'id>) {
    let _: ResolvedControllingActivation<'id> = ResolvedControllingActivation::new(todo!(), brand);
}

fn main() {}
