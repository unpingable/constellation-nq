//! Emits the compile-time build target triple so the evaluator identity records
//! the target it was actually built for, rather than reconstructing it from
//! `uname` at runtime.

fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=NQ_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
