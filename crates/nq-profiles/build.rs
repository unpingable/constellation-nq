//! Conservative source-closure digest for the compiled semantics.
//!
//! The compiled meaning of an admission spans two crates: `nq-profiles`
//! (profiles + shared admission machinery) and `nq-protocol` (the
//! canonicalization admission delegates to). This script hashes both source
//! trees, plus this crate's build script, every workspace manifest (enabled
//! Cargo features change protocol decoding/canonicalization via feature
//! unification and are not recorded in the lockfile), the workspace lockfile
//! (pinned dependency versions), and the toolchain file (compiler version),
//! into `NQ_PROFILES_SOURCE_DIGEST`.
//!
//! It is fail-closed against *omission* — walking directories means a newly
//! added law file cannot be silently dropped — and deliberately conservative: it
//! is crate-global and over-includes (comments, unrelated dependency bumps),
//! which is far safer than letting a behavior-changing edit escape. It is NOT
//! dependency-graph transitive: it hashes the whole source tree of the two
//! law-bearing crates rather than parsing the `mod`/`use` graph. Paths are hashed
//! relative to the workspace root so the digest is reproducible across machines.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

fn main() {
    let crate_root =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let workspace_root = crate_root
        .parent()
        .and_then(Path::parent)
        .expect("crate lives at <workspace>/crates/<name>")
        .to_path_buf();

    let mut files = Vec::new();
    collect_rs(&workspace_root.join("crates/nq-profiles/src"), &mut files);
    collect_rs(&workspace_root.join("crates/nq-protocol/src"), &mut files);
    files.push(workspace_root.join("crates/nq-profiles/build.rs"));
    // Every workspace manifest: enabled Cargo features change protocol decoding
    // and canonicalization via feature unification, and are NOT recorded in
    // Cargo.lock. The lockfile pins versions; the toolchain file pins rustc.
    files.push(workspace_root.join("Cargo.toml"));
    collect_manifests(&workspace_root.join("crates"), &mut files);
    files.push(workspace_root.join("Cargo.lock"));
    files.push(workspace_root.join("rust-toolchain.toml"));
    files.sort();
    files.dedup();

    let mut hasher = Sha256::new();
    for file in &files {
        let relative = file
            .strip_prefix(&workspace_root)
            .expect("closure input is inside the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(file).unwrap_or_else(|error| {
            panic!(
                "cannot read source-closure input {}: {error}",
                file.display()
            )
        });
        let length = u64::try_from(bytes.len()).expect("closure input fits u64");
        hasher.update(relative.as_bytes());
        hasher.update([0u8]);
        hasher.update(length.to_le_bytes());
        hasher.update(&bytes);
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/nq-profiles/src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates/nq-protocol/src").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root.join("crates").display()
    );

    let digest = hex::encode(hasher.finalize());
    println!("cargo:rustc-env=NQ_PROFILES_SOURCE_DIGEST=sha256:{digest}");
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read source dir {}: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn collect_manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read crate dir {}: {error}", dir.display()));
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_manifests(&path, out);
        } else if path.file_name().is_some_and(|name| name == "Cargo.toml") {
            out.push(path);
        }
    }
}
