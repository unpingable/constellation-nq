//! Fail-closed source-closure digest for the compiled semantics crate.
//!
//! Walks the entire crate source tree (plus this script and the manifest) and
//! hashes it into `NQ_PROFILES_SOURCE_DIGEST`. Because it walks the directory
//! rather than a hand-listed set, a newly added law file cannot be silently
//! omitted from the evaluator's semantic identity. Paths are hashed relative to
//! the crate root so the digest is reproducible across machines.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let mut files = Vec::new();
    collect_rs(&root.join("src"), &mut files);
    files.push(root.join("build.rs"));
    files.push(root.join("Cargo.toml"));
    files.sort();

    let mut hasher = Sha256::new();
    for file in &files {
        let relative = file
            .strip_prefix(&root)
            .expect("source file is inside the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(file).unwrap_or_else(|error| {
            panic!("cannot read source-closure input {}: {error}", file.display())
        });
        let length = u64::try_from(bytes.len()).expect("source file fits u64");
        hasher.update(relative.as_bytes());
        hasher.update([0u8]);
        hasher.update(length.to_le_bytes());
        hasher.update(&bytes);
        println!("cargo:rerun-if-changed={}", file.display());
    }
    println!("cargo:rerun-if-changed=src");

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
