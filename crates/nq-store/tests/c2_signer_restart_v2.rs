//! Process-boundary and public-substrate restart evidence retained from Matrix
//! V3 rows SG-WU-07, SG-N-30, SCF-17, and CSH-10.
//!
//! Anchors implemented here: `v2-sg-wu-07-restart-recovery`,
//! `v2-sg-n-30-restart-recovery`, `v2-scf-17-restart-recovery`,
//! `v2-csh-10-restart-recovery`.
//!
//! # Current live-C2 evidence boundary
//!
//! Product reopen now belongs to the Store-owned `live_c2` path. Its live
//! context, admission, custody, actor, and reopen constructors are deliberately
//! crate-private, so this external integration target does not pretend to
//! exercise them. Exact GenerationCurrent reopen and every bound-coordinate
//! mismatch belong in the in-crate `store_generation::live_c2` tests. This
//! file covers only evidence honestly reachable from the external surface:
//!
//! - Public Store substrate: `Store::initialize_unqualified_storage`,
//!   `Store::open`, `Store::open_read_only`, `Store::database_schema_version`,
//!   `Store::validate`, `Store::begin_writer_session`,
//!   `Store::build_restore_declaration`.
//! - Public C2 lock-carrier byte law: `store_generation::lock::
//!   encode_rec_29_generation_lock` / `verify_rec_29_generation_lock`
//!   (encode in the parent, re-verify exact persisted bytes after a real
//!   process boundary in a re-exec child, with exact typed refusals for
//!   tampered, substituted-backlink, and missing artifacts).
//! - Fence/process boundary: `nq_helper_sandbox::C2ForkFence` across re-exec
//!   children (observation, not enforcement, per the V3 SG-WU-07 amendment).
//!
//! What is NOT covered here, by design: minting or reopening live signer
//! authority. Current compile-fail evidence for that boundary lives in the
//! dedicated live-C2 noninjectability harness; old V2 privacy rows are not
//! treated as proof of the new context/permit contract.
//!
//! The re-exec child role is gated by an environment marker and re-executes
//! this binary with `--exact`; without the marker the child-role test is a
//! no-op pass. A child invoked under the marker but without its required
//! premises refuses cleanly (distinct line, exit code 4) — never a panic.
//! Spawning helper processes is test-only evidence gathering; production
//! sources gain no process creation.

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Output};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nq_helper_sandbox::C2ForkFence;
use nq_protocol::{Sha256Digest, sha256_bytes};
use nq_store::store_generation::lock::{
    C2StoreGenerationLockErrorV1, encode_rec_29_generation_lock, verify_rec_29_generation_lock,
};
use nq_store::{Store, StoreError};

/// Environment marker gating the re-exec child role; the value is the mode.
const CHILD_ROLE_ENV: &str = "NQ_STORE_C2_RESTART_CHILD_ROLE";
/// Exact test name re-executed as the child role.
const CHILD_TEST_NAME: &str = "v2_c2_restart_child_role";
/// Child premise: path of the persisted Store database.
const DB_ENV: &str = "NQ_STORE_C2_RESTART_DB";
/// Child premise: parent-observed schema version the child must re-observe.
const EXPECT_SCHEMA_ENV: &str = "NQ_STORE_C2_RESTART_EXPECT_SCHEMA";
/// Child premise: path of the persisted C2 lock-carrier bytes.
const LOCK_BYTES_ENV: &str = "NQ_STORE_C2_RESTART_LOCK_BYTES";
/// Child premise: expected authenticated B-genesis backlink digest.
const B_GENESIS_ENV: &str = "NQ_STORE_C2_RESTART_B_GENESIS";
/// Child premise: parent-verified lock identity the child must recompute.
const EXPECT_LOCK_IDENTITY_ENV: &str = "NQ_STORE_C2_RESTART_EXPECT_LOCK_IDENTITY";
/// Child premise: `dev:ino` identity of the parent custody-analog marker.
const MARKER_IDENTITY_ENV: &str = "NQ_STORE_C2_RESTART_MARKER";
/// Prefix of the single structured result line the child prints.
const LINE_PREFIX: &str = "NQ-C2-RESTART ";
/// Exit code for the clean premises-absent refusal (never a panic).
const PREMISES_EXIT_CODE: i32 = 4;
/// Exit code for a deviation from the expected classification.
const DEVIATION_EXIT_CODE: i32 = 2;
/// Exit code for an infrastructure failure inside the child.
const INFRA_EXIT_CODE: i32 = 3;
/// Exact refusal message of the non-reentrant fence.
const NON_REENTRANT_REFUSAL: &str = "C2 fork fence is non-reentrant";

/// Print the structured result line, flush, and exit with `code`.
fn child_exit(line: &str, code: i32) -> ! {
    println!("{LINE_PREFIX}{line}");
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

/// Read a required child premise or refuse cleanly as premises-absent.
fn require_premise(mode: &str, name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => child_exit(
            &format!("mode={mode} premises=absent missing={name}"),
            PREMISES_EXIT_CODE,
        ),
    }
}

/// Child infrastructure failure: structured line plus the infra exit code.
fn child_infra_error(mode: &str, detail: &str) -> ! {
    child_exit(
        &format!("mode={mode} infra-error={detail}"),
        INFRA_EXIT_CODE,
    );
}

/// Child deviation: the expected classification was not observed.
fn child_deviation(mode: &str, detail: &str) -> ! {
    child_exit(
        &format!("mode={mode} deviation={detail}"),
        DEVIATION_EXIT_CODE,
    );
}

/// Parse a required digest premise.
fn require_digest(mode: &str, name: &str) -> Sha256Digest {
    let value = require_premise(mode, name);
    match Sha256Digest::parse(value) {
        Ok(digest) => digest,
        Err(_) => child_deviation(mode, "malformed-digest-premise"),
    }
}

/// Child mode `reopen`: re-open the persisted Store and re-verify the
/// persisted C2 lock-carrier bytes after the process boundary, comparing
/// every observed fact against the parent-observed premises.
fn child_reopen() {
    let mode = "reopen";
    let db = require_premise(mode, DB_ENV);
    let expected_schema = require_premise(mode, EXPECT_SCHEMA_ENV);
    let lock_path = require_premise(mode, LOCK_BYTES_ENV);
    let b_genesis = require_digest(mode, B_GENESIS_ENV);
    let expected_identity = require_premise(mode, EXPECT_LOCK_IDENTITY_ENV);

    let schema = match Store::database_schema_version(&db) {
        Ok(schema) => schema,
        Err(error) => child_deviation(mode, &format!("schema-version-refused:{error:?}")),
    };
    if schema.to_string() != expected_schema {
        child_deviation(mode, "schema-version-mismatch");
    }
    let store = match Store::open_read_only(&db) {
        Ok(store) => store,
        Err(error) => child_deviation(mode, &format!("reopen-refused:{error:?}")),
    };
    if let Err(error) = store.validate() {
        child_deviation(mode, &format!("validate-refused:{error:?}"));
    }
    let bytes = match std::fs::read(&lock_path) {
        Ok(bytes) => bytes,
        Err(error) => child_infra_error(mode, &format!("read-lock-bytes:{error}")),
    };
    let carrier = match verify_rec_29_generation_lock(&bytes, &b_genesis) {
        Ok(carrier) => carrier,
        Err(error) => child_deviation(mode, &format!("lock-refused:{error:?}")),
    };
    if carrier.lock_identity.as_str() != expected_identity {
        child_deviation(mode, "lock-identity-mismatch");
    }
    child_exit(
        &format!(
            "mode=reopen schema={schema} open=ok validate=ok lock=ok identity={} pid={}",
            carrier.lock_identity.as_str(),
            std::process::id()
        ),
        0,
    );
}

/// Child mode `reopen-missing`: the persisted Store artifact is absent; the
/// public open must refuse with exactly `StoreError::NotInitialized`.
fn child_reopen_missing() {
    let mode = "reopen-missing";
    let db = require_premise(mode, DB_ENV);
    match Store::open(&db) {
        Ok(_) => child_deviation(mode, "missing-artifact-opened"),
        Err(StoreError::NotInitialized(path)) if path == Path::new(&db) => {
            child_exit("mode=reopen-missing store-refusal=NotInitialized", 0);
        }
        Err(error) => child_deviation(mode, &format!("wrong-refusal:{error:?}")),
    }
}

/// Shared child body for the tampered/substituted lock-carrier negatives:
/// the public verifier must refuse with exactly the expected typed variant.
fn child_lock_negative(mode: &str, expected: &str) {
    let lock_path = require_premise(mode, LOCK_BYTES_ENV);
    let b_genesis = require_digest(mode, B_GENESIS_ENV);
    let bytes = match std::fs::read(&lock_path) {
        Ok(bytes) => bytes,
        Err(error) => child_infra_error(mode, &format!("read-lock-bytes:{error}")),
    };
    let classification = match verify_rec_29_generation_lock(&bytes, &b_genesis) {
        Ok(_) => "accepted".to_owned(),
        Err(error) => match &error {
            C2StoreGenerationLockErrorV1::NoncanonicalLengthOrPadding => {
                "NoncanonicalLengthOrPadding".to_owned()
            }
            C2StoreGenerationLockErrorV1::MalformedCarrier => "MalformedCarrier".to_owned(),
            C2StoreGenerationLockErrorV1::BacklinkMismatch => "BacklinkMismatch".to_owned(),
            other => format!("other:{other:?}"),
        },
    };
    if classification == expected {
        child_exit(&format!("mode={mode} lock-refusal={classification}"), 0);
    }
    child_deviation(mode, &format!("expected-{expected}-got-{classification}"));
}

/// Enumerate `/proc/self/fd` and collect every fd whose target carries the
/// `dev:ino` identity of the parent custody-analog marker file.
fn inspect_fd_table(identity: &str) -> Result<(usize, Vec<String>), String> {
    let (dev, ino) = identity
        .split_once(':')
        .ok_or_else(|| format!("malformed marker identity {identity:?}"))?;
    let dev: u64 = dev
        .parse()
        .map_err(|error| format!("marker identity device: {error}"))?;
    let ino: u64 = ino
        .parse()
        .map_err(|error| format!("marker identity inode: {error}"))?;
    let entries = std::fs::read_dir("/proc/self/fd")
        .map_err(|error| format!("read /proc/self/fd: {error}"))?;
    let mut total = 0_usize;
    let mut foreign = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("iterate /proc/self/fd: {error}"))?;
        total += 1;
        let metadata =
            std::fs::metadata(entry.path()).map_err(|error| format!("stat fd entry: {error}"))?;
        if metadata.dev() == dev && metadata.ino() == ino {
            foreign.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok((total, foreign))
}

/// Child fence body: acquire THIS process's fence, prove the same-process
/// binding, and prove the fence is real by requiring the exact non-reentrant
/// refusal on a same-thread second acquire (the non-vacuous control).
/// Returns the shared token suffix on success.
fn child_fence_tokens(mode: &str) -> String {
    let guard = match C2ForkFence::acquire() {
        Ok(guard) => guard,
        Err(error) => child_deviation(mode, &format!("fence-acquire-refused:{error}")),
    };
    if guard.verify_same_process().is_err() {
        child_deviation(mode, "fence-not-same-process");
    }
    let reentry_exact = match C2ForkFence::acquire() {
        Err(error) => error.to_string() == NON_REENTRANT_REFUSAL,
        Ok(extra) => {
            drop(extra);
            false
        }
    };
    drop(guard);
    if !reentry_exact {
        child_deviation(mode, "fence-reentry-not-refused-exactly");
    }
    format!(
        "fence=acquired same-process=ok reentry-refused=exact pid={}",
        std::process::id()
    )
}

/// Child mode `fence`: restart observation at the fence/process boundary —
/// the child process holds its own fresh fence immediately after exec.
fn child_fence() {
    let tokens = child_fence_tokens("fence");
    child_exit(&format!("mode=fence {tokens}"), 0);
}

/// Child mode `fd-probe`: no custody fd may cross exec, and the child
/// acquires a fresh fence of its own (restart delivers no loaded key/fd).
fn child_fd_probe() {
    let mode = "fd-probe";
    let identity = require_premise(mode, MARKER_IDENTITY_ENV);
    let (total, foreign) = match inspect_fd_table(&identity) {
        Ok(observed) => observed,
        Err(message) => child_infra_error(mode, &message),
    };
    if !foreign.is_empty() {
        child_deviation(mode, &format!("foreign-fds:{}", foreign.join(",")));
    }
    let tokens = child_fence_tokens(mode);
    child_exit(
        &format!("mode=fd-probe total={total} foreign-fds=none {tokens}"),
        0,
    );
}

/// Child mode `alias`: the two-process public law — the child opens the same
/// persisted Store read-write and begins its own writer session while the
/// parent holds one (per-process serialization is the observable law).
fn child_alias_open() {
    let mode = "alias";
    let db = require_premise(mode, DB_ENV);
    let expected_schema = require_premise(mode, EXPECT_SCHEMA_ENV);
    let schema = match Store::database_schema_version(&db) {
        Ok(schema) => schema,
        Err(error) => child_deviation(mode, &format!("schema-version-refused:{error:?}")),
    };
    if schema.to_string() != expected_schema {
        child_deviation(mode, "schema-version-mismatch");
    }
    let mut store = match Store::open(&db) {
        Ok(store) => store,
        Err(error) => child_deviation(mode, &format!("open-refused:{error:?}")),
    };
    if let Err(error) = store.validate() {
        child_deviation(mode, &format!("validate-refused:{error:?}"));
    }
    let session = match store.begin_writer_session() {
        Ok(session) => session,
        Err(error) => child_deviation(mode, &format!("writer-session-refused:{error:?}")),
    };
    drop(session);
    child_exit(
        &format!(
            "mode=alias open=ok validate=ok writer-session=ok schema={schema} pid={}",
            std::process::id()
        ),
        0,
    );
}

/// Re-exec child role: dispatched by `CHILD_ROLE_ENV`. A no-op pass when not
/// invoked under the marker; a clean premises-absent refusal (exit code 4,
/// never a panic) when the marker is present but the mode or its required
/// premises are missing.
#[test]
fn v2_c2_restart_child_role() {
    let Ok(mode) = std::env::var(CHILD_ROLE_ENV) else {
        return;
    };
    match mode.as_str() {
        "reopen" => child_reopen(),
        "reopen-missing" => child_reopen_missing(),
        "tampered-lock" => child_lock_negative("tampered-lock", "NoncanonicalLengthOrPadding"),
        "backlink-mismatch" => child_lock_negative("backlink-mismatch", "BacklinkMismatch"),
        "fd-probe" => child_fd_probe(),
        "fence" => child_fence(),
        "alias" => child_alias_open(),
        _ => child_exit(
            &format!("mode=unknown premises=absent detail=unknown-mode:{mode}"),
            PREMISES_EXIT_CODE,
        ),
    }
}

/// Re-exec this test binary as the child role in `mode` with extra premise
/// variables, returning the raw process output for classification.
fn spawn_restart_child(mode: &str, premises: &[(&str, String)]) -> Result<Output, String> {
    let executable =
        std::env::current_exe().map_err(|error| format!("current test executable: {error}"))?;
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(CHILD_TEST_NAME)
        .arg("--nocapture")
        .env(CHILD_ROLE_ENV, mode);
    for (name, value) in premises {
        command.env(name, value);
    }
    command
        .output()
        .map_err(|error| format!("spawn restart child: {error}"))
}

/// Extract the child's single structured result line, if it printed one.
fn child_result_line(output: &Output) -> Option<String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.starts_with(LINE_PREFIX))
        .map(str::to_owned)
}

/// Assert the child exited successfully with a line carrying every token.
fn assert_child_tokens(output: &Output, tokens: &[&str], context: &str) {
    assert!(
        output.status.success(),
        "{context}: child must exit 0: {output:?}"
    );
    let line = child_result_line(output).unwrap_or_else(|| {
        panic!("{context}: child printed no structured result line: {output:?}")
    });
    for token in tokens {
        assert!(
            line.contains(token),
            "{context}: child line must contain {token:?}: {line}"
        );
    }
}

/// Parse the child-reported pid token from a structured result line.
fn child_pid(line: &str) -> u32 {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix("pid="))
        .and_then(|pid| pid.parse().ok())
        .expect("child line must carry a pid token")
}

/// Matrix V3 anchor `v2-sg-wu-07-restart-recovery`: "two-process/alias/copy/
/// fork/exec/shutdown law ...; process, fork, exec and shutdown evidence
/// observes but does not enforce the shared fence".
///
/// Layers covered: public Store substrate + public C2 lock-carrier byte law
/// (persist in parent, re-verify exact bytes across a real exec boundary),
/// fence/process boundary (observation half), and the exact premises-absent
/// refusal. This is substrate/process evidence, not the live-C2 reopen gate.
#[test]
fn v2_sg_wu_07_restart_recovery() {
    // Setup: persist public-substrate C2 state — a versioned Store database
    // plus exact REC-29 lock-carrier bytes — for the cross-boundary reopen.
    let directory = tempfile::tempdir().expect("restart directory");
    let db_path = directory.path().join("restart.sqlite3");
    let store = Store::initialize_unqualified_storage(&db_path).expect("initialize storage store");
    store.validate().expect("fresh store validates");
    let schema = Store::database_schema_version(&db_path).expect("parent schema version");
    drop(store);

    let b_genesis = sha256_bytes(b"sg-wu-07 authenticated b genesis");
    let generation = sha256_bytes(b"sg-wu-07 physical generation");
    let lock_bytes = encode_rec_29_generation_lock(
        "occurrence-sg-wu-07".to_owned(),
        generation,
        b_genesis.clone(),
        2048,
    )
    .expect("encode lock carrier");
    let parent_carrier =
        verify_rec_29_generation_lock(&lock_bytes, &b_genesis).expect("parent pre-verification");
    let lock_path = directory.path().join("lock.carrier");
    std::fs::write(&lock_path, &lock_bytes).expect("persist lock carrier bytes");

    // (a) parent-create -> re-exec-child-reopen -> exact persisted facts.
    let reopen = spawn_restart_child(
        "reopen",
        &[
            (DB_ENV, db_path.display().to_string()),
            (EXPECT_SCHEMA_ENV, schema.to_string()),
            (LOCK_BYTES_ENV, lock_path.display().to_string()),
            (B_GENESIS_ENV, b_genesis.as_str().to_owned()),
            (
                EXPECT_LOCK_IDENTITY_ENV,
                parent_carrier.lock_identity.as_str().to_owned(),
            ),
        ],
    )
    .expect("spawn reopen child");
    assert_child_tokens(
        &reopen,
        &[
            "mode=reopen",
            &format!("schema={schema}"),
            "open=ok",
            "validate=ok",
            "lock=ok",
            &format!("identity={}", parent_carrier.lock_identity.as_str()),
        ],
        "SG-WU-07 reopen",
    );
    let reopen_line = child_result_line(&reopen).expect("reopen line");
    assert_ne!(
        child_pid(&reopen_line),
        std::process::id(),
        "SG-WU-07: the reopen must cross a real process boundary"
    );

    // (a-negative) missing artifact: the exact typed refusal, never generic.
    let missing = spawn_restart_child(
        "reopen-missing",
        &[(
            DB_ENV,
            directory
                .path()
                .join("absent.sqlite3")
                .display()
                .to_string(),
        )],
    )
    .expect("spawn missing-artifact child");
    assert_child_tokens(
        &missing,
        &["mode=reopen-missing", "store-refusal=NotInitialized"],
        "SG-WU-07 missing artifact",
    );

    // (a-negative) tampered carrier bytes: exact padding/length refusal.
    let mut tampered = lock_bytes.clone();
    *tampered.last_mut().expect("carrier bytes nonempty") = 1;
    let tampered_path = directory.path().join("lock.tampered");
    std::fs::write(&tampered_path, &tampered).expect("persist tampered carrier");
    let tampered_child = spawn_restart_child(
        "tampered-lock",
        &[
            (LOCK_BYTES_ENV, tampered_path.display().to_string()),
            (B_GENESIS_ENV, b_genesis.as_str().to_owned()),
        ],
    )
    .expect("spawn tampered-lock child");
    assert_child_tokens(
        &tampered_child,
        &[
            "mode=tampered-lock",
            "lock-refusal=NoncanonicalLengthOrPadding",
        ],
        "SG-WU-07 tampered carrier",
    );

    // (a-negative) substituted backlink: exact typed refusal on valid bytes.
    let substituted = spawn_restart_child(
        "backlink-mismatch",
        &[
            (LOCK_BYTES_ENV, lock_path.display().to_string()),
            (
                B_GENESIS_ENV,
                sha256_bytes(b"sg-wu-07 substituted genesis")
                    .as_str()
                    .to_owned(),
            ),
        ],
    )
    .expect("spawn backlink-mismatch child");
    assert_child_tokens(
        &substituted,
        &["mode=backlink-mismatch", "lock-refusal=BacklinkMismatch"],
        "SG-WU-07 substituted backlink",
    );

    // (b) fence restart observation: the parent holds its fence while the
    // re-exec child starts; the child acquires its OWN process's fence
    // immediately (no fence-interval state is inherited across exec) and its
    // same-process binding verifies. Nothing may panic while the guard is
    // held, so the child output is classified after release.
    let guard = C2ForkFence::acquire().expect("parent fence acquisition");
    let fence_child = spawn_restart_child("fence", &[]);
    let parent_identity_stable = guard.verify_same_process().is_ok();
    drop(guard);
    let fence_child = fence_child.expect("spawn fence child");
    assert_child_tokens(
        &fence_child,
        &[
            "mode=fence",
            "fence=acquired",
            "same-process=ok",
            "reentry-refused=exact",
        ],
        "SG-WU-07 fence restart observation",
    );
    let fence_line = child_result_line(&fence_child).expect("fence line");
    assert_ne!(
        child_pid(&fence_line),
        std::process::id(),
        "SG-WU-07: the child fence owner is a different process"
    );
    assert!(
        parent_identity_stable,
        "SG-WU-07: the protected interval must not have crossed the boundary"
    );

    // (c) restart premises absent: the child invoked under the marker without
    // its required premises refuses cleanly — distinct line, exit code 4,
    // never a panic. An unknown mode refuses identically.
    let absent = spawn_restart_child("reopen", &[]).expect("spawn premises-absent child");
    assert_eq!(
        absent.status.code(),
        Some(PREMISES_EXIT_CODE),
        "SG-WU-07: premises-absent child must refuse with the exact exit code: {absent:?}"
    );
    let absent_line = child_result_line(&absent).expect("premises-absent line");
    assert!(
        absent_line.contains("mode=reopen premises=absent missing="),
        "SG-WU-07: premises-absent refusal must name the missing premise: {absent_line}"
    );
    let unknown = spawn_restart_child("bogus-mode", &[]).expect("spawn unknown-mode child");
    assert_eq!(
        unknown.status.code(),
        Some(PREMISES_EXIT_CODE),
        "SG-WU-07: unknown-mode child must refuse with the exact exit code: {unknown:?}"
    );
    let unknown_line = child_result_line(&unknown).expect("unknown-mode line");
    assert!(
        unknown_line.contains("premises=absent detail=unknown-mode"),
        "SG-WU-07: unknown-mode refusal must be classified: {unknown_line}"
    );
}

/// Matrix V3 anchor `v2-sg-n-30-restart-recovery`: "Two-process, alias,
/// copied Store/key, fork, child, namespace, cross-occurrence, cross-role,
/// and cross-domain behavior follows the exact local custody law and makes
/// no estate claim ... PID and process-epoch observation occurs after the
/// process boundary and cannot serialize it".
///
/// Layers covered: public Store substrate (same-process alias exclusion with
/// the exact `WriterSessionUnavailable` refusal; two-process open/session
/// behavior as actually observable; filesystem copy as an independent
/// instance whose only public cross-instance declaration grants no
/// authority) and the fence/process boundary (per-process pid-bound fence).
/// The cross-process exclusion law of the permanent C2 lock is
/// crate-private and not asserted here (see file header).
#[test]
fn v2_sg_n_30_restart_recovery() {
    let directory = tempfile::tempdir().expect("n-30 directory");
    let db_path = directory.path().join("original.sqlite3");
    let store = Store::initialize_unqualified_storage(&db_path).expect("initialize storage store");
    store.validate().expect("fresh store validates");
    let schema = Store::database_schema_version(&db_path).expect("schema version");
    drop(store);

    // Copied Store: a filesystem copy opens as an independent instance. The
    // copy check runs before any writer session so the copy predates WAL
    // sidecar creation.
    let copy_directory = tempfile::tempdir().expect("copy directory");
    let copy_path = copy_directory.path().join("copy.sqlite3");
    std::fs::copy(&db_path, &copy_path).expect("copy the store file");
    let original_metadata = std::fs::metadata(&db_path).expect("original metadata");
    let copy_metadata = std::fs::metadata(&copy_path).expect("copy metadata");
    assert_ne!(
        (original_metadata.dev(), original_metadata.ino()),
        (copy_metadata.dev(), copy_metadata.ino()),
        "SG-N-30: the copy must be a physically distinct instance"
    );
    let copy_store = Store::open(&copy_path).expect("copied store opens independently");
    copy_store.validate().expect("copied store validates");
    assert_eq!(
        Store::database_schema_version(&copy_path).expect("copy schema version"),
        schema,
        "SG-N-30: the copy carries the same persisted facts"
    );
    drop(copy_store);

    // The copy makes no estate claim: the sole cross-instance declaration
    // the public API can build for it explicitly grants no authority.
    let declaration = Store::build_restore_declaration(&db_path, &copy_path)
        .expect("restore declaration for the copy");
    let declaration_json: serde_json::Value =
        serde_json::from_slice(&declaration.canonical_bytes).expect("declaration canonical JSON");
    assert_eq!(
        declaration_json["grants_authority"],
        serde_json::Value::Bool(false),
        "SG-N-30: the only public declaration for the copy grants no authority"
    );

    // Alias law within one process: a second handle on the same path cannot
    // begin a writer session while one is held — the exact typed refusal.
    let mut store = Store::open(&db_path).expect("open original store");
    let session = store
        .begin_writer_session()
        .expect("first writer session on a fresh store");
    let mut alias = Store::open(&db_path).expect("alias handle opens");
    match alias.begin_writer_session() {
        Ok(extra) => {
            drop(extra);
            panic!("SG-N-30: same-process alias writer session must refuse");
        }
        Err(error) => assert!(
            matches!(error, StoreError::WriterSessionUnavailable(_)),
            "SG-N-30: alias refusal must be exactly WriterSessionUnavailable: {error:?}"
        ),
    }
    drop(alias);

    // Two-process law, as observable at the public substrate: while this
    // process holds its writer session, the re-exec child opens the same
    // Store and begins its own per-process writer session. Cross-process
    // exclusion belongs to the crate-private permanent C2 lock; nothing
    // stronger is asserted.
    let child = spawn_restart_child(
        "alias",
        &[
            (DB_ENV, db_path.display().to_string()),
            (EXPECT_SCHEMA_ENV, schema.to_string()),
        ],
    )
    .expect("spawn alias child");
    assert_child_tokens(
        &child,
        &[
            "mode=alias",
            "open=ok",
            "validate=ok",
            "writer-session=ok",
            &format!("schema={schema}"),
        ],
        "SG-N-30 two-process alias",
    );
    let alias_line = child_result_line(&child).expect("alias line");
    assert_ne!(
        child_pid(&alias_line),
        std::process::id(),
        "SG-N-30: the two-process observation must cross a real boundary"
    );
    drop(session);
    drop(store);

    // PID/process-epoch observation occurs after the boundary and cannot
    // serialize it: each process's fence owner is bound to its own pid, and
    // the parent's acquisition after the children proves no cross-process
    // serialization exists at this layer.
    let guard = C2ForkFence::acquire().expect("parent fence after the boundary");
    guard
        .verify_same_process()
        .expect("parent fence is bound to this process's pid");
    let fence_child = spawn_restart_child("fence", &[]);
    let parent_identity_stable = guard.verify_same_process().is_ok();
    drop(guard);
    let fence_child = fence_child.expect("spawn fence child");
    assert_child_tokens(
        &fence_child,
        &["mode=fence", "fence=acquired", "same-process=ok"],
        "SG-N-30 per-process fence",
    );
    let fence_line = child_result_line(&fence_child).expect("fence line");
    assert_ne!(
        child_pid(&fence_line),
        std::process::id(),
        "SG-N-30: each process's fence owner records its own pid"
    );
    assert!(
        parent_identity_stable,
        "SG-N-30: process-epoch observation stays bound to this process"
    );
}

/// Matrix V3 anchor `v2-scf-17-restart-recovery`: restart restores no signer
/// standing.
///
/// Layer covered: the fd/fence process boundary (a re-exec child holds no
/// custody-analog fd and only a fresh, pid-bound fence). Current live-context
/// noninjectability is tested separately and is not inferred from this V2 row.
#[test]
fn v2_scf_17_restart_recovery() {
    // After re-exec the child holds no custody-analog fd. The
    // parent's O_CLOEXEC marker stands in for the loaded custody fd; the
    // decoy-positive control for this probe shape lives in
    // `c2_signer_hostile_v2.rs` (CSH-10 hostile) and is not repeated here.
    let directory = tempfile::tempdir().expect("scf-17 directory");
    let marker = tempfile::NamedTempFile::new_in(directory.path()).expect("custody-analog marker");
    writeln!(marker.as_file(), "scf-17 restart custody analog").expect("write marker");
    let flags = fcntl(marker.as_file().as_raw_fd(), FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .expect("F_GETFD on marker");
    fcntl(
        marker.as_file().as_raw_fd(),
        FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC),
    )
    .expect("set O_CLOEXEC on marker");
    let metadata = std::fs::metadata(marker.path()).expect("marker metadata");
    let identity = format!("{}:{}", metadata.dev(), metadata.ino());

    let probe = spawn_restart_child("fd-probe", &[(MARKER_IDENTITY_ENV, identity)])
        .expect("spawn fd-probe child");
    assert_child_tokens(
        &probe,
        &[
            "mode=fd-probe",
            "foreign-fds=none",
            "fence=acquired",
            "same-process=ok",
            "reentry-refused=exact",
        ],
        "SCF-17 restart fd probe",
    );
    let line = child_result_line(&probe).expect("fd-probe line");
    let total = line
        .split_whitespace()
        .find_map(|token| token.strip_prefix("total="))
        .and_then(|total| total.parse::<usize>().ok())
        .expect("fd-probe line must carry a total token");
    assert!(
        total >= 3,
        "SCF-17 restart: the fd probe must be non-vacuous (total={total})"
    );
}

/// Matrix V3 anchor `v2-csh-10-restart-recovery`: restart delivers no loaded
/// key/fd.
///
/// Layers covered: the fd/fence process boundary — while the parent holds
/// its fence and a live O_CLOEXEC custody-analog fd, the re-exec child's fd
/// table is clean and the child acquires a fresh fence of its own. The
/// decoy-positive control for this probe shape is already proven in
/// `c2_signer_hostile_v2.rs` (`v2-csh-10-hostile`) and is not repeated here.
#[test]
fn v2_csh_10_restart_recovery() {
    let directory = tempfile::tempdir().expect("csh-10 restart directory");
    let marker = tempfile::NamedTempFile::new_in(directory.path()).expect("custody-analog marker");
    writeln!(marker.as_file(), "csh-10 restart custody analog").expect("write marker");
    let flags = fcntl(marker.as_file().as_raw_fd(), FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .expect("F_GETFD on marker");
    fcntl(
        marker.as_file().as_raw_fd(),
        FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC),
    )
    .expect("set O_CLOEXEC on marker");
    let metadata = std::fs::metadata(marker.path()).expect("marker metadata");
    let identity = format!("{}:{}", metadata.dev(), metadata.ino());

    // The parent holds its fence across the spawn; the child must still
    // acquire a fresh fence of its own (nothing is delivered across exec).
    let guard = C2ForkFence::acquire().expect("parent fence acquisition");
    let probe = spawn_restart_child("fd-probe", &[(MARKER_IDENTITY_ENV, identity)]);
    let parent_identity_stable = guard.verify_same_process().is_ok();
    drop(guard);
    let probe = probe.expect("spawn fd-probe child");
    assert_child_tokens(
        &probe,
        &[
            "mode=fd-probe",
            "foreign-fds=none",
            "fence=acquired",
            "same-process=ok",
            "reentry-refused=exact",
        ],
        "CSH-10 restart fd probe",
    );
    let line = child_result_line(&probe).expect("fd-probe line");
    let total = line
        .split_whitespace()
        .find_map(|token| token.strip_prefix("total="))
        .and_then(|total| total.parse::<usize>().ok())
        .expect("fd-probe line must carry a total token");
    assert!(
        total >= 3,
        "CSH-10 restart: the fd probe must be non-vacuous (total={total})"
    );
    assert_ne!(
        child_pid(&line),
        std::process::id(),
        "CSH-10 restart: the fresh fence belongs to the child process"
    );
    assert!(
        parent_identity_stable,
        "CSH-10 restart: the parent interval must not have crossed the boundary"
    );
}
