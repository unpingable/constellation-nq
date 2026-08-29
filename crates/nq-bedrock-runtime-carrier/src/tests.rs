use super::*;
use std::io;
use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use tempfile::TempDir;

struct CountingRunner(usize);
impl Runner for CountingRunner {
    fn run(&mut self, _: &File, _: &File, _: &[String]) -> std::io::Result<ExitStatus> {
        self.0 += 1;
        Ok(ExitStatus::from_raw(0))
    }
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::parse(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn fixture(root: &Path) -> (RuntimeBindingV1, RuntimeReleaseV1) {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let executable = root.join("nq");
    fs::write(&executable, b"fixed executable").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).unwrap();
    let binding = RuntimeBindingV1 {
        schema: BINDING_SCHEMA.into(),
        occurrence_id: "occurrence-1".into(),
        coordination_domain_id: "domain-1".into(),
        mechanics_digest: digest(1),
        runtime_recheck_digest: digest(2),
        claim_id: digest(3),
        executable_digest: sha256_open_file(&open_bound_executable(&executable).unwrap()).unwrap(),
        arguments: vec!["run-exact".into()],
    };
    let release = RuntimeReleaseV1 {
        schema: RELEASE_SCHEMA.into(),
        binding_id: domain_digest(BINDING_DOMAIN, &binding).unwrap(),
        occurrence_id: binding.occurrence_id.clone(),
        coordination_domain_id: binding.coordination_domain_id.clone(),
        mechanics_digest: binding.mechanics_digest.clone(),
        runtime_recheck_digest: binding.runtime_recheck_digest.clone(),
        claim_id: binding.claim_id.clone(),
        release_nonce: "release-1".into(),
    };
    fs::write(
        root.join("binding.json"),
        canonical_json_bytes(&binding).unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("release.json"),
        canonical_json_bytes(&release).unwrap(),
    )
    .unwrap();
    (binding, release)
}

#[test]
fn no_release_times_out_without_invocation() {
    let temp = TempDir::new().unwrap();
    fixture(temp.path());
    fs::remove_file(temp.path().join("release.json")).unwrap();
    let mut runner = CountingRunner(0);
    let result = hold_until_release(
        &temp.path().join("binding.json"),
        &temp.path().join("release.json"),
        &temp.path().join("state.sqlite3"),
        &temp.path().join("nq"),
        Some(Duration::ZERO),
        &mut runner,
    )
    .unwrap();
    assert_eq!(result, None);
    assert_eq!(runner.0, 0);
}

#[test]
fn exact_release_invokes_once_and_replay_does_not() {
    let temp = TempDir::new().unwrap();
    fixture(temp.path());
    let mut runner = CountingRunner(0);
    let binding = temp.path().join("binding.json");
    let release = temp.path().join("release.json");
    let state = temp.path().join("state.sqlite3");
    let executable = temp.path().join("nq");
    assert!(matches!(
        try_release(&binding, &release, &state, &executable, &mut runner).unwrap(),
        ReleaseDecision::Invoked { .. }
    ));
    assert!(matches!(
        try_release(&binding, &release, &state, &executable, &mut runner).unwrap(),
        ReleaseDecision::AlreadyComplete { .. }
    ));
    assert_eq!(runner.0, 1);
}

#[test]
fn malformed_noncanonical_and_substituted_inputs_do_not_invoke() {
    for case in ["malformed", "noncanonical", "substituted", "executable"] {
        let temp = TempDir::new().unwrap();
        let (_, mut release) = fixture(temp.path());
        match case {
            "malformed" => fs::write(temp.path().join("release.json"), b"{").unwrap(),
            "noncanonical" => fs::write(
                temp.path().join("release.json"),
                serde_json::to_vec_pretty(&release).unwrap(),
            )
            .unwrap(),
            "substituted" => {
                release.occurrence_id = "other".into();
                fs::write(
                    temp.path().join("release.json"),
                    canonical_json_bytes(&release).unwrap(),
                )
                .unwrap();
            }
            "executable" => {
                fs::remove_file(temp.path().join("nq")).unwrap();
                fs::write(temp.path().join("nq"), b"replacement").unwrap();
                fs::set_permissions(temp.path().join("nq"), fs::Permissions::from_mode(0o555))
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let mut runner = CountingRunner(0);
        assert!(
            try_release(
                &temp.path().join("binding.json"),
                &temp.path().join("release.json"),
                &temp.path().join("state.sqlite3"),
                &temp.path().join("nq"),
                &mut runner
            )
            .is_err()
        );
        assert_eq!(runner.0, 0, "case {case}");
    }
}

#[test]
fn unknown_fields_are_refused() {
    let temp = TempDir::new().unwrap();
    fixture(temp.path());
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(temp.path().join("release.json")).unwrap()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), serde_json::json!(true));
    fs::write(
        temp.path().join("release.json"),
        canonical_json_bytes(&value).unwrap(),
    )
    .unwrap();
    let mut runner = CountingRunner(0);
    assert!(
        try_release(
            &temp.path().join("binding.json"),
            &temp.path().join("release.json"),
            &temp.path().join("state.sqlite3"),
            &temp.path().join("nq"),
            &mut runner
        )
        .is_err()
    );
    assert_eq!(runner.0, 0);
}

struct ReplacingRunner {
    pathname: PathBuf,
    bound_calls: usize,
    unbound_calls: usize,
}
impl Runner for ReplacingRunner {
    fn run(&mut self, executable: &File, _: &File, _: &[String]) -> io::Result<ExitStatus> {
        fs::remove_file(&self.pathname)?;
        fs::write(&self.pathname, b"replacement executable")?;
        fs::set_permissions(&self.pathname, fs::Permissions::from_mode(0o555))?;
        let mut opened = [0_u8; 16];
        let count = executable.read_at(&mut opened, 0)?;
        if &opened[..count] == b"fixed executable" {
            self.bound_calls += 1;
        } else {
            self.unbound_calls += 1;
        }
        Ok(ExitStatus::from_raw(0))
    }
}

#[test]
fn pathname_replacement_cannot_change_the_invoked_object() {
    let temp = TempDir::new().unwrap();
    fixture(temp.path());
    let executable = temp.path().join("nq");
    let mut runner = ReplacingRunner {
        pathname: executable.clone(),
        bound_calls: 0,
        unbound_calls: 0,
    };
    assert!(matches!(
        try_release(
            &temp.path().join("binding.json"),
            &temp.path().join("release.json"),
            &temp.path().join("state.sqlite3"),
            &executable,
            &mut runner
        )
        .unwrap(),
        ReleaseDecision::Invoked { .. }
    ));
    assert_eq!(runner.bound_calls, 1);
    assert_eq!(runner.unbound_calls, 0);
}

struct FailingRunner(usize);
impl Runner for FailingRunner {
    fn run(&mut self, _: &File, _: &File, _: &[String]) -> io::Result<ExitStatus> {
        self.0 += 1;
        Err(io::Error::other("deterministic cancellation fixture"))
    }
}

#[test]
fn claimed_restart_is_unknown_until_exact_reconciliation() {
    let temp = TempDir::new().unwrap();
    fixture(temp.path());
    let binding = temp.path().join("binding.json");
    let release = temp.path().join("release.json");
    let state = temp.path().join("state.sqlite3");
    let executable = temp.path().join("nq");
    let mut failing = FailingRunner(0);
    let first = try_release(&binding, &release, &state, &executable, &mut failing).unwrap();
    let ReleaseDecision::OutcomeUnknown { release_id } = first else {
        panic!("runner cancellation must retain an unknown outcome");
    };
    assert_eq!(failing.0, 1);
    let mut replay = CountingRunner(0);
    assert!(matches!(
        try_release(&binding, &release, &state, &executable, &mut replay).unwrap(),
        ReleaseDecision::OutcomeUnknown { .. }
    ));
    assert_eq!(replay.0, 0);
    let evidence = digest(9);
    assert!(matches!(
        reconcile_unknown(&state, &release_id, Some(0), &evidence).unwrap(),
        ReleaseDecision::AlreadyComplete {
            exit_code: Some(0),
            ..
        }
    ));
    assert!(matches!(
        reconcile_unknown(&state, &release_id, Some(0), &evidence).unwrap(),
        ReleaseDecision::AlreadyComplete { .. }
    ));
    assert!(reconcile_unknown(&state, &release_id, Some(1), &digest(8)).is_err());
    assert!(matches!(
        try_release(&binding, &release, &state, &executable, &mut replay).unwrap(),
        ReleaseDecision::AlreadyComplete {
            exit_code: Some(0),
            ..
        }
    ));
    assert_eq!(replay.0, 0);
}

struct ConcurrentRunner(Arc<AtomicUsize>);
impl Runner for ConcurrentRunner {
    fn run(&mut self, _: &File, _: &File, _: &[String]) -> io::Result<ExitStatus> {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(75));
        Ok(ExitStatus::from_raw(0))
    }
}

#[test]
fn concurrent_carriers_never_double_invoke_one_occurrence() {
    let temp = TempDir::new().unwrap();
    fixture(temp.path());
    let root = Arc::new(temp.path().to_path_buf());
    let calls = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let root = Arc::clone(&root);
        let calls = Arc::clone(&calls);
        threads.push(std::thread::spawn(move || {
            try_release(
                &root.join("binding.json"),
                &root.join("release.json"),
                &root.join("state.sqlite3"),
                &root.join("nq"),
                &mut ConcurrentRunner(calls),
            )
        }));
    }
    for thread in threads {
        let decision = thread.join().unwrap().unwrap();
        assert!(matches!(
            decision,
            ReleaseDecision::Invoked { .. }
                | ReleaseDecision::AlreadyComplete { .. }
                | ReleaseDecision::OutcomeUnknown { .. }
                | ReleaseDecision::InFlight { .. }
        ));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn state_symlink_and_nonprivate_parent_are_refused_before_invocation() {
    let temp = TempDir::new().unwrap();
    fixture(temp.path());
    let target = temp.path().join("other.sqlite3");
    fs::write(&target, b"").unwrap();
    symlink(&target, temp.path().join("state.sqlite3")).unwrap();
    let mut runner = CountingRunner(0);
    assert!(
        try_release(
            &temp.path().join("binding.json"),
            &temp.path().join("release.json"),
            &temp.path().join("state.sqlite3"),
            &temp.path().join("nq"),
            &mut runner,
        )
        .is_err()
    );
    assert_eq!(runner.0, 0);

    let second = TempDir::new().unwrap();
    fixture(second.path());
    fs::set_permissions(second.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        try_release(
            &second.path().join("binding.json"),
            &second.path().join("release.json"),
            &second.path().join("state.sqlite3"),
            &second.path().join("nq"),
            &mut runner,
        )
        .is_err()
    );
    assert_eq!(runner.0, 0);
}

struct BlockingRunner {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl Runner for BlockingRunner {
    fn run(&mut self, _: &File, _: &File, _: &[String]) -> io::Result<ExitStatus> {
        self.entered.send(()).unwrap();
        self.release.recv().unwrap();
        Ok(ExitStatus::from_raw(0))
    }
}

#[test]
fn reconciliation_cannot_overtake_a_live_invocation() {
    let temp = TempDir::new().unwrap();
    let (_, release) = fixture(temp.path());
    let root = temp.path().to_path_buf();
    let release_id = domain_digest(RELEASE_DOMAIN, &release).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        try_release(
            &root.join("binding.json"),
            &root.join("release.json"),
            &root.join("state.sqlite3"),
            &root.join("nq"),
            &mut BlockingRunner {
                entered: entered_tx,
                release: release_rx,
            },
        )
    });
    entered_rx.recv().unwrap();
    assert!(matches!(
        reconcile_unknown(
            &temp.path().join("state.sqlite3"),
            &release_id,
            Some(0),
            &digest(7),
        ),
        Err(CarrierError::Refused(message)) if message.contains("live invocation")
    ));
    release_tx.send(()).unwrap();
    assert!(matches!(
        worker.join().unwrap().unwrap(),
        ReleaseDecision::Invoked { .. }
    ));
    let mut replay = CountingRunner(0);
    assert!(matches!(
        try_release(
            &temp.path().join("binding.json"),
            &temp.path().join("release.json"),
            &temp.path().join("state.sqlite3"),
            &temp.path().join("nq"),
            &mut replay,
        )
        .unwrap(),
        ReleaseDecision::AlreadyComplete { .. }
    ));
    assert_eq!(replay.0, 0);
}
