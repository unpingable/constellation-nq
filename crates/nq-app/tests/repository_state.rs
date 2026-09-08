use nq_profiles::repository_state::RepositoryDisposition;
use std::{fs, process::Command};

fn git(root: &std::path::Path, args: &[&str]) {
    assert!(
        Command::new("/usr/bin/git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn real_git_tracked_untracked_ignored_and_unborn_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    let unborn = nq_app::repository_cli::observe(dir.path()).unwrap();
    assert!(matches!(
        unborn.disposition,
        RepositoryDisposition::NotEstablished { .. }
    ));
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
    );
    let clean = nq_app::repository_cli::observe(dir.path()).unwrap();
    assert!(matches!(
        clean.disposition,
        RepositoryDisposition::Clean { .. }
    ));
    fs::write(dir.path().join("new"), "new").unwrap();
    assert!(matches!(
        nq_app::repository_cli::observe(dir.path())
            .unwrap()
            .disposition,
        RepositoryDisposition::ChangesPresent { .. }
    ));
    git(dir.path(), &["add", "new"]);
    assert!(matches!(
        nq_app::repository_cli::observe(dir.path())
            .unwrap()
            .disposition,
        RepositoryDisposition::ChangesPresent { .. }
    ));
    git(
        dir.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "tracked",
        ],
    );
    fs::write(dir.path().join("new"), "changed").unwrap();
    assert!(matches!(
        nq_app::repository_cli::observe(dir.path())
            .unwrap()
            .disposition,
        RepositoryDisposition::ChangesPresent { .. }
    ));
    fs::write(dir.path().join("new"), "new").unwrap();
    fs::write(dir.path().join(".git/info/exclude"), "ignored\n").unwrap();
    fs::write(dir.path().join("ignored"), "excluded").unwrap();
    assert!(matches!(
        nq_app::repository_cli::observe(dir.path())
            .unwrap()
            .disposition,
        RepositoryDisposition::Clean { .. }
    ));
    // Historical replay remains valid after a later worktree change, but does
    // not establish currentness or authorize that later execution.
    clean.replay(&clean.evidence.collector_executable).unwrap();
}
