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
    std::fs::create_dir(dir.path().join("nested")).unwrap();
    let nested = nq_app::repository_cli::observe(&dir.path().join("nested")).unwrap();
    assert_eq!(
        nested.disposition,
        RepositoryDisposition::NotEstablished {
            reason: "exact_worktree_root_required".into()
        }
    );
    for flag in ["--assume-unchanged", "--skip-worktree"] {
        git(dir.path(), &["update-index", flag, "new"]);
        let result = nq_app::repository_cli::observe(dir.path()).unwrap();
        assert_eq!(
            result.disposition,
            RepositoryDisposition::NotEstablished {
                reason: "index_suppression_flags_unsupported".into()
            }
        );
        git(
            dir.path(),
            &["update-index", "--no-assume-unchanged", "new"],
        );
        git(dir.path(), &["update-index", "--no-skip-worktree", "new"]);
    }
}

#[test]
fn repository_command_filter_cannot_execute_or_launder_equal_length_changes() {
    let outer = tempfile::tempdir().unwrap();
    let repo = outer.path().join("repo");
    fs::create_dir(&repo).unwrap();
    git(&repo, &["init", "-q"]);
    fs::write(repo.join("tracked"), "original").unwrap();
    fs::write(repo.join(".gitattributes"), "tracked filter=fixed\n").unwrap();
    git(&repo, &["add", "tracked", ".gitattributes"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
    );
    let marker = outer.path().join("filter-ran");
    // Deliberately populate a stat cache matching the modified worktree while
    // the staged blob remains "original". This deterministically reproduces
    // the copied-index false-clean seam without depending on timestamp races.
    git(&repo, &["config", "filter.fixed.clean", "printf original"]);
    fs::write(repo.join("tracked"), "modified").unwrap();
    git(&repo, &["add", "tracked"]);
    git(
        &repo,
        &[
            "config",
            "filter.fixed.clean",
            &format!("touch {}; printf original", marker.display()),
        ],
    );
    let result = nq_app::repository_cli::observe(&repo).unwrap();
    assert!(matches!(
        result.disposition,
        RepositoryDisposition::ChangesPresent { .. }
    ));
    assert!(
        !marker.exists(),
        "collector must never execute repository command filters"
    );
}
