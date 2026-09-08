use super::*;

fn command(repo: &Path, args: &[&str]) -> std::process::Output {
    let output = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    output
}

#[test]
fn source_flag_removal_does_not_change_the_captured_index_observation() {
    let directory = tempfile::tempdir().unwrap();
    let repo = directory.path().join("repo");
    fs::create_dir(&repo).unwrap();
    command(&repo, &["init", "-q"]);
    fs::write(repo.join("tracked"), "original").unwrap();
    command(&repo, &["add", "tracked"]);
    command(
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
    for flag in ["--assume-unchanged", "--skip-worktree"] {
        command(&repo, &["update-index", flag, "tracked"]);
        let copied = directory.path().join("captured-index");
        let digest = capture_index(&repo.join(".git/index"), &copied)
            .unwrap()
            .unwrap();
        command(
            &repo,
            &[
                "update-index",
                "--no-assume-unchanged",
                "--no-skip-worktree",
                "tracked",
            ],
        );
        assert_eq!(sha256_bytes(&fs::read(&copied).unwrap()), digest);
        let observed = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&repo)
            .env("GIT_INDEX_FILE", &copied)
            .args(["ls-files", "-v", "-z"])
            .output()
            .unwrap();
        assert!(observed.status.success());
        assert!(observed.stdout.starts_with(b"h ") || observed.stdout.starts_with(b"S "));
        assert!(
            command(&repo, &["ls-files", "-v", "-z"])
                .stdout
                .starts_with(b"H ")
        );
    }
}
