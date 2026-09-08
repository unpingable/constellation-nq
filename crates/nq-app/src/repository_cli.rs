//! Fixed local Git collector. No shell, hooks, alias expansion or generic
//! command input. Installed Git/runtime and this local owner are trusted;
//! repository writers need not be quiescent. The claim is interval-limited.
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use nq_profiles::repository_state::{
    CommandObservation, MAX_OUTPUT, RepositoryEvidence, RepositoryExecution, RepositorySubject,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use std::{
    fs,
    io::{Read, Seek, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[derive(Debug, Subcommand)]
pub enum RepositoryCommand {
    /// Observe one exact non-bare worktree. Output is a replayable historical artifact.
    Observe {
        #[arg(long)]
        worktree: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Reopen exact evidence and semantics; never recollect or assert currentness.
    Replay {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        producer_sha256: String,
    },
}

#[cfg(test)]
#[path = "repository_cli_tests.rs"]
mod tests;

pub fn run(command: RepositoryCommand) -> Result<()> {
    match command {
        RepositoryCommand::Observe { worktree, output } => {
            let execution = observe(&worktree)?;
            let bytes = canonical_json_bytes(&execution)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            println!("{}", execution.content_digest.as_str());
        }
        RepositoryCommand::Replay {
            artifact,
            producer_sha256,
        } => {
            let metadata = fs::symlink_metadata(&artifact)?;
            if !metadata.is_file() || metadata.len() > 32 * 1024 * 1024 {
                bail!("artifact is not a bounded regular file");
            }
            let bytes = fs::read(artifact)?;
            let execution: RepositoryExecution = serde_json::from_slice(&bytes)?;
            if canonical_json_bytes(&execution)? != bytes {
                bail!("artifact is not exact canonical JSON");
            }
            execution
                .replay(&Sha256Digest::parse(producer_sha256)?)
                .map_err(anyhow::Error::msg)?;
            // Returning the reopened object lets consumers retain exact provenance.
            println!("{}", String::from_utf8(bytes)?);
        }
    }
    Ok(())
}

fn git(worktree: &Path, operation: &str, arguments: &[&str]) -> Result<CommandObservation> {
    git_in(worktree, None, operation, arguments)
}

fn git_in(
    worktree: &Path,
    git_directory: Option<&Path>,
    operation: &str,
    arguments: &[&str],
) -> Result<CommandObservation> {
    let output = tempfile::tempfile()?;
    let mut reader = output.try_clone()?;
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .args([
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.quotePath=true",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
        ])
        .arg("-C")
        .arg(worktree)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::null());
    if let Some(directory) = git_directory {
        command
            .env("GIT_DIR", directory)
            .env("GIT_WORK_TREE", worktree);
    }
    let started = Instant::now();
    let mut child = command.spawn().context("start fixed Git collector")?;
    let (exit_code, failure) = loop {
        if let Some(status) = child.try_wait()? {
            break (status.code(), None);
        }
        if started.elapsed() > Duration::from_secs(4)
            || reader.metadata()?.len() > MAX_OUTPUT as u64
        {
            child.kill()?;
            child.wait()?;
            break (None, Some("deadline_or_output_limit".into()));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stdout = Vec::new();
    reader.rewind()?;
    std::io::Read::by_ref(&mut reader)
        .take(MAX_OUTPUT as u64 + 1)
        .read_to_end(&mut stdout)?;
    let failure = if stdout.len() > MAX_OUTPUT {
        stdout.clear();
        Some("output_limit".into())
    } else {
        failure
    };
    Ok(CommandObservation {
        operation: operation.into(),
        exit_code,
        stdout,
        failure,
    })
}

/// Capture one opened index into private collector custody. Git status and both
/// flag probes subsequently use this copy, never the mutable repository index.
fn capture_index(source: &Path, destination: &Path) -> Result<Option<Sha256Digest>> {
    let source = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOFOLLOW)
        .open(source)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !source.metadata()?.is_file() || source.metadata()?.len() > MAX_OUTPUT as u64 {
        bail!("unsupported index file or size");
    }
    let mut bytes = Vec::new();
    source.take(MAX_OUTPUT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_OUTPUT {
        bail!("index snapshot exceeded bound");
    }
    fs::write(destination, &bytes)?;
    Ok(Some(sha256_bytes(&bytes)))
}

pub fn observe(worktree: &Path) -> Result<RepositoryExecution> {
    let started_at = chrono::Utc::now();
    let worktree = fs::canonicalize(worktree)?;
    let metadata = fs::metadata(&worktree)?;
    let git_identity = sha256_bytes(&fs::read("/usr/bin/git")?);
    let directory = git(
        &worktree,
        "git_directory",
        &["rev-parse", "--absolute-git-dir"],
    )?;
    if directory.exit_code != Some(0) || directory.failure.is_some() {
        bail!("repository enrollment unavailable");
    }
    let git_directory = String::from_utf8(directory.stdout)?
        .trim_end_matches('\n')
        .to_owned();
    let subject = RepositorySubject {
        worktree: worktree
            .to_str()
            .context("non-UTF8 worktree unsupported")?
            .into(),
        device: metadata.dev(),
        inode: metadata.ino(),
        git_directory,
    };
    let bare = git(&worktree, "bare", &["rev-parse", "--is-bare-repository"])?;
    let head = git(&worktree, "head_before", &["rev-parse", "--verify", "HEAD"])?;
    let root = git(
        &worktree,
        "worktree_root",
        &["rev-parse", "--show-toplevel"],
    )?;
    let common = git(
        &worktree,
        "common_directory",
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    if common.exit_code != Some(0) || common.failure.is_some() {
        bail!("Git object-store enrollment unavailable");
    }
    let common = String::from_utf8(common.stdout)?;
    let common = common.trim_end_matches('\n');
    if !common.starts_with('/') || common.chars().any(char::is_control) {
        bail!("unsupported object-store locator");
    }
    let snapshot = tempfile::tempdir()?;
    fs::create_dir_all(snapshot.path().join("objects/info"))?;
    fs::create_dir(snapshot.path().join("info"))?;
    fs::create_dir(snapshot.path().join("refs"))?;
    fs::write(
        snapshot.path().join("objects/info/alternates"),
        format!("{common}/objects\n"),
    )?;
    // No repository/global/system config, hooks, info attributes or command
    // filters enter this private Git directory. Worktree .gitignore/attributes
    // remain observed data; undefined external filters cannot execute.
    let format = if head.stdout.len() == 65 {
        "[core]\nrepositoryFormatVersion=1\n[extensions]\nobjectFormat=sha256\n"
    } else {
        "[core]\nrepositoryFormatVersion=0\n"
    };
    fs::write(snapshot.path().join("config"), format)?;
    fs::write(
        snapshot.path().join("HEAD"),
        if head.exit_code == Some(0) {
            head.stdout.as_slice()
        } else {
            b"ref: refs/heads/unborn\n"
        },
    )?;
    let index_snapshot = capture_index(
        &Path::new(&subject.git_directory).join("index"),
        &snapshot.path().join("index"),
    )?;
    let exclude_snapshot = capture_index(
        &Path::new(common).join("info/exclude"),
        &snapshot.path().join("info/exclude"),
    )?;
    let before = git_in(
        &worktree,
        Some(snapshot.path()),
        "index_flags_before",
        &["ls-files", "-v", "-z"],
    )?;
    let index = git_in(
        &worktree,
        Some(snapshot.path()),
        "index",
        &["ls-files", "--stage", "-z"],
    )?;
    let status = git_in(
        &worktree,
        Some(snapshot.path()),
        "status",
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ],
    )?;
    let after = git_in(
        &worktree,
        Some(snapshot.path()),
        "index_flags",
        &["ls-files", "-v", "-z"],
    )?;
    let head_after = git(&worktree, "head_after", &["rev-parse", "--verify", "HEAD"])?;
    if let Some(expected) = &index_snapshot {
        if sha256_bytes(&fs::read(snapshot.path().join("index"))?) != *expected {
            bail!("private index changed during collection");
        }
    }
    let commands = vec![bare, head, index, status, head_after, after, root, before];
    if sha256_bytes(&fs::read("/usr/bin/git")?) != git_identity
        || fs::metadata(&worktree)?.ino() != metadata.ino()
    {
        bail!("collector or worktree identity changed");
    }
    RepositoryExecution::produce(RepositoryEvidence {
        subject_identity: subject.identity().map_err(anyhow::Error::msg)?,
        subject,
        started_at,
        ended_at: chrono::Utc::now(),
        git_executable: git_identity,
        collector_executable: sha256_bytes(&fs::read(std::env::current_exe()?)?),
        index_snapshot,
        exclude_snapshot,
        configuration: "nq.isolated_git_configuration.v1".into(),
        commands,
    })
    .map_err(anyhow::Error::msg)
}
