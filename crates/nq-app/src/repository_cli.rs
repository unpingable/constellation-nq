//! Fixed local Git collector. No shell, hooks, alias expansion or generic
//! command input. Installed Git/runtime and this local owner are trusted;
//! repository writers need not be quiescent. The claim is interval-limited.
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use nq_profiles::repository_state::{
    CommandObservation, MAX_OUTPUT, OPERATIONS, RepositoryEvidence, RepositoryExecution,
    RepositorySubject,
};
use nq_protocol::{Sha256Digest, canonical_json_bytes, sha256_bytes};
use std::{
    fs,
    io::{Read, Seek, Write},
    os::unix::fs::MetadataExt,
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
        .args([
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.quotePath=true",
        ])
        .arg("-C")
        .arg(worktree)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::null());
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
    let commands = [
        ["rev-parse", "--is-bare-repository"].as_slice(),
        ["rev-parse", "--verify", "HEAD"].as_slice(),
        ["ls-files", "--stage", "-z"].as_slice(),
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ]
        .as_slice(),
        ["rev-parse", "--verify", "HEAD"].as_slice(),
    ]
    .into_iter()
    .zip(OPERATIONS)
    .map(|(args, operation)| git(&worktree, operation, args))
    .collect::<Result<Vec<_>>>()?;
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
        commands,
    })
    .map_err(anyhow::Error::msg)
}
