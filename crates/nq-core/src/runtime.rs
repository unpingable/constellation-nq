//! Conservative Linux startup-runtime qualification.
//!
//! V1 supports only host-architecture ELF64 little-endian executables using a
//! known glibc loader. Before that loader runs, NQ parses the retained object
//! and every recursively needed startup object without executing them, using a
//! fixed system-directory search and rejecting dynamic tags that can redirect
//! or add code. It then asks the loader to resolve the exact retained memfd
//! with its cache and hardware-capability directories disabled, and requires
//! the returned real-object set to equal the prequalified closure exactly.
//! This is intentionally not a general ELF dependency resolver and makes no
//! claim about objects loaded later through `dlopen`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use nq_helper_sandbox::{
    ExecutionAccount, child_has_exited, isolate_command, require_no_posix_acl,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::{
    ArtifactBudget, IdentityError, MAX_LAUNCH_ARTIFACTS, spawn_with_inherited_descriptors,
};

const ELF_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_DYNAMIC_ENTRY_BYTES: usize = 16;
const ELF64_DYNAMIC_ENTRY_BYTES_U64: u64 = 16;
const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_DYNAMIC_ENTRIES: u64 = 4096;
const MAX_DYNAMIC_STRING_TABLE_BYTES: u64 = 256 * 1024;
const MAX_NEEDED_NAME_BYTES: usize = 255;
const MAX_INTERPRETER_BYTES: u64 = 4096;
const MAX_LOADER_OUTPUT_BYTES: usize = 256 * 1024;
const MAX_LOADER_ENTRIES: usize = 64;
const MAX_DYNAMIC_DEPENDENCY_EDGES: usize = 256;
const MAX_RUNTIME_DIRECTORIES: usize = 128;
const LOADER_TIMEOUT: Duration = Duration::from_secs(5);
const GLOBAL_PRELOAD_PATH: &str = "/etc/ld.so.preload";

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_DEPAUDIT: u64 = 0x6fff_fefb;
const DT_AUDIT: u64 = 0x6fff_fefc;
const DT_AUXILIARY: u64 = 0x7fff_fffd;
const DT_FILTER: u64 = 0x7fff_ffff;

/// Complete normalized startup-runtime identity for one command chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StartupRuntimeIdentity {
    /// Native retained launch objects, including static objects.
    pub native_objects: Vec<NativeRuntimeIdentity>,
    /// Deduplicated on-disk loader and startup shared-object identities.
    pub artifacts: Vec<RuntimeArtifactIdentity>,
    /// Deduplicated lexical directory ancestry used to reach those artifacts.
    pub directories: Vec<RuntimeDirectoryIdentity>,
}

/// Startup linkage observed for one retained native object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeIdentity {
    /// Role of the retained object in the launch chain.
    pub role: RuntimeObjectRole,
    /// Canonical source path whose exact bytes were copied into the memfd.
    pub requester_path: PathBuf,
    /// Host ELF machine accepted by the v1 policy.
    pub machine: RuntimeMachine,
    /// Whether the object is static or uses the qualified glibc loader.
    pub linkage: RuntimeLinkage,
    /// Exact `PT_INTERP` path and canonical loader artifact for dynamic objects.
    pub loader: Option<RuntimeObjectBinding>,
    /// Ordered real-object resolution returned by the loader with addresses removed.
    pub objects: Vec<RuntimeObjectBinding>,
    /// Ordered kernel-provided virtual objects, currently only the vDSO.
    pub virtual_objects: Vec<String>,
}

/// Role of a native object among retained launch artifacts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeObjectRole {
    /// Configured root executable.
    Root,
    /// Kernel-style script interpreter retained by NQ.
    Interpreter,
    /// Fixed target selected through the supported `/usr/bin/env` wrapper.
    WrapperTarget,
}

/// Host machine types supported by the v1 runtime policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMachine {
    /// AMD64 ELF machine 62.
    X86_64,
    /// ARM64 ELF machine 183.
    Aarch64,
}

/// Whether an accepted native object has a startup interpreter.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLinkage {
    /// No `PT_INTERP` entry was present.
    Static,
    /// A supported glibc `PT_INTERP` entry was qualified.
    Dynamic,
}

/// One loader-returned path bound to its canonical runtime artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeObjectBinding {
    /// Absolute path emitted by the loader or stored in `PT_INTERP`.
    pub requested_path: PathBuf,
    /// Canonical artifact path reached through that request path.
    pub artifact_path: PathBuf,
}

/// Immutable identity of one on-disk startup code artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeArtifactIdentity {
    /// Runtime role; loader wins if an inode appears in both roles.
    pub kind: RuntimeArtifactKind,
    /// Canonical path opened with `O_NOFOLLOW`.
    pub path: PathBuf,
    /// Digest of the exact opened bytes.
    pub sha256: String,
    /// Exact descriptor byte length.
    pub size: u64,
    /// Filesystem device.
    pub device: u64,
    /// Filesystem inode.
    pub inode: u64,
    /// Owning Unix user ID.
    pub owner: u32,
    /// Owning Unix group ID.
    pub group: u32,
    /// Complete Unix mode returned by `fstat`.
    pub mode: u32,
    /// Nanosecond modification time used as an additional drift signal.
    pub modified_ns: String,
}

/// Role of an on-disk startup artifact.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeArtifactKind {
    /// ELF startup loader named by `PT_INTERP`.
    Loader,
    /// Shared object resolved by that loader.
    SharedObject,
}

/// Identity and deployment facts for one lexical ancestor directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeDirectoryIdentity {
    /// Absolute lexical prefix used by the loader or configured cwd.
    pub path: PathBuf,
    /// Canonical directory opened with `O_NOFOLLOW`.
    pub resolved_path: PathBuf,
    /// Filesystem device.
    pub device: u64,
    /// Filesystem inode.
    pub inode: u64,
    /// Owning Unix user ID.
    pub owner: u32,
    /// Owning Unix group ID.
    pub group: u32,
    /// Complete Unix mode returned by `fstat`.
    pub mode: u32,
}

pub(crate) struct RuntimeProbe<'a> {
    pub(crate) role: RuntimeObjectRole,
    pub(crate) source_path: &'a Path,
    pub(crate) proc_path: &'a Path,
    pub(crate) file: &'a File,
    pub(crate) prefix: &'a [u8],
}

impl StartupRuntimeIdentity {
    pub(crate) fn validate_and_reserve(
        &self,
        budget: &mut ArtifactBudget,
        seen_inodes: &mut BTreeSet<(u64, u64)>,
    ) -> Result<(), IdentityError> {
        if self.native_objects.len() > MAX_LAUNCH_ARTIFACTS {
            return Err(runtime_error(
                Path::new("/"),
                "startup runtime contains too many native launch objects",
            ));
        }
        if self.directories.len() > MAX_RUNTIME_DIRECTORIES {
            return Err(runtime_error(
                Path::new("/"),
                "startup runtime contains too many directory identities",
            ));
        }

        let mut artifact_paths = BTreeSet::new();
        for artifact in &self.artifacts {
            if !artifact.path.is_absolute() || !artifact_paths.insert(artifact.path.clone()) {
                return Err(runtime_error(
                    &artifact.path,
                    "runtime artifact path is relative or duplicated",
                ));
            }
            if seen_inodes.insert((artifact.device, artifact.inode)) {
                budget.reserve(&artifact.path, artifact.size)?;
            }
        }
        let mut directory_paths = BTreeSet::new();
        for directory in &self.directories {
            if !directory.path.is_absolute()
                || !directory.resolved_path.is_absolute()
                || !directory_paths.insert(directory.path.clone())
            {
                return Err(runtime_error(
                    &directory.path,
                    "runtime directory path is relative or duplicated",
                ));
            }
        }
        for native in &self.native_objects {
            let expected_dynamic = native.linkage == RuntimeLinkage::Dynamic;
            if expected_dynamic != native.loader.is_some()
                || (!expected_dynamic
                    && (!native.objects.is_empty() || !native.virtual_objects.is_empty()))
            {
                return Err(runtime_error(
                    &native.requester_path,
                    "native runtime linkage and loader result disagree",
                ));
            }
            for binding in native.loader.iter().chain(&native.objects) {
                if !binding.requested_path.is_absolute()
                    || !artifact_paths.contains(&binding.artifact_path)
                {
                    return Err(runtime_error(
                        &native.requester_path,
                        "runtime object binding references an unknown artifact",
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn discover_startup_runtime(
    probes: &[RuntimeProbe<'_>],
    account: &ExecutionAccount,
    budget: &mut ArtifactBudget,
    seen_inodes: &mut BTreeSet<(u64, u64)>,
) -> Result<StartupRuntimeIdentity, IdentityError> {
    reject_global_preload()?;
    discover_startup_runtime_with_loader(probes, account, budget, seen_inodes, invoke_loader)
}

fn discover_startup_runtime_with_loader<F>(
    probes: &[RuntimeProbe<'_>],
    account: &ExecutionAccount,
    budget: &mut ArtifactBudget,
    seen_inodes: &mut BTreeSet<(u64, u64)>,
    mut load: F,
) -> Result<StartupRuntimeIdentity, IdentityError>
where
    F: FnMut(
        &Path,
        &Path,
        RawFd,
        &ExecutionAccount,
        RuntimeMachine,
    ) -> Result<Vec<u8>, IdentityError>,
{
    let mut native_objects = Vec::new();
    let mut artifacts = BTreeMap::<PathBuf, RuntimeArtifactIdentity>::new();
    let mut artifact_inodes = BTreeMap::<(u64, u64), PathBuf>::new();
    let mut directories = BTreeMap::<PathBuf, RuntimeDirectoryIdentity>::new();

    for probe in probes {
        let Some(native) = parse_native(probe)? else {
            continue;
        };
        let Some(interpreter) = native.interpreter else {
            if !native.needed.is_empty() {
                return Err(runtime_error(
                    probe.source_path,
                    "ELF declares DT_NEEDED dependencies without PT_INTERP",
                ));
            }
            native_objects.push(NativeRuntimeIdentity {
                role: probe.role,
                requester_path: probe.source_path.to_path_buf(),
                machine: native.machine,
                linkage: RuntimeLinkage::Static,
                loader: None,
                objects: Vec::new(),
                virtual_objects: Vec::new(),
            });
            continue;
        };
        require_supported_loader(&interpreter, native.machine)?;
        add_ancestry(&interpreter, account, &mut directories)?;
        let loader_path = qualify_runtime_artifact(
            &interpreter,
            RuntimeArtifactKind::Loader,
            account,
            budget,
            seen_inodes,
            &mut artifacts,
            &mut artifact_inodes,
        )?;
        let loader = RuntimeObjectBinding {
            requested_path: interpreter.clone(),
            artifact_path: loader_path.clone(),
        };

        let expected_paths = prequalify_startup_closure(
            probe.source_path,
            &native.needed,
            native.machine,
            &loader_path,
            account,
            budget,
            seen_inodes,
            &mut artifacts,
            &mut artifact_inodes,
            &mut directories,
        )?;

        let output = load(
            &loader_path,
            probe.proc_path,
            probe.file.as_raw_fd(),
            account,
            native.machine,
        )?;
        let (objects, virtual_objects) = bind_loader_output_to_closure(
            &output,
            probe.source_path,
            account,
            &mut directories,
            &artifacts,
            &expected_paths,
            &loader_path,
        )?;
        native_objects.push(NativeRuntimeIdentity {
            role: probe.role,
            requester_path: probe.source_path.to_path_buf(),
            machine: native.machine,
            linkage: RuntimeLinkage::Dynamic,
            loader: Some(loader),
            objects,
            virtual_objects,
        });
    }

    let identity = StartupRuntimeIdentity {
        native_objects,
        artifacts: artifacts.into_values().collect(),
        directories: directories.into_values().collect(),
    };
    identity.validate_and_reserve(&mut ArtifactBudget::default(), &mut BTreeSet::new())?;
    Ok(identity)
}

#[allow(clippy::too_many_arguments)]
fn bind_loader_output_to_closure(
    output: &[u8],
    requester: &Path,
    account: &ExecutionAccount,
    directories: &mut BTreeMap<PathBuf, RuntimeDirectoryIdentity>,
    artifacts: &BTreeMap<PathBuf, RuntimeArtifactIdentity>,
    expected_paths: &BTreeSet<PathBuf>,
    loader_path: &Path,
) -> Result<(Vec<RuntimeObjectBinding>, Vec<String>), IdentityError> {
    let parsed = parse_loader_output(output, requester)?;
    let mut objects = Vec::new();
    let mut virtual_objects = Vec::new();
    let mut saw_loader = false;
    let mut observed_paths = BTreeSet::new();
    for object in parsed {
        match object {
            ParsedLoaderObject::Virtual(name) => virtual_objects.push(name),
            ParsedLoaderObject::Path(requested_path) => {
                add_ancestry(&requested_path, account, directories)?;
                let canonical = fs::canonicalize(&requested_path)
                    .map_err(|source| runtime_io(&requested_path, source))?;
                require_system_runtime_path(&canonical)?;
                if !observed_paths.insert(canonical.clone()) {
                    return Err(runtime_error(
                        requester,
                        "glibc loader returned two paths for one canonical startup object",
                    ));
                }
                if !expected_paths.contains(&canonical) {
                    return Err(runtime_error(
                        requester,
                        format!(
                            "glibc loader returned an object absent from the prequalified dependency closure: {}",
                            canonical.display()
                        ),
                    ));
                }
                add_ancestry(&canonical, account, directories)?;
                saw_loader |= canonical == loader_path;
                if !artifacts.contains_key(&canonical) {
                    return Err(runtime_error(
                        requester,
                        "prequalified runtime artifact identity is absent",
                    ));
                }
                objects.push(RuntimeObjectBinding {
                    requested_path,
                    artifact_path: canonical,
                });
            }
        }
    }
    if !saw_loader {
        return Err(runtime_error(
            requester,
            "glibc loader output did not identify its own PT_INTERP artifact",
        ));
    }
    if observed_paths != *expected_paths {
        let missing = expected_paths
            .difference(&observed_paths)
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(runtime_error(
            requester,
            format!("glibc loader omitted prequalified startup objects: {missing}"),
        ));
    }
    Ok((objects, virtual_objects))
}

pub(crate) fn qualify_directory_ancestry(
    path: &Path,
    account: &ExecutionAccount,
    enforce_deployment: bool,
) -> Result<Vec<RuntimeDirectoryIdentity>, IdentityError> {
    if !path.is_absolute() {
        return Err(runtime_error(path, "directory ancestry must be absolute"));
    }
    let mut current = PathBuf::from("/");
    let mut result = vec![qualify_one_directory(
        Path::new("/"),
        account,
        enforce_deployment,
    )?];
    for component in path.components().skip(1) {
        match component {
            Component::Normal(part) => current.push(part),
            Component::CurDir | Component::ParentDir => {
                return Err(runtime_error(
                    path,
                    "directory ancestry contains dot components",
                ));
            }
            Component::RootDir => continue,
            Component::Prefix(_) => {
                return Err(runtime_error(path, "unsupported path prefix"));
            }
        }
        result.push(qualify_one_directory(
            &current,
            account,
            enforce_deployment,
        )?);
        if result.len() > MAX_RUNTIME_DIRECTORIES {
            return Err(runtime_error(path, "directory ancestry is too deep"));
        }
    }
    Ok(result)
}

pub(crate) fn require_directory_descriptor_policy(
    file: &File,
    path: &Path,
    account: &ExecutionAccount,
    enforce_deployment: bool,
) -> Result<(), IdentityError> {
    let metadata = file.metadata().map_err(|source| runtime_io(path, source))?;
    if !metadata.is_dir() {
        return Err(runtime_error(path, "deployment path is not a directory"));
    }
    if enforce_deployment {
        require_deployment_policy(file, &metadata, path, account)?;
    }
    Ok(())
}

fn add_ancestry(
    path: &Path,
    account: &ExecutionAccount,
    directories: &mut BTreeMap<PathBuf, RuntimeDirectoryIdentity>,
) -> Result<(), IdentityError> {
    let parent = path
        .parent()
        .ok_or_else(|| runtime_error(path, "runtime artifact has no parent directory"))?;
    for identity in qualify_directory_ancestry(parent, account, !account.debug_same_identity)? {
        if let Some(previous) = directories.insert(identity.path.clone(), identity.clone())
            && previous != identity
        {
            return Err(runtime_error(
                &identity.path,
                "runtime directory changed during discovery",
            ));
        }
        if directories.len() > MAX_RUNTIME_DIRECTORIES {
            return Err(runtime_error(
                path,
                "startup runtime uses too many directory identities",
            ));
        }
    }
    Ok(())
}

fn qualify_one_directory(
    path: &Path,
    account: &ExecutionAccount,
    enforce_deployment: bool,
) -> Result<RuntimeDirectoryIdentity, IdentityError> {
    let resolved_path = fs::canonicalize(path).map_err(|source| runtime_io(path, source))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&resolved_path)
        .map_err(|source| runtime_io(&resolved_path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| runtime_io(&resolved_path, source))?;
    if !metadata.is_dir() {
        return Err(runtime_error(path, "runtime ancestor is not a directory"));
    }
    if enforce_deployment {
        require_deployment_policy(&file, &metadata, path, account)?;
    }
    Ok(RuntimeDirectoryIdentity {
        path: path.to_path_buf(),
        resolved_path,
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.mode(),
    })
}

#[allow(clippy::too_many_arguments)]
fn qualify_runtime_artifact(
    requested_path: &Path,
    kind: RuntimeArtifactKind,
    account: &ExecutionAccount,
    budget: &mut ArtifactBudget,
    seen_inodes: &mut BTreeSet<(u64, u64)>,
    artifacts: &mut BTreeMap<PathBuf, RuntimeArtifactIdentity>,
    artifact_inodes: &mut BTreeMap<(u64, u64), PathBuf>,
) -> Result<PathBuf, IdentityError> {
    if !requested_path.is_absolute() {
        return Err(runtime_error(
            requested_path,
            "loader returned a non-absolute object path",
        ));
    }
    let path =
        fs::canonicalize(requested_path).map_err(|source| runtime_io(requested_path, source))?;
    require_system_runtime_path(&path)?;
    if let Some(existing) = artifacts.get_mut(&path) {
        if kind == RuntimeArtifactKind::Loader {
            existing.kind = RuntimeArtifactKind::Loader;
        }
        return Ok(path);
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|source| runtime_io(&path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| runtime_io(&path, source))?;
    if !metadata.is_file() || (kind == RuntimeArtifactKind::Loader && metadata.mode() & 0o111 == 0)
    {
        return Err(runtime_error(
            &path,
            "runtime artifact is not a supported regular file",
        ));
    }
    if !account.debug_same_identity {
        require_deployment_policy(&file, &metadata, &path, account)?;
    }
    if let Some(previous) = artifact_inodes.insert((metadata.dev(), metadata.ino()), path.clone())
        && previous != path
    {
        return Err(runtime_error(
            &path,
            "one runtime inode is reachable through multiple canonical hard-link paths",
        ));
    }
    if seen_inodes.insert((metadata.dev(), metadata.ino())) {
        budget.reserve(&path, metadata.len())?;
    }
    let sha256 = hash_file(&file, metadata.len(), &path)?;
    let after = file
        .metadata()
        .map_err(|source| runtime_io(&path, source))?;
    if after.len() != metadata.len()
        || after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.uid() != metadata.uid()
        || after.gid() != metadata.gid()
        || after.mode() != metadata.mode()
        || after.mtime() != metadata.mtime()
        || after.mtime_nsec() != metadata.mtime_nsec()
    {
        return Err(runtime_error(
            &path,
            "runtime artifact changed while it was hashed",
        ));
    }
    artifacts.insert(
        path.clone(),
        RuntimeArtifactIdentity {
            kind,
            path: path.clone(),
            sha256,
            size: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            group: metadata.gid(),
            mode: metadata.mode(),
            modified_ns: modified_ns(&metadata),
        },
    );
    Ok(path)
}

#[allow(clippy::too_many_arguments)]
fn prequalify_startup_closure(
    requester: &Path,
    root_needed: &[String],
    machine: RuntimeMachine,
    loader_path: &Path,
    account: &ExecutionAccount,
    budget: &mut ArtifactBudget,
    seen_inodes: &mut BTreeSet<(u64, u64)>,
    artifacts: &mut BTreeMap<PathBuf, RuntimeArtifactIdentity>,
    artifact_inodes: &mut BTreeMap<(u64, u64), PathBuf>,
    directories: &mut BTreeMap<PathBuf, RuntimeDirectoryIdentity>,
) -> Result<BTreeSet<PathBuf>, IdentityError> {
    let mut expected_paths = BTreeSet::from([loader_path.to_path_buf()]);
    let mut parsed_paths = BTreeSet::new();
    let mut resolved_names = BTreeMap::<PathBuf, String>::new();
    let mut pending = VecDeque::<(PathBuf, String)>::new();
    let mut dependency_edges = 0_usize;

    let loader_needed = parse_qualified_runtime_object(
        loader_path,
        machine,
        artifacts
            .get(loader_path)
            .ok_or_else(|| runtime_error(loader_path, "qualified loader identity is absent"))?,
    )?;
    parsed_paths.insert(loader_path.to_path_buf());
    enqueue_dependencies(
        &mut pending,
        &mut dependency_edges,
        loader_path,
        &loader_needed,
    )?;
    enqueue_dependencies(&mut pending, &mut dependency_edges, requester, root_needed)?;

    while let Some((declaring_object, soname)) = pending.pop_front() {
        let requested_path = resolve_fixed_soname(machine, &soname, &declaring_object)?;
        add_ancestry(&requested_path, account, directories)?;
        let canonical = fs::canonicalize(&requested_path)
            .map_err(|source| runtime_io(&requested_path, source))?;
        add_ancestry(&canonical, account, directories)?;
        if let Some(previous) = resolved_names.insert(canonical.clone(), soname.clone())
            && previous != soname
        {
            return Err(runtime_error(
                &declaring_object,
                format!(
                    "two DT_NEEDED sonames resolve to one canonical object: {previous:?} and {soname:?}"
                ),
            ));
        }
        let kind = if canonical == loader_path {
            RuntimeArtifactKind::Loader
        } else {
            RuntimeArtifactKind::SharedObject
        };
        let artifact_path = qualify_runtime_artifact(
            &requested_path,
            kind,
            account,
            budget,
            seen_inodes,
            artifacts,
            artifact_inodes,
        )?;
        expected_paths.insert(artifact_path.clone());
        if expected_paths.len() > MAX_LOADER_ENTRIES {
            return Err(runtime_error(
                requester,
                "prequalified startup dependency closure is too large",
            ));
        }
        if !parsed_paths.insert(artifact_path.clone()) {
            continue;
        }
        let needed = parse_qualified_runtime_object(
            &artifact_path,
            machine,
            artifacts.get(&artifact_path).ok_or_else(|| {
                runtime_error(&artifact_path, "qualified shared-object identity is absent")
            })?,
        )?;
        enqueue_dependencies(&mut pending, &mut dependency_edges, &artifact_path, &needed)?;
    }
    Ok(expected_paths)
}

fn enqueue_dependencies(
    pending: &mut VecDeque<(PathBuf, String)>,
    edge_count: &mut usize,
    declaring_object: &Path,
    dependencies: &[String],
) -> Result<(), IdentityError> {
    *edge_count = edge_count
        .checked_add(dependencies.len())
        .ok_or_else(|| runtime_error(declaring_object, "dependency edge count overflows"))?;
    if *edge_count > MAX_DYNAMIC_DEPENDENCY_EDGES {
        return Err(runtime_error(
            declaring_object,
            "startup dependency graph has too many edges",
        ));
    }
    pending.extend(
        dependencies
            .iter()
            .cloned()
            .map(|name| (declaring_object.to_path_buf(), name)),
    );
    Ok(())
}

fn resolve_fixed_soname(
    machine: RuntimeMachine,
    soname: &str,
    declaring_object: &Path,
) -> Result<PathBuf, IdentityError> {
    for directory in standard_library_directories(machine) {
        let candidate = Path::new(directory).join(soname);
        match fs::canonicalize(&candidate) {
            Ok(canonical) => {
                require_system_runtime_path(&canonical)?;
                return Ok(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(runtime_io(&candidate, source)),
        }
    }
    Err(runtime_error(
        declaring_object,
        format!("DT_NEEDED soname {soname:?} is absent from the fixed system library path"),
    ))
}

fn standard_library_directories(machine: RuntimeMachine) -> &'static [&'static str] {
    match machine {
        RuntimeMachine::X86_64 => &[
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
        ],
        RuntimeMachine::Aarch64 => &[
            "/lib/aarch64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
            "/lib64",
            "/usr/lib64",
            "/lib",
            "/usr/lib",
        ],
    }
}

fn fixed_library_path(machine: RuntimeMachine) -> String {
    standard_library_directories(machine).join(":")
}

fn parse_qualified_runtime_object(
    path: &Path,
    machine: RuntimeMachine,
    expected: &RuntimeArtifactIdentity,
) -> Result<Vec<String>, IdentityError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| runtime_io(path, source))?;
    let before = file.metadata().map_err(|source| runtime_io(path, source))?;
    require_expected_runtime_metadata(path, &before, expected)?;
    let mut prefix = [0_u8; ELF_HEADER_BYTES];
    read_exact_at(&file, &mut prefix, 0, path)?;
    let probe = RuntimeProbe {
        role: RuntimeObjectRole::Root,
        source_path: path,
        proc_path: path,
        file: &file,
        prefix: &prefix,
    };
    let parsed = parse_native(&probe)?
        .ok_or_else(|| runtime_error(path, "startup runtime object is not ELF"))?;
    if let Some(interpreter) = &parsed.interpreter {
        require_supported_loader(interpreter, machine)?;
    }
    if parsed.object_type != 3 || parsed.machine != machine || !parsed.has_dynamic {
        return Err(runtime_error(
            path,
            "startup runtime object is not a matching dynamic ET_DYN object",
        ));
    }
    let digest = hash_file(&file, before.len(), path)?;
    let after = file.metadata().map_err(|source| runtime_io(path, source))?;
    require_expected_runtime_metadata(path, &after, expected)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || digest != expected.sha256
    {
        return Err(runtime_error(
            path,
            "startup runtime object changed between qualification and dependency parsing",
        ));
    }
    Ok(parsed.needed)
}

fn require_expected_runtime_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    expected: &RuntimeArtifactIdentity,
) -> Result<(), IdentityError> {
    if !metadata.is_file()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.len() != expected.size
        || metadata.uid() != expected.owner
        || metadata.gid() != expected.group
        || metadata.mode() != expected.mode
        || modified_ns(metadata) != expected.modified_ns
    {
        return Err(runtime_error(
            path,
            "startup runtime object metadata differs from its qualified identity",
        ));
    }
    Ok(())
}

fn require_deployment_policy(
    file: &File,
    metadata: &fs::Metadata,
    path: &Path,
    account: &ExecutionAccount,
) -> Result<(), IdentityError> {
    require_no_posix_acl(file).map_err(|source| runtime_io(path, source))?;
    if metadata.uid() != 0 {
        return Err(runtime_error(
            path,
            format!(
                "runtime/deployment object is not root-owned (owner={}, helper_uid={})",
                metadata.uid(),
                account.uid
            ),
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(runtime_error(
            path,
            "runtime/deployment object is writable by group or other",
        ));
    }
    Ok(())
}

fn require_supported_loader(path: &Path, machine: RuntimeMachine) -> Result<(), IdentityError> {
    let accepted = match machine {
        RuntimeMachine::X86_64 => [
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ]
        .as_slice(),
        RuntimeMachine::Aarch64 => [
            "/lib/ld-linux-aarch64.so.1",
            "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
            "/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        ]
        .as_slice(),
    };
    if accepted
        .iter()
        .any(|candidate| path == Path::new(candidate))
    {
        Ok(())
    } else {
        Err(runtime_error(
            path,
            "custom or unsupported ELF startup loader",
        ))
    }
}

fn require_system_runtime_path(path: &Path) -> Result<(), IdentityError> {
    let supported = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        .into_iter()
        .any(|root| path.starts_with(root));
    if supported {
        Ok(())
    } else {
        Err(runtime_error(
            path,
            "startup runtime artifact is outside supported system library roots",
        ))
    }
}

fn reject_global_preload() -> Result<(), IdentityError> {
    let path = Path::new(GLOBAL_PRELOAD_PATH);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(runtime_io(path, source)),
    };
    let _metadata = file.metadata().map_err(|source| runtime_io(path, source))?;
    Err(runtime_error(
        path,
        "global loader preload configuration exists and is unsupported",
    ))
}

struct ParsedNative {
    object_type: u16,
    machine: RuntimeMachine,
    interpreter: Option<PathBuf>,
    has_dynamic: bool,
    needed: Vec<String>,
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
}

#[allow(clippy::too_many_lines)]
fn parse_native(probe: &RuntimeProbe<'_>) -> Result<Option<ParsedNative>, IdentityError> {
    if !probe.prefix.starts_with(b"\x7fELF") {
        return Ok(None);
    }
    let mut header = [0_u8; ELF_HEADER_BYTES];
    read_exact_at(probe.file, &mut header, 0, probe.source_path)?;
    if header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(runtime_error(
            probe.source_path,
            "only ELF64 little-endian version-1 objects are supported",
        ));
    }
    let object_type = u16::from_le_bytes([header[16], header[17]]);
    if !matches!(object_type, 2 | 3) {
        return Err(runtime_error(
            probe.source_path,
            "unsupported ELF object type",
        ));
    }
    let machine_number = u16::from_le_bytes([header[18], header[19]]);
    let machine = RuntimeMachine::for_host(machine_number).ok_or_else(|| {
        runtime_error(
            probe.source_path,
            "ELF machine does not match the supported host architecture",
        )
    })?;
    let program_offset = u64::from_le_bytes(header[32..40].try_into().expect("fixed slice"));
    let header_size = usize::from(u16::from_le_bytes([header[54], header[55]]));
    let header_count = usize::from(u16::from_le_bytes([header[56], header[57]]));
    if header_size != ELF64_PROGRAM_HEADER_BYTES || header_count > MAX_PROGRAM_HEADERS {
        return Err(runtime_error(
            probe.source_path,
            "unsupported ELF program-header layout",
        ));
    }
    let table_bytes = header_size
        .checked_mul(header_count)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| runtime_error(probe.source_path, "ELF header table overflows"))?;
    let file_size = probe
        .file
        .metadata()
        .map_err(|source| runtime_io(probe.source_path, source))?
        .len();
    if program_offset
        .checked_add(table_bytes)
        .is_none_or(|end| end > file_size)
    {
        return Err(runtime_error(
            probe.source_path,
            "ELF program-header table exceeds the retained object",
        ));
    }

    let mut programs = Vec::with_capacity(header_count);
    for index in 0..header_count {
        let offset = program_offset
            + u64::try_from(index * header_size).expect("bounded program-header offset");
        let mut program = [0_u8; ELF64_PROGRAM_HEADER_BYTES];
        read_exact_at(probe.file, &mut program, offset, probe.source_path)?;
        programs.push(ProgramHeader {
            kind: u32::from_le_bytes(program[0..4].try_into().expect("fixed slice")),
            offset: u64::from_le_bytes(program[8..16].try_into().expect("fixed slice")),
            virtual_address: u64::from_le_bytes(program[16..24].try_into().expect("fixed slice")),
            file_size: u64::from_le_bytes(program[32..40].try_into().expect("fixed slice")),
            memory_size: u64::from_le_bytes(program[40..48].try_into().expect("fixed slice")),
        });
    }

    let mut dynamic = None;
    for program in &programs {
        if program.kind == PT_DYNAMIC && dynamic.replace(*program).is_some() {
            return Err(runtime_error(
                probe.source_path,
                "ELF contains multiple PT_DYNAMIC entries",
            ));
        }
    }
    let needed = if let Some(dynamic) = dynamic {
        validate_dynamic_segment(probe, &programs, dynamic, file_size)?
    } else {
        Vec::new()
    };

    let mut interpreter = None;
    for program in &programs {
        if program.kind != PT_INTERP {
            continue;
        }
        if interpreter.is_some() {
            return Err(runtime_error(
                probe.source_path,
                "ELF contains multiple PT_INTERP entries",
            ));
        }
        let string_offset = program.offset;
        let string_size = program.file_size;
        if !(2..=MAX_INTERPRETER_BYTES).contains(&string_size)
            || string_offset
                .checked_add(string_size)
                .is_none_or(|end| end > file_size)
        {
            return Err(runtime_error(
                probe.source_path,
                "ELF PT_INTERP is absent from bounds",
            ));
        }
        let mut bytes = vec![0_u8; usize::try_from(string_size).expect("bounded PT_INTERP")];
        read_exact_at(probe.file, &mut bytes, string_offset, probe.source_path)?;
        if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
            return Err(runtime_error(
                probe.source_path,
                "ELF PT_INTERP is not one NUL-terminated path",
            ));
        }
        bytes.pop();
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| runtime_error(probe.source_path, "ELF PT_INTERP path is not UTF-8"))?;
        let value = PathBuf::from(value);
        if !value.is_absolute() {
            return Err(runtime_error(
                probe.source_path,
                "ELF PT_INTERP path is not absolute",
            ));
        }
        interpreter = Some(value);
    }
    Ok(Some(ParsedNative {
        object_type,
        machine,
        interpreter,
        has_dynamic: dynamic.is_some(),
        needed,
    }))
}

fn validate_dynamic_segment(
    probe: &RuntimeProbe<'_>,
    programs: &[ProgramHeader],
    dynamic: ProgramHeader,
    file_size: u64,
) -> Result<Vec<String>, IdentityError> {
    if dynamic.file_size == 0
        || dynamic.file_size != dynamic.memory_size
        || !dynamic
            .file_size
            .is_multiple_of(ELF64_DYNAMIC_ENTRY_BYTES_U64)
    {
        return Err(runtime_error(
            probe.source_path,
            "ELF PT_DYNAMIC has unsupported file/memory bounds",
        ));
    }
    let entries = dynamic.file_size / ELF64_DYNAMIC_ENTRY_BYTES_U64;
    if entries > MAX_DYNAMIC_ENTRIES
        || dynamic
            .offset
            .checked_add(dynamic.file_size)
            .is_none_or(|end| end > file_size)
    {
        return Err(runtime_error(
            probe.source_path,
            "ELF PT_DYNAMIC exceeds its bounded retained bytes",
        ));
    }
    validate_dynamic_mapping(probe.source_path, programs, dynamic, file_size)?;

    let values = read_dynamic_values(probe, dynamic, entries)?;
    read_needed_names(probe, programs, file_size, values)
}

struct DynamicValues {
    string_table_address: Option<u64>,
    string_table_size: Option<u64>,
    needed_offsets: Vec<u64>,
}

fn read_dynamic_values(
    probe: &RuntimeProbe<'_>,
    dynamic: ProgramHeader,
    entries: u64,
) -> Result<DynamicValues, IdentityError> {
    let mut saw_null = false;
    let mut string_table_address = None;
    let mut string_table_size = None;
    let mut needed_offsets = Vec::new();
    for index in 0..entries {
        let offset = dynamic.offset
            + index
                .checked_mul(ELF64_DYNAMIC_ENTRY_BYTES_U64)
                .expect("bounded dynamic-entry offset");
        let mut entry = [0_u8; ELF64_DYNAMIC_ENTRY_BYTES];
        read_exact_at(probe.file, &mut entry, offset, probe.source_path)?;
        let tag = u64::from_le_bytes(entry[..8].try_into().expect("fixed slice"));
        let value = u64::from_le_bytes(entry[8..].try_into().expect("fixed slice"));
        if tag == DT_NULL {
            saw_null = true;
            break;
        }
        if let Some(name) = forbidden_dynamic_tag_name(tag) {
            return Err(runtime_error(
                probe.source_path,
                format!("ELF PT_DYNAMIC tag {name} can load unqualified code"),
            ));
        }
        match tag {
            DT_NEEDED => {
                if needed_offsets.len() >= MAX_LOADER_ENTRIES {
                    return Err(runtime_error(
                        probe.source_path,
                        "ELF declares too many DT_NEEDED dependencies",
                    ));
                }
                needed_offsets.push(value);
            }
            DT_STRTAB => set_unique_dynamic_value(
                &mut string_table_address,
                value,
                probe.source_path,
                "DT_STRTAB",
            )?,
            DT_STRSZ => set_unique_dynamic_value(
                &mut string_table_size,
                value,
                probe.source_path,
                "DT_STRSZ",
            )?,
            DT_RPATH | DT_RUNPATH => {
                return Err(runtime_error(
                    probe.source_path,
                    "ELF RPATH/RUNPATH is unsupported; startup libraries must use the fixed system search path",
                ));
            }
            _ => {}
        }
    }
    if !saw_null {
        return Err(runtime_error(
            probe.source_path,
            "ELF PT_DYNAMIC has no bounded DT_NULL terminator",
        ));
    }
    Ok(DynamicValues {
        string_table_address,
        string_table_size,
        needed_offsets,
    })
}

fn read_needed_names(
    probe: &RuntimeProbe<'_>,
    programs: &[ProgramHeader],
    file_size: u64,
    values: DynamicValues,
) -> Result<Vec<String>, IdentityError> {
    if values.needed_offsets.is_empty() {
        return Ok(Vec::new());
    }
    let string_table_address = values.string_table_address.ok_or_else(|| {
        runtime_error(
            probe.source_path,
            "ELF DT_NEEDED entries have no unique DT_STRTAB",
        )
    })?;
    let string_table_size = values.string_table_size.ok_or_else(|| {
        runtime_error(
            probe.source_path,
            "ELF DT_NEEDED entries have no unique DT_STRSZ",
        )
    })?;
    if !(1..=MAX_DYNAMIC_STRING_TABLE_BYTES).contains(&string_table_size) {
        return Err(runtime_error(
            probe.source_path,
            format!(
                "ELF dynamic string table is empty or exceeds {MAX_DYNAMIC_STRING_TABLE_BYTES} bytes"
            ),
        ));
    }
    let string_table_offset = map_virtual_file_range(
        probe.source_path,
        programs,
        string_table_address,
        string_table_size,
        file_size,
        "DT_STRTAB",
    )?;
    let mut string_table =
        vec![0_u8; usize::try_from(string_table_size).expect("bounded dynamic string table")];
    read_exact_at(
        probe.file,
        &mut string_table,
        string_table_offset,
        probe.source_path,
    )?;
    let mut names = Vec::with_capacity(values.needed_offsets.len());
    let mut unique = BTreeSet::new();
    for offset in values.needed_offsets {
        let offset = usize::try_from(offset)
            .map_err(|_| runtime_error(probe.source_path, "ELF DT_NEEDED offset exceeds usize"))?;
        let remaining = string_table.get(offset..).ok_or_else(|| {
            runtime_error(
                probe.source_path,
                "ELF DT_NEEDED offset exceeds DT_STRTAB bounds",
            )
        })?;
        let terminator = remaining
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| {
                runtime_error(
                    probe.source_path,
                    "ELF DT_NEEDED name has no bounded NUL terminator",
                )
            })?;
        let name_bytes = &remaining[..terminator];
        if name_bytes.is_empty() || name_bytes.len() > MAX_NEEDED_NAME_BYTES {
            return Err(runtime_error(
                probe.source_path,
                "ELF DT_NEEDED name is empty or oversized",
            ));
        }
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| runtime_error(probe.source_path, "ELF DT_NEEDED name is not UTF-8"))?;
        if name.contains('/')
            || name == "."
            || name == ".."
            || name
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(runtime_error(
                probe.source_path,
                "ELF DT_NEEDED is not a safe bare soname",
            ));
        }
        if !unique.insert(name.to_owned()) {
            return Err(runtime_error(
                probe.source_path,
                "ELF repeats a DT_NEEDED soname",
            ));
        }
        names.push(name.to_owned());
    }
    Ok(names)
}

fn set_unique_dynamic_value(
    slot: &mut Option<u64>,
    value: u64,
    path: &Path,
    tag: &str,
) -> Result<(), IdentityError> {
    if slot.replace(value).is_some() {
        return Err(runtime_error(path, format!("ELF PT_DYNAMIC repeats {tag}")));
    }
    Ok(())
}

fn validate_dynamic_mapping(
    path: &Path,
    programs: &[ProgramHeader],
    dynamic: ProgramHeader,
    file_size: u64,
) -> Result<(), IdentityError> {
    let mapped_offset = map_virtual_file_range(
        path,
        programs,
        dynamic.virtual_address,
        dynamic.file_size,
        file_size,
        "PT_DYNAMIC",
    )?;
    if mapped_offset != dynamic.offset {
        return Err(runtime_error(
            path,
            "ELF PT_DYNAMIC file and virtual mappings disagree",
        ));
    }
    Ok(())
}

fn map_virtual_file_range(
    path: &Path,
    programs: &[ProgramHeader],
    virtual_address: u64,
    size: u64,
    file_size: u64,
    label: &str,
) -> Result<u64, IdentityError> {
    let range_end = virtual_address
        .checked_add(size)
        .ok_or_else(|| runtime_error(path, format!("ELF {label} virtual range overflows")))?;
    let mut containing_load = None;
    for program in programs {
        if program.kind != PT_LOAD {
            continue;
        }
        if program.file_size > program.memory_size
            || program
                .offset
                .checked_add(program.file_size)
                .is_none_or(|end| end > file_size)
        {
            return Err(runtime_error(path, "ELF PT_LOAD exceeds retained bytes"));
        }
        let load_end = program
            .virtual_address
            .checked_add(program.file_size)
            .ok_or_else(|| runtime_error(path, "ELF PT_LOAD virtual range overflows"))?;
        if virtual_address < program.virtual_address || range_end > load_end {
            continue;
        }
        if containing_load.replace(*program).is_some() {
            return Err(runtime_error(
                path,
                format!("ELF {label} has ambiguous overlapping PT_LOAD mappings"),
            ));
        }
    }
    let load = containing_load.ok_or_else(|| {
        runtime_error(
            path,
            format!("ELF {label} is not contained in one file-backed PT_LOAD"),
        )
    })?;
    load.offset
        .checked_add(virtual_address - load.virtual_address)
        .ok_or_else(|| runtime_error(path, format!("ELF {label} file mapping overflows")))
}

fn forbidden_dynamic_tag_name(tag: u64) -> Option<&'static str> {
    match tag {
        DT_AUDIT => Some("DT_AUDIT"),
        DT_DEPAUDIT => Some("DT_DEPAUDIT"),
        DT_FILTER => Some("DT_FILTER"),
        DT_AUXILIARY => Some("DT_AUXILIARY"),
        _ => None,
    }
}

impl RuntimeMachine {
    fn for_host(machine: u16) -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        if machine == 62 {
            return Some(Self::X86_64);
        }
        #[cfg(target_arch = "aarch64")]
        if machine == 183 {
            return Some(Self::Aarch64);
        }
        None
    }
}

enum ParsedLoaderObject {
    Virtual(String),
    Path(PathBuf),
}

fn parse_loader_output(
    output: &[u8],
    requester: &Path,
) -> Result<Vec<ParsedLoaderObject>, IdentityError> {
    let text = std::str::from_utf8(output)
        .map_err(|_| runtime_error(requester, "loader output is not UTF-8"))?;
    let mut result = Vec::new();
    let mut real_paths = BTreeSet::new();
    let mut virtual_names = BTreeSet::new();
    for raw_line in text.lines() {
        if result.len() >= MAX_LOADER_ENTRIES {
            return Err(runtime_error(
                requester,
                "loader output contains too many entries",
            ));
        }
        let line = raw_line.trim();
        if line.is_empty() || line.len() > 4096 {
            return Err(runtime_error(
                requester,
                "loader output contains an empty or oversized entry",
            ));
        }
        let (entry, address) = line
            .rsplit_once(" (")
            .ok_or_else(|| runtime_error(requester, "loader entry has unknown framing"))?;
        let address = address
            .strip_suffix(')')
            .ok_or_else(|| runtime_error(requester, "loader entry has unknown address framing"))?;
        if !address
            .strip_prefix("0x")
            .is_some_and(|hex| !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(runtime_error(
                requester,
                "loader entry contains an invalid address",
            ));
        }
        let object = if let Some((name, resolved)) = entry.split_once(" => ") {
            if name.is_empty()
                || name.bytes().any(|byte| byte.is_ascii_whitespace())
                || resolved == "not found"
            {
                return Err(runtime_error(
                    requester,
                    "loader reported an unresolved or malformed shared object",
                ));
            }
            ParsedLoaderObject::Path(PathBuf::from(resolved))
        } else if entry == "linux-vdso.so.1" {
            ParsedLoaderObject::Virtual(entry.to_owned())
        } else if Path::new(entry).is_absolute() {
            ParsedLoaderObject::Path(PathBuf::from(entry))
        } else {
            return Err(runtime_error(
                requester,
                "loader returned an unsupported virtual or relative object",
            ));
        };
        match &object {
            ParsedLoaderObject::Virtual(name) if !virtual_names.insert(name.clone()) => {
                return Err(runtime_error(requester, "loader repeated a virtual object"));
            }
            ParsedLoaderObject::Path(path) if !real_paths.insert(path.clone()) => {
                return Err(runtime_error(requester, "loader repeated an object path"));
            }
            _ => {}
        }
        result.push(object);
    }
    if result.is_empty() {
        return Err(runtime_error(requester, "loader produced no object list"));
    }
    Ok(result)
}

fn invoke_loader(
    loader: &Path,
    retained_path: &Path,
    descriptor: RawFd,
    account: &ExecutionAccount,
    machine: RuntimeMachine,
) -> Result<Vec<u8>, IdentityError> {
    let mut command = Command::new(loader);
    command
        .arg("--inhibit-cache")
        .arg("--library-path")
        .arg(fixed_library_path(machine))
        .arg("--glibc-hwcaps-mask")
        .arg("")
        .arg("--list")
        .arg(retained_path)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("TZ", "UTC")
        .env("HOME", "/nonexistent")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    isolate_command(&mut command, account);
    let mut child = spawn_with_inherited_descriptors(&mut command, &[descriptor])
        .map_err(|source| runtime_io(loader, source))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| runtime_error(loader, "loader stdout pipe is absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| runtime_error(loader, "loader stderr pipe is absent"))?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_thread = spawn_bounded_reader(stdout, Arc::clone(&overflow));
    let stderr_thread = spawn_bounded_reader(stderr, Arc::clone(&overflow));
    let deadline = Instant::now() + LOADER_TIMEOUT;
    let status;
    let mut timed_out = false;
    loop {
        if overflow.load(Ordering::Acquire) || Instant::now() >= deadline {
            timed_out = !overflow.load(Ordering::Acquire);
            status = reap_loader_group(&mut child, loader)?;
            break;
        }
        match child_has_exited(child.id()) {
            Ok(true) => {
                status = reap_loader_group(&mut child, loader)?;
                break;
            }
            Ok(false) => thread::sleep(Duration::from_millis(5)),
            Err(source) => {
                let _ = reap_loader_group(&mut child, loader);
                return Err(runtime_io(loader, source));
            }
        }
    }
    let stdout = join_reader(stdout_thread, loader)?;
    let stderr = join_reader(stderr_thread, loader)?;
    if overflow.load(Ordering::Acquire) {
        return Err(runtime_error(
            loader,
            "loader output exceeded its byte bound",
        ));
    }
    if timed_out {
        return Err(runtime_error(loader, "loader discovery timed out"));
    }
    require_success(status, &stderr, loader)?;
    Ok(stdout)
}

fn reap_loader_group(
    child: &mut std::process::Child,
    loader: &Path,
) -> Result<ExitStatus, IdentityError> {
    let group = Pid::from_raw(
        i32::try_from(child.id())
            .map_err(|_| runtime_error(loader, "loader PID exceeds process-group range"))?,
    );
    signal_loader_group_or_abort(group, Signal::SIGTERM, loader);
    thread::sleep(Duration::from_millis(5));
    signal_loader_group_or_abort(group, Signal::SIGKILL, loader);
    child.wait().map_err(|source| runtime_io(loader, source))
}

fn signal_loader_group_or_abort(group: Pid, signal_value: Signal, loader: &Path) {
    match signal::killpg(group, signal_value) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(error) => {
            eprintln!(
                "nq: cannot contain loader process group {} for {} with {signal_value:?}: {error}",
                group.as_raw(),
                loader.display()
            );
            std::process::abort();
        }
    }
}

fn require_success(status: ExitStatus, stderr: &[u8], loader: &Path) -> Result<(), IdentityError> {
    if !status.success() || !stderr.is_empty() {
        let diagnostic = String::from_utf8_lossy(stderr);
        let diagnostic: String = diagnostic.chars().take(512).collect();
        return Err(runtime_error(
            loader,
            format!("loader discovery exited with {status}; bounded stderr={diagnostic:?}"),
        ));
    }
    Ok(())
}

struct BoundedRead {
    bytes: Vec<u8>,
    error: Option<io::Error>,
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
    overflow: Arc<AtomicBool>,
) -> thread::JoinHandle<BoundedRead> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return BoundedRead { bytes, error: None },
                Ok(read) => {
                    let remaining = MAX_LOADER_OUTPUT_BYTES.saturating_sub(bytes.len());
                    bytes.extend_from_slice(&buffer[..read.min(remaining)]);
                    if read > remaining {
                        overflow.store(true, Ordering::Release);
                    }
                }
                Err(error) => {
                    return BoundedRead {
                        bytes,
                        error: Some(error),
                    };
                }
            }
        }
    })
}

fn join_reader(
    handle: thread::JoinHandle<BoundedRead>,
    loader: &Path,
) -> Result<Vec<u8>, IdentityError> {
    let result = handle
        .join()
        .map_err(|_| runtime_error(loader, "loader output reader panicked"))?;
    if let Some(source) = result.error {
        return Err(runtime_io(loader, source));
    }
    Ok(result.bytes)
}

fn hash_file(file: &File, size: u64, path: &Path) -> Result<String, IdentityError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut offset = 0_u64;
    while offset < size {
        let remaining = usize::try_from(size - offset).unwrap_or(usize::MAX);
        let chunk_size = remaining.min(buffer.len());
        let read = file
            .read_at(&mut buffer[..chunk_size], offset)
            .map_err(|source| runtime_io(path, source))?;
        if read == 0 {
            return Err(runtime_error(
                path,
                "runtime artifact became shorter while hashing",
            ));
        }
        hasher.update(&buffer[..read]);
        offset = offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn read_exact_at(
    file: &File,
    mut bytes: &mut [u8],
    mut offset: u64,
    path: &Path,
) -> Result<(), IdentityError> {
    while !bytes.is_empty() {
        let read = file
            .read_at(bytes, offset)
            .map_err(|source| runtime_io(path, source))?;
        if read == 0 {
            return Err(runtime_error(path, "ELF structure ends unexpectedly"));
        }
        offset = offset.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        bytes = &mut bytes[read..];
    }
    Ok(())
}

fn modified_ns(metadata: &fs::Metadata) -> String {
    (i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec())).to_string()
}

fn runtime_error(path: &Path, message: impl Into<String>) -> IdentityError {
    IdentityError::RuntimeChain {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

#[allow(clippy::needless_pass_by_value)]
fn runtime_io(path: &Path, source: io::Error) -> IdentityError {
    runtime_error(path, source.to_string())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::config::CommandConfig;
    use crate::identity::VerifiedLaunch;

    fn write_program_header(
        output: &mut [u8],
        kind: u32,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
    ) {
        output[0..4].copy_from_slice(&kind.to_le_bytes());
        output[8..16].copy_from_slice(&offset.to_le_bytes());
        output[16..24].copy_from_slice(&virtual_address.to_le_bytes());
        output[32..40].copy_from_slice(&file_size.to_le_bytes());
        output[40..48].copy_from_slice(&memory_size.to_le_bytes());
    }

    #[cfg(target_arch = "x86_64")]
    const TEST_MACHINE: u16 = 62;
    #[cfg(target_arch = "x86_64")]
    const TEST_LOADER: &str = "/lib64/ld-linux-x86-64.so.2";
    #[cfg(target_arch = "aarch64")]
    const TEST_MACHINE: u16 = 183;
    #[cfg(target_arch = "aarch64")]
    const TEST_LOADER: &str = "/lib/ld-linux-aarch64.so.1";

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn synthetic_dynamic_elf(tag: u64) -> Vec<u8> {
        const PROGRAM_OFFSET: usize = ELF_HEADER_BYTES;
        const PROGRAM_COUNT: usize = 3;
        const INTERPRETER_OFFSET: usize = 240;
        const DYNAMIC_OFFSET: usize = 320;
        const FILE_BYTES: usize = DYNAMIC_OFFSET + 2 * ELF64_DYNAMIC_ENTRY_BYTES;

        let mut bytes = vec![0_u8; FILE_BYTES];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&TEST_MACHINE.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(
            &u64::try_from(PROGRAM_OFFSET)
                .expect("bounded program offset")
                .to_le_bytes(),
        );
        bytes[52..54].copy_from_slice(
            &u16::try_from(ELF_HEADER_BYTES)
                .expect("bounded ELF header")
                .to_le_bytes(),
        );
        bytes[54..56].copy_from_slice(
            &u16::try_from(ELF64_PROGRAM_HEADER_BYTES)
                .expect("bounded program header")
                .to_le_bytes(),
        );
        bytes[56..58].copy_from_slice(
            &u16::try_from(PROGRAM_COUNT)
                .expect("bounded program count")
                .to_le_bytes(),
        );

        write_program_header(
            &mut bytes[PROGRAM_OFFSET..PROGRAM_OFFSET + ELF64_PROGRAM_HEADER_BYTES],
            PT_LOAD,
            0,
            0,
            u64::try_from(FILE_BYTES).expect("bounded synthetic ELF"),
            u64::try_from(FILE_BYTES).expect("bounded synthetic ELF"),
        );
        let interpreter = format!("{TEST_LOADER}\0");
        write_program_header(
            &mut bytes[PROGRAM_OFFSET + ELF64_PROGRAM_HEADER_BYTES
                ..PROGRAM_OFFSET + 2 * ELF64_PROGRAM_HEADER_BYTES],
            PT_INTERP,
            u64::try_from(INTERPRETER_OFFSET).expect("bounded interpreter offset"),
            u64::try_from(INTERPRETER_OFFSET).expect("bounded interpreter offset"),
            u64::try_from(interpreter.len()).expect("bounded interpreter length"),
            u64::try_from(interpreter.len()).expect("bounded interpreter length"),
        );
        write_program_header(
            &mut bytes[PROGRAM_OFFSET + 2 * ELF64_PROGRAM_HEADER_BYTES
                ..PROGRAM_OFFSET + 3 * ELF64_PROGRAM_HEADER_BYTES],
            PT_DYNAMIC,
            u64::try_from(DYNAMIC_OFFSET).expect("bounded dynamic offset"),
            u64::try_from(DYNAMIC_OFFSET).expect("bounded dynamic offset"),
            2 * ELF64_DYNAMIC_ENTRY_BYTES_U64,
            2 * ELF64_DYNAMIC_ENTRY_BYTES_U64,
        );
        bytes[INTERPRETER_OFFSET..INTERPRETER_OFFSET + interpreter.len()]
            .copy_from_slice(interpreter.as_bytes());
        bytes[DYNAMIC_OFFSET..DYNAMIC_OFFSET + 8].copy_from_slice(&tag.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_real_glibc_loader_output_without_addresses() {
        let parsed = parse_loader_output(
            b"\tlinux-vdso.so.1 (0x1234)\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0xabcd)\n\t/lib64/ld-linux-x86-64.so.2 (0xbeef)\n",
            Path::new("/bin/true"),
        )
        .expect("parse loader output");
        assert_eq!(parsed.len(), 3);
        assert!(
            matches!(&parsed[0], ParsedLoaderObject::Virtual(name) if name == "linux-vdso.so.1")
        );
        assert!(
            matches!(&parsed[1], ParsedLoaderObject::Path(path) if path == Path::new("/lib/x86_64-linux-gnu/libc.so.6"))
        );
    }

    #[test]
    fn unresolved_loader_object_is_refused() {
        assert!(matches!(
            parse_loader_output(
                b"libescape.so => not found (0x1234)\n",
                Path::new("/bin/true")
            ),
            Err(IdentityError::RuntimeChain { .. })
        ));
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn audit_and_filter_tags_are_refused_before_any_loader_call() {
        for (tag, name) in [
            (DT_AUDIT, "DT_AUDIT"),
            (DT_DEPAUDIT, "DT_DEPAUDIT"),
            (DT_FILTER, "DT_FILTER"),
            (DT_AUXILIARY, "DT_AUXILIARY"),
        ] {
            let bytes = synthetic_dynamic_elf(tag);
            let file = tempfile::NamedTempFile::new().expect("synthetic ELF file");
            fs::write(file.path(), &bytes).expect("write synthetic ELF");
            let prefix = bytes[..ELF_HEADER_BYTES].to_vec();
            let probe = RuntimeProbe {
                role: RuntimeObjectRole::Root,
                source_path: file.path(),
                proc_path: file.path(),
                file: file.as_file(),
                prefix: &prefix,
            };
            let account = ExecutionAccount {
                configured: "fixture".into(),
                name: "fixture".into(),
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
                debug_same_identity: true,
            };
            let invoked = Cell::new(false);
            let error = discover_startup_runtime_with_loader(
                &[probe],
                &account,
                &mut ArtifactBudget::default(),
                &mut BTreeSet::new(),
                |_, _, _, _, _| {
                    invoked.set(true);
                    panic!("loader callback ran for forbidden {name}");
                },
            )
            .expect_err("forbidden dynamic tag must fail closed");
            assert!(!invoked.get());
            assert!(
                matches!(error, IdentityError::RuntimeChain { message, .. } if message.contains(name))
            );
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn rpath_and_runpath_are_refused_before_any_loader_call() {
        for tag in [DT_RPATH, DT_RUNPATH] {
            let bytes = synthetic_dynamic_elf(tag);
            let file = tempfile::NamedTempFile::new().expect("synthetic ELF file");
            fs::write(file.path(), &bytes).expect("write synthetic ELF");
            let prefix = bytes[..ELF_HEADER_BYTES].to_vec();
            let probe = RuntimeProbe {
                role: RuntimeObjectRole::Root,
                source_path: file.path(),
                proc_path: file.path(),
                file: file.as_file(),
                prefix: &prefix,
            };
            let account = ExecutionAccount {
                configured: "fixture".into(),
                name: "fixture".into(),
                uid: nix::unistd::geteuid().as_raw(),
                gid: nix::unistd::getegid().as_raw(),
                debug_same_identity: true,
            };
            let invoked = Cell::new(false);
            let error = discover_startup_runtime_with_loader(
                &[probe],
                &account,
                &mut ArtifactBudget::default(),
                &mut BTreeSet::new(),
                |_, _, _, _, _| {
                    invoked.set(true);
                    panic!("loader callback ran for forbidden search-path tag");
                },
            )
            .expect_err("dynamic search path must fail closed");
            assert!(!invoked.get());
            assert!(
                matches!(error, IdentityError::RuntimeChain { message, .. } if message.contains("RPATH/RUNPATH"))
            );
        }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn dependency_object_parser_refuses_code_loading_tags() {
        for tag in [
            DT_AUDIT,
            DT_DEPAUDIT,
            DT_FILTER,
            DT_AUXILIARY,
            DT_RPATH,
            DT_RUNPATH,
        ] {
            let bytes = synthetic_dynamic_elf(tag);
            let file = tempfile::NamedTempFile::new().expect("synthetic dependency file");
            fs::write(file.path(), &bytes).expect("write synthetic dependency");
            let metadata = file.as_file().metadata().expect("dependency metadata");
            let identity = RuntimeArtifactIdentity {
                kind: RuntimeArtifactKind::SharedObject,
                path: file.path().to_path_buf(),
                sha256: hash_file(file.as_file(), metadata.len(), file.path())
                    .expect("hash dependency"),
                size: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                owner: metadata.uid(),
                group: metadata.gid(),
                mode: metadata.mode(),
                modified_ns: modified_ns(&metadata),
            };
            assert!(matches!(
                parse_qualified_runtime_object(
                    file.path(),
                    RuntimeMachine::for_host(TEST_MACHINE).expect("host machine"),
                    &identity
                ),
                Err(IdentityError::RuntimeChain { .. })
            ));
        }
    }

    #[test]
    fn parses_the_host_dynamic_table_from_its_file_backed_load_mapping() {
        let path = Path::new("/bin/true");
        let file = File::open(path).expect("open host ELF fixture");
        let mut prefix = vec![0_u8; ELF_HEADER_BYTES];
        read_exact_at(&file, &mut prefix, 0, path).expect("read host ELF prefix");
        let parsed = parse_native(&RuntimeProbe {
            role: RuntimeObjectRole::Root,
            source_path: path,
            proc_path: path,
            file: &file,
            prefix: &prefix,
        })
        .expect("parse host ELF")
        .expect("host fixture is ELF");
        assert!(parsed.interpreter.is_some());
        assert!(parsed.needed.iter().any(|name| name == "libc.so.6"));
    }

    #[test]
    fn loader_output_must_equal_the_prequalified_closure() {
        let path = Path::new("/bin/true");
        let file = File::open(path).expect("open host ELF fixture");
        let mut prefix = vec![0_u8; ELF_HEADER_BYTES];
        read_exact_at(&file, &mut prefix, 0, path).expect("read host ELF prefix");
        let probe = RuntimeProbe {
            role: RuntimeObjectRole::Root,
            source_path: path,
            proc_path: path,
            file: &file,
            prefix: &prefix,
        };
        let account = ExecutionAccount {
            configured: "fixture".into(),
            name: "fixture".into(),
            uid: nix::unistd::geteuid().as_raw(),
            gid: nix::unistd::getegid().as_raw(),
            debug_same_identity: true,
        };
        let error = discover_startup_runtime_with_loader(
            &[probe],
            &account,
            &mut ArtifactBudget::default(),
            &mut BTreeSet::new(),
            |loader, _, _, _, _| {
                Ok(format!(
                    "\tlinux-vdso.so.1 (0x1234)\n\t{} (0x5678)\n",
                    loader.display()
                )
                .into_bytes())
            },
        )
        .expect_err("loader omission must fail exact closure comparison");
        assert!(
            matches!(error, IdentityError::RuntimeChain { message, .. } if message.contains("omitted prequalified startup objects"))
        );
    }

    #[test]
    fn helper_owned_directory_is_refused_even_without_owner_write_bit() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let account = ExecutionAccount {
            configured: "fixture".into(),
            name: "fixture".into(),
            uid: directory.path().metadata().expect("metadata").uid(),
            gid: u32::MAX,
            debug_same_identity: false,
        };
        assert!(matches!(
            qualify_directory_ancestry(directory.path(), &account, true),
            Err(IdentityError::RuntimeChain { .. })
        ));
    }

    #[test]
    fn mutable_runpath_shared_object_is_refused_before_it_can_be_swapped() {
        if !cfg!(debug_assertions) {
            return;
        }
        let compiler = Command::new("cc").arg("--version").output();
        if !compiler.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping RUNPATH fixture: no C compiler");
            return;
        }
        let directory = tempfile::tempdir().expect("temporary directory");
        let library_source = directory.path().join("escape.c");
        let helper_source = directory.path().join("helper.c");
        let library = directory.path().join("libescape.so");
        let helper = directory.path().join("helper");
        fs::write(&library_source, "int escaped(void) { return 0; }\n")
            .expect("write library source");
        fs::write(
            &helper_source,
            "extern int escaped(void); int main(void) { return escaped(); }\n",
        )
        .expect("write helper source");
        let shared = Command::new("cc")
            .args(["-fPIC", "-shared"])
            .arg(&library_source)
            .arg("-o")
            .arg(&library)
            .status()
            .expect("run C compiler");
        assert!(shared.success());
        let runpath = format!("-Wl,-rpath,{}", directory.path().display());
        let linked = Command::new("cc")
            .arg(&helper_source)
            .arg("-L")
            .arg(directory.path())
            .arg(&runpath)
            .arg("-lescape")
            .arg("-o")
            .arg(&helper)
            .status()
            .expect("run linker");
        assert!(linked.success());
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755))
            .expect("make helper executable");
        let command = CommandConfig {
            executable: helper,
            args: Vec::new(),
            env: BTreeMap::new(),
            execution_account: nix::unistd::geteuid().as_raw().to_string(),
            allow_same_identity_in_debug: true,
            working_directory: directory.path().to_path_buf(),
        };
        assert!(matches!(
            VerifiedLaunch::open(&command),
            Err(IdentityError::RuntimeChain { .. })
        ));
    }
}
