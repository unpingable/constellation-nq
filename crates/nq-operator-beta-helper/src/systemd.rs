use std::{fs::OpenOptions, future::Future, io::Read, os::unix::fs::OpenOptionsExt};

use async_io::Timer;
use futures_util::{future::Either, pin_mut};
use nq_protocol::{HelperRequest, Sha256Digest};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use zbus::{Connection, Message, Proxy, zvariant::OwnedObjectPath};

use crate::{CollectionFailure, DeadlineClock, evidence_basis, remaining};

const SYSTEMD_SERVICE: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";
const MAX_UNIT_FILE_BYTES: usize = 1_048_576;

type UnitListEntry = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);
type UnitFileListEntry = (String, String);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemdScope {
    schema: String,
    subject_identity: String,
    target_machine_identity: String,
    unit_name: String,
    unit_file_sha256: Sha256Digest,
    manager_interface: String,
    properties: Vec<String>,
}

pub(super) fn acquire(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
) -> Result<Value, CollectionFailure> {
    let scope: SystemdScope =
        serde_json::from_value(request.binding.scope.value.clone()).map_err(|_| {
            CollectionFailure::new(
                "systemd_scope_invalid",
                "systemd scope was not reopenable",
                false,
            )
        })?;
    let _ = (
        &scope.schema,
        &scope.subject_identity,
        &scope.manager_interface,
        &scope.properties,
    );
    let observation = async_io::block_on(acquire_dbus(request, clock, &scope))?;
    Ok(json!({
        "evidence_basis": evidence_basis(request, "systemd_dbus", "systemd_properties"),
        "target_machine_identity": observation.machine_identity,
        "unit_name": scope.unit_name,
        "unit_file_sha256": observation.unit_file_sha256,
        "manager_object_path": MANAGER_PATH,
        "unit_object_path": observation.unit_path,
        "load_state": observation.load_state,
        "active_state": observation.active_state,
        "sub_state": observation.sub_state,
        "unit_file_state": observation.unit_file_state,
    }))
}

struct DbusObservation {
    machine_identity: String,
    unit_path: String,
    unit_file_sha256: Sha256Digest,
    load_state: String,
    active_state: String,
    sub_state: String,
    unit_file_state: String,
}

struct UnitStateObservation {
    unit_path: OwnedObjectPath,
    fragment_path: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    unit_file_state: String,
}

#[allow(clippy::too_many_lines)]
async fn acquire_dbus(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
    scope: &SystemdScope,
) -> Result<DbusObservation, CollectionFailure> {
    let connection = within_request(request, clock, Connection::system())
        .await?
        .map_err(|_| {
            CollectionFailure::new(
                "system_bus_unavailable",
                "system bus connection failed",
                true,
            )
        })?;

    let machine_reply = call(
        request,
        clock,
        connection.call_method(
            Some(SYSTEMD_SERVICE),
            MANAGER_PATH,
            Some(PEER_INTERFACE),
            "GetMachineId",
            &(),
        ),
        "systemd_machine_identity_timeout",
        "systemd machine identity read exceeded the request deadline",
        "systemd_machine_identity_failed",
        "systemd machine identity read failed",
    )
    .await?;
    let machine_identity: String = decode_body(
        &machine_reply,
        "systemd_machine_identity_malformed",
        "systemd machine identity reply was malformed",
    )?;
    if machine_identity != scope.target_machine_identity {
        return Err(CollectionFailure::new(
            "systemd_machine_identity_mismatch",
            "live D-Bus machine identity differs from the exact request scope",
            false,
        ));
    }

    let manager = within_request(
        request,
        clock,
        Proxy::new(
            &connection,
            SYSTEMD_SERVICE,
            MANAGER_PATH,
            MANAGER_INTERFACE,
        ),
    )
    .await?
    .map_err(|_| {
        CollectionFailure::new(
            "systemd_manager_unavailable",
            "systemd manager interface was unavailable",
            true,
        )
    })?;

    let unit_reply = call(
        request,
        clock,
        manager.call_method("ListUnitsByNames", &(vec![scope.unit_name.as_str()],)),
        "systemd_unit_list_timeout",
        "systemd unit-state list exceeded the request deadline",
        "systemd_unit_list_failed",
        "systemd unit-state list failed",
    )
    .await?;
    let unit_rows: Vec<UnitListEntry> = decode_body(
        &unit_reply,
        "systemd_unit_list_malformed",
        "ListUnitsByNames reply was malformed",
    )?;

    let unit_file_reply = call(
        request,
        clock,
        manager.call_method(
            "ListUnitFilesByPatterns",
            &(Vec::<&str>::new(), vec![scope.unit_name.as_str()]),
        ),
        "systemd_unit_file_list_timeout",
        "systemd unit-file list exceeded the request deadline",
        "systemd_unit_file_list_failed",
        "systemd unit-file list failed",
    )
    .await?;
    let unit_file_rows: Vec<UnitFileListEntry> = decode_body(
        &unit_file_reply,
        "systemd_unit_file_list_malformed",
        "ListUnitFilesByPatterns reply was malformed",
    )?;
    let state = exact_unit_state(scope, unit_rows, unit_file_rows)?;
    let unit_file_sha256 = read_unit_file_digest(&state.fragment_path)?;
    if unit_file_sha256 != scope.unit_file_sha256 {
        return Err(CollectionFailure::new(
            "systemd_unit_file_digest_mismatch",
            "observed unit-file digest differs from the exact request scope",
            false,
        ));
    }
    let _ = remaining(request, clock)?;

    Ok(DbusObservation {
        machine_identity,
        unit_path: state.unit_path.to_string(),
        unit_file_sha256,
        load_state: state.load_state,
        active_state: state.active_state,
        sub_state: state.sub_state,
        unit_file_state: state.unit_file_state,
    })
}

fn exact_unit_state(
    scope: &SystemdScope,
    mut unit_rows: Vec<UnitListEntry>,
    mut unit_file_rows: Vec<UnitFileListEntry>,
) -> Result<UnitStateObservation, CollectionFailure> {
    if unit_rows.len() != 1 || unit_file_rows.len() != 1 {
        return Err(CollectionFailure::new(
            "systemd_unit_cardinality",
            "systemd did not return one exact unit and unit-file row",
            false,
        ));
    }
    let (
        unit_name,
        _description,
        load_state,
        active_state,
        sub_state,
        following,
        unit_path,
        job_id,
        job_type,
        job_path,
    ) = unit_rows.pop().expect("one unit row was checked");
    let (fragment_path, unit_file_state) =
        unit_file_rows.pop().expect("one unit-file row was checked");
    if unit_name != scope.unit_name || !following.is_empty() {
        Err(CollectionFailure::new(
            "systemd_unit_identity_mismatch",
            "systemd returned a different or followed unit identity",
            false,
        ))
    } else if job_id != 0 || !job_type.is_empty() || job_path.as_str() != "/" {
        Err(CollectionFailure::new(
            "systemd_unit_transition_in_progress",
            "systemd reported an in-progress unit job instead of one stable state cut",
            true,
        ))
    } else {
        Ok(UnitStateObservation {
            unit_path,
            fragment_path,
            load_state,
            active_state,
            sub_state,
            unit_file_state,
        })
    }
}

async fn call<F>(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
    future: F,
    timeout_code: &'static str,
    timeout_message: &'static str,
    failure_code: &'static str,
    failure_message: &'static str,
) -> Result<Message, CollectionFailure>
where
    F: Future<Output = zbus::Result<Message>>,
{
    within_request(request, clock, future)
        .await
        .map_err(|_| CollectionFailure::new(timeout_code, timeout_message, true))?
        .map_err(|_| CollectionFailure::new(failure_code, failure_message, true))
}

async fn within_request<F, T>(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
    future: F,
) -> Result<T, CollectionFailure>
where
    F: Future<Output = T>,
{
    let duration = remaining(request, clock)?;
    pin_mut!(future);
    let timer = Timer::after(duration);
    pin_mut!(timer);
    match futures_util::future::select(future, timer).await {
        Either::Left((value, _)) => Ok(value),
        Either::Right(_) => Err(CollectionFailure::new(
            "deadline_expired",
            "request deadline expired during systemd collection",
            true,
        )),
    }
}

fn decode_body<T>(
    reply: &Message,
    code: &'static str,
    message: &'static str,
) -> Result<T, CollectionFailure>
where
    T: for<'de> Deserialize<'de> + zbus::zvariant::Type,
{
    reply
        .body()
        .deserialize()
        .map_err(|_| CollectionFailure::new(code, message, false))
}

fn read_unit_file_digest(path: &str) -> Result<Sha256Digest, CollectionFailure> {
    if path.is_empty() || path.len() > 4_096 || !path.starts_with('/') {
        return Err(CollectionFailure::new(
            "systemd_unit_file_path_invalid",
            "FragmentPath was not one bounded absolute path",
            false,
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| {
            CollectionFailure::new(
                "systemd_unit_file_open_failed",
                "unit file could not be opened without following a final symlink",
                true,
            )
        })?;
    let metadata = file.metadata().map_err(|_| {
        CollectionFailure::new(
            "systemd_unit_file_metadata_failed",
            "unit-file metadata could not be read",
            true,
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_UNIT_FILE_BYTES as u64 {
        return Err(CollectionFailure::new(
            "systemd_unit_file_bound",
            "unit file is not regular or exceeds 1048576 bytes",
            false,
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.by_ref()
        .take((MAX_UNIT_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            CollectionFailure::new(
                "systemd_unit_file_read_failed",
                "unit-file bytes could not be read",
                true,
            )
        })?;
    if bytes.len() > MAX_UNIT_FILE_BYTES || bytes.len() as u64 != metadata.len() {
        return Err(CollectionFailure::new(
            "systemd_unit_file_changed",
            "unit-file length changed during bounded acquisition",
            true,
        ));
    }
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    Sha256Digest::parse(digest).map_err(|_| {
        CollectionFailure::new(
            "systemd_unit_file_digest",
            "unit-file digest could not be represented",
            false,
        )
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::*;

    fn unit_row(name: &str, job_id: u32) -> UnitListEntry {
        (
            name.to_owned(),
            "fixture".to_owned(),
            "loaded".to_owned(),
            "inactive".to_owned(),
            "dead".to_owned(),
            String::new(),
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/fixture").unwrap(),
            job_id,
            if job_id == 0 { "" } else { "start" }.to_owned(),
            OwnedObjectPath::try_from(if job_id == 0 {
                "/"
            } else {
                "/org/freedesktop/systemd1/job/1"
            })
            .unwrap(),
        )
    }

    fn scope() -> SystemdScope {
        SystemdScope {
            schema: "nq.operator_beta.systemd_unit_scope.v1".to_owned(),
            subject_identity: "sha256:fixture".to_owned(),
            target_machine_identity: "machine:fixture".to_owned(),
            unit_name: "fixture.service".to_owned(),
            unit_file_sha256: Sha256Digest::parse(format!("sha256:{}", "a".repeat(64))).unwrap(),
            manager_interface: MANAGER_INTERFACE.to_owned(),
            properties: vec![
                "LoadState".to_owned(),
                "ActiveState".to_owned(),
                "SubState".to_owned(),
                "UnitFileState".to_owned(),
            ],
        }
    }

    #[test]
    fn exact_unprivileged_unit_rows_project_one_stable_state() {
        let state = exact_unit_state(
            &scope(),
            vec![unit_row("fixture.service", 0)],
            vec![(
                "/etc/systemd/system/fixture.service".to_owned(),
                "disabled".to_owned(),
            )],
        )
        .unwrap();
        assert_eq!(state.load_state, "loaded");
        assert_eq!(state.active_state, "inactive");
        assert_eq!(state.sub_state, "dead");
        assert_eq!(state.unit_file_state, "disabled");
        assert_eq!(state.fragment_path, "/etc/systemd/system/fixture.service");
    }

    #[test]
    fn substituted_or_transitioning_unit_rows_fail_closed() {
        assert!(
            exact_unit_state(
                &scope(),
                vec![unit_row("other.service", 0)],
                vec![(
                    "/etc/systemd/system/fixture.service".to_owned(),
                    "disabled".to_owned()
                )],
            )
            .is_err()
        );
        assert!(
            exact_unit_state(
                &scope(),
                vec![unit_row("fixture.service", 1)],
                vec![(
                    "/etc/systemd/system/fixture.service".to_owned(),
                    "disabled".to_owned()
                )],
            )
            .is_err()
        );
        assert!(exact_unit_state(&scope(), Vec::new(), Vec::new()).is_err());
    }

    #[test]
    fn unit_file_digest_is_exact_and_regular() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.service");
        fs::write(&path, b"[Service]\nExecStart=/bin/true\n").unwrap();
        let expected = format!(
            "sha256:{:x}",
            Sha256::digest(b"[Service]\nExecStart=/bin/true\n")
        );
        assert_eq!(
            read_unit_file_digest(path.to_str().unwrap())
                .unwrap()
                .as_str(),
            expected
        );
    }

    #[test]
    fn unit_file_bound_and_final_symlink_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let exact = dir.path().join("exact.service");
        fs::write(&exact, vec![b'x'; MAX_UNIT_FILE_BYTES]).unwrap();
        assert!(read_unit_file_digest(exact.to_str().unwrap()).is_ok());

        let oversized = dir.path().join("oversized.service");
        fs::write(&oversized, vec![b'x'; MAX_UNIT_FILE_BYTES + 1]).unwrap();
        assert!(read_unit_file_digest(oversized.to_str().unwrap()).is_err());

        let link = dir.path().join("replacement.service");
        symlink(&exact, &link).unwrap();
        assert!(read_unit_file_digest(link.to_str().unwrap()).is_err());
    }
}
