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
const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const PEER_INTERFACE: &str = "org.freedesktop.DBus.Peer";
const MAX_UNIT_FILE_BYTES: usize = 1_048_576;

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

    call(
        request,
        clock,
        manager.call_method("RefUnit", &(&scope.unit_name,)),
        "systemd_unit_reference_timeout",
        "systemd unit reference exceeded the request deadline",
        "systemd_unit_reference_failed",
        "systemd unit reference failed",
    )
    .await?
    .body()
    .deserialize::<()>()
    .map_err(|_| {
        CollectionFailure::new(
            "systemd_unit_reference_malformed",
            "RefUnit reply was malformed",
            false,
        )
    })?;

    let unit_reply = call(
        request,
        clock,
        manager.call_method("GetUnit", &(&scope.unit_name,)),
        "systemd_unit_lookup_timeout",
        "systemd unit lookup exceeded the request deadline",
        "systemd_unit_lookup_failed",
        "systemd unit lookup failed",
    )
    .await?;
    let unit_path: OwnedObjectPath = decode_body(
        &unit_reply,
        "systemd_unit_lookup_malformed",
        "GetUnit reply was malformed",
    )?;

    let file_state_reply = call(
        request,
        clock,
        manager.call_method("GetUnitFileState", &(&scope.unit_name,)),
        "systemd_unit_file_state_timeout",
        "systemd unit-file state read exceeded the request deadline",
        "systemd_unit_file_state_failed",
        "systemd unit-file state read failed",
    )
    .await?;
    let unit_file_state: String = decode_body(
        &file_state_reply,
        "systemd_unit_file_state_malformed",
        "GetUnitFileState reply was malformed",
    )?;
    let load_state = property(request, clock, &connection, unit_path.as_str(), "LoadState").await?;
    let active_state = property(
        request,
        clock,
        &connection,
        unit_path.as_str(),
        "ActiveState",
    )
    .await?;
    let sub_state = property(request, clock, &connection, unit_path.as_str(), "SubState").await?;
    let fragment_path = property(
        request,
        clock,
        &connection,
        unit_path.as_str(),
        "FragmentPath",
    )
    .await?;

    let unit_file_sha256 = read_unit_file_digest(&fragment_path)?;
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
        unit_path: unit_path.to_string(),
        unit_file_sha256,
        load_state,
        active_state,
        sub_state,
        unit_file_state,
    })
}

async fn property(
    request: &HelperRequest,
    clock: &impl DeadlineClock,
    connection: &Connection,
    path: &str,
    property: &str,
) -> Result<String, CollectionFailure> {
    let reply = call(
        request,
        clock,
        connection.call_method(
            Some(SYSTEMD_SERVICE),
            path,
            Some(PROPERTIES_INTERFACE),
            "Get",
            &(UNIT_INTERFACE, property),
        ),
        "systemd_property_timeout",
        "systemd property read exceeded the request deadline",
        "systemd_property_failed",
        "systemd property read failed",
    )
    .await?;
    let value: zbus::zvariant::OwnedValue = decode_body(
        &reply,
        "systemd_property_malformed",
        "systemd property reply was malformed",
    )?;
    String::try_from(value).map_err(|_| {
        CollectionFailure::new(
            "systemd_property_not_string",
            "systemd property reply was not a string",
            false,
        )
    })
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
