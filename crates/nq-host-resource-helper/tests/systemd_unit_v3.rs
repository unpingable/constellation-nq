//! The systemd branch reads the manager and never interprets beyond the
//! closed rules: the manager's machine identity, exactly one row for exactly
//! the canonical requested name, and the systemd 255 state vocabularies. An
//! unexpected unit state is an observation; only an unanswerable query is a
//! typed `SystemdUnitFailureCode`.

use std::{
    cell::{Cell, RefCell},
    time::Duration,
};

use nq_host_resource_helper::{
    CollectionFailure, ManagerUnitReply, ManagerUnitRow, ResourceSource, StatfsCut,
    observe_boot_bound_systemd_unit,
};
use nq_profiles::{
    host_filesystem::FilesystemFailureCode,
    host_memory::MemoryFailureCode,
    systemd_unit_v2::{SCOPE_SCHEMA, SystemdUnitFailureCode, SystemdUnitScope},
};

const MACHINE: &str = "1a5b08928e884e73bf4f60a3c73ef497";

struct Manager {
    reply: Result<ManagerUnitReply, CollectionFailure<SystemdUnitFailureCode>>,
    queried: Cell<usize>,
    boots: RefCell<Vec<Result<String, String>>>,
}

impl Manager {
    fn answering(machine_id: &str, rows: Vec<ManagerUnitRow>) -> Self {
        Self {
            reply: Ok(ManagerUnitReply {
                machine_id: machine_id.to_owned(),
                rows,
            }),
            queried: Cell::new(0),
            boots: RefCell::new(vec![Ok(BOOT.into()), Ok(BOOT.into())]),
        }
    }
    fn failing(code: SystemdUnitFailureCode, retriable: bool) -> Self {
        Self {
            reply: Err(CollectionFailure::owner(code, "manager fixture", retriable)),
            queried: Cell::new(0),
            boots: RefCell::new(vec![Ok(BOOT.into()), Ok(BOOT.into())]),
        }
    }
}

impl ResourceSource for Manager {
    fn boot_id(&self) -> Result<String, String> {
        self.boots.borrow_mut().remove(0)
    }
    fn machine_id(&self) -> Result<String, String> {
        unreachable!("the systemd branch reads the manager's identity, not /etc/machine-id")
    }
    fn mountinfo(&self) -> Result<String, String> {
        unreachable!("the systemd branch reads no mount table")
    }
    fn by_uuid_rdev(&self, _uuid: &str) -> Result<Option<u64>, String> {
        unreachable!("the systemd branch reads no device")
    }
    fn statfs_cut(
        &self,
        _mountpoint: &str,
        _expected_mount_id: u64,
    ) -> Result<StatfsCut, CollectionFailure<FilesystemFailureCode>> {
        unreachable!("the systemd branch takes no statfs cut")
    }
    fn pressure_memory(&self) -> Result<String, CollectionFailure<MemoryFailureCode>> {
        unreachable!("the systemd branch reads no PSI")
    }
    fn systemd_unit(
        &self,
        _unit_name: &str,
        _budget: Duration,
    ) -> Result<ManagerUnitReply, CollectionFailure<SystemdUnitFailureCode>> {
        self.queried.set(self.queried.get() + 1);
        self.reply.clone()
    }
}

fn row(name: &str, load: &str, active: &str, sub: &str) -> ManagerUnitRow {
    ManagerUnitRow {
        name: name.to_owned(),
        load_state: load.to_owned(),
        active_state: active.to_owned(),
        sub_state: sub.to_owned(),
        following: String::new(),
    }
}

fn scope(unit: &str) -> SystemdUnitScope {
    SystemdUnitScope {
        schema: SCOPE_SCHEMA.to_owned(),
        machine_id: MACHINE.to_owned(),
        unit_name: unit.to_owned(),
    }
}

const BUDGET: Duration = Duration::from_secs(5);

const BOOT: &str = "7e3e2a67-f95e-437a-b6c6-d2bf99d44e0c";
#[test]
fn manager_cut_is_bound_to_two_equal_native_boot_reads() {
    let source = Manager::answering(
        MACHINE,
        vec![row("cron.service", "loaded", "active", "running")],
    );
    let (observed, boot) =
        observe_boot_bound_systemd_unit(&scope("cron.service"), &source, BUDGET).unwrap();
    assert_eq!(boot, BOOT);
    assert_eq!(observed.active_state, "active");
    assert_eq!(source.queried.get(), 1);
    assert!(source.boots.borrow().is_empty());
}
#[test]
fn unavailable_or_malformed_boot_refuses_before_manager_read() {
    use nq_profiles::systemd_unit_v3::SystemdUnitFailureCode as Code;
    for (boot, expected) in [
        (Err("read failure".into()), Code::BootIdentityUnavailable),
        (Ok("invented".into()), Code::BootIdentityMalformed),
    ] {
        let source = Manager::answering(
            MACHINE,
            vec![row("cron.service", "loaded", "active", "running")],
        );
        *source.boots.borrow_mut() = vec![boot];
        let failure =
            observe_boot_bound_systemd_unit(&scope("cron.service"), &source, BUDGET).unwrap_err();
        assert_eq!(failure.code(), expected);
        assert_eq!(source.queried.get(), 0);
    }
}
#[test]
fn transition_boot_refuses_a_manager_cut_as_unchanged_evidence() {
    use nq_profiles::systemd_unit_v3::SystemdUnitFailureCode as Code;
    let source = Manager::answering(
        MACHINE,
        vec![row("cron.service", "loaded", "active", "running")],
    );
    *source.boots.borrow_mut() = vec![
        Ok(BOOT.into()),
        Ok("313a2679-0aa3-4a1b-9122-0caa5756e006".into()),
    ];
    let failure =
        observe_boot_bound_systemd_unit(&scope("cron.service"), &source, BUDGET).unwrap_err();
    assert_eq!(failure.code(), Code::BootIdentityChanged);
    assert!(failure.retriable());
}
#[test]
fn manager_failure_remains_owner_typed_and_never_health() {
    use nq_profiles::systemd_unit_v3::SystemdUnitFailureCode as Code;
    let source = Manager::failing(SystemdUnitFailureCode::QueryTimeout, true);
    let failure =
        observe_boot_bound_systemd_unit(&scope("cron.service"), &source, BUDGET).unwrap_err();
    assert_eq!(
        failure.code(),
        Code::Manager(SystemdUnitFailureCode::QueryTimeout)
    );
    assert_eq!(source.queried.get(), 1);
}
