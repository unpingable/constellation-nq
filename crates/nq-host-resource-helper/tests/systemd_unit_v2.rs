//! The systemd branch reads the manager and never interprets beyond the
//! closed rules: the manager's machine identity, exactly one row for exactly
//! the canonical requested name, and the systemd 255 state vocabularies. An
//! unexpected unit state is an observation; only an unanswerable query is a
//! typed `SystemdUnitFailureCode`.

use std::{cell::Cell, time::Duration};

use nq_host_resource_helper::{
    CollectionFailure, ManagerUnitReply, ManagerUnitRow, ResourceSource, StatfsCut,
    observe_systemd_unit,
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
}

impl Manager {
    fn answering(machine_id: &str, rows: Vec<ManagerUnitRow>) -> Self {
        Self {
            reply: Ok(ManagerUnitReply {
                machine_id: machine_id.to_owned(),
                rows,
            }),
            queried: Cell::new(0),
        }
    }
    fn failing(code: SystemdUnitFailureCode, retriable: bool) -> Self {
        Self {
            reply: Err(CollectionFailure::owner(code, "manager fixture", retriable)),
            queried: Cell::new(0),
        }
    }
}

impl ResourceSource for Manager {
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

fn code(
    result: Result<
        nq_host_resource_helper::SystemdUnitObservation,
        CollectionFailure<SystemdUnitFailureCode>,
    >,
) -> (SystemdUnitFailureCode, bool) {
    let failure = result.expect_err("typed failure");
    (failure.code(), failure.retriable())
}

#[test]
fn every_manager_reported_state_is_an_observation_not_a_failure() {
    for (load, active, sub) in [
        ("loaded", "active", "running"),
        ("loaded", "inactive", "dead"),
        ("loaded", "failed", "failed"),
        ("loaded", "activating", "auto-restart"),
        ("loaded", "deactivating", "stop-sigterm"),
        ("loaded", "reloading", "reload"),
        ("loaded", "maintenance", "cleaning"),
        ("not-found", "inactive", "dead"),
        ("masked", "inactive", "dead"),
        ("bad-setting", "inactive", "dead"),
        ("error", "inactive", "dead"),
    ] {
        let manager = Manager::answering(MACHINE, vec![row("cron.service", load, active, sub)]);
        let observation = observe_systemd_unit(&scope("cron.service"), &manager, BUDGET)
            .unwrap_or_else(|failure| panic!("{load}/{active}: {:?}", failure.code()));
        assert_eq!(
            (
                observation.load_state.as_str(),
                observation.active_state.as_str(),
                observation.sub_state.as_str()
            ),
            (load, active, sub)
        );
    }
}

#[test]
fn another_machine_another_unit_or_an_alias_is_refused_never_followed() {
    let other_machine = Manager::answering(
        "ffffffffffffffffffffffffffffffff",
        vec![row("cron.service", "loaded", "active", "running")],
    );
    assert_eq!(
        code(observe_systemd_unit(
            &scope("cron.service"),
            &other_machine,
            BUDGET
        )),
        (SystemdUnitFailureCode::MachineIdentityMismatch, false)
    );
    // The manager answers an alias with the canonical row (as crow does for
    // syslog.service -> rsyslog.service).
    let alias = Manager::answering(
        MACHINE,
        vec![row("rsyslog.service", "loaded", "active", "running")],
    );
    assert_eq!(
        code(observe_systemd_unit(
            &scope("syslog.service"),
            &alias,
            BUDGET
        )),
        (SystemdUnitFailureCode::UnitNameNotCanonical, false)
    );
    let mut following = row("cron.service", "loaded", "active", "running");
    following.following = "other.service".to_owned();
    assert_eq!(
        code(observe_systemd_unit(
            &scope("cron.service"),
            &Manager::answering(MACHINE, vec![following]),
            BUDGET
        )),
        (SystemdUnitFailureCode::UnitNameNotCanonical, false)
    );
    for rows in [
        Vec::new(),
        vec![
            row("cron.service", "loaded", "active", "running"),
            row("cron.service", "loaded", "active", "running"),
        ],
    ] {
        assert_eq!(
            code(observe_systemd_unit(
                &scope("cron.service"),
                &Manager::answering(MACHINE, rows),
                BUDGET
            )),
            (SystemdUnitFailureCode::UnitListCardinality, false)
        );
    }
}

#[test]
fn states_outside_the_admitted_vocabulary_are_not_interpreted() {
    for (load, active, sub) in [
        ("loaded", "refreshing", "running"),
        ("Loaded", "active", "running"),
        ("loaded", "", "running"),
        ("loaded", "active", ""),
        ("loaded", "active", "run ning"),
    ] {
        assert_eq!(
            code(observe_systemd_unit(
                &scope("cron.service"),
                &Manager::answering(MACHINE, vec![row("cron.service", load, active, sub)]),
                BUDGET
            )),
            (SystemdUnitFailureCode::UnitStateUnrecognized, false),
            "{load}/{active}/{sub}"
        );
    }
}

#[test]
fn query_failures_keep_the_owner_code_and_retriable_as_emitted() {
    for (failure, retriable) in [
        (SystemdUnitFailureCode::SystemBusUnavailable, true),
        (SystemdUnitFailureCode::ManagerUnavailable, true),
        (SystemdUnitFailureCode::QueryTimeout, true),
        (SystemdUnitFailureCode::QueryFailed, true),
        (SystemdUnitFailureCode::ReplyMalformed, false),
    ] {
        assert_eq!(
            code(observe_systemd_unit(
                &scope("cron.service"),
                &Manager::failing(failure, retriable),
                BUDGET
            )),
            (failure, retriable)
        );
    }
}

#[test]
fn an_exhausted_budget_never_queries_the_manager() {
    let manager = Manager::answering(
        MACHINE,
        vec![row("cron.service", "loaded", "active", "running")],
    );
    assert_eq!(
        code(observe_systemd_unit(
            &scope("cron.service"),
            &manager,
            Duration::ZERO
        )),
        (SystemdUnitFailureCode::QueryTimeout, true)
    );
    assert_eq!(manager.queried.get(), 0);
}

#[test]
fn the_bus_budget_keeps_a_report_margin_before_the_request_deadline() {
    use nq_host_resource_helper::{SYSTEMD_REPORT_MARGIN, systemd_query_budget};
    assert_eq!(
        systemd_query_budget(Duration::from_secs(5)),
        Duration::from_millis(4_250)
    );
    // With no more than the margin left, the manager is never queried and
    // the report still carries the typed timeout.
    for remaining in [
        SYSTEMD_REPORT_MARGIN,
        Duration::from_millis(1),
        Duration::ZERO,
    ] {
        let budget = systemd_query_budget(remaining);
        assert!(budget.is_zero());
        let manager = Manager::answering(
            MACHINE,
            vec![row("cron.service", "loaded", "active", "running")],
        );
        assert_eq!(
            code(observe_systemd_unit(
                &scope("cron.service"),
                &manager,
                budget
            )),
            (SystemdUnitFailureCode::QueryTimeout, true)
        );
        assert_eq!(manager.queried.get(), 0);
    }
}
