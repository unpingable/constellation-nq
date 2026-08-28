#!/usr/bin/env python3
"""SOCKETWRENCH fresh Ubuntu systemd VM qualification for passive nq-ng custody.

The driver is copied into a disposable guest and must run as root.  Every
authority identity and mutable path is guest-local and SOCKETWRENCH-specific.
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import grp
import secrets
import shutil
import signal
import subprocess
import sys
import time
import traceback
import uuid
from pathlib import Path


RESULTS = Path("/var/tmp/passive-vm-lifecycle-repair-v1-s2-final-results")
CONTROL = Path("/etc/passive-vm-lifecycle-repair-v1-s2-final")
DATA = Path("/var/lib/passive-vm-lifecycle-repair-v1-s2-final")
OPERATING = DATA / "operating"
SAMPLES = Path("/var/lib/nq-passive-load/samples/passive-vm-lifecycle-repair-v1-s2-final")
STAGING = Path("/var/lib/nq-passive-load/staging/passive-vm-lifecycle-repair-v1-s2-final")
KEY = Path("/var/lib/nq-passive-load/keys/passive-vm-lifecycle-repair-v1-s2-final.key")
CONFIG = CONTROL / "nq.toml"
HELPER = Path("/usr/lib/nq/helpers/nq-passive-load-helper")
ORIGIN_HELPER = Path("/usr/lib/nq/helpers/nq-linode-origin-helper")
DEB = Path("/home/nqtest/socketwrench-nq-ng.deb")
DEB_SHA = "821c8f7f5dc536c46222c514f9d3b0114efd23a9045bf946d1eb76cd0ddcf0a8"
SOURCE = "4e109f889330b876e7c1776b27fcde697ef77f21"
ISSUER = "nq-passive-load-observer:passive-vm-lifecycle-repair-v1-s2-final"
KEY_ID = "passive-vm-lifecycle-repair-v1-s2-final-key-1"
DOMAIN = "passive-vm-lifecycle-repair-v1-s2-final:guest:v1"
INSTANCE_ID = "9382051"
INSTANCE_DIGEST = "sha256:" + hashlib.sha256(INSTANCE_ID.encode()).hexdigest()
BOUNDARY = "nq.passive_host_load_preexisting_sample_provider.v1"
PROFILE = "nq.host_load_passive_sampler.v1"
SCHEMA = "nq.signed_passive_host_load_sample.v1"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object, mode: int = 0o640, group: str = "nq") -> None:
    path.write_bytes(canonical(value))
    os.chmod(path, mode)
    os.chown(path, 0, grp.getgrnam(group).gr_gid)


def record(name: str, value: object) -> None:
    (RESULTS / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def run(label: str, argv: list[str], *, check: bool = True, user: str | None = None) -> subprocess.CompletedProcess[str]:
    command = argv
    if user is not None:
        command = ["runuser", "-u", user, "--", *argv]
    completed = subprocess.run(command, text=True, capture_output=True)
    (RESULTS / f"{label}.stdout").write_text(completed.stdout)
    (RESULTS / f"{label}.stderr").write_text(completed.stderr)
    record(f"{label}.status.json", {"argv": command, "status": completed.returncode})
    if check and completed.returncode != 0:
        raise RuntimeError(f"{label} failed with status {completed.returncode}: {completed.stderr[-1200:]}")
    return completed


unit_counter = 0


def run_nq(label: str, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    global unit_counter
    unit_counter += 1
    unit = f"nq-passive-vm-lifecycle-repair-v1-s2-final-{os.getpid()}-{unit_counter}.service"
    return run(
        label,
        [
            "systemd-run", "--quiet", "--wait", "--pipe", "--collect", f"--unit={unit}",
            "--property=Type=exec", "--property=User=nq", "--property=Group=nq",
            "--property=SupplementaryGroups=nq-passive-load-reader",
            "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
            "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
            "--property=RestrictSUIDSGID=yes", "--property=LockPersonality=yes",
            "--property=RemoveIPC=yes", "--property=KeyringMode=private",
            "--property=SystemCallArchitectures=native",
            "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "--property=ReadOnlyPaths=/etc/passive-vm-lifecycle-repair-v1-s2-final /etc/nq /var/lib/nq-passive-load/keys",
            "--property=ReadWritePaths=/var/lib/passive-vm-lifecycle-repair-v1-s2-final /var/lib/nq-passive-load/samples /run/passive-vm-lifecycle-repair-v1-s2-final /run/nq",
            "--property=CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL",
            "--property=AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL",
            "--property=LimitNOFILE=4096", "--property=LimitFSIZE=1G",
            "--property=LimitCORE=0", "--property=TasksMax=64",
            "--property=MemoryMax=1G", "--property=MemorySwapMax=0",
            "/usr/bin/nq", "--config", str(CONFIG), "--json", *args,
        ],
        check=check,
    )


def run_observer(label: str, args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    global unit_counter
    unit_counter += 1
    unit = f"nq-socketwrench-observer-{os.getpid()}-{unit_counter}.service"
    return run(
        label,
        [
            "systemd-run", "--quiet", "--wait", "--pipe", "--collect", f"--unit={unit}",
            "--property=Type=exec", "--property=User=nq-passive-load-observer",
            "--property=Group=nq-passive-load-reader", "--property=NoNewPrivileges=yes",
            "--property=PrivateNetwork=yes", "--property=PrivateTmp=yes",
            "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
            "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
            "--property=RestrictSUIDSGID=yes", "--property=LockPersonality=yes",
            "--property=RemoveIPC=yes", "--property=KeyringMode=private",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
            "--property=ReadOnlyPaths=/etc/passive-vm-lifecycle-repair-v1-s2-final /var/lib/nq-passive-load/keys",
            "--property=ReadWritePaths=/var/lib/nq-passive-load/samples /var/lib/nq-passive-load/staging",
            "--property=MemoryMax=64M", "--property=MemorySwapMax=0",
            str(HELPER), *args,
        ],
        check=check,
    )


def parse_json(completed: subprocess.CompletedProcess[str]) -> object:
    return json.loads(completed.stdout)


def field(value: object, key: str) -> str:
    if isinstance(value, dict):
        if isinstance(value.get(key), str):
            return value[key]  # type: ignore[index]
        for nested in value.values():
            try:
                return field(nested, key)
            except KeyError:
                pass
    if isinstance(value, list):
        for nested in value:
            try:
                return field(nested, key)
            except KeyError:
                pass
    raise KeyError(key)


def wait_until(epoch_ms: int) -> None:
    while int(time.time() * 1000) < epoch_ms:
        time.sleep(0.1)


def main() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("guest driver must run as root")
    if RESULTS.exists():
        raise RuntimeError("guest results already exist")
    RESULTS.mkdir(mode=0o755)
    os.environ["TZ"] = "UTC"
    run("guest-release", ["sh", "-c", ". /etc/os-release; printf '%s:%s\\n' \"$ID\" \"$VERSION_ID\""])
    if (RESULTS / "guest-release.stdout").read_text().strip() != "ubuntu:24.04":
        raise RuntimeError("not exact Ubuntu 24.04")
    if not Path("/run/systemd/system").is_dir():
        raise RuntimeError("guest is not booted under systemd")
    if hashlib.sha256(DEB.read_bytes()).hexdigest() != DEB_SHA:
        raise RuntimeError("Debian artifact digest mismatch")
    absent = subprocess.run(["dpkg-query", "-W", "nq-ng"], capture_output=True).returncode != 0
    if not absent:
        raise RuntimeError("package exists before clean install")
    run("package-install", ["dpkg", "-i", str(DEB)])

    accounts = {name: {"uid": pwd.getpwnam(name).pw_uid, "gid": pwd.getpwnam(name).pw_gid}
                for name in ["nq", "nq-helper", "nq-origin-helper", "nq-passive-load-observer", "nq-passive-load-reader"]}
    if len({entry["uid"] for entry in accounts.values()}) != len(accounts):
        raise RuntimeError("package service identities are not distinct")
    record("service-identities.json", accounts)
    for unit in ["nqd.service", "nq-passive-load-observer.service", "nq-recurring-office.service", "nq-recurring-office.timer"]:
        active = run(f"initial-{unit}-active", ["systemctl", "is-active", unit], check=False).stdout.strip()
        enabled = run(f"initial-{unit}-enabled", ["systemctl", "is-enabled", unit], check=False).stdout.strip()
        if active not in {"inactive", "failed"} or enabled not in {"disabled", "static"}:
            raise RuntimeError(f"package installation armed {unit}: {active}/{enabled}")

    CONTROL.mkdir(mode=0o750)
    os.chown(CONTROL, 0, grp.getgrnam("nq-passive-load-reader").gr_gid)
    DATA.mkdir(mode=0o700)
    os.chown(DATA, pwd.getpwnam("nq").pw_uid, grp.getgrnam("nq").gr_gid)
    OPERATING.mkdir(mode=0o700)
    os.chown(OPERATING, pwd.getpwnam("nq").pw_uid, grp.getgrnam("nq").gr_gid)
    Path("/run/passive-vm-lifecycle-repair-v1-s2-final/helpers").mkdir(parents=True, mode=0o711)
    os.chown("/run/passive-vm-lifecycle-repair-v1-s2-final", pwd.getpwnam("nq").pw_uid, grp.getgrnam("nq").gr_gid)
    os.chown("/run/passive-vm-lifecycle-repair-v1-s2-final/helpers", pwd.getpwnam("nq").pw_uid, grp.getgrnam("nq").gr_gid)
    STAGING.mkdir(parents=True, mode=0o750)
    os.chown(STAGING, pwd.getpwnam("nq-passive-load-observer").pw_uid,
             grp.getgrnam("nq-passive-load-reader").gr_gid)

    key_result = run("passive-keygen", [str(HELPER), "keygen", str(KEY), ISSUER, KEY_ID], user="nq-passive-load-observer")
    passive_public = field(parse_json(key_result), "public_key_hex")
    capacity = parse_json(run_observer("capacity-context", ["inspect-capacity-context"]))
    capacity_id = field(capacity, "capacity_context_id")
    helper_digest = sha_file(HELPER)

    now = int(time.time() * 1000)
    start = ((now + 59_999) // 5_000) * 5_000
    generation_ms = 60_000
    horizon_end = start + 2 * generation_ms
    observer_policy = {
        "schema": "nq.passive_load_operational_policy.v1",
        "deployment_profile_ref": "passive-vm-lifecycle-repair-v1-s2-final-accelerated-20260828:v1",
        "min_sampling_interval_ms": 5_000, "max_sampling_interval_ms": 5_000,
        "min_timer_granularity_ms": 1_000, "max_scheduling_jitter_ms": 1_000,
        "max_generation_duration_ms": generation_ms, "max_generation_samples": 12,
        "max_active_store_bytes": 8 * 1024 * 1024,
        "min_required_free_bytes": 10 * 1024 * 1024 * 1024,
        "max_consecutive_sample_failures": 2, "max_sample_eligibility_age_ms": 15_000,
        "max_key_overlap_ms": 0,
        "allowed_startup_policies": ["sample_current_slot", "wait_for_next_sample_slot"],
        "allowed_retention_modes": ["retain_all"],
    }
    write_json(CONTROL / "observer-policy.json", observer_policy, group="nq-passive-load-reader")
    binding = {"subject": "host:passive-vm-lifecycle-repair-v1-s2-final", "scope": {"kind": "host", "value": {"id": "passive-vm-lifecycle-repair-v1-s2-final"}}, "vantage": {"kind": "local", "value": {}}}
    generations: list[dict[str, object]] = []
    previous_path: Path | None = None
    previous_id: str | None = None
    for index in [1, 2]:
        gstart = start + (index - 1) * generation_ms
        gend = gstart + generation_ms
        store = SAMPLES / f"g{index}"
        spec = {
            "schema": "nq.passive_load_observer_generation_spec.v1",
            "operator_occurrence_id": f"passive-vm-lifecycle-repair-v1-s2-final-g{index}-{secrets.token_hex(8)}",
            "created_at_unix_ms": now, "not_before_unix_ms": gstart,
            "expires_at_unix_ms": gend, "sampling_anchor_unix_ms": gstart,
            "sample_interval_ms": 5_000, "max_samples": 12,
            "sample_store": str(store), "max_store_bytes": 8 * 1024 * 1024,
            "min_free_bytes": 10 * 1024 * 1024 * 1024,
            "failure_pause_threshold": 2, "max_sample_eligibility_age_ms": 15_000,
            "startup_policy": "sample_current_slot", "retention_mode": "retain_all",
            "binding": binding, "capacity_context_id": capacity_id,
            "private_key_path": str(KEY), "producer_issuer": ISSUER,
            "producer_key_id": KEY_ID, "producer_public_key_hex": passive_public,
            "key_not_before_unix_ms": gstart, "key_retire_at_unix_ms": gend,
        }
        if previous_id is not None:
            spec["previous_generation_id"] = previous_id
        spec_path = CONTROL / f"g{index}-spec.json"
        staged_generation_path = STAGING / f"g{index}-generation.json"
        generation_path = CONTROL / f"g{index}-generation.json"
        write_json(spec_path, spec, group="nq-passive-load-reader")
        argv = ["prepare-generation", str(CONTROL / "observer-policy.json"), str(spec_path), str(staged_generation_path)]
        if previous_path is not None:
            argv.extend(["--previous-generation", str(previous_path)])
        # Deterministic negative control for the exact prior defect: the
        # observer-bound capacity context must refuse root-operator
        # materialization. The accepted construction then materializes under
        # the same observer service context into an observer-writable staging
        # directory. Root installs the exact immutable bytes afterward; it
        # does not recreate or reinterpret them.
        if index == 1:
            mismatched = run(
                "prepare-g1-context-mismatch-negative-control",
                [str(HELPER), "prepare-generation", str(CONTROL / "observer-policy.json"),
                 str(spec_path), str(RESULTS / "must-not-materialize-generation.json")],
                check=False,
            )
            if mismatched.returncode == 0 or "capacity/vantage context does not match" not in mismatched.stderr:
                raise RuntimeError("operator-context negative control did not refuse on capacity/vantage binding")
        materialized = parse_json(run_observer(f"prepare-g{index}", argv))
        if not staged_generation_path.is_file():
            raise RuntimeError(f"observer did not materialize generation {index} into staging")
        shutil.copyfile(staged_generation_path, generation_path)
        os.chmod(generation_path, 0o640)
        os.chown(generation_path, 0, grp.getgrnam("nq-passive-load-reader").gr_gid)
        generation_id = field(materialized, "generation_id")
        generation = json.loads(generation_path.read_text())
        generations.append({"id": generation_id, "path": str(generation_path), "store": str(store), "document": generation})
        previous_path, previous_id = generation_path, generation_id

    providers: list[dict[str, object]] = []
    for index, generation in enumerate(generations, 1):
        provider = {
            "schema": "nq.passive_load_provider_config.v1", "sample_store": generation["store"],
            "max_sample_age_ms": 15_000, "observer_profile": PROFILE,
            "observer_artifact_digest": helper_digest,
            "observer_config_digest": sha_bytes(canonical(generation["document"])),
            "producer_issuer": ISSUER, "producer_key_id": KEY_ID,
            "producer_public_key_hex": passive_public, "capacity_context_id": capacity_id,
        }
        path = CONTROL / f"provider-g{index}.json"
        write_json(path, provider, group="nq-passive-load-reader")
        providers.append({"path": str(path), "digest": sha_file(path), "document": provider})

    watcher_sections = []
    for index, provider in enumerate(providers, 1):
        generation = generations[index - 1]
        watcher_sections.append(f'''[[watchers]]
instance_id = "passive-vm-lifecycle-repair-v1-s2-final-w{index}-{secrets.token_hex(8)}"
carrier = "stdio"
subject = "host:passive-vm-lifecycle-repair-v1-s2-final"
capability_ceiling = ["read_procfs", "read_system_info"]
checkpoint_policy = "disabled"
[watchers.command]
executable = "{HELPER}"
args = ["serve-stdio", "{provider['path']}"]
env = {{}}
execution_account = "nq-passive-load-reader"
working_directory = "/usr"
[watchers.profile]
id = "nq.host"
version = 1
[watchers.scope]
kind = "host"
value = {{ id = "passive-vm-lifecycle-repair-v1-s2-final" }}
[watchers.vantage]
kind = "local"
value = {{}}
[watchers.schedule]
interval_seconds = 86400
jitter_seconds = 0
deadline_ms = 10000
retry_backoff_seconds = 1
max_retry_backoff_seconds = 10
[watchers.resources]
max_response_bytes = 1048576
max_stderr_bytes = 65536
max_observations = 1
max_address_space_bytes = 536870912
max_cpu_seconds = 30
max_processes = 4
max_open_files = 64
max_file_bytes = 67108864
[watchers.passive_host_load_sample]
schema = "nq.passive_host_load_provider_config.v1"
max_sample_age_ms = 15000
observer_profile = "{PROFILE}"
observer_artifact_digest = "{helper_digest}"
observer_config_digest = "{provider['document']['observer_config_digest']}"
producer_issuer = "{ISSUER}"
producer_key_id = "{KEY_ID}"
producer_public_key_hex = "{passive_public}"
capacity_context_id = "{capacity_id}"
''')
    watcher_ids = [section.split('instance_id = "', 1)[1].split('"', 1)[0] for section in watcher_sections]
    CONFIG.write_text(f'''schema = "nq.config.v1"
database_path = "{DATA / 'nq.db'}"
socket_path = "/run/passive-vm-lifecycle-repair-v1-s2-final/nqd.sock"
admissions_dir = "{DATA / 'admissions'}"
helper_runtime_dir = "/run/passive-vm-lifecycle-repair-v1-s2-final/helpers"

''' + "\n".join(watcher_sections))
    os.chmod(CONFIG, 0o640)
    os.chown(CONFIG, 0, grp.getgrnam("nq").gr_gid)
    run_nq("config-check", ["config", "check"])
    run_nq("database-init", ["init"])

    digest1 = field(parse_json(run_nq("watcher-digest-g1", ["watcher", "digest", watcher_ids[0]])), "watcher_semantic_digest")
    digest2 = field(parse_json(run_nq("watcher-digest-g2", ["watcher", "digest", watcher_ids[1]])), "watcher_semantic_digest")
    relation = parse_json(run_nq("build-succession", [
        "operating", "build-watcher-succession", watcher_ids[0], watcher_ids[1],
        "--predecessor-provider-config", providers[0]["path"],
        "--successor-provider-config", providers[1]["path"],
        "--operator-occurrence-id", f"passive-vm-lifecycle-repair-v1-s2-final-succession-{secrets.token_hex(8)}",
    ]))
    relation_path = CONTROL / "succession.json"
    write_json(relation_path, relation, group="nq")
    relation_id = field(relation, "relation_id")

    origin_uid = pwd.getpwnam("nq-origin-helper").pw_uid
    origin_gid = pwd.getpwnam("nq-origin-helper").pw_gid
    origin_key = Path("/var/lib/nq-origin-helper/signing-key.hex")
    origin_key.write_text(secrets.token_hex(32) + "\n")
    os.chmod(origin_key, 0o600)
    os.chown(origin_key, origin_uid, origin_gid)
    origin_public = run("origin-public-key", [str(ORIGIN_HELPER), "--public-key"], user="nq-origin-helper").stdout.strip()
    origin_public_path = CONTROL / "origin-public-key.hex"
    origin_public_path.write_text(origin_public + "\n")
    os.chmod(origin_public_path, 0o640)
    os.chown(origin_public_path, 0, grp.getgrnam("nq").gr_gid)
    origin_digest = sha_file(ORIGIN_HELPER)
    origin_key_id = "origin-helper-key:sha256:" + hashlib.sha256(bytes.fromhex(origin_public)).hexdigest()

    recurrence_policy = {
        "schema": "nq.recurring_office_policy.v1", "deployment_profile_ref": "passive-vm-lifecycle-repair-v1-s2-final-accelerated-20260828:v1",
        "min_interval_ms": 15_000, "max_interval_ms": 15_000, "min_timer_granularity_ms": 1_000,
        "max_enrollment_lifetime_ms": generation_ms + 60_000, "max_acquisition_occurrences": 4,
        "allowed_missed_slot_policies": ["latest_only"], "allowed_startup_policies": ["evaluate_current_slot"],
        "max_pre_provider_attempts": 2, "min_pre_provider_backoff_ms": 100,
        "max_pre_provider_backoff_ms": 1_000, "max_consecutive_failure_threshold": 2,
        "max_in_flight_per_watcher": 1, "provider_timeout_ceiling_ms": 10_000,
        "max_store_bytes": 128 * 1024 * 1024, "min_free_bytes": 10 * 1024 * 1024 * 1024,
        "allowed_acquisition_reasons": ["diagnostic_recurrence"],
        "coordination_domains": [{"domain_id": DOMAIN, "max_in_flight": 1, "min_provider_start_spacing_ms": 15_000}],
        "watcher_bindings": [],
    }
    for wid, digest in zip(watcher_ids, [digest1, digest2]):
        recurrence_policy["watcher_bindings"].append({
            "watcher_instance_id": wid, "watcher_semantic_digest": digest,
            "coordination_domain_id": DOMAIN, "origin_profile": "linode_instance_metadata_v1",
            "expected_instance_id_sha256": INSTANCE_DIGEST, "origin_helper_path": str(ORIGIN_HELPER),
            "origin_helper_sha256": origin_digest, "origin_helper_account": "nq-origin-helper",
            "origin_helper_issuer": "origin-helper:linode-instance-metadata:v1",
            "origin_helper_key_id": origin_key_id, "origin_helper_public_key_path": str(origin_public_path),
        })
    def enrollment_spec(index: int, wid: str, estart: int, policy_id: str) -> dict[str, object]:
        return {
            "schema": "nq.recurrence_enrollment_spec.v1", "operator_occurrence_id": f"passive-vm-lifecycle-repair-v1-s2-final-e{index}-{secrets.token_hex(8)}",
            "watcher_instance_id": wid, "policy_id": policy_id, "anchor_unix_ms": estart,
            "interval_ms": 15_000, "max_acquisition_occurrences": 4,
            "expires_at_unix_ms": estart + generation_ms, "missed_slot_policy": "latest_only",
            "startup_policy": "evaluate_current_slot", "max_pre_provider_attempts": 2,
            "pre_provider_backoff_ms": 100, "failure_pause_threshold": 2,
            "requested_domain_concurrency": 1, "acquisition_reason": "diagnostic_recurrence",
        }

    # Deterministic negative control for the prior E2 fixture construction.
    # With both children prepared before G1, E2 expires at start+120s but its
    # lifetime begins when it is created. A 120s policy therefore must refuse.
    old_recurrence_path = CONTROL / "recurrence-policy-old-120s.json"
    write_json(old_recurrence_path, recurrence_policy)
    old_policy_id = field(parse_json(run_nq(
        "old-recurrence-policy-register",
        ["recurring", "policy-register", str(old_recurrence_path)],
    )), "policy_id")
    run_nq("old-recurrence-policy-activate", [
        "recurring", "policy-activate", old_policy_id,
        "--operation-id", f"socketwrench-old-policy-{secrets.token_hex(8)}",
    ])
    if int(time.time() * 1000) >= start:
        raise RuntimeError("fixture preparation consumed the E2 negative-control lead")
    old_e2_path = CONTROL / "e2-old-120s-negative-spec.json"
    write_json(old_e2_path, enrollment_spec(2, watcher_ids[1], start + generation_ms, old_policy_id))
    old_e2 = run_nq("e2-old-120s-lifetime-negative-control", [
        "recurring", "enroll", str(old_e2_path),
    ], check=False)
    if old_e2.returncode == 0 or "lifetime_exceeds_policy" not in old_e2.stderr:
        raise RuntimeError("old 120s E2 construction did not refuse for lifetime_exceeds_policy")

    # The corrected clean-target fixture explicitly budgets the two-generation
    # horizon plus at most 60s of bounded pre-creation lead. No product gate is
    # weakened; this policy now states the fixture's actual creation interval.
    recurrence_policy["max_enrollment_lifetime_ms"] = 2 * generation_ms + 60_000
    recurrence_path = CONTROL / "recurrence-policy.json"
    write_json(recurrence_path, recurrence_policy)
    policy_id = field(parse_json(run_nq(
        "recurrence-policy-register",
        ["recurring", "policy-register", str(recurrence_path)],
    )), "policy_id")
    run_nq("recurrence-policy-activate", [
        "recurring", "policy-activate", policy_id,
        "--operation-id", f"socketwrench-policy-{secrets.token_hex(8)}",
    ])

    enrollments: list[str] = []
    for index, (wid, estart) in enumerate(zip(watcher_ids, [start, start + generation_ms]), 1):
        spec = enrollment_spec(index, wid, estart, policy_id)
        path = CONTROL / f"e{index}-spec.json"
        write_json(path, spec)
        enrollment = parse_json(run_nq(f"enroll-e{index}", ["recurring", "enroll", str(path)]))
        enrollments.append(field(enrollment, "enrollment_id"))

    hspec = {
        "schema": "nq.passive_load_operating_grant_spec.v1",
        "operator_occurrence_id": f"passive-vm-lifecycle-repair-v1-s2-final-h-{secrets.token_hex(8)}",
        "not_before_unix_ms": start, "expires_at_unix_ms": horizon_end,
        "watcher_instance_id": watcher_ids[0], "watcher_semantic_digest": digest1,
        "subject_binding_digest": sha_bytes(canonical(binding)), "passive_provider_boundary_id": BOUNDARY,
        "observer_profile": PROFILE, "observer_artifact_digest": helper_digest, "sample_schema": SCHEMA,
        "capacity_context_id": capacity_id, "sample_eligibility_profile_id": "passive-vm-lifecycle-repair-v1-s2-final:max-age-15s:v1",
        "coordination_domain_id": DOMAIN, "sample_interval_ms": 5_000, "acquisition_interval_ms": 15_000,
        "recurrence_startup_policy": "evaluate_current_slot", "recurrence_missed_slot_policy": "latest_only",
        "observer_generation_duration_ms": generation_ms, "observer_generation_max_samples": 12,
        "recurrence_enrollment_duration_ms": generation_ms, "recurrence_enrollment_max_occurrences": 4,
        "max_observer_generations": 2, "max_recurrence_enrollments": 2,
        "max_watcher_succession_edges": 1, "max_aggregate_samples": 24,
        "max_aggregate_acquisitions": 8, "observer_renewal_lead_ms": 5_000,
        "recurrence_renewal_lead_slots": 1, "allowed_signing_key_ids": [KEY_ID],
        "allowed_watcher_succession_relation_ids": [relation_id],
    }
    hspec_path = CONTROL / "grant-spec.json"
    write_json(hspec_path, hspec)
    grant = parse_json(run_nq("grant-create", ["operating", "grant-create", str(hspec_path), "--observer-policy", str(CONTROL / "observer-policy.json"), "--recurrence-policy", str(recurrence_path), "--state-dir", str(OPERATING)]))
    grant_id = field(grant, "grant_id")
    wait_until(start)
    run_nq("grant-activate", ["operating", "grant-activate", grant_id, "--operation-id", f"socketwrench-activate-{secrets.token_hex(8)}", "--state-dir", str(OPERATING)])
    run_nq("issue-succession", ["operating", "issue-watcher-succession", grant_id, str(relation_path), "--state-dir", str(OPERATING)])
    for index, generation in enumerate(generations, 1):
        run_nq(f"issue-g{index}", ["operating", "issue-generation", grant_id, generation["path"], "--operation-id", f"socketwrench-issue-g{index}-{secrets.token_hex(8)}", "--state-dir", str(OPERATING)])
        run_nq(f"issue-e{index}", ["operating", "issue-enrollment", grant_id, enrollments[index - 1], "--operation-id", f"socketwrench-issue-e{index}-{secrets.token_hex(8)}", "--state-dir", str(OPERATING)])

    # A packaged-style recurrence unit is present but remains inert until the
    # exact activation is armed. No timer is created or enabled in this guest.
    env_path = CONTROL / "recurring-office.env"
    env_path.write_text(f"NQ_OPERATING_GRANT_ID={grant_id}\n")
    os.chmod(env_path, 0o640); os.chown(env_path, 0, grp.getgrnam("nq").gr_gid)
    unit_path = Path("/etc/systemd/system/nq-passive-vm-lifecycle-repair-v1-s2-final-recurrence.service")
    unit_path.write_text(f'''[Unit]\nDescription=NQ SOCKETWRENCH VM finite recurrence\n[Service]\nType=oneshot\nUser=nq\nGroup=nq\nSupplementaryGroups=nq-passive-load-reader\nEnvironmentFile={env_path}\nExecStart=/usr/bin/nq --config={CONFIG} --json operating tick-grant ${{NQ_OPERATING_GRANT_ID}} --state-dir={OPERATING}\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nCapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL\nAmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL\nReadOnlyPaths={CONTROL} /var/lib/nq-passive-load/keys\nReadWritePaths={DATA} /var/lib/nq-passive-load/samples /run/passive-vm-lifecycle-repair-v1-s2-final /run/nq\nTimeoutStartSec=90s\n''')
    os.chmod(unit_path, 0o644)
    run("daemon-reload", ["systemctl", "daemon-reload"])
    if run("custom-unit-enabled", ["systemctl", "is-enabled", unit_path.name], check=False).stdout.strip() != "static":
        raise RuntimeError("custom recurrence unit was enabled")
    inert = run("preactivation-unit-wakeup", ["systemctl", "start", unit_path.name], check=False)
    if inert.returncode != 0:
        raise RuntimeError("inert preactivation service wakeup refused unexpectedly")
    pre_status = parse_json(run_nq("preactivation-grant-status", ["operating", "grant-status", grant_id, "--state-dir", str(OPERATING)]))
    record("preactivation-proof.json", {"timer_enabled": False, "grant_status": pre_status})

    # Local deterministic metadata fixture for the closed production helper.
    run("metadata-address", ["ip", "address", "add", "169.254.169.254/32", "dev", "lo"])
    metadata = {"id": int(INSTANCE_ID), "host_uuid": "passive-vm-lifecycle-repair-v1-s2-final-host", "label": "passive-vm-lifecycle-repair-v1-s2-final",
                "region": "vm-local", "type": "g6-standard-1", "tags": ["socketwrench"],
                "specs": {"vcpus": 2, "memory": 2048, "disk": 20480, "transfer": 0, "gpus": 0},
                "backups": {"enabled": False, "status": None}, "account_euuid": "passive-vm-lifecycle-repair-v1-s2-final",
                "image": {"id": "ubuntu24.04", "label": "Ubuntu 24.04"}}
    server_code = r'''import http.server,json,os
data=os.environ["NQ_VM_METADATA"].encode()
class H(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def do_PUT(self):
  body=b"socketwrench-token"
  self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
 def do_GET(self):
  self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
http.server.ThreadingHTTPServer(("169.254.169.254",80),H).serve_forever()
'''
    server_env = dict(os.environ, NQ_VM_METADATA=json.dumps(metadata, separators=(",", ":")))
    server = subprocess.Popen(["python3", "-c", server_code], env=server_env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    if server.poll() is not None:
        raise RuntimeError(f"metadata fixture did not start: {server.stderr.read()}")
    try:
        wait_until(start)
        run_observer("g1-sample-1", ["sample-once-generation", str(CONTROL / "observer-policy.json"), generations[0]["path"]])
        run_observer("g1-index-reconstruct", ["reconstruct-selection-index", providers[0]["path"]])
        run_nq("g1-provider-test", ["watcher", "test", watcher_ids[0]])
        admission1 = parse_json(run_nq("g1-admission", ["watcher", "admit", watcher_ids[0]]))
        admission1_id = field(admission1, "admission_id")
        genesis_id = f"passive-vm-lifecycle-repair-v1-s2-final-genesis-{secrets.token_hex(12)}"
        run_nq("g1-genesis", ["diagnostics", "execute-linode-origin", watcher_ids[0], "--acquisition-id", genesis_id,
            "--expected-instance-id-sha256", INSTANCE_DIGEST, "--origin-helper", str(ORIGIN_HELPER),
            "--origin-helper-sha256", origin_digest, "--origin-helper-account", "nq-origin-helper",
            "--origin-helper-public-key", str(origin_public_path)])
        service_digest = sha_file(unit_path)
        activation_spec = {
            "schema": "nq.passive_load_office_activation_spec.v1", "operation_id": f"socketwrench-stage-{secrets.token_hex(8)}",
            "grant_id": grant_id, "generation_id": generations[0]["id"], "generation_path": generations[0]["path"],
            "enrollment_id": enrollments[0], "watcher_instance_id": watcher_ids[0], "watcher_semantic_digest": digest1,
            "admission_id": admission1_id, "genesis_acquisition_id": genesis_id,
            "provider_config_path": providers[0]["path"], "provider_config_digest": providers[0]["digest"],
            "passive_provider_boundary_id": BOUNDARY, "sample_store": generations[0]["store"],
            "capacity_context_id": capacity_id, "service_manager_deployment_path": str(unit_path),
            "service_manager_deployment_digest": service_digest,
        }
        activation_path = CONTROL / "activation-g1.json"
        write_json(activation_path, activation_spec)
        activation = parse_json(run_nq("activation-stage", ["operating", "activation-stage", str(activation_path), "--state-dir", str(OPERATING)]))
        activation_id = field(activation, "activation_id")
        staged_tick = parse_json(run_nq("staged-tick-inert", ["operating", "tick", activation_id, "--state-dir", str(OPERATING)]))
        run_nq("activation-validate", ["operating", "activation-validate", activation_id, "--operation-id", f"socketwrench-validate-{secrets.token_hex(8)}", "--state-dir", str(OPERATING)])
        validated_tick = parse_json(run_nq("validated-tick-inert", ["operating", "tick", activation_id, "--state-dir", str(OPERATING)]))
        run_nq("activation-arm", ["operating", "activation-arm", activation_id, "--operation-id", f"socketwrench-arm-{secrets.token_hex(8)}", "--state-dir", str(OPERATING)])

        # Pre-stage the exact G2/E2 activation and the bounded handoff while G1
        # remains armed. Neither object creates admission or exposes E2.
        expected_admission2_id = str(uuid.uuid4())
        genesis2_id = f"passive-vm-lifecycle-repair-v1-s2-final-genesis-g2-{secrets.token_hex(12)}"
        activation2_spec = {
            "schema": "nq.passive_load_office_activation_spec.v1",
            "operation_id": f"socketwrench-stage-g2-{secrets.token_hex(8)}",
            "grant_id": grant_id, "generation_id": generations[1]["id"],
            "generation_path": generations[1]["path"], "enrollment_id": enrollments[1],
            "watcher_instance_id": watcher_ids[1], "watcher_semantic_digest": digest2,
            "admission_id": expected_admission2_id, "genesis_acquisition_id": genesis2_id,
            "provider_config_path": providers[1]["path"],
            "provider_config_digest": providers[1]["digest"],
            "passive_provider_boundary_id": BOUNDARY, "sample_store": generations[1]["store"],
            "capacity_context_id": capacity_id,
            "service_manager_deployment_path": str(unit_path),
            "service_manager_deployment_digest": service_digest,
        }
        activation2_path = CONTROL / "activation-g2.json"
        write_json(activation2_path, activation2_spec)
        activation2 = parse_json(run_nq("activation-g2-stage", [
            "operating", "activation-stage", str(activation2_path),
            "--state-dir", str(OPERATING),
        ]))
        activation2_id = field(activation2, "activation_id")
        handoff_spec = {
            "schema": "nq.passive_load_successor_handoff_spec.v1",
            "operation_id": f"socketwrench-handoff-stage-{secrets.token_hex(8)}",
            "grant_id": grant_id, "succession_relation_id": relation_id,
            "predecessor_activation_id": activation_id,
            "next_generation_id": generations[1]["id"],
            "next_generation_path": generations[1]["path"],
            "successor_watcher_instance_id": watcher_ids[1],
            "successor_watcher_semantic_digest": digest2,
            "expected_admission_id": expected_admission2_id,
            "genesis_acquisition_id": genesis2_id,
            "expected_instance_id_sha256": INSTANCE_DIGEST,
            "origin_helper_path": str(ORIGIN_HELPER),
            "origin_helper_sha256": origin_digest,
            "origin_helper_account": "nq-origin-helper",
            "origin_helper_public_key_path": str(origin_public_path),
            "next_enrollment_id": enrollments[1],
            "next_activation_id": activation2_id,
        }
        handoff_path = CONTROL / "handoff-g1-g2.json"
        write_json(handoff_path, handoff_spec)
        handoff = parse_json(run_nq("handoff-stage", [
            "operating", "handoff-stage", str(handoff_path),
            "--state-dir", str(OPERATING),
        ]))
        handoff_id = field(handoff, "handoff_id")
        handoff_early = parse_json(run_nq("handoff-before-g2-inert", [
            "operating", "handoff-tick", handoff_id, "--state-dir", str(OPERATING),
        ]))

        run("armed-recurrence-1", ["systemctl", "start", unit_path.name])

        next_slot = start + 15_000
        wait_until(next_slot)
        run_observer("g1-sample-2", ["sample-once-generation", str(CONTROL / "observer-policy.json"), generations[0]["path"]])
        # Selection and indexed append overlap as a real concurrent-writer case.
        selector = subprocess.Popen(["systemctl", "start", unit_path.name])
        appender = subprocess.Popen(["systemd-run", "--quiet", "--wait", "--collect", "--unit=nq-socketwrench-concurrent-append.service",
            "--property=User=nq-passive-load-observer", "--property=Group=nq-passive-load-reader",
            str(HELPER), "sample-once-generation", str(CONTROL / "observer-policy.json"), generations[0]["path"]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        selector_status = selector.wait(timeout=90)
        append_out, append_err = appender.communicate(timeout=90)
        record("concurrent-selection-append.json", {"selector_status": selector_status, "appender_status": appender.returncode,
               "appender_stdout": append_out, "appender_stderr": append_err})
        if selector_status != 0 or appender.returncode != 0:
            raise RuntimeError("concurrent selection/indexed append case failed")

        for slot in [2, 3]:
            wait_until(start + slot * 15_000)
            run_observer(f"g1-sample-slot-{slot}", [
                "sample-once-generation", str(CONTROL / "observer-policy.json"),
                generations[0]["path"],
            ])
            run(f"g1-recurrence-slot-{slot}", ["systemctl", "start", unit_path.name])

        recurrence_status = parse_json(run_nq("g1-recurrence-status", ["recurring", "status", enrollments[0]]))
        # Remove only derived selection metadata, prove provider refusal, then reconstruct.
        derived = Path(generations[0]["store"]) / "selection-index"
        if not derived.exists():
            candidates = [p for p in Path(generations[0]["store"]).iterdir() if "selection" in p.name or "index" in p.name]
            if not candidates:
                raise RuntimeError("selection metadata path was not discoverable")
            derived = candidates[0]
        preserved = RESULTS / "removed-derived-selection-metadata"
        shutil.move(str(derived), preserved)
        refusal = run_nq("missing-derived-provider-refusal", ["watcher", "test", watcher_ids[0]], check=False)
        if refusal.returncode == 0:
            raise RuntimeError("provider silently accepted absent derived selection metadata")
        run_observer("derived-index-reconstruction", ["reconstruct-selection-index", providers[0]["path"]])
        run_nq("post-reconstruction-provider-test", ["watcher", "test", watcher_ids[0]])

        wait_until(start + generation_ms)
        run_observer("g2-sample-1", ["sample-once-generation", str(CONTROL / "observer-policy.json"), generations[1]["path"]])
        run_observer("g2-index-reconstruct", ["reconstruct-selection-index", providers[1]["path"]])
        handoff_terminal: object | None = None
        for handoff_attempt in range(20):
            handoff_terminal = parse_json(run_nq(f"handoff-tick-{handoff_attempt}", [
                "operating", "handoff-tick", handoff_id, "--state-dir", str(OPERATING),
            ]))
            handoff_state = field(handoff_terminal, "state")
            if handoff_state == "armed":
                break
            if handoff_state in {
                "admission_refused", "genesis_refused", "outcome_unknown", "expired",
            }:
                raise RuntimeError(f"successor handoff terminated {handoff_state}")
            if handoff_attempt % 4 == 3:
                run_observer(f"g2-handoff-refresh-{handoff_attempt}", [
                    "sample-once-generation", str(CONTROL / "observer-policy.json"),
                    generations[1]["path"],
                ])
            time.sleep(1)
        else:
            raise RuntimeError("successor handoff did not reach armed within its bounded evaluator window")

        predecessor_after_handoff = parse_json(run_nq("g1-activation-after-handoff", [
            "operating", "activation-status", activation_id, "--state-dir", str(OPERATING),
        ]))
        successor_after_handoff = parse_json(run_nq("g2-activation-after-handoff", [
            "operating", "activation-status", activation2_id, "--state-dir", str(OPERATING),
        ]))
        run("g2-recurrence-slot-0", ["systemctl", "start", unit_path.name])
        wait_until(start + generation_ms + 15_000)
        run_observer("g2-sample-slot-1", [
            "sample-once-generation", str(CONTROL / "observer-policy.json"),
            generations[1]["path"],
        ])
        run("g2-recurrence-slot-1", ["systemctl", "start", unit_path.name])

        # Deliberately omit slot 2. One wake at slot 3 must account for the
        # skipped slot without a catch-up burst.
        wait_until(start + generation_ms + 45_000)
        run_observer("g2-sample-slot-3", [
            "sample-once-generation", str(CONTROL / "observer-policy.json"),
            generations[1]["path"],
        ])
        run("g2-recurrence-slot-3-latest-only", ["systemctl", "start", unit_path.name])
        recurrence2_status = parse_json(run_nq("g2-recurrence-status", [
            "recurring", "status", enrollments[1],
        ]))

        # Fail-closed negative control: relation replay cannot mint another succession edge.
        replay = run_nq("succession-replay-refusal", ["operating", "issue-watcher-succession", grant_id, str(relation_path), "--state-dir", str(OPERATING)], check=False)
        if replay.returncode == 0:
            raise RuntimeError("succession relation replay was accepted as new authority")

        wait_until(horizon_end)
        run_nq("activation-g2-close", [
            "operating", "activation-close", activation2_id,
            "--operation-id", f"socketwrench-close-g2-{secrets.token_hex(8)}",
            "--reason", "bounded VM generation complete", "--state-dir", str(OPERATING),
        ])
        for index, enrollment in enumerate(enrollments, 1):
            run_nq(f"revoke-e{index}", ["recurring", "revoke", enrollment, "--operation-id", f"socketwrench-revoke-e{index}-{secrets.token_hex(8)}", "--reason", "bounded VM closeout"])
        for index, wid in enumerate(watcher_ids, 1):
            run_nq(f"revoke-w{index}", ["watcher", "revoke", wid])
        for index, generation in enumerate(generations, 1):
            run_observer(f"retire-g{index}", ["retire-generation", generation["path"], f"socketwrench-retire-g{index}-{secrets.token_hex(8)}", "bounded VM closeout"])
            run_observer(f"revoke-g{index}-key", ["revoke-generation-key", generation["path"], f"socketwrench-revoke-g{index}-key-{secrets.token_hex(8)}", "bounded VM closeout"])
        run_nq("grant-retire", ["operating", "grant-retire", grant_id, "--operation-id", f"socketwrench-retire-h-{secrets.token_hex(8)}", "--reason", "bounded VM closeout", "--state-dir", str(OPERATING)])
        final_activation = parse_json(run_nq("final-g1-activation-status", ["operating", "activation-status", activation_id, "--state-dir", str(OPERATING)]))
        final_activation2 = parse_json(run_nq("final-g2-activation-status", ["operating", "activation-status", activation2_id, "--state-dir", str(OPERATING)]))
        final_grant = parse_json(run_nq("final-grant-status", ["operating", "grant-status", grant_id, "--state-dir", str(OPERATING)]))
        run("disable-socketwrench", ["systemctl", "disable", "--now", unit_path.name], check=False)
        loaded = run("final-units", ["systemctl", "list-units", "--all", "--no-legend", "nq-passive-vm-lifecycle-repair-v1-s2-final*"], check=False).stdout
        timers = run("final-timers", ["systemctl", "list-timers", "--all", "--no-legend", "nq-passive-vm-lifecycle-repair-v1-s2-final*"], check=False).stdout
        record("authority-summary.json", {"source_commit": SOURCE, "grant_id": grant_id,
            "generation_ids": [g["id"] for g in generations], "enrollment_ids": enrollments,
            "watcher_ids": watcher_ids, "watcher_digests": [digest1, digest2],
            "relation_id": relation_id, "admission_ids": [admission1_id, expected_admission2_id],
            "activation_ids": [activation_id, activation2_id], "handoff_id": handoff_id,
            "coordination_domain": DOMAIN,
            "interval": {"start_unix_ms": start, "end_unix_ms": horizon_end},
            "staged_tick": staged_tick, "validated_tick": validated_tick,
            "handoff_before_boundary": handoff_early, "handoff_terminal": handoff_terminal,
            "predecessor_after_handoff": predecessor_after_handoff,
            "successor_after_handoff": successor_after_handoff,
            "recurrence_status": [recurrence_status, recurrence2_status],
            "final_activations": [final_activation, final_activation2],
            "final_grant": final_grant, "loaded_units": loaded, "timers": timers})
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()

    installed = {str(path): sha_file(path) for path in [Path("/usr/bin/nq"), HELPER, ORIGIN_HELPER,
        Path("/lib/systemd/system/nq-passive-load-observer.service"),
        Path("/lib/systemd/system/nq-recurring-office.service"),
        Path("/lib/systemd/system/nq-recurring-office.timer")]}
    record("installed-digests.json", installed)
    record("RESULT.json", {"classification": "PASSIVE-VM-DEPLOYMENT-AND-RECOVERY-QUALIFIED",
        "source_commit": SOURCE, "package_sha256": "sha256:" + DEB_SHA,
        "notes": ["accelerated finite two-generation VM charter", "no timer enabled",
                  "local deterministic Linode metadata substitution fixture"]})


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        RESULTS.mkdir(parents=True, exist_ok=True)
        record("FAILURE.json", {"error": str(error), "traceback": traceback.format_exc()})
        subprocess.run(["systemctl", "disable", "--now", "nq-passive-vm-lifecycle-repair-v1-s2-final-recurrence.service"], capture_output=True)
        raise
