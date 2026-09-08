#!/usr/bin/env python3
"""Bounded two-VM producer for the NQ-ng operator-beta M1B qualification."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import sqlite3
import signal
import socket
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

CAMPAIGN = "constellation-operator-beta-nq-ng-m1b-v1"
ACCEPTED_PACKAGE_RESULT = "8865dcad23f17a1f26716161554530237e04bb9e"
IMAGE_NAME = "debian-12-genericcloud-amd64-20260903-2590.qcow2"
IMAGE_SHA512 = (
    "490f38e2665bc4c31f1bd4cd66dfab3c7695f652a62862a7034d95f8f05ede414"
    "6d6dd55c70cc8b0ac9d9b4f54e18f8860bd5ad5ebfb7a8d5e934f3d12cf3817"
)
NQ_DEB_SHA256 = "0fd1ce9e1be48b56ba5e526993a94c4682499bb9dbd9304dffd4500c01603636"
AG_DEB_SHA256 = "98a4f31f0b6c13653ae95ce55586dbac6d0826b649cd7612882f3716b80e2279"
AG_DEB_VERSION = "0.1.0-1+m1a4"
AG_STORE_AUDIT_RESULT = "db4bad1fba2b5ab512cc58356314228167b2f48e"
AG_EXECUTABLE_SHA256 = "668bdd26646ef6a5ba5502b64984844b84c1f70024a76eb5236af2b17702d068"
AG_AUDIT_STORE_MAX_BYTES = 64 * 1024 * 1024
UNIT = "constellation-beta-http-fixture.service"
FIXTURE_UNIT_BYTES = b"""[Unit]
Description=Constellation operator-beta HTTP fixture
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server 18080 --bind 192.168.76.2 --directory /var/lib/constellation-beta-http-fixture
WorkingDirectory=/var/lib/constellation-beta-http-fixture
User=nobody
Group=nogroup
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
FIXTURE_HEALTH_BYTES = b"operator-beta-ok\n"
FIXTURE_ADDRESS = "192.168.76.2"
CONTROLLER_ADDRESS = "192.168.76.1"
FIXTURE_PORT = 18080
MIN_FREE_BYTES = 24 * 1024 * 1024 * 1024
MAX_RUN_SECONDS = 7200
MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024
FIXTURE_READINESS_SECONDS = 30
PROFILE_DIGESTS = {
    "nq.systemd_unit": "sha256:85beec374d8c3a19dca3aafe892792237c7ed2a886a3ecbd6fce6245578c0d8d",
    "nq.http_endpoint": "sha256:d277728a076d75d8bf5a5294635905b74f6b15b7a9d7a5274ea42a888eb68fae",
}
QUESTION_DIGESTS = {
    "nq.systemd_unit": "sha256:b3f34fc485a8d3db4e05282f5b1c0d11f96b439f538e2079bce2ca1242140b4c",
    "nq.http_endpoint": "sha256:e35597a98cf37be6310766c783f7f9aeb22192e520a69916bec5b758f3a175d1",
}
REQUIRED_TERMINAL_PATHS = {
    "RECOVERY.json",
    "host.log",
    "input/SHA512SUMS",
    f"input/{IMAGE_NAME}",
    "input/nq-ng_amd64.deb",
    "input/agent-governor-ng-systemd-executor_amd64.deb",
    "runtime/id_ed25519.pub",
    "runtime/ag-package/usr/libexec/agent-governor-ng/ag-effectd",
    "evidence/input-receipt.json",
    "evidence/guest-identities.json",
    "evidence/constellation-beta-http-fixture.service",
    "evidence/healthz",
    "evidence/service-subject.json",
    "evidence/bindings.json",
    "evidence/target-nq.toml",
    "evidence/control-nq.toml",
    "evidence/target-prestate.txt",
    "evidence/controller-http-prestate.txt",
    "evidence/systemd-pre-artifact.json",
    "evidence/http-pre-artifact.json",
    "evidence/systemd-plan-v2.json",
    "evidence/docket-shaped-dispatch-v1.json",
    "evidence/executor-outcome-v1.json",
    "evidence/effect-occurrence.json",
    "evidence/ag-attempt-store-cut.sqlite",
    "evidence/ag-store-cut.json",
    "evidence/ag-store-audit-outcome-v1.json",
    "evidence/systemd-post-artifact.json",
    "evidence/http-post-artifact.json",
    "evidence/controller-http-readiness.txt",
    "evidence/target-poststate.txt",
    "evidence/control-package-continuity.txt",
    "evidence/target-package-continuity.txt",
    "evidence/control-boot-before.txt",
    "evidence/control-boot-after.txt",
    "evidence/target-boot-before.txt",
    "evidence/target-boot-after.txt",
    "evidence/systemd-restart-artifact.json",
    "evidence/http-restart-artifact.json",
    "evidence/current-support-after-restart.json",
    "evidence/control-nq-backup.sqlite",
    "evidence/target-nq-backup.sqlite",
    "evidence/control-revocations.json",
    "evidence/target-revocations.json",
    "evidence/host-final-observation.json",
}



class Refusal(RuntimeError):
    """Fail-closed qualification refusal."""


NQ_HELPER_UNIT_PROPERTIES = (
    "User=nq",
    "Group=nq",
    "UMask=0077",
    "NoNewPrivileges=yes",
    "PrivateTmp=yes",
    "TemporaryFileSystem=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M /var/tmp:rw,nosuid,nodev,noexec,mode=1777,size=64M",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "ProtectClock=yes",
    "ProtectControlGroups=yes",
    "ProtectKernelLogs=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelTunables=yes",
    "ProtectHostname=yes",
    "RestrictNamespaces=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "RemoveIPC=yes",
    "KeyringMode=private",
    "SystemCallArchitectures=native",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "ReadOnlyPaths=/etc/nq",
    "ReadWritePaths=/var/lib/nq /run/nq",
    "CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL",
    "AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_KILL",
    "LimitNOFILE=4096",
    "LimitFSIZE=1G",
    "LimitCORE=0",
    "TasksMax=256",
    "MemoryMax=2G",
    "MemorySwapMax=0",
    "CPUQuota=200%",
)

NQ_PACKAGE_PAYLOAD_PATHS = (
    "/usr/bin/nq",
    "/usr/bin/nqd",
    "/usr/lib/nq/helpers/nq-host-helper",
    "/usr/lib/nq/helpers/nq-operator-beta-helper",
    "/usr/lib/nq/helpers/nq_conformance_helper.py",
    "/usr/lib/systemd/system/nqd.service",
)
AG_PACKAGE_PAYLOAD_PATHS = (
    "/usr/libexec/agent-governor-ng/ag-effectd",
)
PACKAGE_PAYLOAD_ABSENCE_SCRIPT = r"""package=$1
shift
status=
if status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null); then
    query_rc=0
else
    query_rc=$?
fi
case "$query_rc:$status" in
    "0:deinstall ok config-files"|"1:") ;;
    *) exit 1 ;;
esac
for path do
    if [ -e "$path" ] || [ -L "$path" ]; then
        exit 1
    fi
done
"""


def nq_helper_command(arguments: list[str]) -> str:
    if not arguments or any(not argument or "\n" in argument for argument in arguments):
        raise Refusal("NQ helper command has an invalid argument")
    command = ["sudo", "systemd-run", "--quiet", "--wait", "--pipe", "--collect"]
    for value in NQ_HELPER_UNIT_PROPERTIES:
        command.append(f"--property={value}")
    command.extend(
        ["--", "/usr/bin/nq", "--config=/etc/nq/operator-beta.toml", *arguments]
    )
    return shlex.join(command)


def package_payload_absence_command(package: str, paths: tuple[str, ...]) -> str:
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package):
        raise Refusal("package payload assertion has an invalid package name")
    if not paths or len(set(paths)) != len(paths):
        raise Refusal("package payload assertion requires distinct paths")
    if any(not path.startswith("/") or "\n" in path for path in paths):
        raise Refusal("package payload assertion has an invalid path")
    return shlex.join(
        [
            "sudo",
            "sh",
            "-eu",
            "-c",
            PACKAGE_PAYLOAD_ABSENCE_SCRIPT,
            "package-payload-absence",
            package,
            *paths,
        ]
    )



def interrupted(signum: int, _frame: Any) -> None:
    raise Refusal(f"producer received signal {signum}; reopen retained recovery state")
def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def ag_store_cut_command(
    source_store: str,
    destination: str,
    *,
    owner: str = "betaoperator",
    privileged: bool = True,
) -> str:
    script = """import hashlib
import os
import pwd
import sqlite3
import stat
import sys

source, destination, owner, maximum = sys.argv[1:]
maximum_bytes = int(maximum)
connection = sqlite3.connect(source)
connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
connection.close()
wal_path = source + "-wal"
try:
    wal = os.lstat(wal_path)
except FileNotFoundError:
    wal = None
if wal is not None and (not stat.S_ISREG(wal.st_mode) or wal.st_size != 0):
    raise SystemExit("AG attempt-store WAL is not absent or zero length")
source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
try:
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum_bytes:
        raise SystemExit("AG attempt-store source exceeds the bounded regular-file law")
    source_bytes = bytearray()
    while block := os.read(source_fd, min(1024 * 1024, maximum_bytes + 1 - len(source_bytes))):
        source_bytes.extend(block)
        if len(source_bytes) > maximum_bytes:
            raise SystemExit("AG attempt-store source exceeds the byte bound")
    after = os.fstat(source_fd)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns
    ):
        raise SystemExit("AG attempt-store source changed during the locked copy")
finally:
    os.close(source_fd)
account = pwd.getpwnam(owner)
destination_fd = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
    0o400,
)
try:
    os.fchown(destination_fd, account.pw_uid, account.pw_gid)
    view = memoryview(source_bytes)
    while view:
        written = os.write(destination_fd, view)
        view = view[written:]
    os.fsync(destination_fd)
finally:
    os.close(destination_fd)
with open(destination, "rb") as copied:
    copied_bytes = copied.read(maximum_bytes + 1)
if copied_bytes != source_bytes:
    raise SystemExit("copied AG attempt-store bytes disagree with the locked source")
print(f"source_sha256={hashlib.sha256(source_bytes).hexdigest()}")
print(f"source_bytes={len(source_bytes)}")
print("wal=ABSENT_OR_ZERO_LENGTH")
"""
    command = [] if not privileged else ["sudo"]
    command.extend(
        [
            "flock",
            "--exclusive",
            "--timeout",
            "5",
            source_store + ".systemd-execution-lock",
            "flock",
            "--exclusive",
            "--timeout",
            "5",
            source_store,
            "python3",
            "-c",
            script,
            source_store,
            destination,
            owner,
            str(AG_AUDIT_STORE_MAX_BYTES),
        ]
    )
    return shlex.join(command)


def ag_domain_digest(domain: str, value: bytes) -> str:
    framed = (
        b"ag-ng\0digest\0v1\0"
        + len(domain.encode()).to_bytes(16, "big")
        + domain.encode()
        + len(value).to_bytes(16, "big")
        + value
    )
    return sha256_bytes(framed)


def digest_file(path: pathlib.Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            hasher.update(block)
    return hasher.hexdigest()


def regular_file(path: pathlib.Path, label: str) -> os.stat_result:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise Refusal(f"{label} is not an openable physical file: {error}") from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise Refusal(f"{label} is not a regular file")
        if before.st_size > MAX_INPUT_BYTES:
            raise Refusal(f"{label} exceeds the {MAX_INPUT_BYTES}-byte input bound")
        while os.read(fd, 1024 * 1024):
            pass
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise Refusal(f"{label} changed during bounded inspection")
        return before
    finally:
        os.close(fd)


def atomic_write(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    temporary = path.with_name(path.name + ".partial")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def run(
    command: list[str],
    *,
    stdin: bytes | None = None,
    cwd: pathlib.Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            command,
            input=stdin,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise Refusal(f"command {command[0]} exceeded the 600-second bound") from error
    except OSError as error:
        raise Refusal(f"command {command[0]} could not start: {error}") from error
    if check and completed.returncode != 0:
        diagnostic = completed.stderr.decode(errors="replace")[-2000:]
        raise Refusal(f"command {command[0]} exited {completed.returncode}: {diagnostic}")
    return completed

def effect_outcome_state(outcome: str) -> str:
    mapping = {
        "success": "KNOWN_EFFECT_OWNER_SUCCESS",
        "failure": "KNOWN_NO_EFFECT_OWNER_FAILURE",
        "indeterminate": "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE",
    }
    try:
        return mapping[outcome]
    except KeyError as error:
        raise Refusal("AG owner emitted an unknown outcome class") from error


def expected_effect_plan(
    bindings: dict[str, Any], identities: dict[str, Any]
) -> dict[str, Any]:
    subject = bindings["subject_identity"]
    scope = sha256_bytes(
        canonical(
            {
                "schema": "constellation.operator_beta.effect_scope.v1",
                "subject": subject,
            }
        )
    )
    return {
        "attempt_store": "/var/lib/ag-effectd-m1b/attempts.sqlite",
        "effect": {
            "action": "start",
            "expected_active_state": "inactive",
            "expected_unit_file_state": "disabled",
            "kind": "systemd_unit",
            "target": "constellation-beta-http-fixture",
            "unit": UNIT,
        },
        "effect_index": 0,
        "execution_lock_timeout_ms": 5000,
        "file_policy": {
            "max_content_bytes": 1024,
            "require_private_parent_writes": True,
            "trusted_ancestor_uid": 0,
            "trusted_parent_uid": 0,
        },
        "job_timeout_ms": 30000,
        "schema": "ag-effectd.docket-executor-systemd-plan/v2",
        "scope": scope,
        "subject": subject,
        "systemd_machine_identity": identities["target_machine_identity"],
    }


def expected_effect_dispatch(
    run_id: str, plan: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    work = ag_domain_digest(
        "ag-effectd.docket-executor-systemd-plan/v2", canonical(plan)
    )
    return (
        {
            "attempt": sha256_bytes((run_id + "\0attempt\0" + work).encode()),
            "marker": sha256_bytes((run_id + "\0marker\0" + work).encode()),
            "scope": plan["scope"],
            "subject": plan["subject"],
            "work": work,
            "work_schema": "ag-effectd.docket-executor-systemd-work/v2",
        },
        work,
    )


def verify_effect_outcome(
    outcome: dict[str, Any], dispatch: dict[str, Any]
) -> str:
    if (
        set(outcome) != {"attempt", "marker", "receipt", "outcome"}
        or outcome.get("attempt") != dispatch["attempt"]
        or outcome.get("marker") != dispatch["marker"]
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", outcome.get("receipt", ""))
    ):
        raise Refusal("AG owner outcome does not bind the exact retained attempt")
    outcome_class = outcome.get("outcome")
    effect_outcome_state(outcome_class)
    return outcome_class


def exact_physical_parent(path: pathlib.Path) -> pathlib.Path:
    if not path.is_absolute():
        raise Refusal("output must be an absolute path")
    if path.exists() or path.is_symlink():
        raise Refusal(f"output already exists: {path}")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise Refusal(f"output parent is not a physical directory: {parent}")
    resolved = parent.resolve(strict=True)
    if resolved != parent:
        raise Refusal(f"output parent is not its exact physical path: {parent}")
    return parent


def port_absent(port: int, socktype: int) -> bool:
    address = "0.0.0.0" if socktype == socket.SOCK_DGRAM else "127.0.0.1"
    probe = socket.socket(socket.AF_INET, socktype)
    try:
        if socktype == socket.SOCK_DGRAM:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        probe.bind((address, port))
        return True
    except OSError:
        return False
    finally:
        probe.close()

def process_has_token(token: str) -> bool:
    encoded = token.encode()
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            arguments = (entry / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if any(argument == encoded or argument.startswith(encoded + b",") for argument in arguments):
            return True
    return False

def process_start_ticks(pid: int) -> int:
    try:
        stat_fields = (pathlib.Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
        return int(stat_fields[19])
    except (OSError, IndexError, ValueError) as error:
        raise Refusal(f"process {pid} cannot be reopened: {error}") from error


def process_identity(pid: int, token: str) -> int:
    try:
        arguments = (pathlib.Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0")
    except OSError as error:
        raise Refusal(f"process {pid} cannot be reopened: {error}") from error
    if not any(
        argument == token.encode() or argument.startswith(token.encode() + b",")
        for argument in arguments
    ):
        raise Refusal(f"process {pid} does not match exact token {token}")
    return process_start_ticks(pid)


def read_pid_file(path: pathlib.Path) -> int:
    regular_file(path, "QEMU PID file")
    text = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", text):
        raise Refusal("QEMU PID file is not one bounded process identity")
    return int(text)


def package_field(path: pathlib.Path, field: str) -> str:
    return run(["dpkg-deb", "-f", str(path), field]).stdout.decode().strip()


def verify_checksum_manifest(path: pathlib.Path, image: pathlib.Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    matches = []
    for line in lines:
        pieces = line.split()
        if len(pieces) == 2 and pieces[1].lstrip("*") == IMAGE_NAME:
            matches.append(pieces[0])
    if matches != [IMAGE_SHA512]:
        raise Refusal("versioned SHA512SUMS does not contain one exact selected-image relation")
    if digest_file(image, "sha512") != IMAGE_SHA512:
        raise Refusal("Debian image SHA-512 differs from the selected identity")


def require_tools() -> None:
    for tool in (
        "dpkg-deb",
        "git",
        "qemu-img",
        "qemu-system-x86_64",
        "scp",
        "sha256sum",
        "ssh",
        "ssh-keygen",
        "systemctl",
        "xorriso",
    ):
        if shutil.which(tool) is None:
            raise Refusal(f"required tool is absent: {tool}")


@dataclass
class Guest:
    role: str
    ssh_port: int
    mgmt_mac: str
    fixture_mac: str
    fixture_address: str
    root: pathlib.Path
    process: subprocess.Popen[bytes] | None = None
    start_ticks: int | None = None

    @property
    def name(self) -> str:
        return f"constellation-beta-{self.role}-m1b"

    @property
    def known_hosts(self) -> pathlib.Path:
        return self.root / "known_hosts"

    @property
    def private_key(self) -> pathlib.Path:
        return self.root.parent / "runtime" / "id_ed25519"

    def ssh_base(self) -> list[str]:
        return [
            "ssh",
            "-i",
            str(self.private_key),
            "-p",
            str(self.ssh_port),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "betaoperator@127.0.0.1",
        ]


class Producer:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.output = args.output
        self.started = time.monotonic()
        self.run_id = args.run_id
        self.last_completed = "none"
        self.next_action = "preflight"
        self.producer_start_ticks: int | None = None
        self.effect_outcome = "NO_EFFECT_ATTEMPTED"
        self.guests: list[Guest] = []
        self.created = False
        self.input_facts: dict[str, Any] = {}
        self.effect_custody: dict[str, Any] | None = None

    def check_runtime(self) -> None:
        elapsed = time.monotonic() - self.started
        if elapsed > MAX_RUN_SECONDS:
            raise Refusal(f"run exceeded the {MAX_RUN_SECONDS}-second bound")

    def verify_producer(self) -> None:
        invocation = os.environ.get("INVOCATION_ID", "")
        unit = self.args.producer_unit
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,255}\.service", unit):
            raise Refusal("producer unit is not one bounded service-unit identity")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", invocation):
            raise Refusal("live run has no exact user-systemd invocation identity")
        result = run(
            [
                "systemctl",
                "--user",
                "show",
                unit,
                "--property=InvocationID",
                "--property=MainPID",
            ]
        )
        properties = dict(
            line.split("=", 1)
            for line in result.stdout.decode().splitlines()
            if "=" in line
        )
        if properties.get("InvocationID", "").lower() != invocation.lower():
            raise Refusal("producer unit invocation differs from the current process")
        if properties.get("MainPID") != str(os.getpid()):
            raise Refusal("producer unit main PID differs from the current process")
        self.producer_start_ticks = process_start_ticks(os.getpid())

    def state(self, phase: str, next_action: str, **facts: Any) -> None:
        self.next_action = next_action
        self.check_runtime()
        record = {
            "schema": "constellation.operator_beta.m1b_recovery.v1",
            "campaign": CAMPAIGN,
            "run_id": self.run_id,
            "host": socket.gethostname(),
            "working_directory": str(pathlib.Path.cwd()),
            "harness_subject": self.args.harness_subject,
            "accepted_package_result": ACCEPTED_PACKAGE_RESULT,
            "input_facts": self.input_facts,
            "protocols": {
                "systemd_profile": PROFILE_DIGESTS["nq.systemd_unit"],
                "http_profile": PROFILE_DIGESTS["nq.http_endpoint"],
                "ag_effect_plan": "ag-effectd.docket-executor-systemd-plan/v2",
                "docket_transport": "gwr.executor-transport/v1-shaped testimony only",
            },
            "phase": phase,
            "last_completed_phase": self.last_completed,
            "next_lawful_action": next_action,
            "effect_outcome": self.effect_outcome,
            "effect_custody": self.effect_custody,
            "updated_at": utc_now(),
            "producer": {
                "systemd_unit": self.args.producer_unit,
                "invocation_id": os.environ.get("INVOCATION_ID", "NOT_OBSERVABLE"),
                "main_pid": os.getpid(),
                "start_ticks": self.producer_start_ticks,
            },
            "expected_terminal_records": [
                "RESULT.json + ARTIFACTS.sha256",
                "or REFUSAL.json + RECOVERY.json",
            ],
            "paths": {
                "run_root": str(self.output),
                "host_log": str(self.output / "host.log"),
                "evidence": str(self.output / "evidence"),
            },
            "guests": [
                {
                    "role": guest.role,
                    "name": guest.name,
                    "ssh_port": guest.ssh_port,
                    "pid_file": str(guest.root / "qemu.pid"),
                    "serial_log": str(guest.root / "serial.log"),
                    "pid": guest.process.pid if guest.process is not None else None,
                    "start_ticks": guest.start_ticks,
                }
                for guest in self.guests
            ],
            **facts,
        }
        atomic_write(self.output / "RECOVERY.json", canonical(record) + b"\n")

    def complete_phase(self, phase: str, next_action: str, **facts: Any) -> None:
        self.last_completed = phase
        self.state(phase, next_action, **facts)

    def preflight(self) -> dict[str, Any]:
        require_tools()
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.run_id):
            raise Refusal("run ID is not one bounded identity token")
        if not re.fullmatch(r"[A-Za-z0-9_.@:-]{1,255}\.service", self.args.producer_unit):
            raise Refusal("producer unit is not one bounded service-unit identity")
        ports = (
            self.args.controller_ssh_port,
            self.args.target_ssh_port,
            self.args.fixture_link_port,
        )
        if any(port < 1024 or port > 65535 for port in ports) or len(set(ports)) != 3:
            raise Refusal("qualification ports must be distinct integers in 1024..=65535")
        if not re.fullmatch(r"[0-9a-f]{40}", self.args.harness_subject):
            raise Refusal("harness subject is not one lowercase 40-hex commit identity")
        parent = exact_physical_parent(self.output)
        usage = shutil.disk_usage(parent)
        if usage.free < MIN_FREE_BYTES:
            raise Refusal(f"fewer than {MIN_FREE_BYTES} bytes are free at {parent}")
        for path, label in (
            (self.args.image, "Debian image"),
            (self.args.checksums, "Debian SHA512SUMS"),
            (self.args.nq_deb, "NQ Debian package"),
            (self.args.ag_deb, "AG Debian package"),
        ):
            regular_file(path, label)
        verify_checksum_manifest(self.args.checksums, self.args.image)
        if digest_file(self.args.nq_deb, "sha256") != NQ_DEB_SHA256:
            raise Refusal("NQ package SHA-256 differs from the accepted package checkpoint")
        if digest_file(self.args.ag_deb, "sha256") != AG_DEB_SHA256:
            raise Refusal("AG package SHA-256 differs from the accepted M1A package")
        if package_field(self.args.nq_deb, "Package") != "nq-ng":
            raise Refusal("NQ input has the wrong Debian package name")
        if package_field(self.args.nq_deb, "Architecture") != "amd64":
            raise Refusal("NQ input is not amd64")
        if package_field(self.args.ag_deb, "Package") != "agent-governor-ng-systemd-executor":
            raise Refusal("AG input has the wrong Debian package name")
        if package_field(self.args.ag_deb, "Version") != AG_DEB_VERSION:
            raise Refusal("AG input has the wrong qualified package version")
        if package_field(self.args.ag_deb, "Architecture") != "amd64":
            raise Refusal("AG input is not amd64")
        info = json.loads(run(["qemu-img", "info", "--output=json", str(self.args.image)]).stdout)
        if info.get("format") != "qcow2" or info.get("backing-filename"):
            raise Refusal("Debian input is not a self-contained qcow2 image")
        run(["qemu-img", "check", str(self.args.image)])
        for port in (self.args.controller_ssh_port, self.args.target_ssh_port):
            if not port_absent(port, socket.SOCK_STREAM):
                raise Refusal(f"loopback SSH port is already bound: {port}")
        if not port_absent(self.args.fixture_link_port, socket.SOCK_DGRAM):
            raise Refusal(f"fixture-link UDP port is already bound: {self.args.fixture_link_port}")
        for role in ("control", "target"):
            if process_has_token(f"constellation-beta-{role}-m1b"):
                raise Refusal(f"same-name {role} guest process already exists")
        repository = pathlib.Path(__file__).resolve().parents[2]
        head = run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.decode().strip()
        if head != self.args.harness_subject:
            raise Refusal(f"harness checkout is {head}, not admitted {self.args.harness_subject}")
        if run(["git", "status", "--porcelain"], cwd=repository).stdout:
            raise Refusal("harness checkout is not clean")
        ancestor = run(
            ["git", "merge-base", "--is-ancestor", ACCEPTED_PACKAGE_RESULT, head],
            cwd=repository,
            check=False,
        )
        if ancestor.returncode != 0:
            raise Refusal("accepted package result is not an ancestor of the harness subject")
        return {
            "image_sha512": IMAGE_SHA512,
            "image_checksum_signature": "UPSTREAM_DETACHED_SIGNATURE_NOT_PUBLISHED",
            "nq_deb_sha256": NQ_DEB_SHA256,
            "ag_deb_sha256": AG_DEB_SHA256,
            "ag_store_audit_result": AG_STORE_AUDIT_RESULT,
            "ag_executable_sha256": AG_EXECUTABLE_SHA256,
            "free_bytes": usage.free,
        }

    def create_run(self, preflight: dict[str, Any]) -> None:
        self.output.mkdir(mode=0o700)
        self.created = True
        for name in ("input", "runtime", "evidence", "control", "target"):
            (self.output / name).mkdir(mode=0o700)
        self.guests = [
            Guest(
                "control",
                self.args.controller_ssh_port,
                "52:54:00:0b:10:01",
                "52:54:00:0b:20:01",
                CONTROLLER_ADDRESS,
                self.output / "control",
            ),
            Guest(
                "target",
                self.args.target_ssh_port,
                "52:54:00:0b:10:02",
                "52:54:00:0b:20:02",
                FIXTURE_ADDRESS,
                self.output / "target",
            ),
        ]
        self.state("created", "retain exact inputs", preflight=preflight)
        copies = (
            (self.args.image, self.output / "input" / IMAGE_NAME, 0o400),
            (self.args.checksums, self.output / "input" / "SHA512SUMS", 0o400),
            (self.args.nq_deb, self.output / "input" / "nq-ng_amd64.deb", 0o400),
            (
                self.args.ag_deb,
                self.output / "input" / "agent-governor-ng-systemd-executor_amd64.deb",
                0o400,
            ),
        )
        for source, destination, mode in copies:
            shutil.copyfile(source, destination)
            os.chmod(destination, mode)
        retained_image = self.output / "input" / IMAGE_NAME
        retained_checksums = self.output / "input" / "SHA512SUMS"
        retained_nq = self.output / "input" / "nq-ng_amd64.deb"
        retained_ag = self.output / "input" / "agent-governor-ng-systemd-executor_amd64.deb"
        verify_checksum_manifest(retained_checksums, retained_image)
        if digest_file(retained_nq, "sha256") != NQ_DEB_SHA256:
            raise Refusal("retained NQ package differs from the admitted input")
        if digest_file(retained_ag, "sha256") != AG_DEB_SHA256:
            raise Refusal("retained AG package differs from the admitted input")
        if package_field(retained_nq, "Package") != "nq-ng":
            raise Refusal("retained NQ package metadata differs after copy")
        if package_field(retained_ag, "Version") != AG_DEB_VERSION:
            raise Refusal("retained AG package metadata differs after copy")
        ag_package_root = self.output / "runtime" / "ag-package"
        run(["dpkg-deb", "--extract", str(retained_ag), str(ag_package_root)])
        ag_audit_binary = (
            ag_package_root / "usr" / "libexec" / "agent-governor-ng" / "ag-effectd"
        )
        ag_audit_metadata = regular_file(ag_audit_binary, "retained AG audit executable")
        if (
            digest_file(ag_audit_binary, "sha256") != AG_EXECUTABLE_SHA256
            or stat.S_IMODE(ag_audit_metadata.st_mode) != 0o755
        ):
            raise Refusal("retained AG audit executable differs from the accepted package")
        audit_help = run([str(ag_audit_binary), "audit-store", "--help"])
        if any(
            required not in audit_help.stdout
            for required in (b"--store-cut", b"--store-bytes", b"--store-sha256")
        ):
            raise Refusal("retained AG package lacks the accepted audit-store interface")
        run(["qemu-img", "check", str(retained_image)])
        input_receipt = {
            "schema": "constellation.operator_beta.m1b_inputs.v1",
            "run_id": self.run_id,
            "recorded_at": utc_now(),
            "harness_subject": self.args.harness_subject,
            "accepted_package_result": ACCEPTED_PACKAGE_RESULT,
            "image": {
                "name": IMAGE_NAME,
                "sha512": IMAGE_SHA512,
                "checksum_manifest_sha256": digest_file(
                    self.output / "input" / "SHA512SUMS", "sha256"
                ),
                "detached_signature": "UPSTREAM_DETACHED_SIGNATURE_NOT_PUBLISHED",
            },
            "nq_package_sha256": NQ_DEB_SHA256,
            "ag_package_sha256": AG_DEB_SHA256,
            "ag_package_version": AG_DEB_VERSION,
            "ag_store_audit_result": AG_STORE_AUDIT_RESULT,
            "ag_executable_sha256": AG_EXECUTABLE_SHA256,
            "ports": {
                "control_ssh": self.args.controller_ssh_port,
                "target_ssh": self.args.target_ssh_port,
                "fixture_link_udp": self.args.fixture_link_port,
            },
        }
        atomic_write(self.output / "evidence" / "input-receipt.json", canonical(input_receipt) + b"\n")
        self.complete_phase("inputs_retained", "create overlays and NoCloud seeds")

    def create_seed(self, guest: Guest, public_key: str) -> None:
        meta = f"instance-id: {self.run_id}-{guest.role}\nlocal-hostname: {guest.name}\n"
        user = f"""#cloud-config
disable_root: true
hostname: {guest.name}
package_update: false
package_upgrade: false
preserve_hostname: false
ssh_pwauth: false
users:
  - name: betaoperator
    groups: [sudo]
    lock_passwd: true
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - "{public_key}"
"""
        network = f"""version: 2
ethernets:
  management:
    match:
      macaddress: "{guest.mgmt_mac}"
    set-name: eth0
    dhcp4: true
  fixture:
    match:
      macaddress: "{guest.fixture_mac}"
    set-name: eth1
    addresses:
      - {guest.fixture_address}/24
"""
        for name, content in (
            ("meta-data", meta),
            ("user-data", user),
            ("network-config", network),
        ):
            atomic_write(guest.root / name, content.encode(), 0o400)
        run(
            [
                "xorriso",
                "-as",
                "mkisofs",
                "-quiet",
                "-output",
                str(guest.root / "seed.iso"),
                "-volid",
                "cidata",
                "-joliet",
                "-rock",
                str(guest.root / "user-data"),
                str(guest.root / "meta-data"),
                str(guest.root / "network-config"),
            ]
        )
        os.chmod(guest.root / "seed.iso", 0o400)

    def prepare_guests(self) -> None:
        key = self.output / "runtime" / "id_ed25519"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", self.run_id, "-f", str(key)])
        public_key = key.with_suffix(".pub").read_text(encoding="ascii").strip()
        base = self.output / "input" / IMAGE_NAME
        for guest in self.guests:
            overlay = guest.root / "overlay.qcow2"
            run(
                [
                    "qemu-img",
                    "create",
                    "-q",
                    "-f",
                    "qcow2",
                    "-F",
                    "qcow2",
                    "-b",
                    str(base),
                    str(overlay),
                    "8G",
                ]
            )
            run(["qemu-img", "check", str(overlay)])
            self.create_seed(guest, public_key)
        self.complete_phase("guests_prepared", "start exact QEMU guests")

    def start_guest(self, guest: Guest) -> None:
        acceleration = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg,thread=multi"
        cpu = "host" if acceleration == "kvm" else "max"
        stdout = (guest.root / "qemu.stdout.log").open("wb")
        stderr = (guest.root / "qemu.stderr.log").open("wb")
        command = [
            "qemu-system-x86_64",
            "-name",
            f"{guest.name},process={guest.name}",
            "-no-user-config",
            "-nodefaults",
            "-accel",
            acceleration,
            "-machine",
            "q35",
            "-cpu",
            cpu,
            "-smp",
            "2",
            "-m",
            "2048",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            f"file:{guest.root / 'serial.log'}",
            "-pidfile",
            str(guest.root / "qemu.pid"),
            "-drive",
            f"if=virtio,file={guest.root / 'overlay.qcow2'},format=qcow2,cache=none,aio=threads",
            "-drive",
            f"if=virtio,file={guest.root / 'seed.iso'},format=raw,readonly=on",
            "-netdev",
            f"user,id=mgmt,restrict=on,hostfwd=tcp:127.0.0.1:{guest.ssh_port}-:22",
            "-device",
            f"virtio-net-pci,netdev=mgmt,mac={guest.mgmt_mac}",
            "-netdev",
            f"socket,id=fixture,mcast=230.0.0.1:{self.args.fixture_link_port}",
            "-device",
            f"virtio-net-pci,netdev=fixture,mac={guest.fixture_mac}",
            "-sandbox",
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ]
        guest.process = subprocess.Popen(
            command,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        atomic_write(guest.root / "producer-pid", f"{guest.process.pid}\n".encode())
        deadline = time.monotonic() + 10
        pid_file = guest.root / "qemu.pid"
        while not pid_file.exists() and time.monotonic() < deadline:
            if guest.process.poll() is not None:
                raise Refusal(f"{guest.name} exited before retaining its PID identity")
            time.sleep(0.05)
        pid = read_pid_file(pid_file)
        if pid != guest.process.pid:
            raise Refusal(f"{guest.name} PID file disagrees with the launched process")
        guest.start_ticks = process_identity(pid, guest.name)

    def wait_ssh(self, guest: Guest, expected_up: bool, limit: int) -> None:
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            self.check_runtime()
            if guest.process is not None and guest.process.poll() is not None:
                if expected_up:
                    raise Refusal(f"{guest.name} exited before SSH became available")
                return
            result = run(guest.ssh_base() + ["true"], check=False)
            if (result.returncode == 0) == expected_up:
                return
            time.sleep(2)
        state = "up" if expected_up else "down"
        raise Refusal(f"{guest.name} SSH did not become {state} within {limit} seconds")

    def wait_boot_identity_change(self, guest: Guest, before: bytes, limit: int) -> bytes:
        boot_identity = re.compile(
            rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n"
        )
        if boot_identity.fullmatch(before) is None:
            raise Refusal(f"{guest.name} pre-restart boot identity is malformed")
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            self.check_runtime()
            if guest.process is not None and guest.process.poll() is not None:
                raise Refusal(f"{guest.name} exited while waiting for a changed boot identity")
            result = run(
                guest.ssh_base() + ["cat /proc/sys/kernel/random/boot_id"],
                check=False,
            )
            if result.returncode == 0:
                if boot_identity.fullmatch(result.stdout) is None:
                    raise Refusal(f"{guest.name} post-restart boot identity is malformed")
                if result.stdout != before:
                    return result.stdout
            time.sleep(2)
        raise Refusal(f"{guest.name} boot identity did not change within {limit} seconds")

    def ssh(self, guest: Guest, command: str, *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        completed = run(guest.ssh_base() + [command], check=False)
        self.check_runtime()
        with (self.output / "host.log").open("ab") as log:
            log.write(f"\n[{utc_now()}] {guest.role}\n".encode())
            log.write(completed.stdout)
            log.write(completed.stderr)
        if check and completed.returncode != 0:
            raise Refusal(f"{guest.name} command exited {completed.returncode}")
        return completed

    def scp_to(self, guest: Guest, sources: list[pathlib.Path], destination: str) -> None:
        command = [
            "scp",
            "-i",
            str(guest.private_key),
            "-P",
            str(guest.ssh_port),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={guest.known_hosts}",
            *[str(path) for path in sources],
            f"betaoperator@127.0.0.1:{destination}",
        ]
        run(command)

    def scp_from(self, guest: Guest, source: str, destination: pathlib.Path) -> None:
        command = [
            "scp",
            "-i",
            str(guest.private_key),
            "-P",
            str(guest.ssh_port),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={guest.known_hosts}",
            f"betaoperator@127.0.0.1:{source}",
            str(destination),
        ]
        run(command)

    def boot_guests(self) -> None:
        for guest in self.guests:
            self.start_guest(guest)
        self.state("guests_starting", "wait for SSH and cloud-init")
        for guest in self.guests:
            self.wait_ssh(guest, True, 900)
            self.ssh(
                guest,
                "cloud-init status --wait && "
                "test \"$(. /etc/os-release; printf '%s:%s' \"$ID\" \"$VERSION_ID\")\" = debian:12",
            )
        self.complete_phase("guests_ready", "install exact packages and fixture")

    def install_inputs(self) -> tuple[Guest, Guest]:
        control, target = self.guests
        nq_deb = self.output / "input" / "nq-ng_amd64.deb"
        ag_deb = self.output / "input" / "agent-governor-ng-systemd-executor_amd64.deb"
        self.scp_to(control, [nq_deb], "/home/betaoperator/nq-ng.deb")
        self.scp_to(target, [nq_deb], "/home/betaoperator/nq-ng.deb")
        self.scp_to(target, [ag_deb], "/home/betaoperator/")
        self.ssh(
            control,
            f"printf '{NQ_DEB_SHA256}  /home/betaoperator/nq-ng.deb\n' | sha256sum -c -; "
            "sudo dpkg -i /home/betaoperator/nq-ng.deb; "
            "test \"$(systemctl is-active nqd.service || true)\" = inactive",
        )
        self.ssh(
            target,
            f"printf '{NQ_DEB_SHA256}  /home/betaoperator/nq-ng.deb\n' | sha256sum -c -; "
            f"printf '{AG_DEB_SHA256}  /home/betaoperator/agent-governor-ng-systemd-executor_amd64.deb\n' | sha256sum -c -; "
            "sudo dpkg -i /home/betaoperator/nq-ng.deb "
            "/home/betaoperator/agent-governor-ng-systemd-executor_amd64.deb; "
            "test \"$(systemctl is-active nqd.service || true)\" = inactive; "
            f"test \"$(systemctl is-active {UNIT} || true)\" = inactive",
        )
        atomic_write(self.output / "evidence" / UNIT, FIXTURE_UNIT_BYTES, 0o400)
        atomic_write(
            self.output / "evidence" / "healthz", FIXTURE_HEALTH_BYTES, 0o400
        )
        self.scp_to(
            target,
            [self.output / "evidence" / UNIT, self.output / "evidence" / "healthz"],
            "/home/betaoperator/",
        )
        self.ssh(
            target,
            "sudo install -d -o root -g root -m 0755 /var/lib/constellation-beta-http-fixture; "
            "sudo install -o root -g root -m 0644 /home/betaoperator/healthz "
            "/var/lib/constellation-beta-http-fixture/healthz; "
            f"sudo install -o root -g root -m 0644 /home/betaoperator/{UNIT} "
            f"/etc/systemd/system/{UNIT}; "
            "sudo systemctl daemon-reload; "
            f"sudo systemctl disable {UNIT} >/dev/null 2>&1 || true; "
            f"sudo systemctl stop {UNIT}; "
            f"test \"$(systemctl is-active {UNIT} || true)\" = inactive; "
            f"test \"$(systemctl is-enabled {UNIT} || true)\" = disabled",
        )
        machine = self.ssh(target, "cat /etc/machine-id").stdout.decode().strip()
        controller_machine = self.ssh(control, "cat /etc/machine-id").stdout.decode().strip()
        if len(machine) != 32 or len(controller_machine) != 32 or machine == controller_machine:
            raise Refusal("controller and target machine identities are not distinct 32-hex values")
        unit_sha = self.ssh(target, f"sha256sum /etc/systemd/system/{UNIT}").stdout.decode().split()[0]
        facts = {
            "schema": "constellation.operator_beta.m1b_guest_identity.v1",
            "run_id": self.run_id,
            "controller_machine_identity": controller_machine,
            "target_machine_identity": machine,
            "unit_name": UNIT,
            "unit_file_sha256": "sha256:" + unit_sha,
            "controller_address": CONTROLLER_ADDRESS,
            "target_address": FIXTURE_ADDRESS,
        }
        atomic_write(self.output / "evidence" / "guest-identities.json", canonical(facts) + b"\n")
        self.complete_phase("packages_fixture_installed", "generate exact NQ configuration")
        return control, target

    def scope_identity(self, subject: str, scope: dict[str, Any], profile: str) -> dict[str, str]:
        value = {
            "schema": "nq.diagnostic_scope.v1",
            "subject": subject,
            "scope": scope,
            "profile": {"id": profile, "version": "1", "digest": PROFILE_DIGESTS[profile]},
        }
        return {"id": f"nq.scope.{scope['kind']}", "version": "1", "digest": sha256_bytes(canonical(value))}

    def service_subject(self, identities: dict[str, Any]) -> tuple[dict[str, Any], str]:
        value = {
            "schema": "constellation.operator_beta.service_subject.v1",
            "campaign_id": "constellation-operator-beta-2026",
            "fixture_run_id": self.run_id,
            "target_machine_identity": identities["target_machine_identity"],
            "unit_name": UNIT,
            "unit_file_sha256": identities["unit_file_sha256"],
        }
        raw = canonical(value)
        domain = b"constellation/operator-beta/service-subject/v1"
        framed = (
            b"ag-ng\0digest\0v1\0"
            + len(domain).to_bytes(16, "big")
            + domain
            + len(raw).to_bytes(16, "big")
            + raw
        )
        return value, sha256_bytes(framed)

    def watcher_block(
        self,
        instance: str,
        profile: str,
        subject: str,
        scope: dict[str, Any],
        vantage: dict[str, Any],
        capability: str,
        policy: dict[str, Any],
    ) -> str:
        policy_digest = sha256_bytes(canonical(policy))
        def toml(value: Any) -> str:
            if isinstance(value, str):
                return json.dumps(value)
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, int):
                return str(value)
            if isinstance(value, list):
                return "[" + ", ".join(toml(item) for item in value) + "]"
            if isinstance(value, dict):
                return (
                    "{ "
                    + ", ".join(
                        f"{key} = {toml(value[key])}" for key in sorted(value)
                    )
                    + " }"
                )
            raise TypeError(value)
        return f"""
[[watchers]]
instance_id = {toml(instance)}
carrier = "stdio"
subject = {toml(subject)}
capability_ceiling = [{toml(capability)}]
checkpoint_policy = "disabled"

[watchers.command]
executable = "/usr/lib/nq/helpers/nq-operator-beta-helper"
args = []
env = {{}}
execution_account = "nq-helper"
working_directory = "/usr/lib/nq/helpers"

[watchers.profile]
id = {toml(profile)}
version = 1

[watchers.threshold_policy]
id = {toml(profile + ".postcondition.threshold_policy")}
version = {toml(self.run_id)}
digest = {toml(policy_digest)}
value = {toml(policy)}

[watchers.scope]
kind = {toml(scope["kind"])}
value = {toml(scope["value"])}

[watchers.vantage]
kind = {toml(vantage["kind"])}
value = {toml(vantage["value"])}

[watchers.schedule]
interval_seconds = 300
jitter_seconds = 0
deadline_ms = 30000
retry_backoff_seconds = 10
max_retry_backoff_seconds = 30

[watchers.resources]
max_response_bytes = 32768
max_stderr_bytes = 65536
max_observations = 1
max_address_space_bytes = 536870912
max_cpu_seconds = 60
max_processes = 32
max_open_files = 128
max_file_bytes = 67108864
"""

    def configure_nq(self, control: Guest, target: Guest) -> dict[str, Any]:
        identities = json.loads((self.output / "evidence" / "guest-identities.json").read_text())
        service_subject, subject = self.service_subject(identities)
        atomic_write(
            self.output / "evidence" / "service-subject.json",
            canonical(service_subject) + b"\n",
            0o400,
        )
        systemd_scope = {
            "kind": "systemd_unit",
            "value": {
                "schema": "nq.operator_beta.systemd_unit_scope.v1",
                "subject_identity": subject,
                "target_machine_identity": identities["target_machine_identity"],
                "unit_name": UNIT,
                "unit_file_sha256": identities["unit_file_sha256"],
                "manager_interface": "org.freedesktop.systemd1",
                "properties": ["LoadState", "ActiveState", "SubState", "UnitFileState"],
            },
        }
        http_scope = {
            "kind": "http_endpoint",
            "value": {
                "schema": "nq.operator_beta.http_endpoint_scope.v1",
                "subject_identity": subject,
                "controller_vantage_identity": "machine:" + identities["controller_machine_identity"],
                "endpoint": f"http://{FIXTURE_ADDRESS}:{FIXTURE_PORT}/healthz",
                "method": "GET",
                "redirect_policy": "refuse",
                "max_response_bytes": 1024,
            },
        }
        systemd_policy = {
            "schema": "nq.operator_beta.systemd_unit_threshold_policy.v1",
            "fixture_run_id": self.run_id,
            "service_subject": service_subject,
            "subject_identity": subject,
            "request_scope": self.scope_identity(subject, systemd_scope, "nq.systemd_unit"),
            "expected_load_state": "loaded",
            "expected_active_state": "active",
            "expected_sub_state": "running",
            "expected_unit_file_state": "disabled",
        }
        http_policy = {
            "schema": "nq.operator_beta.http_endpoint_threshold_policy.v1",
            "fixture_run_id": self.run_id,
            "service_subject": service_subject,
            "subject_identity": subject,
            "request_scope": self.scope_identity(subject, http_scope, "nq.http_endpoint"),
            "expected_status": 200,
            "expected_body_sha256": sha256_bytes(FIXTURE_HEALTH_BYTES),
        }
        prefix_target = """schema = "nq.config.v1"
database_path = "/var/lib/nq/operator-beta.sqlite"
socket_path = "/run/nq/operator-beta.sock"
admissions_dir = "/var/lib/nq/operator-beta-admissions"
helper_runtime_dir = "/run/nq/operator-beta-helpers"
"""
        prefix_control = prefix_target
        target_config = prefix_target
        control_config = prefix_control
        for suffix in ("pre", "post", "restart"):
            target_config += self.watcher_block(
                f"systemd-{suffix}",
                "nq.systemd_unit",
                subject,
                systemd_scope,
                {"kind": "target_local", "value": {}},
                "read_systemd_unit",
                systemd_policy,
            )
            control_config += self.watcher_block(
                f"http-{suffix}",
                "nq.http_endpoint",
                subject,
                http_scope,
                {
                    "kind": "controller_http",
                    "value": {
                        "controller_vantage_identity": "machine:"
                        + identities["controller_machine_identity"]
                    },
                },
                "read_http_endpoint",
                http_policy,
            )
        atomic_write(self.output / "evidence" / "target-nq.toml", target_config.encode(), 0o400)
        atomic_write(self.output / "evidence" / "control-nq.toml", control_config.encode(), 0o400)
        self.scp_to(target, [self.output / "evidence" / "target-nq.toml"], "/home/betaoperator/")
        self.scp_to(control, [self.output / "evidence" / "control-nq.toml"], "/home/betaoperator/")
        for guest, name in ((target, "target-nq.toml"), (control, "control-nq.toml")):
            self.ssh(
                guest,
                "sudo install -d -o nq -g nq -m 0700 "
                "/var/lib/nq/operator-beta-admissions /run/nq/operator-beta-helpers; "
                f"sudo install -o root -g nq -m 0640 /home/betaoperator/{name} "
                "/etc/nq/operator-beta.toml; "
                "sudo -u nq /usr/bin/nq --config /etc/nq/operator-beta.toml config check; "
                "sudo -u nq /usr/bin/nq --config /etc/nq/operator-beta.toml init",
            )
        bindings = {
            "schema": "constellation.operator_beta.m1b_bindings.v1",
            "run_id": self.run_id,
            "service_subject": service_subject,
            "subject_identity": subject,
            "service_subject_plain_sha256": sha256_bytes(canonical(service_subject)),
            "systemd_scope": systemd_scope,
            "systemd_policy": systemd_policy,
            "http_scope": http_scope,
            "http_policy": http_policy,
        }
        atomic_write(self.output / "evidence" / "bindings.json", canonical(bindings) + b"\n")
        self.complete_phase("nq_configured", "record pre-effect artifacts")
        return bindings

    def execute_diagnostic(
        self,
        guest: Guest,
        instance: str,
        output_name: str,
        expected_profile: str,
        expected_condition: str,
    ) -> dict[str, Any]:
        self.ssh(
            guest,
            nq_helper_command(["watcher", "admit", instance]),
        )
        result = self.ssh(
            guest,
            nq_helper_command(["diagnostics", "execute", instance]),
        )
        destination = self.output / "evidence" / output_name
        atomic_write(destination, result.stdout, 0o400)
        try:
            artifact = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise Refusal(f"{instance} did not emit one JSON diagnostic artifact") from error
        bindings = json.loads((self.output / "evidence" / "bindings.json").read_bytes())
        family = "systemd" if expected_profile == "nq.systemd_unit" else "http"
        policy = bindings[f"{family}_policy"]
        expected_policy = {
            "id": f"{expected_profile}.postcondition.threshold_policy",
            "version": self.run_id,
            "digest": sha256_bytes(canonical(policy)),
        }
        expected_question = {
            "id": f"{expected_profile}.postcondition",
            "version": "1",
            "digest": QUESTION_DIGESTS[expected_profile],
        }
        if artifact.get("schema") != "nq.diagnostic_execution.v2":
            raise Refusal(f"{instance} emitted an unexpected diagnostic schema")
        if artifact.get("profile") != {
            "id": expected_profile,
            "version": "1",
            "digest": PROFILE_DIGESTS[expected_profile],
        }:
            raise Refusal(f"{instance} emitted the wrong profile identity")
        if artifact.get("question") != expected_question:
            raise Refusal(f"{instance} emitted the wrong compiled question identity")
        if artifact.get("threshold_policy") != expected_policy:
            raise Refusal(f"{instance} emitted the wrong decision-cut policy identity")
        if artifact.get("subject") != {
            "id": bindings["subject_identity"],
            "scope": policy["request_scope"],
        }:
            raise Refusal(f"{instance} emitted the wrong subject or scope identity")
        vantage = artifact.get("vantage", {})
        if (
            not isinstance(vantage, dict)
            or not vantage.get("id", "").endswith(f".{instance}")
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", vantage.get("digest", ""))
        ):
            raise Refusal(f"{instance} emitted the wrong concrete vantage identity")
        preimage = dict(artifact)
        observed_artifact_id = preimage.pop("artifact_id", None)
        if observed_artifact_id != sha256_bytes(canonical(preimage)):
            raise Refusal(f"{instance} emitted an invalid artifact self-identity")
        try:
            started = dt.datetime.fromisoformat(artifact["started_at"].replace("Z", "+00:00"))
            completed = dt.datetime.fromisoformat(artifact["completed_at"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as error:
            raise Refusal(f"{instance} emitted invalid decision-cut times") from error
        if completed < started or (completed - started).total_seconds() > 60:
            raise Refusal(f"{instance} exceeded the admitted freshness interval")
        if artifact.get("outcome", {}).get("condition") != expected_condition:
            raise Refusal(f"{instance} emitted an unexpected warranted condition")
        bindings = json.loads((self.output / "evidence" / "bindings.json").read_bytes())
        verify_diagnostic_artifact(
            artifact,
            profile=expected_profile,
            condition=expected_condition,
            instance=instance,
            bindings=bindings,
        )
        return artifact
    def pre_effect(self, control: Guest, target: Guest) -> dict[str, Any]:
        target_state = self.ssh(
            target,
            f"systemctl show {UNIT} -p LoadState -p ActiveState -p SubState; "
            f"systemctl is-enabled {UNIT} || true",
        ).stdout
        atomic_write(self.output / "evidence" / "target-prestate.txt", target_state, 0o400)
        http = self.ssh(
            control,
            f"python3 -c 'import socket; s=socket.socket(); s.settimeout(2); "
            f"r=s.connect_ex((\"{FIXTURE_ADDRESS}\",{FIXTURE_PORT})); print(r); "
            "raise SystemExit(0 if r != 0 else 1)'",
        ).stdout
        atomic_write(self.output / "evidence" / "controller-http-prestate.txt", http, 0o400)
        systemd = self.execute_diagnostic(
            target, "systemd-pre", "systemd-pre-artifact.json", "nq.systemd_unit", "present"
        )
        http_artifact = self.execute_diagnostic(
            control, "http-pre", "http-pre-artifact.json", "nq.http_endpoint", "unresolved"
        )
        self.complete_phase("pre_effect_recorded", "execute one fresh AG M1A occurrence")
        return {"systemd": systemd, "http": http_artifact}

    def enact(self, target: Guest, bindings: dict[str, Any]) -> dict[str, Any]:
        identities = json.loads((self.output / "evidence" / "guest-identities.json").read_text())
        plan = expected_effect_plan(bindings, identities)
        scope = plan["scope"]
        plan_path = self.output / "evidence" / "systemd-plan-v2.json"
        atomic_write(plan_path, canonical(plan) + b"\n", 0o400)
        self.scp_to(target, [plan_path], "/home/betaoperator/")
        self.ssh(
            target,
            "sudo install -d -o root -g root -m 0700 /var/lib/ag-effectd-m1b/input; "
            "sudo install -o root -g root -m 0600 /home/betaoperator/systemd-plan-v2.json "
            "/var/lib/ag-effectd-m1b/input/plan.json",
        )
        work = self.ssh(
            target,
            "sudo /usr/libexec/agent-governor-ng/ag-effectd "
            "plan-id /var/lib/ag-effectd-m1b/input/plan.json",
        ).stdout.decode().strip()
        dispatch, expected_work = expected_effect_dispatch(self.run_id, plan)
        if work != expected_work:
            raise Refusal("AG plan identity disagrees with the exact retained plan")
        attempt = dispatch["attempt"]
        marker = dispatch["marker"]
        dispatch_path = self.output / "evidence" / "docket-shaped-dispatch-v1.json"
        atomic_write(dispatch_path, canonical(dispatch) + b"\n", 0o400)
        self.scp_to(target, [dispatch_path], "/home/betaoperator/")
        self.effect_custody = {
            "plan_sha256": digest_file(plan_path, "sha256"),
            "dispatch_sha256": digest_file(dispatch_path, "sha256"),
            "attempt": attempt,
            "marker": marker,
            "work": work,
            "subject": dispatch["subject"],
            "scope": scope,
        }
        self.effect_outcome = "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE"
        self.state(
            "effect_dispatch_prepared",
            "invoke the exact AG attempt; reconcile the same attempt after ambiguous loss",
            effect_attempt=attempt,
            effect_marker=marker,
            effect_work=work,
        )
        result = self.ssh(
            target,
            "sudo /usr/libexec/agent-governor-ng/ag-effectd "
            "execute /var/lib/ag-effectd-m1b/input/plan.json "
            "< /home/betaoperator/docket-shaped-dispatch-v1.json",
        )
        atomic_write(self.output / "evidence" / "executor-outcome-v1.json", result.stdout, 0o400)
        try:
            outcome = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise Refusal("AG execute did not emit one JSON outcome") from error
        if result.stdout != canonical(outcome) + b"\n":
            raise Refusal("AG execute outcome is not canonical JSON")
        outcome_class = verify_effect_outcome(outcome, dispatch)
        self.effect_custody["outcome_sha256"] = digest_file(
            self.output / "evidence" / "executor-outcome-v1.json", "sha256"
        )
        self.effect_custody["receipt"] = outcome["receipt"]
        self.effect_outcome = effect_outcome_state(outcome_class)
        if outcome_class != "success":
            raise Refusal(f"fresh AG M1A occurrence returned {outcome_class}")
        record = {
            "schema": "constellation.operator_beta.m1b_effect_occurrence.v1",
            "run_id": self.run_id,
            "owner": "AG-ng M1A adapter",
            "docket_database_occurrence": "NOT_RECORDED",
            "authorization_consumption": "NOT_RECORDED",
            "plan": plan,
            "dispatch": dispatch,
            "outcome": outcome,
        }
        atomic_write(self.output / "evidence" / "effect-occurrence.json", canonical(record) + b"\n")
        self.complete_phase("effect_owner_completed", "record fresh post-effect observations")
        return record

    def post_effect(self, control: Guest, target: Guest) -> dict[str, Any]:
        systemd = self.execute_diagnostic(
            target, "systemd-post", "systemd-post-artifact.json", "nq.systemd_unit", "explicitly_absent"
        )
        http = self.execute_diagnostic(
            control, "http-post", "http-post-artifact.json", "nq.http_endpoint", "explicitly_absent"
        )
        state = self.ssh(
            target,
            f"systemctl show {UNIT} -p LoadState -p ActiveState -p SubState; "
            f"systemctl is-enabled {UNIT} || true",
        ).stdout
        expected_state = (
            b"LoadState=loaded\n"
            b"ActiveState=active\n"
            b"SubState=running\n"
            b"disabled\n"
        )
        if state != expected_state:
            raise Refusal(
                "target direct post-effect state differs from the exact expected tuple"
            )
        atomic_write(self.output / "evidence" / "target-poststate.txt", state, 0o400)
        self.complete_phase("post_effect_recorded", "exercise package remove/reinstall continuity")
        return {"systemd": systemd, "http": http}

    def wait_http_fixture_ready(self, control: Guest) -> None:
        script = """import socket
import sys
import time

address = sys.argv[1]
port = int(sys.argv[2])
deadline = time.monotonic() + int(sys.argv[3])
while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemExit("fixture TCP readiness was not observed")
    with socket.socket() as stream:
        stream.settimeout(min(1.0, remaining))
        if stream.connect_ex((address, port)) == 0:
            print("fixture_tcp_ready=true")
            break
    time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
"""
        command = shlex.join(
            [
                "python3",
                "-c",
                script,
                FIXTURE_ADDRESS,
                str(FIXTURE_PORT),
                str(FIXTURE_READINESS_SECONDS),
            ]
        )
        result = self.ssh(control, command)
        if result.stdout != b"fixture_tcp_ready=true\n" or result.stderr:
            raise Refusal("fixture readiness did not emit its exact bounded result")
        atomic_write(
            self.output / "evidence" / "controller-http-readiness.txt",
            result.stdout,
            0o400,
        )
        self.complete_phase(
            "fixture_readiness_observed",
            "execute one fresh post-effect NQ observation per profile",
        )

    def export_artifact(self, guest: Guest, artifact_id: str) -> bytes:
        result = self.ssh(
            guest,
            "sudo -u nq /usr/bin/nq --config /etc/nq/operator-beta.toml "
            f"diagnostics export {artifact_id}",
        )
        return result.stdout

    def package_continuity(
        self, control: Guest, target: Guest, artifacts: list[tuple[Guest, dict[str, Any], pathlib.Path]]
    ) -> None:
        for guest in (control, target):
            result = self.ssh(
                guest,
                "sudo python3 -c 'import sqlite3; "
                "c=sqlite3.connect(\"/var/lib/nq/operator-beta.sqlite\"); "
                "c.execute(\"PRAGMA wal_checkpoint(TRUNCATE)\"); c.close()'; "
                "sudo test ! -s /var/lib/nq/operator-beta.sqlite-wal; "
                "before=$(sudo sha256sum /var/lib/nq/operator-beta.sqlite | cut -d ' ' -f1); "
                "sudo dpkg -r nq-ng; "
                "sudo test -f /var/lib/nq/operator-beta.sqlite; "
                "test ! -e /usr/lib/nq/helpers/nq-operator-beta-helper; "
                "sudo dpkg -i /home/betaoperator/nq-ng.deb; "
                "test -x /usr/lib/nq/helpers/nq-operator-beta-helper; "
                "after=$(sudo sha256sum /var/lib/nq/operator-beta.sqlite | cut -d ' ' -f1); "
                "test \"$before\" = \"$after\"; printf 'store_sha256=%s\\n' \"$after\"",
            )
            atomic_write(
                self.output / "evidence" / f"{guest.role}-package-continuity.txt",
                result.stdout,
                0o400,
            )
        for guest, artifact, original in artifacts:
            exported = self.export_artifact(guest, artifact["artifact_id"])
            if exported != original.read_bytes():
                raise Refusal(f"artifact {artifact['artifact_id']} changed across package lifecycle")
        self.complete_phase("package_continuity_proved", "restart guests and reopen exact artifacts")

    def restart_and_reopen(
        self,
        control: Guest,
        target: Guest,
        artifacts: list[tuple[Guest, dict[str, Any], pathlib.Path]],
    ) -> None:
        before_by_role = {}
        for guest in (control, target):
            before = self.ssh(guest, "cat /proc/sys/kernel/random/boot_id").stdout
            before_by_role[guest.role] = before
            atomic_write(self.output / "evidence" / f"{guest.role}-boot-before.txt", before, 0o400)
            self.ssh(guest, "sudo systemctl reboot", check=False)
        for guest in (control, target):
            after = self.wait_boot_identity_change(guest, before_by_role[guest.role], 900)
            atomic_write(self.output / "evidence" / f"{guest.role}-boot-after.txt", after, 0o400)
        for guest, artifact, original in artifacts:
            exported = self.export_artifact(guest, artifact["artifact_id"])
            if exported != original.read_bytes():
                raise Refusal(f"artifact {artifact['artifact_id']} changed across guest restart")
        systemd = self.execute_diagnostic(
            target,
            "systemd-restart",
            "systemd-restart-artifact.json",
            "nq.systemd_unit",
            "present",
        )
        http = self.execute_diagnostic(
            control,
            "http-restart",
            "http-restart-artifact.json",
            "nq.http_endpoint",
            "unresolved",
        )
        atomic_write(
            self.output / "evidence" / "current-support-after-restart.json",
            canonical(
                {
                    "schema": "constellation.operator_beta.current_support.v1",
                    "historical_effect": "AG_OWNER_RECEIPT_RETAINED",
                    "systemd_artifact": systemd["artifact_id"],
                    "systemd_current_condition": "present",
                    "http_artifact": http["artifact_id"],
                    "http_current_condition": "unresolved",
                    "aggregate_postcondition": "NOT_RECORDED",
                }
            )
            + b"\n",
        )
        self.complete_phase("restart_reopen_proved", "export stores and perform bounded teardown")

    def retain_and_audit_ag_store_cut(self, target: Guest) -> None:
        source_store = "/var/lib/ag-effectd-m1b/attempts.sqlite"
        guest_cut = "/home/betaoperator/ag-attempt-store-cut.sqlite"
        stable = self.ssh(
            target,
            ag_store_cut_command(source_store, guest_cut),
        )
        stable_facts = dict(
            line.split("=", 1)
            for line in stable.stdout.decode().splitlines()
            if "=" in line
        )
        cut = self.output / "evidence" / "ag-attempt-store-cut.sqlite"
        self.scp_from(target, guest_cut, cut)
        os.chmod(cut, 0o400)
        cut_metadata = regular_file(cut, "copied AG attempt-store cut")
        if cut_metadata.st_size <= 0 or cut_metadata.st_size > AG_AUDIT_STORE_MAX_BYTES:
            raise Refusal("copied AG attempt-store cut exceeds the owner audit bound")
        cut_sha256 = digest_file(cut, "sha256")
        if stable_facts != {
            "source_sha256": cut_sha256,
            "source_bytes": str(cut_metadata.st_size),
            "wal": "ABSENT_OR_ZERO_LENGTH",
        }:
            raise Refusal("copied AG attempt-store cut disagrees with the locked source cut")

        plan_path = self.output / "evidence" / "systemd-plan-v2.json"
        dispatch_path = self.output / "evidence" / "docket-shaped-dispatch-v1.json"
        expected_outcome_path = self.output / "evidence" / "executor-outcome-v1.json"
        audit_binary = (
            self.output
            / "runtime"
            / "ag-package"
            / "usr"
            / "libexec"
            / "agent-governor-ng"
            / "ag-effectd"
        )
        completed = run(
            [
                str(audit_binary),
                "audit-store",
                str(plan_path),
                "--store-cut",
                str(cut),
                "--store-bytes",
                str(cut_metadata.st_size),
                "--store-sha256",
                "sha256:" + cut_sha256,
            ],
            stdin=dispatch_path.read_bytes(),
        )
        if completed.stderr or completed.stdout != expected_outcome_path.read_bytes():
            raise Refusal("AG owner store audit disagrees with the original terminal outcome")
        audit_outcome_path = self.output / "evidence" / "ag-store-audit-outcome-v1.json"
        atomic_write(audit_outcome_path, completed.stdout, 0o400)

        custody = self.effect_custody
        if not isinstance(custody, dict):
            raise Refusal("effect custody is absent before AG store-cut audit")
        store_cut_record = {
            "schema": "constellation.operator_beta.m1b_ag_store_cut.v1",
            "run_id": self.run_id,
            "owner": "AG-ng",
            "owner_package_result": AG_STORE_AUDIT_RESULT,
            "ag_package_sha256": AG_DEB_SHA256,
            "ag_executable_sha256": AG_EXECUTABLE_SHA256,
            "source_store": source_store,
            "wal": "ABSENT_OR_ZERO_LENGTH",
            "store_bytes": cut_metadata.st_size,
            "store_sha256": "sha256:" + cut_sha256,
            "plan_sha256": custody["plan_sha256"],
            "dispatch_sha256": custody["dispatch_sha256"],
            "attempt": custody["attempt"],
            "marker": custody["marker"],
            "work": custody["work"],
            "subject": custody["subject"],
            "scope": custody["scope"],
            "owner_outcome_sha256": digest_file(audit_outcome_path, "sha256"),
            "receipt": custody["receipt"],
        }
        store_cut_record_path = self.output / "evidence" / "ag-store-cut.json"
        atomic_write(store_cut_record_path, canonical(store_cut_record) + b"\n", 0o400)
        custody.update(
            {
                "ag_store_cut_bytes": cut_metadata.st_size,
                "ag_store_cut_sha256": cut_sha256,
                "ag_store_cut_record_sha256": digest_file(
                    store_cut_record_path, "sha256"
                ),
                "ag_store_audit_outcome_sha256": digest_file(
                    audit_outcome_path, "sha256"
                ),
                "ag_store_audit_result": AG_STORE_AUDIT_RESULT,
                "ag_executable_sha256": AG_EXECUTABLE_SHA256,
            }
        )
        self.complete_phase("ag_store_cut_audited", "perform bounded teardown")

    def teardown(self, control: Guest, target: Guest) -> None:
        for guest, instances in (
            (control, ("http-pre", "http-post", "http-restart")),
            (target, ("systemd-pre", "systemd-post", "systemd-restart")),
        ):
            revocations = []
            for instance in instances:
                result = self.ssh(
                    guest,
                    "sudo -u nq /usr/bin/nq --config /etc/nq/operator-beta.toml "
                    f"watcher revoke {instance}",
                )
                revocations.append({
                    "instance_id": instance,
                    "stdout_sha256": sha256_bytes(result.stdout),
                    "stderr_sha256": sha256_bytes(result.stderr),
                })
            atomic_write(
                self.output / "evidence" / f"{guest.role}-revocations.json",
                canonical({
                    "schema": "constellation.operator_beta.m1b_revocations.v1",
                    "run_id": self.run_id,
                    "role": guest.role,
                    "disposition": "REVOKED",
                    "instances": revocations,
                }) + b"\n",
                0o400,
            )
            self.ssh(
                guest,
                "sudo -u nq /usr/bin/nq --config /etc/nq/operator-beta.toml "
                "backup /var/lib/nq/operator-beta-backup.sqlite",
            )
            self.ssh(
                guest,
                "sudo cp --reflink=never /var/lib/nq/operator-beta-backup.sqlite "
                "/home/betaoperator/operator-beta-backup.sqlite; "
                "sudo chown betaoperator:betaoperator /home/betaoperator/operator-beta-backup.sqlite; "
                "chmod 0400 /home/betaoperator/operator-beta-backup.sqlite",
            )
            evidence_dir = self.output / "evidence"
            command = [
                "scp",
                "-i",
                str(guest.private_key),
                "-P",
                str(guest.ssh_port),
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={guest.known_hosts}",
                f"betaoperator@127.0.0.1:/home/betaoperator/operator-beta-backup.sqlite",
                str(evidence_dir / f"{guest.role}-nq-backup.sqlite"),
            ]
            run(command)
            self.ssh(guest, "rm -f /home/betaoperator/operator-beta-backup.sqlite")
        self.ssh(
            target,
            f"sudo systemctl stop {UNIT}; sudo systemctl disable {UNIT} >/dev/null 2>&1 || true; "
            f"sudo rm -f /etc/systemd/system/{UNIT}; "
            "sudo rm -rf /var/lib/constellation-beta-http-fixture /var/lib/ag-effectd-m1b; "
            "sudo systemctl daemon-reload; "
            "sudo dpkg -r agent-governor-ng-systemd-executor nq-ng; "
            "sudo rm -rf /etc/nq/operator-beta.toml /var/lib/nq/operator-beta.sqlite "
            "/var/lib/nq/operator-beta.sqlite-shm /var/lib/nq/operator-beta.sqlite-wal "
            "/var/lib/nq/operator-beta-admissions /var/lib/nq/operator-beta-backup.sqlite; "
            "rm -f /home/betaoperator/nq-ng.deb "
            "/home/betaoperator/agent-governor-ng-systemd-executor_amd64.deb "
            "/home/betaoperator/target-nq.toml /home/betaoperator/systemd-plan-v2.json "
            "/home/betaoperator/docket-shaped-dispatch-v1.json "
            "/home/betaoperator/ag-attempt-store-cut.sqlite "
            f"/home/betaoperator/{UNIT} /home/betaoperator/healthz; "
            f"test ! -e /etc/systemd/system/{UNIT} && "
            "test ! -e /var/lib/constellation-beta-http-fixture && "
            "test ! -e /var/lib/ag-effectd-m1b && "
            "sudo test ! -e /var/lib/nq/operator-beta.sqlite && "
            f"{package_payload_absence_command('nq-ng', NQ_PACKAGE_PAYLOAD_PATHS)} && "
            f"{package_payload_absence_command('agent-governor-ng-systemd-executor', AG_PACKAGE_PAYLOAD_PATHS)}",
        )
        self.ssh(
            control,
            "sudo dpkg -r nq-ng; "
            "sudo rm -rf /etc/nq/operator-beta.toml /var/lib/nq/operator-beta.sqlite "
            "/var/lib/nq/operator-beta.sqlite-shm /var/lib/nq/operator-beta.sqlite-wal "
            "/var/lib/nq/operator-beta-admissions /var/lib/nq/operator-beta-backup.sqlite; "
            "rm -f /home/betaoperator/nq-ng.deb /home/betaoperator/control-nq.toml; "
            "sudo test ! -e /var/lib/nq/operator-beta.sqlite && "
            f"{package_payload_absence_command('nq-ng', NQ_PACKAGE_PAYLOAD_PATHS)}",
        )
        for guest in (control, target):
            self.ssh(guest, "sudo systemctl poweroff", check=False)
        for guest in (control, target):
            if guest.process is None:
                raise Refusal("guest process identity was lost before poweroff")
            try:
                guest.process.wait(timeout=180)
            except subprocess.TimeoutExpired as error:
                raise Refusal(f"{guest.name} did not power off within 180 seconds") from error
            run(["qemu-img", "check", str(guest.root / "overlay.qcow2")])
        final_observation = {
            "schema": "constellation.operator_beta.m1b_host_teardown.v1",
            "recorded_at": utc_now(),
            "control_process_absent": not process_has_token("constellation-beta-control-m1b"),
            "target_process_absent": not process_has_token("constellation-beta-target-m1b"),
            "control_ssh_port_absent": port_absent(self.args.controller_ssh_port, socket.SOCK_STREAM),
            "target_ssh_port_absent": port_absent(self.args.target_ssh_port, socket.SOCK_STREAM),
            "fixture_link_port_absent": port_absent(self.args.fixture_link_port, socket.SOCK_DGRAM),
        }
        if not all(value for key, value in final_observation.items() if key.endswith("_absent")):
            raise Refusal("final host process or listener absence was not established")
        atomic_write(
            self.output / "evidence" / "host-final-observation.json",
            canonical(final_observation) + b"\n",
            0o400,
        )
        self.complete_phase("teardown_complete", "seal exact evidence inventory")

    def seal(self) -> None:
        private_key = self.output / "runtime" / "id_ed25519"
        if private_key.exists():
            private_key.unlink()
        result = {
            "schema": "constellation.operator_beta.m1b_run_result.v1",
            "run_id": self.run_id,
            "disposition": "MECHANISM_CASES_COMPLETED_WITH_DECLARED_LIMITATIONS",
            "completed_at": utc_now(),
            "harness_subject": self.args.harness_subject,
            "accepted_package_result": ACCEPTED_PACKAGE_RESULT,
            "signed_upstream_checksum": "NOT_QUALIFIED",
            "docket_database_occurrence": "NOT_RUN",
            "authorization_consumption": "NOT_RUN",
            "production": "NOT_RUN",
        }
        self.last_completed = "sealed"
        self.state(
            "sealed",
            "independent evidence audit",
            terminal_disposition=result["disposition"],
        )
        files = []
        for path in sorted(self.output.rglob("*")):
            if not path.is_file() or path.name in {"ARTIFACTS.sha256", "RESULT.json"}:
                continue
            relative = path.relative_to(self.output).as_posix()
            files.append(
                {
                    "path": relative,
                    "bytes": path.stat().st_size,
                    "sha256": digest_file(path, "sha256"),
                }
            )
        manifest = {
            "schema": "constellation.operator_beta.m1b_artifact_manifest.v1",
            "files": files,
        }
        atomic_write(self.output / "ARTIFACTS.sha256", canonical(manifest) + b"\n", 0o400)
        result["manifest_sha256"] = digest_file(self.output / "ARTIFACTS.sha256", "sha256")
        atomic_write(self.output / "RESULT.json", canonical(result) + b"\n", 0o400)

    def terminate_guests(self) -> None:
        for guest in self.guests:
            process = guest.process
            if process is None or process.poll() is not None:
                continue
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def execute(self) -> None:
        preflight = self.preflight()
        self.input_facts = preflight
        if self.args.preflight_only:
            print(json.dumps({"result": "PREFLIGHT_PASSED", **preflight}, sort_keys=True))
            return
        self.verify_producer()
        signal.signal(signal.SIGINT, interrupted)
        signal.signal(signal.SIGTERM, interrupted)
        self.create_run(preflight)
        try:
            self.prepare_guests()
            self.boot_guests()
            control, target = self.install_inputs()
            bindings = self.configure_nq(control, target)
            pre = self.pre_effect(control, target)
            self.enact(target, bindings)
            self.wait_http_fixture_ready(control)
            post = self.post_effect(control, target)
            artifacts: list[tuple[Guest, dict[str, Any], pathlib.Path]] = [
                (target, pre["systemd"], self.output / "evidence" / "systemd-pre-artifact.json"),
                (control, pre["http"], self.output / "evidence" / "http-pre-artifact.json"),
                (target, post["systemd"], self.output / "evidence" / "systemd-post-artifact.json"),
                (control, post["http"], self.output / "evidence" / "http-post-artifact.json"),
            ]
            self.package_continuity(control, target, artifacts)
            self.restart_and_reopen(control, target, artifacts)
            self.retain_and_audit_ag_store_cut(target)
            self.teardown(control, target)
            self.seal()
        except BaseException as error:
            if self.created:
                refusal = {
                    "schema": "constellation.operator_beta.m1b_refusal.v1",
                    "run_id": self.run_id,
                    "occurred_at": utc_now(),
                    "phase": self.last_completed,
                    "reason": str(error)[:4096],
                    "effect_outcome": self.effect_outcome,
                }
                atomic_write(self.output / "REFUSAL.json", canonical(refusal) + b"\n")
                self.state("refused", "reopen evidence; do not restart producer", refusal=refusal)
            if self.effect_outcome in {
                "NO_EFFECT_ATTEMPTED",
                "KNOWN_NO_EFFECT_OWNER_FAILURE",
            }:
                self.terminate_guests()
            raise


def load_recovery(path: pathlib.Path) -> dict[str, Any]:
    if path.resolve(strict=True) != path or not path.is_dir() or path.is_symlink():
        raise Refusal("run path is not one exact physical directory")
    recovery_path = path / "RECOVERY.json"
    regular_file(recovery_path, "recovery record")
    raw = recovery_path.read_bytes()
    try:
        recovery = json.loads(raw)
    except json.JSONDecodeError as error:
        raise Refusal("recovery record is not JSON") from error
    if raw != canonical(recovery) + b"\n":
        raise Refusal("recovery record is not canonical JSON")
    if (
        not isinstance(recovery, dict)
        or recovery.get("schema") != "constellation.operator_beta.m1b_recovery.v1"
        or recovery.get("campaign") != CAMPAIGN
        or recovery.get("paths", {}).get("run_root") != str(path)
        or not isinstance(recovery.get("guests"), list)
    ):
        raise Refusal("recovery record does not bind this exact run")
    return recovery


def inspect_run(path: pathlib.Path) -> dict[str, Any]:
    recovery = load_recovery(path)
    guest_states = []
    for guest in recovery["guests"]:
        role = guest.get("role")
        pid = guest.get("pid")
        start_ticks = guest.get("start_ticks")
        token = f"constellation-beta-{role}-m1b"
        if not isinstance(pid, int) or not isinstance(start_ticks, int):
            state = "NOT_RECORDED"
        else:
            try:
                observed_ticks = process_identity(pid, token)
            except Refusal:
                state = "EXITED"
            else:
                state = "ACTIVE" if observed_ticks == start_ticks else "DISAGREEMENT"
        guest_states.append({"role": role, "pid": pid, "state": state})
    producer = recovery.get("producer", {})
    producer_pid = producer.get("main_pid")
    producer_ticks = producer.get("start_ticks")
    try:
        arguments = (pathlib.Path("/proc") / str(producer_pid) / "cmdline").read_bytes()
        observed_ticks = process_start_ticks(producer_pid)
    except Refusal:
        producer_state = "EXITED"
    except OSError:
        producer_state = "EXITED"
    else:
        if not isinstance(producer_ticks, int):
            producer_state = "NOT_RECORDED"
        elif b"run_two_vm.py" not in arguments or observed_ticks != producer_ticks:
            producer_state = "DISAGREEMENT"
        else:
            producer_state = "ACTIVE"
    result = {
        "schema": "constellation.operator_beta.m1b_inspection.v1",
        "campaign": CAMPAIGN,
        "run_id": recovery.get("run_id"),
        "phase": recovery.get("phase"),
        "effect_outcome": recovery.get("effect_outcome", "NOT_RECORDED"),
        "producer_state": producer_state,
        "guests": guest_states,
        "next_lawful_action": recovery.get("next_lawful_action"),
    }
    print(json.dumps(result, sort_keys=True))
    return result


def reconcile_effect(path: pathlib.Path) -> None:
    recovery = load_recovery(path)
    if recovery.get("effect_outcome") != "OUTCOME_UNKNOWN_REQUIRES_AG_RECONCILE":
        raise Refusal("effect reconciliation is allowed only for the retained unknown outcome")
    inspection = inspect_run(path)
    if inspection["producer_state"] == "ACTIVE":
        raise Refusal("original producer remains active; do not race its effect custody")
    target = next((guest for guest in recovery["guests"] if guest.get("role") == "target"), None)
    target_state = next((guest for guest in inspection["guests"] if guest.get("role") == "target"), None)
    if target is None or target_state is None or target_state.get("state") != "ACTIVE":
        raise Refusal("exact target guest is not active; outcome remains unknown")
    identities, bindings, retained_plan, retained_dispatch = verify_effect_attempt_inputs(
        path, recovery.get("run_id"), recovery.get("harness_subject")
    )
    plan = path / "evidence" / "systemd-plan-v2.json"
    dispatch = path / "evidence" / "docket-shaped-dispatch-v1.json"
    key = path / "runtime" / "id_ed25519"
    known_hosts = path / "target" / "known_hosts"
    for artifact, label in (
        (plan, "retained AG plan"),
        (dispatch, "retained dispatch"),
        (key, "retained SSH key"),
        (known_hosts, "retained target host key"),
    ):
        regular_file(artifact, label)
    expected_plan = expected_effect_plan(bindings, identities)
    expected_dispatch, expected_work = expected_effect_dispatch(
        recovery["run_id"], expected_plan
    )
    if retained_plan != expected_plan or retained_dispatch != expected_dispatch:
        raise Refusal("retained effect inputs differ from the exact original attempt")
    custody = recovery.get("effect_custody")
    expected_custody = {
        "plan_sha256": digest_file(plan, "sha256"),
        "dispatch_sha256": digest_file(dispatch, "sha256"),
        "attempt": expected_dispatch["attempt"],
        "marker": expected_dispatch["marker"],
        "work": expected_work,
        "subject": expected_dispatch["subject"],
        "scope": expected_dispatch["scope"],
    }
    if not isinstance(custody, dict) or any(
        custody.get(key) != value for key, value in expected_custody.items()
    ):
        raise Refusal("recovery custody does not bind the exact original attempt")
    port = target.get("ssh_port")
    if not isinstance(port, int):
        raise Refusal("target SSH port is not retained")
    ssh = [
        "ssh", "-i", str(key), "-p", str(port), "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        "betaoperator@127.0.0.1",
    ]
    remote_check = (
        f"test $(sudo sha256sum /var/lib/ag-effectd-m1b/input/plan.json | cut -d\x27 \x27 -f1) = {digest_file(plan, 'sha256')}; "
        f"test $(sha256sum /home/betaoperator/docket-shaped-dispatch-v1.json | cut -d\x27 \x27 -f1) = {digest_file(dispatch, 'sha256')}"
    )
    run(ssh + [remote_check])
    completed = run(
        ssh
        + [
            "sudo /usr/libexec/agent-governor-ng/ag-effectd reconcile "
            "/var/lib/ag-effectd-m1b/input/plan.json "
            "< /home/betaoperator/docket-shaped-dispatch-v1.json"
        ]
    )
    try:
        outcome = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise Refusal("AG reconcile did not emit one JSON outcome") from error
    if completed.stdout != canonical(outcome) + b"\n":
        raise Refusal("AG reconcile outcome is not canonical JSON")
    outcome_class = verify_effect_outcome(outcome, expected_dispatch)
    reconciled_state = effect_outcome_state(outcome_class)
    evidence_path = path / "evidence" / "reconciliation-outcome-v1.json"
    if evidence_path.exists():
        if evidence_path.read_bytes() != completed.stdout:
            raise Refusal("retained reconciliation outcome disagrees")
    else:
        atomic_write(evidence_path, completed.stdout, 0o400)
    custody.update(expected_custody)
    custody["reconciliation_outcome_sha256"] = digest_file(
        evidence_path, "sha256"
    )
    custody["receipt"] = outcome["receipt"]
    recovery["effect_outcome"] = reconciled_state
    recovery["effect_custody"] = custody
    recovery["phase"] = "effect_reconciled"
    recovery["next_lawful_action"] = (
        "inspect retained state; do not resume automatically"
        if outcome_class != "indeterminate"
        else "outcome remains unknown; preserve guest and owner evidence"
    )
    recovery["updated_at"] = utc_now()
    recovery["reconciliation_evidence"] = str(evidence_path)
    atomic_write(path / "RECOVERY.json", canonical(recovery) + b"\n")
    print(json.dumps({"result": "EFFECT_RECONCILED", "outcome": outcome_class}, sort_keys=True))


def load_json_artifact(path: pathlib.Path, label: str) -> dict[str, Any]:
    regular_file(path, label)
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise Refusal(f"{label} is not JSON") from error
    if not isinstance(value, dict):
        raise Refusal(f"{label} is not one object")
    if raw not in {canonical(value), canonical(value) + b"\n"}:
        raise Refusal(f"{label} is not canonical JSON")
    return value


def verify_ag_store_cut(
    path: pathlib.Path,
    run_id: str,
    base_custody: dict[str, Any],
    expected_outcome: dict[str, Any],
) -> dict[str, Any]:
    input_receipt = load_json_artifact(
        path / "evidence" / "input-receipt.json", "input receipt"
    )
    if (
        input_receipt.get("ag_package_sha256") != AG_DEB_SHA256
        or input_receipt.get("ag_package_version") != AG_DEB_VERSION
        or input_receipt.get("ag_store_audit_result") != AG_STORE_AUDIT_RESULT
        or input_receipt.get("ag_executable_sha256") != AG_EXECUTABLE_SHA256
    ):
        raise Refusal("input receipt does not bind the accepted AG owner package")
    binary = (
        path
        / "runtime"
        / "ag-package"
        / "usr"
        / "libexec"
        / "agent-governor-ng"
        / "ag-effectd"
    )
    binary_metadata = regular_file(binary, "retained AG audit executable")
    if (
        stat.S_IMODE(binary_metadata.st_mode) != 0o755
        or digest_file(binary, "sha256") != AG_EXECUTABLE_SHA256
    ):
        raise Refusal("retained AG audit executable differs from the accepted package")

    cut = path / "evidence" / "ag-attempt-store-cut.sqlite"
    cut_metadata = regular_file(cut, "copied AG attempt-store cut")
    if cut_metadata.st_size <= 0 or cut_metadata.st_size > AG_AUDIT_STORE_MAX_BYTES:
        raise Refusal("copied AG attempt-store cut exceeds the owner audit bound")
    if pathlib.Path(str(cut) + "-wal").exists():
        raise Refusal("copied AG attempt-store cut has adjacent WAL state")
    cut_sha256 = digest_file(cut, "sha256")
    audit_outcome_path = path / "evidence" / "ag-store-audit-outcome-v1.json"
    audit_outcome = load_json_artifact(audit_outcome_path, "AG store-audit outcome")
    if audit_outcome != expected_outcome:
        raise Refusal("retained AG store-audit outcome differs from the original outcome")
    audit_outcome_bytes = audit_outcome_path.read_bytes()
    if audit_outcome_bytes != canonical(audit_outcome) + b"\n":
        raise Refusal("retained AG store-audit outcome lacks exact owner framing")

    store_record_path = path / "evidence" / "ag-store-cut.json"
    store_record = load_json_artifact(store_record_path, "AG store-cut record")
    expected_record = {
        "schema": "constellation.operator_beta.m1b_ag_store_cut.v1",
        "run_id": run_id,
        "owner": "AG-ng",
        "owner_package_result": AG_STORE_AUDIT_RESULT,
        "ag_package_sha256": AG_DEB_SHA256,
        "ag_executable_sha256": AG_EXECUTABLE_SHA256,
        "source_store": "/var/lib/ag-effectd-m1b/attempts.sqlite",
        "wal": "ABSENT_OR_ZERO_LENGTH",
        "store_bytes": cut_metadata.st_size,
        "store_sha256": "sha256:" + cut_sha256,
        "plan_sha256": base_custody["plan_sha256"],
        "dispatch_sha256": base_custody["dispatch_sha256"],
        "attempt": base_custody["attempt"],
        "marker": base_custody["marker"],
        "work": base_custody["work"],
        "subject": base_custody["subject"],
        "scope": base_custody["scope"],
        "owner_outcome_sha256": digest_file(audit_outcome_path, "sha256"),
        "receipt": expected_outcome["receipt"],
    }
    if store_record != expected_record:
        raise Refusal("AG store-cut record disagrees with the exact effect occurrence")

    plan = path / "evidence" / "systemd-plan-v2.json"
    dispatch = path / "evidence" / "docket-shaped-dispatch-v1.json"
    completed = run(
        [
            str(binary),
            "audit-store",
            str(plan),
            "--store-cut",
            str(cut),
            "--store-bytes",
            str(cut_metadata.st_size),
            "--store-sha256",
            "sha256:" + cut_sha256,
        ],
        stdin=dispatch.read_bytes(),
    )
    if completed.stderr or completed.stdout != audit_outcome_bytes:
        raise Refusal("AG owner reopener disagrees with retained store-audit custody")
    return {
        "ag_store_cut_bytes": cut_metadata.st_size,
        "ag_store_cut_sha256": cut_sha256,
        "ag_store_cut_record_sha256": digest_file(store_record_path, "sha256"),
        "ag_store_audit_outcome_sha256": digest_file(
            audit_outcome_path, "sha256"
        ),
        "ag_store_audit_result": AG_STORE_AUDIT_RESULT,
        "ag_executable_sha256": AG_EXECUTABLE_SHA256,
    }


def verify_diagnostic_artifact(
    artifact: dict[str, Any],
    *,
    profile: str,
    condition: str,
    instance: str,
    bindings: dict[str, Any],
) -> None:
    family = "systemd" if profile == "nq.systemd_unit" else "http"
    policy = bindings[f"{family}_policy"]
    expected_policy = {
        "id": f"{profile}.postcondition.threshold_policy",
        "version": bindings["run_id"],
        "digest": sha256_bytes(canonical(policy)),
    }
    if artifact.get("schema") != "nq.diagnostic_execution.v2":
        raise Refusal(f"{instance} has the wrong artifact schema")
    if artifact.get("profile") != {
        "id": profile,
        "version": "1",
        "digest": PROFILE_DIGESTS[profile],
    }:
        raise Refusal(f"{instance} has the wrong profile identity")
    if artifact.get("question") != {
        "id": f"{profile}.postcondition",
        "version": "1",
        "digest": QUESTION_DIGESTS[profile],
    }:
        raise Refusal(f"{instance} has the wrong question identity")
    if artifact.get("threshold_policy") != expected_policy:
        raise Refusal(f"{instance} has the wrong historical policy identity")
    if artifact.get("subject") != {
        "id": bindings["subject_identity"],
        "scope": policy["request_scope"],
    }:
        raise Refusal(f"{instance} has the wrong subject or scope")
    vantage = artifact.get("vantage", {})
    if (
        not isinstance(vantage, dict)
        or not vantage.get("id", "").endswith(f".{instance}")
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", vantage.get("digest", ""))
    ):
        raise Refusal(f"{instance} has the wrong vantage identity")
    preimage = dict(artifact)
    observed_id = preimage.pop("artifact_id", None)
    if observed_id != sha256_bytes(canonical(preimage)):
        raise Refusal(f"{instance} has an invalid artifact self-identity")
    try:
        started = dt.datetime.fromisoformat(artifact["started_at"].replace("Z", "+00:00"))
        completed = dt.datetime.fromisoformat(artifact["completed_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise Refusal(f"{instance} has invalid decision-cut times") from error
    if completed < started or (completed - started).total_seconds() > 60:
        raise Refusal(f"{instance} exceeded the admitted freshness interval")
    if artifact.get("outcome", {}).get("condition") != condition:
        raise Refusal(f"{instance} has the wrong warranted condition")


def expected_m1b_bindings(
    run_id: str, identities: dict[str, Any]
) -> dict[str, Any]:
    renderer = Producer.__new__(Producer)
    renderer.run_id = run_id
    service_subject, subject = renderer.service_subject(identities)
    systemd_scope = {
        "kind": "systemd_unit",
        "value": {
            "schema": "nq.operator_beta.systemd_unit_scope.v1",
            "subject_identity": subject,
            "target_machine_identity": identities["target_machine_identity"],
            "unit_name": UNIT,
            "unit_file_sha256": identities["unit_file_sha256"],
            "manager_interface": "org.freedesktop.systemd1",
            "properties": [
                "LoadState",
                "ActiveState",
                "SubState",
                "UnitFileState",
            ],
        },
    }
    http_scope = {
        "kind": "http_endpoint",
        "value": {
            "schema": "nq.operator_beta.http_endpoint_scope.v1",
            "subject_identity": subject,
            "controller_vantage_identity": "machine:"
            + identities["controller_machine_identity"],
            "endpoint": f"http://{FIXTURE_ADDRESS}:{FIXTURE_PORT}/healthz",
            "method": "GET",
            "redirect_policy": "refuse",
            "max_response_bytes": 1024,
        },
    }
    systemd_policy = {
        "schema": "nq.operator_beta.systemd_unit_threshold_policy.v1",
        "fixture_run_id": run_id,
        "service_subject": service_subject,
        "subject_identity": subject,
        "request_scope": renderer.scope_identity(
            subject, systemd_scope, "nq.systemd_unit"
        ),
        "expected_load_state": "loaded",
        "expected_active_state": "active",
        "expected_sub_state": "running",
        "expected_unit_file_state": "disabled",
    }
    http_policy = {
        "schema": "nq.operator_beta.http_endpoint_threshold_policy.v1",
        "fixture_run_id": run_id,
        "service_subject": service_subject,
        "subject_identity": subject,
        "request_scope": renderer.scope_identity(
            subject, http_scope, "nq.http_endpoint"
        ),
        "expected_status": 200,
        "expected_body_sha256": sha256_bytes(FIXTURE_HEALTH_BYTES),
    }
    return {
        "schema": "constellation.operator_beta.m1b_bindings.v1",
        "run_id": run_id,
        "service_subject": service_subject,
        "subject_identity": subject,
        "service_subject_plain_sha256": sha256_bytes(canonical(service_subject)),
        "systemd_scope": systemd_scope,
        "systemd_policy": systemd_policy,
        "http_scope": http_scope,
        "http_policy": http_policy,
    }


def expected_nq_config(bindings: dict[str, Any], role: str) -> bytes:
    renderer = Producer.__new__(Producer)
    renderer.run_id = bindings["run_id"]
    prefix = (
        'schema = "nq.config.v1"\n'
        'database_path = "/var/lib/nq/operator-beta.sqlite"\n'
        'socket_path = "/run/nq/operator-beta.sock"\n'
        'admissions_dir = "/var/lib/nq/operator-beta-admissions"\n'
        'helper_runtime_dir = "/run/nq/operator-beta-helpers"\n'
    )
    config = prefix
    if role == "target":
        family = "systemd"
        profile = "nq.systemd_unit"
        capability = "read_systemd_unit"
        vantage = {"kind": "target_local", "value": {}}
    elif role == "control":
        family = "http"
        profile = "nq.http_endpoint"
        capability = "read_http_endpoint"
        vantage = {
            "kind": "controller_http",
            "value": {
                "controller_vantage_identity": bindings["http_scope"]["value"][
                    "controller_vantage_identity"
                ]
            },
        }
    else:
        raise Refusal("unknown NQ configuration role")
    for suffix in ("pre", "post", "restart"):
        config += renderer.watcher_block(
            f"{family}-{suffix}",
            profile,
            bindings["subject_identity"],
            bindings[f"{family}_scope"],
            vantage,
            capability,
            bindings[f"{family}_policy"],
        )
    return config.encode()


def verify_effect_attempt_inputs(
    path: pathlib.Path, run_id: str, harness_subject: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Reopen the exact retained occurrence before any owner query."""
    input_receipt = load_json_artifact(
        path / "evidence" / "input-receipt.json", "input receipt"
    )
    identities = load_json_artifact(
        path / "evidence" / "guest-identities.json", "guest identities"
    )
    service_subject = load_json_artifact(
        path / "evidence" / "service-subject.json", "service subject"
    )
    bindings = load_json_artifact(path / "evidence" / "bindings.json", "bindings")
    if any(record.get("run_id") != run_id for record in (input_receipt, identities, bindings)):
        raise Refusal("retained effect inputs name another run occurrence")
    if (
        input_receipt.get("schema") != "constellation.operator_beta.m1b_inputs.v1"
        or input_receipt.get("harness_subject") != harness_subject
        or input_receipt.get("accepted_package_result") != ACCEPTED_PACKAGE_RESULT
        or input_receipt.get("nq_package_sha256") != NQ_DEB_SHA256
        or input_receipt.get("ag_package_sha256") != AG_DEB_SHA256
        or input_receipt.get("ag_package_version") != AG_DEB_VERSION
        or input_receipt.get("ag_store_audit_result") != AG_STORE_AUDIT_RESULT
        or input_receipt.get("ag_executable_sha256") != AG_EXECUTABLE_SHA256
    ):
        raise Refusal("retained input receipt names another admitted execution")
    expected_bindings = expected_m1b_bindings(run_id, identities)
    if service_subject != expected_bindings["service_subject"] or bindings != expected_bindings:
        raise Refusal("retained effect bindings name another fixture occurrence")
    unit_path = path / "evidence" / UNIT
    health_path = path / "evidence" / "healthz"
    if (
        unit_path.read_bytes() != FIXTURE_UNIT_BYTES
        or health_path.read_bytes() != FIXTURE_HEALTH_BYTES
        or identities.get("unit_file_sha256")
        != "sha256:" + digest_file(unit_path, "sha256")
    ):
        raise Refusal("retained fixture bytes name another service subject")
    plan = load_json_artifact(path / "evidence" / "systemd-plan-v2.json", "AG plan")
    dispatch = load_json_artifact(
        path / "evidence" / "docket-shaped-dispatch-v1.json", "dispatch"
    )
    expected_plan = expected_effect_plan(bindings, identities)
    expected_dispatch, _ = expected_effect_dispatch(run_id, expected_plan)
    if plan != expected_plan or dispatch != expected_dispatch:
        raise Refusal("retained effect input binding disagrees with the exact original occurrence")
    return identities, bindings, plan, dispatch


def verify_terminal_evidence(path: pathlib.Path, result: dict[str, Any], inventory: set[str]) -> None:
    missing = sorted(REQUIRED_TERMINAL_PATHS - inventory)
    if missing:
        raise Refusal(f"terminal evidence inventory is incomplete: {missing[0]}")
    if (path / "evidence/controller-http-readiness.txt").read_bytes() != b"fixture_tcp_ready=true\n":
        raise Refusal("fixture readiness artifact differs from the bounded result")
    run_id = result.get("run_id")
    verify_effect_attempt_inputs(path, run_id, result.get("harness_subject"))
    input_receipt = load_json_artifact(path / "evidence" / "input-receipt.json", "input receipt")
    identities = load_json_artifact(path / "evidence" / "guest-identities.json", "guest identities")
    service_subject = load_json_artifact(path / "evidence" / "service-subject.json", "service subject")
    bindings = load_json_artifact(path / "evidence" / "bindings.json", "bindings")
    if any(record.get("run_id") != run_id for record in (input_receipt, identities, bindings)):
        raise Refusal("terminal evidence names another run occurrence")
    machine_pattern = r"[0-9a-f]{32}"
    if (
        set(identities)
        != {
            "schema",
            "run_id",
            "controller_machine_identity",
            "target_machine_identity",
            "unit_name",
            "unit_file_sha256",
            "controller_address",
            "target_address",
        }
        or identities.get("schema")
        != "constellation.operator_beta.m1b_guest_identity.v1"
        or not re.fullmatch(
            machine_pattern, identities.get("controller_machine_identity", "")
        )
        or not re.fullmatch(
            machine_pattern, identities.get("target_machine_identity", "")
        )
        or identities.get("controller_machine_identity")
        == identities.get("target_machine_identity")
        or identities.get("unit_name") != UNIT
        or identities.get("controller_address") != CONTROLLER_ADDRESS
        or identities.get("target_address") != FIXTURE_ADDRESS
    ):
        raise Refusal("guest identities do not describe the exact fixture pair")
    input_fields = {
        "schema",
        "run_id",
        "recorded_at",
        "harness_subject",
        "accepted_package_result",
        "image",
        "nq_package_sha256",
        "ag_package_sha256",
        "ag_package_version",
        "ag_store_audit_result",
        "ag_executable_sha256",
        "ports",
    }
    if set(input_receipt) != input_fields:
        raise Refusal("input receipt is not one closed owner record")
    if (
        input_receipt.get("schema") != "constellation.operator_beta.m1b_inputs.v1"
        or input_receipt.get("accepted_package_result") != ACCEPTED_PACKAGE_RESULT
        or input_receipt.get("harness_subject") != result.get("harness_subject")
    ):
        raise Refusal("input receipt names another harness subject")
    if (
        input_receipt.get("nq_package_sha256") != NQ_DEB_SHA256
        or input_receipt.get("ag_package_sha256") != AG_DEB_SHA256
        or input_receipt.get("ag_package_version") != AG_DEB_VERSION
        or input_receipt.get("ag_store_audit_result") != AG_STORE_AUDIT_RESULT
        or input_receipt.get("ag_executable_sha256") != AG_EXECUTABLE_SHA256
    ):
        raise Refusal("input receipt names different package bytes")
    retained_image = path / "input" / IMAGE_NAME
    retained_checksums = path / "input" / "SHA512SUMS"
    retained_nq = path / "input" / "nq-ng_amd64.deb"
    retained_ag = (
        path / "input" / "agent-governor-ng-systemd-executor_amd64.deb"
    )
    verify_checksum_manifest(retained_checksums, retained_image)
    image_record = input_receipt.get("image")
    if image_record != {
        "name": IMAGE_NAME,
        "sha512": IMAGE_SHA512,
        "checksum_manifest_sha256": digest_file(retained_checksums, "sha256"),
        "detached_signature": "UPSTREAM_DETACHED_SIGNATURE_NOT_PUBLISHED",
    }:
        raise Refusal("input receipt does not bind the retained image relation")
    if (
        digest_file(retained_nq, "sha256") != NQ_DEB_SHA256
        or digest_file(retained_ag, "sha256") != AG_DEB_SHA256
    ):
        raise Refusal("retained package bytes differ from the admitted inputs")
    ports = input_receipt.get("ports")
    if (
        not isinstance(ports, dict)
        or set(ports) != {"control_ssh", "target_ssh", "fixture_link_udp"}
        or any(
            not isinstance(value, int) or value < 1024 or value > 65535
            for value in ports.values()
        )
        or len(set(ports.values())) != 3
    ):
        raise Refusal("input receipt has invalid qualification ports")
    expected_bindings = expected_m1b_bindings(run_id, identities)
    if (
        service_subject != expected_bindings["service_subject"]
        or bindings != expected_bindings
    ):
        raise Refusal("bindings disagree with exact retained fixture semantics")
    subject_identity = ag_domain_digest(
        "constellation/operator-beta/service-subject/v1", canonical(service_subject)
    )
    if bindings.get("subject_identity") != subject_identity:
        raise Refusal("service-subject identity does not recompute")
    if (
        service_subject.get("fixture_run_id") != run_id
        or service_subject.get("target_machine_identity") != identities.get("target_machine_identity")
        or service_subject.get("unit_name") != UNIT
        or service_subject.get("unit_file_sha256") != identities.get("unit_file_sha256")
    ):
        raise Refusal("service subject does not bind the exact fixture occurrence")
    unit_path = path / "evidence" / UNIT
    health_path = path / "evidence" / "healthz"
    if (
        "sha256:" + digest_file(unit_path, "sha256")
        != identities.get("unit_file_sha256")
        or unit_path.read_bytes() != FIXTURE_UNIT_BYTES
        or health_path.read_bytes() != FIXTURE_HEALTH_BYTES
    ):
        raise Refusal("fixture bytes differ from the retained service identity")
    for family, profile in (("systemd", "nq.systemd_unit"), ("http", "nq.http_endpoint")):
        scope = bindings.get(f"{family}_scope")
        policy = bindings.get(f"{family}_policy")
        if not isinstance(scope, dict) or not isinstance(policy, dict):
            raise Refusal(f"{family} scope or policy is absent")
        expected_scope = {
            "id": f"nq.scope.{scope.get('kind')}",
            "version": "1",
            "digest": sha256_bytes(canonical({
                "schema": "nq.diagnostic_scope.v1",
                "subject": subject_identity,
                "scope": scope,
                "profile": {"id": profile, "version": "1", "digest": PROFILE_DIGESTS[profile]},
            })),
        }
        if policy.get("request_scope") != expected_scope or policy.get("subject_identity") != subject_identity:
            raise Refusal(f"{family} policy does not bind its exact subject and scope")
    if bindings.get("service_subject_plain_sha256") != sha256_bytes(
        canonical(service_subject)
    ):
        raise Refusal("bindings do not retain the plain service-subject digest")
    if (path / "evidence" / "target-nq.toml").read_bytes() != expected_nq_config(
        bindings, "target"
    ) or (path / "evidence" / "control-nq.toml").read_bytes() != expected_nq_config(
        bindings, "control"
    ):
        raise Refusal("retained NQ configuration differs from exact bound semantics")
    artifact_cases = (
        ("systemd-pre-artifact.json", "nq.systemd_unit", "present", "systemd-pre"),
        ("http-pre-artifact.json", "nq.http_endpoint", "unresolved", "http-pre"),
        ("systemd-post-artifact.json", "nq.systemd_unit", "explicitly_absent", "systemd-post"),
        ("http-post-artifact.json", "nq.http_endpoint", "explicitly_absent", "http-post"),
        ("systemd-restart-artifact.json", "nq.systemd_unit", "present", "systemd-restart"),
        ("http-restart-artifact.json", "nq.http_endpoint", "unresolved", "http-restart"),
    )
    observed_artifacts = {}
    for name, profile, condition, instance in artifact_cases:
        artifact = load_json_artifact(path / "evidence" / name, name)
        observed_artifacts[name] = artifact
        verify_diagnostic_artifact(
            artifact,
            profile=profile,
            condition=condition,
            instance=instance,
            bindings=bindings,
        )
    plan = load_json_artifact(path / "evidence" / "systemd-plan-v2.json", "AG plan")
    dispatch = load_json_artifact(path / "evidence" / "docket-shaped-dispatch-v1.json", "dispatch")
    outcome = load_json_artifact(path / "evidence" / "executor-outcome-v1.json", "AG outcome")
    occurrence = load_json_artifact(path / "evidence" / "effect-occurrence.json", "effect occurrence")
    expected_plan = expected_effect_plan(bindings, identities)
    expected_dispatch, work = expected_effect_dispatch(run_id, expected_plan)
    if (
        plan != expected_plan
        or dispatch != expected_dispatch
        or occurrence.get("run_id") != run_id
        or occurrence.get("owner") != "AG-ng M1A adapter"
        or occurrence.get("docket_database_occurrence") != "NOT_RECORDED"
        or occurrence.get("authorization_consumption") != "NOT_RECORDED"
        or occurrence.get("plan") != plan
        or occurrence.get("dispatch") != dispatch
        or occurrence.get("outcome") != outcome
    ):
        raise Refusal("AG plan, dispatch, outcome, or occurrence binding disagrees")
    outcome_class = verify_effect_outcome(outcome, expected_dispatch)
    if outcome_class != "success":
        raise Refusal("terminal golden evidence does not retain AG owner success")
    current = load_json_artifact(
        path / "evidence" / "current-support-after-restart.json", "current support"
    )
    if (
        current.get("historical_effect") != "AG_OWNER_RECEIPT_RETAINED"
        or current.get("systemd_artifact")
        != observed_artifacts["systemd-restart-artifact.json"].get("artifact_id")
        or current.get("http_artifact")
        != observed_artifacts["http-restart-artifact.json"].get("artifact_id")
        or current.get("systemd_current_condition") != "present"
        or current.get("http_current_condition") != "unresolved"
        or current.get("aggregate_postcondition") != "NOT_RECORDED"
    ):
        raise Refusal("current-support record collapses historical effect or restart evidence")
    recovery = load_recovery(path)
    expected_custody = {
        "plan_sha256": digest_file(path / "evidence" / "systemd-plan-v2.json", "sha256"),
        "dispatch_sha256": digest_file(
            path / "evidence" / "docket-shaped-dispatch-v1.json", "sha256"
        ),
        "outcome_sha256": digest_file(
            path / "evidence" / "executor-outcome-v1.json", "sha256"
        ),
        "attempt": expected_dispatch["attempt"],
        "marker": expected_dispatch["marker"],
        "work": work,
        "subject": expected_dispatch["subject"],
        "scope": expected_dispatch["scope"],
        "receipt": outcome["receipt"],
    }
    expected_custody.update(
        verify_ag_store_cut(path, run_id, expected_custody, outcome)
    )
    custody = recovery.get("effect_custody")
    if (
        recovery.get("run_id") != run_id
        or recovery.get("effect_outcome") != "KNOWN_EFFECT_OWNER_SUCCESS"
        or not isinstance(custody, dict)
        or any(custody.get(key) != value for key, value in expected_custody.items())
    ):
        raise Refusal("terminal recovery record disagrees with exact effect custody")
    for role in ("control", "target"):
        revocations = load_json_artifact(
            path / "evidence" / f"{role}-revocations.json", f"{role} revocations"
        )
        expected_instances = [f"{prefix}-{suffix}" for prefix in (("http",) if role == "control" else ("systemd",)) for suffix in ("pre", "post", "restart")]
        if (
            revocations.get("schema") != "constellation.operator_beta.m1b_revocations.v1"
            or revocations.get("run_id") != run_id
            or revocations.get("role") != role
            or revocations.get("disposition") != "REVOKED"
            or [item.get("instance_id") for item in revocations.get("instances", [])]
            != expected_instances
        ):
            raise Refusal(f"{role} watcher revocation evidence disagrees")
        continuity = (path / "evidence" / f"{role}-package-continuity.txt").read_text()
        if not re.search(r"store_sha256=[0-9a-f]{64}", continuity):
            raise Refusal(f"{role} package continuity evidence is incomplete")
        before = (path / "evidence" / f"{role}-boot-before.txt").read_bytes()
        after = (path / "evidence" / f"{role}-boot-after.txt").read_bytes()
        if not before.strip() or not after.strip() or before == after:
            raise Refusal(f"{role} restart identity did not change")
        backup = path / "evidence" / f"{role}-nq-backup.sqlite"
        try:
            connection = sqlite3.connect(f"file:{backup}?mode=ro&immutable=1", uri=True)
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            connection.close()
        except sqlite3.Error as error:
            raise Refusal(f"{role} NQ backup cannot reopen: {error}") from error
        if integrity != ("ok",):
            raise Refusal(f"{role} NQ backup fails integrity_check")
    final_host = load_json_artifact(
        path / "evidence" / "host-final-observation.json", "host teardown observation"
    )
    absent_fields = [value for key, value in final_host.items() if key.endswith("_absent")]
    if not absent_fields or not all(value is True for value in absent_fields):
        raise Refusal("host teardown observation does not establish bounded absence")


def check_run(path: pathlib.Path) -> None:
    if path.resolve(strict=True) != path or not path.is_dir() or path.is_symlink():
        raise Refusal("run path is not one exact physical directory")
    manifest_path = path / "ARTIFACTS.sha256"
    result_path = path / "RESULT.json"
    regular_file(manifest_path, "artifact manifest")
    regular_file(result_path, "result")
    manifest_raw = manifest_path.read_bytes()
    result_raw = result_path.read_bytes()
    manifest = json.loads(manifest_raw)
    result = json.loads(result_raw)
    if manifest_raw != canonical(manifest) + b"\n" or result_raw != canonical(result) + b"\n":
        raise Refusal("manifest or result is not canonical JSON")
    if set(manifest) != {"schema", "files"}:
        raise Refusal("artifact manifest root is not closed")
    if manifest.get("schema") != "constellation.operator_beta.m1b_artifact_manifest.v1":
        raise Refusal("unknown artifact manifest schema")
    entries = manifest.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > 4096:
        raise Refusal("artifact manifest inventory is missing or exceeds its bound")
    expected = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise Refusal("artifact manifest entry is not closed")
        relative = entry.get("path")
        if not isinstance(relative, str) or relative.startswith("/") or ".." in pathlib.PurePosixPath(relative).parts:
            raise Refusal("manifest has an unsafe relative path")
        if not isinstance(entry.get("bytes"), int) or entry["bytes"] < 0:
            raise Refusal("manifest has an invalid byte length")
        if not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise Refusal("manifest has an invalid SHA-256 value")
        artifact = path / relative
        regular_file(artifact, f"artifact {relative}")
        if artifact.stat().st_size != entry["bytes"] or digest_file(artifact, "sha256") != entry["sha256"]:
            raise Refusal(f"artifact differs from manifest: {relative}")
        if relative in expected:
            raise Refusal(f"duplicate artifact path: {relative}")
        expected.add(relative)
    actual = {
        item.relative_to(path).as_posix()
        for item in path.rglob("*")
        if item.is_file() and item.name not in {"ARTIFACTS.sha256", "RESULT.json"}
    }
    if actual != expected:
        raise Refusal("manifest does not cover the exact artifact inventory")
    result_fields = {
        "schema",
        "run_id",
        "disposition",
        "completed_at",
        "harness_subject",
        "accepted_package_result",
        "signed_upstream_checksum",
        "docket_database_occurrence",
        "authorization_consumption",
        "production",
        "manifest_sha256",
    }
    if not isinstance(result, dict) or set(result) != result_fields:
        raise Refusal("run result is not closed")
    if result.get("schema") != "constellation.operator_beta.m1b_run_result.v1":
        raise Refusal("run result has an unknown schema")
    if result.get("accepted_package_result") != ACCEPTED_PACKAGE_RESULT:
        raise Refusal("run result names a different accepted package checkpoint")
    if not re.fullmatch(r"[0-9a-f]{40}", result.get("harness_subject", "")):
        raise Refusal("run result has an invalid harness subject")
    if result.get("signed_upstream_checksum") != "NOT_QUALIFIED":
        raise Refusal("run result overstates signed upstream checksum custody")
    if result.get("docket_database_occurrence") != "NOT_RUN":
        raise Refusal("run result overstates Docket occurrence custody")
    if result.get("authorization_consumption") != "NOT_RUN":
        raise Refusal("run result overstates authorization consumption")
    if result.get("production") != "NOT_RUN":
        raise Refusal("run result overstates production activity")
    if result.get("manifest_sha256") != digest_file(manifest_path, "sha256"):
        raise Refusal("result does not bind the exact artifact manifest")
    if result.get("disposition") != "MECHANISM_CASES_COMPLETED_WITH_DECLARED_LIMITATIONS":
        raise Refusal("run has no admitted terminal disposition")
    verify_terminal_evidence(path, result, expected)
    print(json.dumps({"result": "RUN_REOPENED", "run_id": result.get("run_id")}, sort_keys=True))

def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)
    execute = sub.add_parser("run")
    execute.add_argument("--image", type=pathlib.Path, required=True)
    execute.add_argument("--checksums", type=pathlib.Path, required=True)
    execute.add_argument("--nq-deb", type=pathlib.Path, required=True)
    execute.add_argument("--ag-deb", type=pathlib.Path, required=True)
    execute.add_argument("--output", type=pathlib.Path, required=True)
    execute.add_argument("--run-id", required=True)
    execute.add_argument("--harness-subject", required=True)
    execute.add_argument("--producer-unit", required=True)
    execute.add_argument("--controller-ssh-port", type=int, default=23141)
    execute.add_argument("--target-ssh-port", type=int, default=23142)
    execute.add_argument("--fixture-link-port", type=int, default=24567)
    execute.add_argument("--preflight-only", action="store_true")
    check = sub.add_parser("check-run")
    check.add_argument("path", type=pathlib.Path)
    inspect = sub.add_parser("inspect-run")
    inspect.add_argument("path", type=pathlib.Path)
    reconcile = sub.add_parser("reconcile-effect")
    reconcile.add_argument("path", type=pathlib.Path)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "check-run":
            check_run(args.path)
        elif args.command == "inspect-run":
            inspect_run(args.path)
        elif args.command == "reconcile-effect":
            reconcile_effect(args.path)
        else:
            Producer(args).execute()
    except Refusal as error:
        print(f"M1B qualification refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
