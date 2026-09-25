#!/usr/bin/env python3
"""Release-closure VM acceptance for the NQ-ng candidate package.

Single-purpose harness for ACCEPTANCE-SPEC.md (release-closure-20260925).
It boots two disposable Debian 12 guests from a verified read-only base image
(qcow2 overlays, cloud-init seed, user networking with restrict=on and one
SSH hostfwd on 127.0.0.1, qemu -sandbox), installs the candidate .deb in guest A
and the M3 predecessor in guest B, runs every case in the spec, and writes
ACCEPTANCE-RESULT.json plus a log per case. Every case ends as PASS, FAIL or
NOT_EXERCISED with the exact observed messages; nothing is relabelled.

Only the release artifacts, the build receipt and the campaign-owned guest
scripts enter a guest. No source tree, share or host PATH is exposed.
"""

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
import socket
import subprocess
import sys
import time
import traceback
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
GUEST_SCRIPTS = ("nq-run.sh", "fixtures.sh", "load.sh", "assert-clean.sh")
IMAGE_NAME = "debian-12-genericcloud-amd64-20260903-2590.qcow2"
DEFAULT_IMAGE_DIR = pathlib.Path(
    "/data/git/.campaign-artifacts/constellation-operator-beta-composed-m2-run-002/input"
)
DEFAULT_CAMPAIGN = pathlib.Path("/data/git/.campaign-artifacts/release-closure-20260925")
DEFAULT_PREDECESSOR = pathlib.Path(
    "/data/git/.campaign-artifacts/operator-beta-completion-20260908/m3-nq-package-001"
)
DEFAULT_STATE = pathlib.Path("/home/jbeck/.local/state/release-closure-20260925")
PACKAGE = "nq-ng_0.1.0_amd64.deb"
TARBALL = "nq-ng-0.1.0-linux-amd64.tar.gz"
RECEIPT = "bookworm-build-receipt.v1.json"
BUNDLE_FILES = (PACKAGE, TARBALL, f"{PACKAGE}.sha256", f"{TARBALL}.sha256", "SHA256SUMS")
GUEST_USER = "nqacceptor"
HELPER_DIR = "/usr/lib/nq/helpers"
RESOURCE_HELPER = f"{HELPER_DIR}/nq-host-resource-helper"
HOST_HELPER = f"{HELPER_DIR}/nq-host-helper"
EXECUTABLES = (
    "/usr/bin/nq",
    "/usr/bin/nqd",
    HOST_HELPER,
    RESOURCE_HELPER,
    f"{HELPER_DIR}/nq-operator-beta-helper",
    f"{HELPER_DIR}/nq-synthetic-cache-result-helper",
    f"{HELPER_DIR}/nq_conformance_helper.py",
)
COMPILED = EXECUTABLES[:6]
RESOURCE_PROFILES = {
    "nq.host_filesystem_capacity@1",
    "nq.host_filesystem_inodes@1",
    "nq.host_memory@1",
    "nq.systemd_unit@2",
}
FS_CEILING = ["read_machine_identity", "read_mount_table", "read_filesystem_statistics"]
NQ = "sudo -u nq /usr/bin/nq --config=/etc/nq/nq.toml"
NQ_RUN = "/home/nqacceptor/bin/nq-run.sh --config=/etc/nq/nq.toml"
FIX = "/home/nqacceptor/bin/fixtures.sh"
MANIFEST_CHECK = "cd /usr && sha256sum --quiet --check /usr/share/nq/MANIFEST.sha256"

# Every case the spec names, in execution order. Anything not reached is
# recorded NOT_EXERCISED with the reason.
CASES: list[tuple[str, str]] = [
    ("A-01", "install: sha256sum --check SHA256SUMS in the guest"),
    ("A-02", "install: dpkg -i offline, dependencies satisfied"),
    ("A-03", "install: nq and nq-helper accounts"),
    ("A-04", "install: tmpfiles paths and modes"),
    ("A-05", "install: unit installed, not enabled, not started"),
    ("A-06", "install: executables at allowlisted paths and modes"),
    ("A-07", "install: MANIFEST.sha256 verifies"),
    ("A-08", "install: --build-info on every compiled binary"),
    ("A-09", "environment: no source tree, no host share, no egress"),
    ("A-10", "outside-in: nq profiles list equals installed manifest.json"),
    ("A-11", "outside-in: failure-codes agree (nq, file, resource helper)"),
    ("A-12", "outside-in: nq protocol check"),
    ("A-13", "runtime: production config, nq init, nq config check"),
    ("A-14", "runtime: watcher admit per instance"),
    ("A-15", "runtime: load normal -> explicitly_absent"),
    ("A-16", "runtime: load induced -> present"),
    ("A-17", "runtime: filesystem capacity >= 91% -> present"),
    ("A-18", "runtime: filesystem capacity roomy -> explicitly_absent"),
    ("A-19", "runtime: filesystem inodes >= 91% -> present"),
    ("A-20", "runtime: filesystem inodes roomy -> explicitly_absent"),
    ("A-21", "runtime: memory PSI baseline"),
    ("A-22", "runtime: memory PSI after psi=1 reboot"),
    ("A-23", "runtime: systemd v2 active -> explicitly_absent"),
    ("A-24", "runtime: systemd v2 stopped -> present (inactive)"),
    ("A-25", "runtime: systemd v2 exits non-zero -> present (failed)"),
    ("A-26", "runtime: systemd v2 alias name -> cannot_evaluate unit_name_not_canonical"),
    ("A-27", "runtime: systemd v2 nonexistent -> present (not-found)"),
    ("A-28", "runtime: systemd v2 wrong machine id -> cannot_evaluate machine_identity_mismatch"),
    ("A-29", "runtime: typed owner failure detail on every cannot_evaluate"),
    ("A-30", "runtime: nqd.service start (ExecStartPre), status, stop, restart"),
    ("A-31", "runtime: nqd scheduled collections after start (journal)"),
    ("N-01", "negative: execution_account = nq refused"),
    ("N-02", "negative: helper missing refused; dpkg -i reinstall restores"),
    ("N-03", "negative: helper mode 0700 root refused"),
    ("N-04", "negative: helper bytes substituted -> execution and nqd refused"),
    ("N-05", "negative: modified failure-codes.json detected"),
    ("N-06", "negative: wrong subject refused by config check"),
    ("N-07", "negative: wrong profile/scope substitution refused"),
    ("N-08", "negative: stale support at the NQ level"),
    ("N-09", "replay: qualify/export byte-identical across nqd restart"),
    ("N-10", "restart: store persists, new executions work, old artifacts unchanged"),
    ("N-11", "packaging: corrupted .deb"),
    ("N-12", "packaging: missing artifact"),
    ("N-13", "packaging: truncated .deb"),
    ("N-14", "negative: /run/nq after nqd stop (RuntimeDirectory=nq) and the documented CLI wrapper"),
    ("B-01", "predecessor: install M3 package"),
    ("B-02", "predecessor: configure nq.host, init, admit, execute"),
    ("B-03", "predecessor: dpkg -i candidate over M3 (prerm/postinst)"),
    ("B-04", "predecessor: store schema, old config, re-admission, new executions"),
    ("B-05", "predecessor: roll back to M3 against the touched store"),
]


class Refusal(Exception):
    """A precondition or harness invariant that stops the run."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha512_file(path: pathlib.Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    command: list[str],
    *,
    check: bool = True,
    timeout: float | None = 600,
    stdin: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        command, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        raise Refusal(
            f"command failed ({completed.returncode}): {shlex.join(command)}\n"
            f"{completed.stderr.decode(errors='replace')[-2000:]}"
        )
    return completed


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def parse_json(data: bytes) -> Any:
    try:
        return json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def toml_value(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {toml_value(value[k])}" for k in value) + " }"
    raise TypeError(value)


def watcher_block(
    instance: str,
    profile: str,
    version: int,
    subject: str,
    ceiling: list[str],
    scope_kind: str,
    scope_value: dict[str, Any],
    executable: str,
    *,
    execution_account: str = "nq-helper",
    interval: int = 300,
) -> str:
    return f"""
[[watchers]]
instance_id = {toml_value(instance)}
carrier = "stdio"
subject = {toml_value(subject)}
capability_ceiling = {toml_value(ceiling)}
checkpoint_policy = "disabled"

[watchers.command]
executable = {toml_value(executable)}
args = []
env = {{}}
execution_account = {toml_value(execution_account)}
working_directory = {toml_value(HELPER_DIR)}

[watchers.profile]
id = {toml_value(profile)}
version = {version}

[watchers.scope]
kind = {toml_value(scope_kind)}
value = {toml_value(scope_value)}

[watchers.vantage]
kind = "local"
value = {{}}

[watchers.schedule]
interval_seconds = {interval}
jitter_seconds = 0
deadline_ms = 30000
retry_backoff_seconds = 30
max_retry_backoff_seconds = 300

[watchers.resources]
max_response_bytes = 1048576
max_stderr_bytes = 65536
max_observations = 1
max_address_space_bytes = 536870912
max_cpu_seconds = 60
max_processes = 32
max_open_files = 128
max_file_bytes = 67108864
"""


CONFIG_PREFIX = """schema = "nq.config.v1"
database_path = "/var/lib/nq/nq.db"
socket_path = "/run/nq/nqd.sock"
admissions_dir = "/var/lib/nq/admissions"
helper_runtime_dir = "/run/nq/helpers"
"""


def fs_scope(machine_id: str, uuid: str, mountpoint: str) -> dict[str, str]:
    return {
        "schema": "nq.host_filesystem_scope.v1",
        "machine_id": machine_id,
        "filesystem_uuid": uuid,
        "filesystem_type": "ext4",
        "mountpoint": mountpoint,
    }


def unit_scope(machine_id: str, unit: str) -> dict[str, str]:
    return {"schema": "nq.systemd_unit_scope.v2", "machine_id": machine_id, "unit_name": unit}


def classify(artifact: dict[str, Any] | None) -> dict[str, Any]:
    """Reduce one diagnostic artifact to the fields the spec asks for."""
    if not isinstance(artifact, dict):
        return {"condition": None, "note": "no JSON artifact"}
    outcome = artifact.get("outcome", {})
    result: dict[str, Any] = {
        "artifact_id": artifact.get("artifact_id"),
        "schema": artifact.get("schema"),
        "profile": artifact.get("profile"),
        "subject": (artifact.get("subject") or {}).get("id"),
        "condition": outcome.get("condition"),
        "derivation": outcome.get("derivation"),
        "summary": outcome.get("summary"),
        "refusals": [],
    }
    for entry in outcome.get("refusals", []) or []:
        refusal = ((entry.get("origin") or {}).get("payload") or {}).get("refusal") or {}
        details = refusal.get("details") or {}
        result["refusals"].append(
            {
                "code": refusal.get("code"),
                "boundary": refusal.get("boundary"),
                "message": refusal.get("message"),
                "reason": details.get("reason"),
                "failure_code": details.get("failure_code"),
                "failure_retriable": details.get("failure_retriable"),
                "details": details,
            }
        )
    return result


def effective(cls: dict[str, Any]) -> str:
    """present | explicitly_absent | cannot_evaluate | <other>."""
    if cls.get("condition") in ("present", "explicitly_absent"):
        return str(cls["condition"])
    if cls.get("derivation") == "refused" and any(
        r.get("code") == "cannot_evaluate" for r in cls.get("refusals", [])
    ):
        return "cannot_evaluate"
    return f"{cls.get('condition')}/{cls.get('derivation')}"


class Guest:
    def __init__(self, role: str, port: int, root: pathlib.Path, key: pathlib.Path) -> None:
        self.role = role
        self.port = port
        self.root = root
        self.key = key
        self.process: subprocess.Popen[bytes] | None = None
        self.command: list[str] = []

    @property
    def name(self) -> str:
        return f"nq-rc-{self.role}"

    def ssh_base(self, *, connect_timeout: int = 5) -> list[str]:
        return [
            "ssh",
            "-i", str(self.key),
            "-p", str(self.port),
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self.root / 'known_hosts'}",
            "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4",
            "-o", "LogLevel=ERROR",
            f"{GUEST_USER}@127.0.0.1",
        ]

    def scp_base(self) -> list[str]:
        return [
            "scp", "-q",
            "-i", str(self.key),
            "-P", str(self.port),
            "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"UserKnownHostsFile={self.root / 'known_hosts'}",
            "-o", "LogLevel=ERROR",
        ]


class Harness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.campaign: pathlib.Path = args.campaign_dir
        self.candidate = self.campaign / "candidate-001"
        self.out = self.campaign / "acceptance-001"
        self.state: pathlib.Path = args.state_dir
        self.started = utc_now()
        self.results: dict[str, dict[str, Any]] = {
            case_id: {"id": case_id, "title": title, "outcome": "NOT_EXERCISED",
                      "reason": "not reached"}
            for case_id, title in CASES
        }
        self.current: str | None = None
        self.guests: dict[str, Guest] = {}
        self.identities: dict[str, dict[str, Any]] = {}
        self.fixtures: dict[str, Any] = {}
        self.artifacts: dict[str, dict[str, Any]] = {}
        self.exports: dict[str, bytes] = {}
        self.cannot_evaluate: list[dict[str, Any]] = []
        self.host_log = None

    # ----------------------------------------------------------------- logging
    def log(self, message: str) -> None:
        line = f"[{utc_now()}] {message}"
        print(line, flush=True)
        if self.host_log is not None:
            self.host_log.write(line + "\n")
            self.host_log.flush()

    def case_log(self, case_id: str) -> pathlib.Path:
        return self.out / "cases" / f"{case_id}.log"

    def append_case(self, data: str) -> None:
        if self.current is None:
            return
        with self.case_log(self.current).open("a", encoding="utf-8") as handle:
            handle.write(data)

    def evidence(self, name: str, data: bytes) -> str:
        path = self.out / "evidence" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return f"evidence/{name}"

    def write_results(self) -> None:
        document = {
            "schema": "release_closure.acceptance_result.v1",
            "campaign": "release-closure-20260925",
            "started_at": self.started,
            "updated_at": utc_now(),
            "candidate": getattr(self, "candidate_identity", None),
            "predecessor": getattr(self, "predecessor_identity", None),
            "base_image": getattr(self, "image_identity", None),
            "guests": {
                role: {"name": guest.name, "ssh_port": guest.port,
                       "qemu_command": guest.command}
                for role, guest in self.guests.items()
            },
            "guest_identities": self.identities,
            "fixtures": self.fixtures,
            "summary": {
                outcome: sum(1 for r in self.results.values() if r["outcome"] == outcome)
                for outcome in ("PASS", "FAIL", "NOT_EXERCISED")
            },
            "cases": [self.results[case_id] for case_id, _ in CASES],
        }
        tmp = self.out / "ACCEPTANCE-RESULT.json.tmp"
        tmp.write_text(json.dumps(document, indent=2, sort_keys=False, default=str) + "\n", encoding="utf-8")
        os.replace(tmp, self.out / "ACCEPTANCE-RESULT.json")

    # ------------------------------------------------------------------ cases
    def begin(self, case_id: str) -> None:
        self.current = case_id
        title = dict(CASES)[case_id]
        self.log(f"== {case_id} {title}")
        self.append_case(f"# {case_id} {title}\n# started {utc_now()}\n")

    def record(self, outcome: str, **fields: Any) -> None:
        assert self.current is not None
        entry = self.results[self.current]
        entry.update({"outcome": outcome, "recorded_at": utc_now(),
                      "log": f"cases/{self.current}.log"})
        entry.pop("reason", None)
        entry.update(fields)
        self.append_case(f"# outcome {outcome} {json.dumps(fields, default=str)}\n")
        self.log(f"   -> {outcome}")
        self.write_results()
        self.current = None

    def run_case(self, case_id: str, function, *args: Any, **kwargs: Any) -> None:
        self.begin(case_id)
        try:
            function(*args, **kwargs)
        except Refusal as error:
            self.record("FAIL", error=str(error), note="harness refusal during the case")
        except Exception as error:  # noqa: BLE001 - record, never hide
            self.append_case(traceback.format_exc())
            self.record("FAIL", error=f"{type(error).__name__}: {error}",
                        note="unexpected exception during the case")
        if self.current is not None:
            self.record("FAIL", error="case ended without recording an outcome")

    def skip(self, case_id: str, reason: str) -> None:
        self.results[case_id].update({"outcome": "NOT_EXERCISED", "reason": reason,
                                      "recorded_at": utc_now()})
        self.write_results()

    # ---------------------------------------------------------------- guest io
    def ssh(
        self,
        guest: Guest,
        command: str,
        *,
        check: bool = False,
        timeout: float = 600,
        label: str | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        started = time.monotonic()
        try:
            completed = run(guest.ssh_base() + [command], check=False, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            completed = subprocess.CompletedProcess(
                error.cmd, 124, error.stdout or b"", (error.stderr or b"") + b"\n[timeout]"
            )
        elapsed = time.monotonic() - started
        self.append_case(
            f"\n$ [{guest.role}] {command}\n"
            + (f"# {label}\n" if label else "")
            + f"# exit {completed.returncode} in {elapsed:.1f}s\n"
            + (f"--- stdout\n{text(completed.stdout)}\n" if completed.stdout else "")
            + (f"--- stderr\n{text(completed.stderr)}\n" if completed.stderr else "")
        )
        if check and completed.returncode != 0:
            raise Refusal(
                f"[{guest.role}] exit {completed.returncode}: {command}\n"
                f"{text(completed.stderr)[-1500:]}{text(completed.stdout)[-1500:]}"
            )
        return completed

    def scp_to(self, guest: Guest, sources: list[pathlib.Path], destination: str) -> None:
        run(guest.scp_base() + [str(s) for s in sources] + [f"{GUEST_USER}@127.0.0.1:{destination}"])

    def scp_from(self, guest: Guest, source: str, destination: pathlib.Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(guest.scp_base() + [f"{GUEST_USER}@127.0.0.1:{source}", str(destination)], check=False)

    # -------------------------------------------------------------- preflight
    def preflight(self) -> None:
        for tool in ("qemu-img", "qemu-system-x86_64", "xorriso", "ssh", "ssh-keygen", "scp",
                     "sha256sum", "dpkg-deb"):
            if shutil.which(tool) is None:
                raise Refusal(f"required tool is absent: {tool}")
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise Refusal("/dev/kvm is not accessible")
        for port in (self.args.ssh_port_a, self.args.ssh_port_b):
            if not port_free(port):
                raise Refusal(f"127.0.0.1:{port} is not free")
        if self.state.exists() and any(self.state.iterdir()):
            raise Refusal(f"state directory is not empty: {self.state}")
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        if (self.out / "ACCEPTANCE-RESULT.json").exists():
            raise Refusal(f"output already exists: {self.out}")
        for sub in ("cases", "evidence", "qemu", "guest-logs"):
            (self.out / sub).mkdir(parents=True, exist_ok=True)
        self.host_log = (self.out / "host.log").open("a", encoding="utf-8")

        # Candidate: built by the pinned builder, exit 0, exact files.
        exit_file = self.campaign / "build.exit"
        if not exit_file.exists() or exit_file.read_text().strip() != "0":
            raise Refusal("build.exit is missing or non-zero; not accepting a candidate")
        for name in (*BUNDLE_FILES, RECEIPT):
            if not (self.candidate / name).is_file():
                raise Refusal(f"candidate file missing: {name}")
        checked = subprocess.run(
            ["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=self.candidate,
            capture_output=True, text=True, check=False,
        )
        if checked.returncode != 0:
            raise Refusal(f"candidate SHA256SUMS do not verify on the host: {checked.stdout}")
        receipt = json.loads((self.candidate / RECEIPT).read_text())
        self.candidate_identity = {
            "directory": str(self.candidate),
            "deb_sha256": sha256_file(self.candidate / PACKAGE),
            "tarball_sha256": sha256_file(self.candidate / TARBALL),
            "receipt_sha256": sha256_file(self.candidate / RECEIPT),
            "receipt_source": receipt.get("source"),
        }
        # Predecessor: verified against its own SHA256SUMS.
        pre = self.args.predecessor_dir
        sums = {}
        for line in (pre / "SHA256SUMS").read_text().splitlines():
            digest, _, name = line.strip().partition("  ")
            sums[name] = digest
        pre_digest = sha256_file(pre / PACKAGE)
        if sums.get(PACKAGE) != pre_digest:
            raise Refusal("predecessor .deb does not match its SHA256SUMS")
        self.predecessor_identity = {"directory": str(pre), "deb_sha256": pre_digest}
        # Base image: verified against the adjacent SHA512SUMS, used read-only.
        image = self.args.image
        expected = None
        for line in (image.parent / "SHA512SUMS").read_text().splitlines():
            digest, _, name = line.strip().partition("  ")
            if name == image.name:
                expected = digest
        if expected is None:
            raise Refusal("base image is not listed in SHA512SUMS")
        actual = sha512_file(image)
        if actual != expected:
            raise Refusal("base image SHA-512 differs from SHA512SUMS")
        if os.access(image, os.W_OK):
            raise Refusal("base image must not be writable")
        self.image_identity = {"path": str(image), "sha512": actual}
        self.log("preflight complete")
        self.write_results()

    # ------------------------------------------------------------------ guests
    def prepare_guest(self, role: str, port: int, key: pathlib.Path) -> Guest:
        root = self.state / role
        root.mkdir(mode=0o700)
        guest = Guest(role, port, root, key)
        public_key = key.with_suffix(".pub").read_text().strip()
        meta = f"instance-id: release-closure-{role}\nlocal-hostname: {guest.name}\n"
        user = f"""#cloud-config
disable_root: true
hostname: {guest.name}
package_update: false
package_upgrade: false
preserve_hostname: false
ssh_pwauth: false
users:
  - name: {GUEST_USER}
    groups: [sudo]
    lock_passwd: true
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    ssh_authorized_keys:
      - "{public_key}"
"""
        (root / "meta-data").write_text(meta)
        (root / "user-data").write_text(user)
        run([
            "xorriso", "-as", "mkisofs", "-quiet", "-output", str(root / "seed.iso"),
            "-volid", "cidata", "-joliet", "-rock",
            str(root / "user-data"), str(root / "meta-data"),
        ])
        run([
            "qemu-img", "create", "-q", "-f", "qcow2", "-b", str(self.args.image), "-F", "qcow2",
            str(root / "overlay.qcow2"),
        ])
        self.guests[role] = guest
        return guest

    def start_guest(self, guest: Guest) -> None:
        root = guest.root
        guest.command = [
            "qemu-system-x86_64",
            "-name", f"{guest.name},process={guest.name}",
            "-no-user-config", "-nodefaults",
            "-accel", "kvm",
            "-machine", "q35",
            "-cpu", "host",
            "-smp", "2",
            "-m", "2048",
            "-display", "none",
            "-monitor", "none",
            "-serial", f"file:{root / 'serial.log'}",
            "-pidfile", str(root / "qemu.pid"),
            "-drive", f"if=virtio,file={root / 'overlay.qcow2'},format=qcow2,cache=none,aio=threads",
            "-drive", f"if=virtio,file={root / 'seed.iso'},format=raw,readonly=on",
            "-netdev", f"user,id=mgmt,restrict=on,hostfwd=tcp:127.0.0.1:{guest.port}-:22",
            "-device", f"virtio-net-pci,netdev=mgmt,mac=52:54:00:9c:00:{1 if guest.role == 'a' else 2:02x}",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ]
        (self.out / "qemu" / f"{guest.role}-command.txt").write_text(
            shlex.join(guest.command) + "\n"
        )
        guest.process = subprocess.Popen(
            guest.command,
            stdout=(root / "qemu.stdout.log").open("wb"),
            stderr=(root / "qemu.stderr.log").open("wb"),
            start_new_session=True,
        )
        self.log(f"started {guest.name} pid {guest.process.pid} ssh 127.0.0.1:{guest.port}")

    def wait_ssh(self, guest: Guest, limit: int = 900) -> None:
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            if guest.process is not None and guest.process.poll() is not None:
                raise Refusal(f"{guest.name} exited: {(guest.root / 'qemu.stderr.log').read_text()[-1000:]}")
            try:
                result = run(guest.ssh_base() + ["true"], check=False, timeout=30)
            except subprocess.TimeoutExpired:
                continue
            if result.returncode == 0:
                return
            time.sleep(3)
        raise Refusal(f"{guest.name} SSH not reachable within {limit}s")

    def boot(self, guest: Guest) -> None:
        self.start_guest(guest)
        self.wait_ssh(guest)
        self.ssh(guest, "cloud-init status --wait >/dev/null; cloud-init status", timeout=900)
        result = self.ssh(guest, '. /etc/os-release; printf "%s:%s" "$ID" "$VERSION_ID"', check=True)
        if result.stdout != b"debian:12":
            raise Refusal(f"{guest.name} is not Debian 12: {result.stdout!r}")
        self.ssh(guest, "mkdir -p /home/nqacceptor/bin /home/nqacceptor/candidate", check=True)
        self.scp_to(guest, [HERE / "guest" / name for name in GUEST_SCRIPTS], "/home/nqacceptor/bin/")
        self.scp_to(
            guest,
            [self.candidate / name for name in (*BUNDLE_FILES, RECEIPT)],
            "/home/nqacceptor/candidate/",
        )
        self.ssh(guest, "chmod 0755 /home/nqacceptor/bin/*.sh", check=True)
        ident = self.ssh(guest, f"{FIX} identities", check=True)
        self.identities[guest.role] = json.loads(ident.stdout)
        self.log(f"{guest.name} ready: {self.identities[guest.role]['machine_id']}")

    def reboot(self, guest: Guest) -> None:
        before = self.ssh(guest, "cat /proc/sys/kernel/random/boot_id", check=True).stdout
        self.ssh(guest, "sudo systemctl reboot", check=False, timeout=30)
        time.sleep(10)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                result = run(guest.ssh_base() + ["cat /proc/sys/kernel/random/boot_id"], check=False,
                             timeout=30)
            except subprocess.TimeoutExpired:
                continue
            if result.returncode == 0 and result.stdout != before:
                return
            time.sleep(3)
        raise Refusal(f"{guest.name} did not come back after reboot")

    # -------------------------------------------------------------- nq helpers
    def nq_json(self, guest: Guest, arguments: str, *, privileged: bool = False,
                config: str = "/etc/nq/nq.toml", timeout: float = 300):
        base = (
            f"/home/nqacceptor/bin/nq-run.sh --config={config}" if privileged
            else f"sudo -u nq /usr/bin/nq --config={config}"
        )
        result = self.ssh(guest, f"{base} {arguments}", timeout=timeout)
        return result, parse_json(result.stdout)

    def execute(self, guest: Guest, instance: str, tag: str) -> tuple[dict[str, Any], dict[str, Any] | None, subprocess.CompletedProcess[bytes]]:
        result, artifact = self.nq_json(guest, f"diagnostics execute {instance}", privileged=True)
        name = f"{guest.role}-{instance}-{tag}.json"
        ref = self.evidence(name, result.stdout + (b"\n--- stderr\n" + result.stderr if result.stderr else b""))
        cls = classify(artifact)
        cls["evidence"] = ref
        cls["exit"] = result.returncode
        if artifact is None:
            cls["stderr"] = text(result.stderr)[-2000:]
            cls["stdout"] = text(result.stdout)[-2000:]
        if isinstance(artifact, dict) and artifact.get("artifact_id"):
            self.artifacts[f"{guest.role}:{instance}:{tag}"] = artifact
        if effective(cls) == "cannot_evaluate":
            for refusal in cls["refusals"]:
                self.cannot_evaluate.append({"instance": instance, "tag": tag, **refusal})
        return cls, artifact, result

    def admit(self, guest: Guest, instance: str) -> dict[str, Any]:
        r, doc = self.nq_json(guest, f"watcher admit {instance}", privileged=True)
        activated = isinstance(doc, dict) and doc.get("outcome") == "activated"
        return {"instance": instance, "exit": r.returncode, "activated": activated,
                "admission_id": doc.get("admission_id") if isinstance(doc, dict) else None,
                "output": None if activated else text(r.stdout + r.stderr)[-2000:]}

    def acquire(self, guest: Guest, instance: str, acquisition_id: str, tag: str) -> dict[str, Any]:
        """Documented second observation of the same admitted watcher (LOCAL_SUCCESSOR.md)."""
        result, artifact = self.nq_json(
            guest, f"diagnostics acquire-next-local {instance} --acquisition-id {acquisition_id}", privileged=True)
        ref = self.evidence(f"{guest.role}-{instance}-{tag}-acquire.json",
                            result.stdout + (b"\n--- stderr\n" + result.stderr if result.stderr else b""))
        cls = classify(artifact)
        cls.update({"evidence": ref, "exit": result.returncode, "acquisition_id": acquisition_id})
        if artifact is None:
            cls["stderr"] = text(result.stderr)[-2000:]
        else:
            replay = self.ssh(guest, f"{NQ_RUN} diagnostics replay-local-successor {instance} --acquisition-id {acquisition_id}")
            cls["replay_byte_identical"] = replay.returncode == 0 and replay.stdout == result.stdout
        cls["effective"] = effective(cls)
        return cls

    def wait_boot_age(self, guest: Guest, seconds: int) -> str:
        return text(self.ssh(guest, f"while [ $(cut -d. -f1 /proc/uptime) -lt {seconds} ]; do sleep 5; done; cat /proc/uptime", timeout=seconds + 60).stdout).strip()

    def expect_condition(self, guest: Guest, instance: str, tag: str, expected: str,
                         failure_code: str | None = None, prepare: str | None = None,
                         admit_first: bool = False, **extra: Any) -> None:
        if prepare is not None:
            extra["prepare"] = text(self.ssh(guest, prepare, check=True).stdout)
        if admit_first:
            extra["admission"] = self.admit(guest, instance)
        cls, _, _ = self.execute(guest, instance, tag)
        observed = effective(cls)
        ok = observed == expected
        if ok and failure_code is not None:
            ok = any(r.get("failure_code") == failure_code for r in cls["refusals"])
        self.record(
            "PASS" if ok else "FAIL",
            expected=expected + (f" {failure_code}" if failure_code else ""),
            observed=observed,
            artifact=cls,
            **extra,
        )

    def install_config(self, guest: Guest, body: str, path: str = "/etc/nq/nq.toml") -> str:
        name = f"{guest.role}-{pathlib.Path(path).name}"
        local = self.out / "evidence" / name
        local.write_text(body)
        self.scp_to(guest, [local], "/home/nqacceptor/staging.toml")
        self.ssh(guest, f"sudo install -o root -g nq -m 0640 /home/nqacceptor/staging.toml {path}",
                 check=True)
        return f"evidence/{name}"

    # ------------------------------------------------------------ guest A cases
    def candidate_config(self, guest: Guest, *, execution_account: str = "nq-helper") -> str:
        ident = self.identities[guest.role]
        mid = ident["machine_id"]
        fx = self.fixtures["filesystems"]
        body = CONFIG_PREFIX
        body += watcher_block(
            "host-local", "nq.host", 1, f"host:{ident['hostname']}",
            ["read_procfs", "read_system_info"], "host", {"id": ident["hostname"]},
            HOST_HELPER, execution_account=execution_account,
        )
        for instance, profile, fs in (
            ("fs-full-capacity", "nq.host_filesystem_capacity", "full"),
            ("fs-roomy-capacity", "nq.host_filesystem_capacity", "roomy"),
            ("fs-inodes-full", "nq.host_filesystem_inodes", "inodes"),
            ("fs-inodes-roomy", "nq.host_filesystem_inodes", "roomy"),
        ):
            body += watcher_block(
                instance, profile, 1, f"host-filesystem:{mid}/{fx[fs]['uuid']}", FS_CEILING,
                "host_filesystem", fs_scope(mid, fx[fs]["uuid"], fx[fs]["mountpoint"]),
                RESOURCE_HELPER, execution_account=execution_account,
            )
        body += watcher_block(
            "host-local-load", "nq.host", 1, f"host:{ident['hostname']}",
            ["read_procfs", "read_system_info"], "host", {"id": ident["hostname"]},
            HOST_HELPER, execution_account=execution_account,
        )
        for spare in ("fs-roomy-n02", "fs-roomy-n02b", "fs-roomy-n02c", "fs-roomy-n03", "fs-roomy-n03b",
                      "fs-roomy-n03c", "fs-roomy-n04", "fs-roomy-n04b", "fs-roomy-n10"):
            body += watcher_block(
                spare, "nq.host_filesystem_capacity", 1, f"host-filesystem:{mid}/{fx['roomy']['uuid']}",
                FS_CEILING, "host_filesystem", fs_scope(mid, fx["roomy"]["uuid"], fx["roomy"]["mountpoint"]),
                RESOURCE_HELPER, execution_account=execution_account,
            )
        body += watcher_block(
            "mem-local", "nq.host_memory", 1, f"host:{mid}",
            ["read_machine_identity", "read_procfs"], "host_memory",
            {"schema": "nq.host_memory_scope.v1", "machine_id": mid},
            RESOURCE_HELPER, execution_account=execution_account,
        )
        absent = self.fixtures["absent_unit"]
        for instance, unit_mid, unit in (
            ("unit-fixture", mid, "nq-fixture.service"),
            ("unit-fixture-stopped", mid, "nq-fixture.service"),
            ("unit-fail", mid, "nq-fixture-fail.service"),
            ("unit-alias", mid, "nq-fixture-alias.service"),
            ("unit-absent", mid, absent),
            ("unit-machine", "f" * 32, "nq-fixture.service"),
        ):
            body += watcher_block(
                instance, "nq.systemd_unit", 2, f"systemd-unit:{unit_mid}/{unit}",
                ["read_systemd_unit"], "systemd_unit", unit_scope(unit_mid, unit),
                RESOURCE_HELPER, execution_account=execution_account,
            )
        return body

    def case_a01(self, g: Guest) -> None:
        r = self.ssh(g, "cd /home/nqacceptor/candidate && sha256sum --check --strict SHA256SUMS && sha256sum *")
        self.record("PASS" if r.returncode == 0 else "FAIL", exit=r.returncode,
                    output=text(r.stdout), stderr=text(r.stderr))

    def case_a02(self, g: Guest) -> None:
        r = self.ssh(g, f"sudo dpkg -i /home/nqacceptor/candidate/{PACKAGE}", timeout=300)
        status = self.ssh(g, "dpkg -s nq-ng | grep -E '^(Status|Version|Depends):'; dpkg --audit; echo audit-exit=$?")
        ok = r.returncode == 0 and b"Status: install ok installed" in status.stdout
        self.record("PASS" if ok else "FAIL", dpkg_exit=r.returncode, dpkg_output=text(r.stdout + r.stderr),
                    status=text(status.stdout))

    def case_a03(self, g: Guest) -> None:
        r = self.ssh(g, "getent passwd nq nq-helper; getent group nq nq-helper", check=True)
        lines = text(r.stdout).splitlines()
        nq = next((l for l in lines if l.startswith("nq:")), "")
        helper = next((l for l in lines if l.startswith("nq-helper:")), "")
        ok = (
            nq.endswith(":/var/lib/nq:/usr/sbin/nologin")
            and helper.endswith(":/nonexistent:/usr/sbin/nologin")
            and nq and helper
        )
        self.record("PASS" if ok else "FAIL", accounts=lines)

    def case_a04(self, g: Guest) -> None:
        r = self.ssh(g, "sudo stat -c '%n %a %U:%G' /etc/nq /var/lib/nq /var/lib/nq/admissions /var/lib/nq/backups /run/nq /run/nq/helpers", check=True)
        observed = text(r.stdout).splitlines()
        expected = {
            "/etc/nq 750 root:nq", "/var/lib/nq 700 nq:nq", "/var/lib/nq/admissions 700 nq:nq",
            "/var/lib/nq/backups 700 nq:nq", "/run/nq 751 nq:nq", "/run/nq/helpers 711 nq:nq",
        }
        self.record("PASS" if set(observed) == expected else "FAIL", observed=observed,
                    expected=sorted(expected))

    def case_a05(self, g: Guest) -> None:
        r = self.ssh(g, "systemctl is-enabled nqd.service; systemctl is-active nqd.service; systemctl show nqd.service -p UnitFileState,ActiveState,LoadState,FragmentPath")
        out = text(r.stdout)
        ok = "UnitFileState=disabled" in out and "ActiveState=inactive" in out and "LoadState=loaded" in out
        self.record("PASS" if ok else "FAIL", observed=out)

    def case_a06(self, g: Guest) -> None:
        r = self.ssh(g, "stat -c '%n %a %U:%G %F' " + " ".join(EXECUTABLES) + "; ls -la /usr/lib/nq/helpers /usr/bin/nq /usr/bin/nqd", check=False)
        lines = text(r.stdout).splitlines()
        ok = r.returncode == 0 and all(
            any(l == f"{path} 755 root:root regular file" for l in lines) for path in EXECUTABLES
        )
        self.record("PASS" if ok else "FAIL", observed=lines, count=len(EXECUTABLES))

    def case_a07(self, g: Guest) -> None:
        r = self.ssh(g, f"{MANIFEST_CHECK} && echo manifest-ok; grep -c . /usr/share/nq/MANIFEST.sha256")
        self.record("PASS" if r.returncode == 0 and b"manifest-ok" in r.stdout else "FAIL",
                    exit=r.returncode, output=text(r.stdout + r.stderr))

    def case_a08(self, g: Guest) -> None:
        results = {}
        ok = True
        for path in COMPILED:
            r = self.ssh(g, f"{path} --build-info")
            info = parse_json(r.stdout)
            results[path] = info if info is not None else text(r.stdout + r.stderr)
            good = (
                isinstance(info, dict) and info.get("version") == "0.1.0"
                and info.get("debug_assertions") is False
                and info.get("helper_isolation_policy") == "production_separate_identity_required"
                and info.get("component") == pathlib.Path(path).name
            )
            ok = ok and good
        py = self.ssh(g, f"{EXECUTABLES[6]} --build-info </dev/null")
        self.record("PASS" if ok else "FAIL", build_info=results,
                    python_helper={"exit": py.returncode, "output": text(py.stdout + py.stderr)[-500:],
                                   "note": "script, not a compiled binary; recorded for completeness"})

    def case_a09(self, g: Guest) -> None:
        r = self.ssh(g, "/home/nqacceptor/bin/assert-clean.sh", timeout=600)
        out = text(r.stdout)
        found = [l for l in out.splitlines() if l.startswith("found:")]
        egress = [l for l in out.splitlines() if l.startswith("egress: CONNECTED") or "dns: resolved" in l]
        self.record("PASS" if not found and not egress else "FAIL", findings=found, egress=egress,
                    report=self.evidence(f"{g.role}-assert-clean.txt", r.stdout + r.stderr))

    def case_a10(self, g: Guest) -> None:
        r, compiled = self.nq_json(g, "profiles list")
        manifest = parse_json(self.ssh(g, "cat /usr/share/nq/profiles/manifest.json", check=True).stdout)
        if not isinstance(compiled, list) or not isinstance(manifest, dict):
            self.record("FAIL", output=text(r.stdout + r.stderr)[-2000:])
            return
        compiled_set = {(e["id"], e["version"], e["digest"]) for e in compiled}
        manifest_set = {(e["id"], e["version"], e["semantic_digest"]) for e in manifest["profiles"]}
        ok = compiled_set == manifest_set and {("nq.systemd_unit", 1), ("nq.systemd_unit", 2)} <= {
            (i, v) for i, v, _ in compiled_set}
        self.record("PASS" if ok else "FAIL", compiled_count=len(compiled_set),
                    manifest_count=len(manifest_set),
                    only_in_compiled=sorted(compiled_set - manifest_set),
                    only_in_manifest=sorted(manifest_set - compiled_set),
                    identities=sorted((i, v) for i, v, _ in compiled_set))

    def failure_code_comparison(self, g: Guest) -> dict[str, Any]:
        _, compiled = self.nq_json(g, "profiles failure-codes")
        packaged = parse_json(self.ssh(g, "cat /usr/share/nq/profiles/failure-codes.json", check=True).stdout)
        helper = parse_json(self.ssh(g, f"{RESOURCE_HELPER} --failure-codes", check=False).stdout)
        norm = lambda entries: {f'{e["id"]}@{e["version"]}': list(e["codes"]) for e in entries}  # noqa: E731
        c = norm(compiled) if isinstance(compiled, list) else None
        p = norm(packaged["profiles"]) if isinstance(packaged, dict) else None
        h = norm(helper) if isinstance(helper, list) else None
        return {
            "compiled": c, "packaged": p, "helper": h,
            "packaged_equals_compiled": c == p,
            "helper_keys": sorted(h) if h else None,
            "helper_agrees": bool(c and h) and all(c.get(k) == v for k, v in h.items()),
            "helper_serves_exactly_resource_profiles": bool(h) and set(h) == RESOURCE_PROFILES,
            "code_count": sum(len(v) for v in (c or {}).values()),
        }

    def case_a11(self, g: Guest) -> None:
        cmp = self.failure_code_comparison(g)
        ok = cmp["packaged_equals_compiled"] and cmp["helper_agrees"] and cmp["helper_serves_exactly_resource_profiles"]
        self.record("PASS" if ok else "FAIL", **{k: v for k, v in cmp.items() if k not in ("compiled", "packaged", "helper")},
                    vocabularies=self.evidence(f"{g.role}-failure-codes.json", json.dumps(cmp, indent=1, default=list).encode()))

    def case_a12(self, g: Guest) -> None:
        r, receipt = self.nq_json(g, "--json protocol check")
        digests = self.ssh(g, "cd /usr/share/nq/protocol && sha256sum fixtures/manifest.json && find . -type f | wc -l")
        self.record("PASS" if r.returncode == 0 and receipt is not None else "FAIL", exit=r.returncode,
                    receipt=self.evidence(f"{g.role}-protocol-check.json", r.stdout + r.stderr),
                    installed_corpus=text(digests.stdout))

    def setup_fixtures(self, g: Guest) -> None:
        fs = self.ssh(g, f"{FIX} setup-fs", check=True, timeout=600)
        self.fixtures["filesystems"] = json.loads(fs.stdout)
        absent = f"nq-fixture-absent-{os.urandom(4).hex()}.service"
        self.fixtures["absent_unit"] = absent
        units = self.ssh(g, f"{FIX} setup-units; {FIX} report-units {absent}", check=True)
        self.fixtures["units_at_setup"] = text(units.stdout)
        self.write_results()

    def case_a13(self, g: Guest) -> None:
        body = self.candidate_config(g)
        ref = self.install_config(g, body)
        stat = self.ssh(g, "sudo stat -c '%n %a %U:%G' /etc/nq/nq.toml", check=True)
        init, init_json = self.nq_json(g, "--json init")
        check, _ = self.nq_json(g, "config check")
        ok = init.returncode == 0 and check.returncode == 0 and "root:nq" in text(stat.stdout) and " 640 " in text(stat.stdout)
        self.record("PASS" if ok else "FAIL", config=ref, config_stat=text(stat.stdout).strip(),
                    init=init_json or text(init.stdout + init.stderr), init_exit=init.returncode,
                    config_check_exit=check.returncode, config_check=text(check.stdout + check.stderr)[-1500:])

    def case_a14(self, g: Guest) -> None:
        instances = ["host-local", "fs-full-capacity", "fs-roomy-capacity", "fs-inodes-full",
                     "fs-inodes-roomy", "mem-local", "unit-fixture", "unit-fail", "unit-alias",
                     "unit-absent", "unit-machine"]
        outcomes = {}
        ok = True
        for instance in instances:
            r, doc = self.nq_json(g, f"watcher admit {instance}", privileged=True)
            outcomes[instance] = {
                "exit": r.returncode,
                "outcome": doc.get("outcome") if isinstance(doc, dict) else None,
                "admission_id": doc.get("admission_id") if isinstance(doc, dict) else None,
                "output": None if isinstance(doc, dict) and doc.get("outcome") == "activated" else text(r.stdout + r.stderr)[-2000:],
            }
            ok = ok and r.returncode == 0 and isinstance(doc, dict) and doc.get("outcome") == "activated"
        self.fixtures["admissions"] = outcomes
        self.record("PASS" if ok else "FAIL", admissions=outcomes)

    def case_a16(self, g: Guest) -> None:
        load = self.ssh(g, "/home/nqacceptor/bin/load.sh start 16 4.5 300", timeout=400)
        started = parse_json(load.stdout)
        try:
            admission = self.admit(g, "host-local-load")
            cls, _, _ = self.execute(g, "host-local-load", "under-load")
            successor = self.acquire(g, "host-local", "load-001", "under-load")
            after = text(self.ssh(g, "cat /proc/loadavg").stdout).strip()
        finally:
            self.ssh(g, "/home/nqacceptor/bin/load.sh stop")
        observed = effective(cls)
        self.record("PASS" if observed == "present" and started and started.get("reached") else "FAIL",
                    expected="present", observed=observed, load_fixture=started, loadavg_after=after,
                    admission=admission, artifact=cls,
                    supplementary_acquire_next_local_on_host_local=successor,
                    note="fresh instance host-local-load (same scope) because diagnostics execute refuses an instance with prior history; acquire-next-local is the documented successor path and is recorded as supplementary evidence")
    def case_a21(self, g: Guest) -> None:
        uptime = self.wait_boot_age(g, 185)
        ident = json.loads(self.ssh(g, f"{FIX} identities", check=True).stdout)
        self.identities[g.role] = ident
        present = ident["psi_memory_present"]
        cls, _, _ = self.execute(g, "mem-local", "baseline")
        observed = effective(cls)
        if present:
            expected = "explicitly_absent"
            ok = observed == expected
        else:
            expected = "cannot_evaluate psi_not_provided"
            ok = observed == "cannot_evaluate" and any(r.get("failure_code") == "psi_not_provided" for r in cls["refusals"])
        self.fixtures["psi_memory_present_at_baseline"] = present
        self.record("PASS" if ok else "FAIL", psi_memory_present=present, psi_memory=ident.get("psi_memory"),
                    kernel=ident["kernel"], cmdline=ident["cmdline"], uptime_at_execution=uptime,
                    expected=expected, observed=observed, artifact=cls,
                    note="executed after boot age >= 185 s because the memory detector refuses psi_average_warming_up below 180 s; memory pressure present is not induced (spec: not required)")
    def case_a22(self, g: Guest) -> None:
        if self.fixtures.get("psi_memory_present_at_baseline"):
            self.record("NOT_EXERCISED", reason="/proc/pressure/memory is already provided by the Debian kernel at baseline; the psi=1 reboot branch is not needed (baseline case A-21 recorded explicitly_absent)")
            return
        self.ssh(g, "sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 psi=1\"/' /etc/default/grub && grep CMDLINE_LINUX_DEFAULT /etc/default/grub && sudo update-grub", check=True, timeout=300)
        self.reboot(g)
        self.ssh(g, f"{FIX} setup-units >/dev/null; sudo mount -a; for n in full roomy inodes; do sudo mount -o loop /srv/nq-fixture/img/$n.img /srv/nq-fixture/$n; done; true")
        ident = json.loads(self.ssh(g, f"{FIX} identities", check=True).stdout)
        cls, _, _ = self.execute(g, "mem-local", "after-psi-reboot")
        observed = effective(cls)
        self.record("PASS" if observed == "explicitly_absent" and ident["psi_memory_present"] else "FAIL",
                    cmdline=ident["cmdline"], psi_memory_present=ident["psi_memory_present"],
                    expected="explicitly_absent", observed=observed, artifact=cls)

    def case_a29(self, g: Guest) -> None:
        entries = []
        complete = True
        for e in self.cannot_evaluate:
            owner = "failure_error_count" in (e.get("details") or {})
            entry = {k: v for k, v in e.items() if k != "details"}
            entry["owner_failure"] = owner
            if owner and not (e.get("failure_code") and e.get("failure_retriable") in ("true", "false")):
                complete = False
            entries.append(entry)
        owner_count = sum(1 for e in entries if e["owner_failure"])
        self.record("PASS" if complete and owner_count else "FAIL", cannot_evaluate_refusals=entries,
                    owner_failure_count=owner_count,
                    note="failure_code and failure_retriable read from each artifact refusal's details; detector-level refusals without an owner collection failure carry neither field")
    def unit_state(self, g: Guest, props: str = "ExecStartPre,ActiveState,SubState,Result,NRestarts,ExecMainPID") -> str:
        return text(self.ssh(g, f"systemctl show nqd.service -p {props}").stdout)

    def case_a30(self, g: Guest) -> None:
        start = self.ssh(g, "sudo systemctl start nqd.service; echo start-exit=$?; sleep 3; systemctl is-active nqd.service", timeout=120)
        show = self.unit_state(g)
        status = self.ssh(g, "systemctl status nqd.service --no-pager -l; sudo journalctl -u nqd.service -b --no-pager -o short-iso | tail -60")
        stop = self.ssh(g, "sudo systemctl stop nqd.service; echo stop-exit=$?; systemctl is-active nqd.service")
        restart = self.ssh(g, "sudo systemctl start nqd.service; echo start-exit=$?; sleep 2; systemctl is-active nqd.service; sudo systemctl restart nqd.service; echo restart-exit=$?; sleep 2; systemctl is-active nqd.service; systemctl show nqd.service -p ActiveState,SubState,NRestarts,ExecMainPID", timeout=180)
        pre = re.findall(r"ExecStartPre=\{[^}]*\}", show)
        pre_ok = len(pre) == 3 and all(re.search(r"status=0(/SUCCESS)? \}", p) for p in pre)
        ok = b"start-exit=0" in start.stdout and text(start.stdout).strip().endswith("active") and pre_ok and b"stop-exit=0" in stop.stdout and text(stop.stdout).strip().endswith("inactive") and b"restart-exit=0" in restart.stdout and "ActiveState=active" in text(restart.stdout)
        self.record("PASS" if ok else "FAIL", start=text(start.stdout), exec_start_pre=pre, stop=text(stop.stdout),
                    restart=text(restart.stdout), status=self.evidence(f"{g.role}-nqd-status.txt", status.stdout + status.stderr))

    def case_a31(self, g: Guest) -> None:
        self.ssh(g, "systemctl is-active nqd.service || sudo systemctl start nqd.service; sleep 25")
        journal = self.ssh(g, "sudo journalctl -u nqd.service -b --no-pager -o short-iso")
        lines = text(journal.stdout).splitlines()
        errors = [l for l in lines if " ERROR " in l or "error=" in l]
        warns = [l for l in lines if " WARN " in l]
        admitted = [l for l in lines if "collection admitted and evaluated" in l]
        messages = sorted({re.sub(r"run [0-9a-f-]{36}", "run <uuid>", l.split(" nqd[", 1)[-1].split("]: ", 1)[-1]) for l in errors})
        refusals = self.ssh(g, f"{NQ} --json refusals export --limit 20")
        self.evidence(f"{g.role}-nqd-journal-after-start.txt", journal.stdout)
        self.evidence(f"{g.role}-refusals-export.json", refusals.stdout + refusals.stderr)
        self.ssh(g, "sudo systemctl stop nqd.service")
        self.record("PASS" if not errors else "FAIL", error_count=len(errors), warn_count=len(warns),
                    admitted_and_evaluated_count=len(admitted), distinct_error_messages=messages,
                    first_errors=errors[:6], journal="evidence/" + f"{g.role}-nqd-journal-after-start.txt",
                    note="nqd started against watchers admitted and executed by the nq CLI; any ERROR line is recorded verbatim")

    def case_n14(self, g: Guest) -> None:
        state = self.ssh(g, "systemctl is-active nqd.service; ls -ld /run/nq /run/nq/helpers 2>&1; systemctl show nqd.service -p RuntimeDirectory,RuntimeDirectoryPreserve")
        wrapper = self.ssh(g, f"{NQ_RUN} watcher test host-local")
        direct = self.ssh(g, f"{NQ} config check")
        restore = self.ssh(g, "sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/nq.conf; echo tmpfiles-exit=$?; ls -ld /run/nq /run/nq/helpers 2>&1")
        wrapper_after = self.ssh(g, f"{NQ_RUN} watcher test host-local")
        missing = "No such file" in text(state.stdout)
        self.record("FAIL" if missing else "PASS",
                    after_nqd_stop=text(state.stdout), wrapper_exit=wrapper.returncode,
                    wrapper_output=text(wrapper.stdout + wrapper.stderr)[-1500:],
                    config_check_direct_exit=direct.returncode,
                    tmpfiles_restore=text(restore.stdout + restore.stderr),
                    wrapper_after_restore={"exit": wrapper_after.returncode, "output": text(wrapper_after.stdout + wrapper_after.stderr)[-1200:]},
                    note="systemd removes a RuntimeDirectory when the unit stops; OPERATIONS.md's nq_helper_command (ReadWritePaths=/run/nq) and helper_runtime_dir=/run/nq/helpers then depend on it existing; exit 226 is systemd EXIT_NAMESPACE")

    # negatives -------------------------------------------------------------
    def case_n01(self, g: Guest) -> None:
        ident = self.identities[g.role]
        body = CONFIG_PREFIX + watcher_block(
            "neg-same-identity", "nq.host", 1, f"host:{ident['hostname']}",
            ["read_procfs", "read_system_info"], "host", {"id": ident["hostname"]}, HOST_HELPER,
            execution_account="nq",
        )
        ref = self.install_config(g, body, "/etc/nq/neg-same-identity.toml")
        check = self.ssh(g, f"{NQ} config check /etc/nq/neg-same-identity.toml")
        steps = {"config_check": {"exit": check.returncode, "output": text(check.stdout + check.stderr)[-2000:]}}
        refused = check.returncode != 0
        if not refused:
            test = self.ssh(g, "/home/nqacceptor/bin/nq-run.sh --config=/etc/nq/neg-same-identity.toml watcher test neg-same-identity")
            steps["watcher_test"] = {"exit": test.returncode, "output": text(test.stdout + test.stderr)[-3000:]}
            refused = test.returncode != 0
            if not refused:
                admit = self.ssh(g, "/home/nqacceptor/bin/nq-run.sh --config=/etc/nq/neg-same-identity.toml watcher admit neg-same-identity")
                steps["watcher_admit"] = {"exit": admit.returncode, "output": text(admit.stdout + admit.stderr)[-3000:]}
                refused = admit.returncode != 0
        self.record("PASS" if refused else "FAIL", config=ref, steps=steps)

    def quiesce_nqd(self, g: Guest) -> str:
        """Leave nqd exactly inactive (prerm refuses a failed/auto-restarting unit)."""
        return text(self.ssh(g, "sudo systemctl stop nqd.service; sudo systemctl reset-failed nqd.service 2>/dev/null; systemctl show nqd.service -p ActiveState --value").stdout).strip()

    def reinstall(self, g: Guest, label: str) -> dict[str, Any]:
        nqd_state = self.quiesce_nqd(g)
        before = text(self.ssh(g, "sudo sha256sum /var/lib/nq/nq.db | cut -d' ' -f1; getent passwd nq nq-helper | cut -d: -f1-4").stdout)
        r = self.ssh(g, f"sudo dpkg -i /home/nqacceptor/candidate/{PACKAGE}", timeout=300)
        after = text(self.ssh(g, "sudo sha256sum /var/lib/nq/nq.db | cut -d' ' -f1; getent passwd nq nq-helper | cut -d: -f1-4").stdout)
        manifest = self.ssh(g, f"{MANIFEST_CHECK} && echo manifest-ok")
        return {"label": label, "nqd_state_before": nqd_state, "dpkg_exit": r.returncode, "dpkg_output": text(r.stdout + r.stderr)[-2500:],
                "store_and_accounts_before": before, "store_and_accounts_after": after,
                "unchanged": before == after, "manifest": text(manifest.stdout + manifest.stderr).strip()}

    def case_n02(self, g: Guest) -> None:
        pre = self.admit(g, "fs-roomy-n02")
        self.ssh(g, f"sudo mv {RESOURCE_HELPER} /root/nq-host-resource-helper.moved && sudo test ! -e {RESOURCE_HELPER}", check=True)
        try:
            test = self.ssh(g, f"{NQ_RUN} watcher test fs-roomy-capacity")
            admit_missing = self.admit(g, "fs-roomy-n02c")
            cls, _, exe = self.execute(g, "fs-roomy-n02", "helper-missing")
        finally:
            self.ssh(g, "sudo rm -f /root/nq-host-resource-helper.moved")
        reinstall = self.reinstall(g, "restore after helper removal")
        stale = self.ssh(g, f"{NQ_RUN} watcher test fs-roomy-capacity")
        post = self.admit(g, "fs-roomy-n02b")
        cls2, _, _ = self.execute(g, "fs-roomy-n02b", "after-reinstall")
        refused = test.returncode != 0 and not admit_missing["activated"] and (exe.returncode != 0 or effective(cls) not in ("present", "explicitly_absent"))
        self.record("PASS" if pre["activated"] and refused and reinstall["dpkg_exit"] == 0 and reinstall["unchanged"] and post["activated"] and effective(cls2) == "explicitly_absent" else "FAIL",
                    admission_before_removal=pre,
                    watcher_test={"exit": test.returncode, "output": text(test.stdout + test.stderr)[-2500:]},
                    admission_while_missing=admit_missing, execute_while_missing=cls, reinstall=reinstall,
                    existing_admission_after_reinstall={"exit": stale.returncode, "output": text(stale.stdout + stale.stderr)[-1500:],
                                                        "note": "watcher test of an instance admitted before the reinstall; recorded, not gating"},
                    admission_after_reinstall=post, execute_after_reinstall=effective(cls2))
    def case_n03(self, g: Guest) -> None:
        pre = self.admit(g, "fs-roomy-n03")
        self.ssh(g, f"sudo chmod 0700 {RESOURCE_HELPER} && stat -c '%a %U' {RESOURCE_HELPER}", check=True)
        try:
            test = self.ssh(g, f"{NQ_RUN} watcher test fs-roomy-capacity")
            admit_mode = self.admit(g, "fs-roomy-n03c")
            cls, _, exe = self.execute(g, "fs-roomy-n03", "helper-0700")
        finally:
            self.ssh(g, f"sudo chmod 0755 {RESOURCE_HELPER}")
        post = self.admit(g, "fs-roomy-n03b")
        cls2, _, _ = self.execute(g, "fs-roomy-n03b", "after-chmod-restore")
        refused = test.returncode != 0 and not admit_mode["activated"] and (exe.returncode != 0 or effective(cls) not in ("present", "explicitly_absent"))
        self.record("PASS" if pre["activated"] and refused and post["activated"] and effective(cls2) == "explicitly_absent" else "FAIL",
                    admission_before_chmod=pre,
                    watcher_test={"exit": test.returncode, "output": text(test.stdout + test.stderr)[-2500:]},
                    admission_while_0700=admit_mode, execute_while_0700=cls,
                    admission_after_restore=post, execute_after_restore=effective(cls2))
    def case_n04(self, g: Guest) -> None:
        pre = self.admit(g, "fs-roomy-n04")
        self.ssh(g, f"sudo cp {HOST_HELPER} {RESOURCE_HELPER} && sha256sum {HOST_HELPER} {RESOURCE_HELPER}", check=True)
        cls, _, exe = self.execute(g, "fs-roomy-n04", "helper-substituted")
        start = self.ssh(g, "sudo systemctl start nqd.service; echo start-exit=$?; sleep 2; systemctl is-active nqd.service; systemctl show nqd.service -p ExecStartPre,ActiveState,Result; sudo journalctl -u nqd.service -b --no-pager -o short-iso | tail -15; sudo systemctl stop nqd.service; sudo systemctl reset-failed nqd.service 2>/dev/null; true", timeout=120)
        reinstall = self.reinstall(g, "restore after helper substitution")
        post = self.admit(g, "fs-roomy-n04b")
        cls2, _, _ = self.execute(g, "fs-roomy-n04b", "after-substitution-reinstall")
        after = self.ssh(g, "sudo systemctl start nqd.service; echo start-exit=$?; sleep 3; systemctl is-active nqd.service; sudo systemctl stop nqd.service", timeout=120)
        exec_refused = exe.returncode != 0 or effective(cls) not in ("present", "explicitly_absent")
        nqd_refused = re.search(r"sha256sum[^}]*status=1\b", text(start.stdout)) is not None and "\nactive\n" not in text(start.stdout)
        self.record("PASS" if pre["activated"] and exec_refused and nqd_refused and reinstall["dpkg_exit"] == 0 and post["activated"] and effective(cls2) == "explicitly_absent" and "\nactive\n" in text(after.stdout) else "FAIL",
                    admission_before_substitution=pre, execute_after_substitution=cls,
                    nqd_start_with_substituted_helper=text(start.stdout + start.stderr), reinstall=reinstall,
                    admission_after_reinstall=post, execute_after_reinstall=effective(cls2),
                    nqd_after_reinstall=text(after.stdout))
    def case_n05(self, g: Guest) -> None:
        self.ssh(g, "sudo cp -p /usr/share/nq/profiles/failure-codes.json /root/failure-codes.json.orig && sudo python3 - <<'PY'\nimport json\np='/usr/share/nq/profiles/failure-codes.json'\nd=json.load(open(p))\nfor e in d['profiles']:\n    if e['id']=='nq.host_memory':\n        e['codes'].remove('psi_not_provided')\njson.dump(d, open(p,'w'), indent=2)\nPY", check=True)
        try:
            cmp = self.failure_code_comparison(g)
            manifest = self.ssh(g, f"{MANIFEST_CHECK}; echo manifest-exit=$?")
        finally:
            self.ssh(g, "sudo cp -p /root/failure-codes.json.orig /usr/share/nq/profiles/failure-codes.json && sudo rm /root/failure-codes.json.orig", check=True)
        restored = self.ssh(g, f"{MANIFEST_CHECK} && echo manifest-ok")
        detected = not cmp["packaged_equals_compiled"]
        self.record("PASS" if detected and b"manifest-exit=1" in manifest.stdout and b"manifest-ok" in restored.stdout else "FAIL",
                    packaged_equals_compiled=cmp["packaged_equals_compiled"], helper_agrees=cmp["helper_agrees"],
                    manifest_check=text(manifest.stdout + manifest.stderr)[-1500:], restored=text(restored.stdout).strip(),
                    note="assembler-time refusal covered by test_release_failure_atomicity.sh (not re-run here)")

    def case_n06(self, g: Guest) -> None:
        ident = self.identities[g.role]
        mid = ident["machine_id"]
        fx = self.fixtures["filesystems"]
        body = CONFIG_PREFIX + watcher_block(
            "neg-wrong-subject", "nq.host_filesystem_capacity", 1,
            f"host-filesystem:{mid}/{fx['roomy']['uuid']}", FS_CEILING, "host_filesystem",
            fs_scope(mid, fx["full"]["uuid"], fx["full"]["mountpoint"]), RESOURCE_HELPER,
        )
        body += watcher_block(
            "neg-wrong-subject-unit", "nq.systemd_unit", 2, f"systemd-unit:{mid}/nq-fixture-fail.service",
            ["read_systemd_unit"], "systemd_unit", unit_scope(mid, "nq-fixture.service"), RESOURCE_HELPER,
        )
        ref = self.install_config(g, body, "/etc/nq/neg-wrong-subject.toml")
        check = self.ssh(g, f"{NQ} config check /etc/nq/neg-wrong-subject.toml")
        self.record("PASS" if check.returncode != 0 else "FAIL", config=ref, exit=check.returncode,
                    message=text(check.stdout + check.stderr)[-2500:])

    def case_n07(self, g: Guest) -> None:
        ident = self.identities[g.role]
        mid = ident["machine_id"]
        v1_scope = {
            "schema": "nq.operator_beta.systemd_unit_scope.v1",
            "subject_identity": "sha256:" + "0" * 64,
            "target_machine_identity": mid,
            "unit_name": "nq-fixture.service",
            "unit_file_sha256": "0" * 64,
            "manager_interface": "org.freedesktop.systemd1",
            "properties": ["LoadState", "ActiveState", "SubState", "UnitFileState"],
        }
        a = CONFIG_PREFIX + watcher_block(
            "neg-v1-scope-under-v2", "nq.systemd_unit", 2, f"systemd-unit:{mid}/nq-fixture.service",
            ["read_systemd_unit"], "systemd_unit", v1_scope, RESOURCE_HELPER,
        )
        b = CONFIG_PREFIX + watcher_block(
            "neg-v2-scope-under-v1", "nq.systemd_unit", 1, f"systemd-unit:{mid}/nq-fixture.service",
            ["read_systemd_unit"], "systemd_unit", unit_scope(mid, "nq-fixture.service"),
            f"{HELPER_DIR}/nq-operator-beta-helper",
        )
        ref_a = self.install_config(g, a, "/etc/nq/neg-v1-scope-under-v2.toml")
        ref_b = self.install_config(g, b, "/etc/nq/neg-v2-scope-under-v1.toml")
        ca = self.ssh(g, f"{NQ} config check /etc/nq/neg-v1-scope-under-v2.toml")
        cb = self.ssh(g, f"{NQ} config check /etc/nq/neg-v2-scope-under-v1.toml")
        self.record("PASS" if ca.returncode != 0 and cb.returncode != 0 else "FAIL",
                    v1_scope_under_v2={"config": ref_a, "exit": ca.returncode, "message": text(ca.stdout + ca.stderr)[-2500:]},
                    v2_scope_under_v1={"config": ref_b, "exit": cb.returncode, "message": text(cb.stdout + cb.stderr)[-2500:]})

    def case_n08(self, g: Guest) -> None:
        help_out = self.ssh(g, f"{NQ} diagnostics --help; {NQ} --help")
        self.record(
            "NOT_EXERCISED",
            reason=(
                "no supported operator command in the installed CLI evaluates a stored report at a later "
                "instant: `diagnostics execute` collects and evaluates in one cut, and nqd evaluates only "
                "after a successful scheduled collection; the compiled `invalid_freshness` cannot_evaluate "
                "therefore has no NQ-level operator trigger in this release. Pulse staleness is outside the "
                "released scope."
            ),
            cli_surface=self.evidence(f"{g.role}-nq-help.txt", help_out.stdout + help_out.stderr),
        )

    def qualify_export(self, g: Guest, artifact_id: str, tag: str) -> dict[str, Any]:
        q = self.ssh(g, f"{NQ} diagnostics qualify {artifact_id}")
        e = self.ssh(g, f"{NQ} diagnostics export {artifact_id}")
        self.evidence(f"{g.role}-{tag}-qualify.json", q.stdout + q.stderr)
        self.evidence(f"{g.role}-{tag}-export.json", e.stdout)
        return {"qualify_exit": q.returncode, "qualify_sha256": hashlib.sha256(q.stdout).hexdigest(),
                "export_exit": e.returncode, "export_sha256": hashlib.sha256(e.stdout).hexdigest(),
                "export_bytes": e.stdout, "qualify_bytes": q.stdout}

    def case_n09(self, g: Guest) -> None:
        key = "a:fs-full-capacity:initial"
        artifact = self.artifacts.get(key)
        if artifact is None:
            self.record("NOT_EXERCISED", reason="no initial fs-full-capacity artifact was produced")
            return
        aid = artifact["artifact_id"]
        original = json.dumps(artifact, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
        before = self.qualify_export(g, aid, "replay-before")
        cycle = self.ssh(g, "sudo systemctl restart nqd.service; echo restart-exit=$?; sleep 2; systemctl is-active nqd.service", timeout=120)
        after = self.qualify_export(g, aid, "replay-after")
        identical = before["export_bytes"] == after["export_bytes"] and before["qualify_bytes"] == after["qualify_bytes"]
        matches_execute = after["export_bytes"] == original
        self.exports[aid] = after["export_bytes"]
        ok = identical and before["export_exit"] == 0 and before["qualify_exit"] == 0 and b"restart-exit=0" in cycle.stdout
        self.record("PASS" if ok else "FAIL", artifact_id=aid,
                    before={k: v for k, v in before.items() if not k.endswith("_bytes")},
                    after={k: v for k, v in after.items() if not k.endswith("_bytes")},
                    byte_identical=identical, export_equals_execute_canonical=matches_execute,
                    nqd_restart=text(cycle.stdout))

    def case_n10(self, g: Guest) -> None:
        before_db = text(self.ssh(g, "sudo ls -la /var/lib/nq/; sudo sha256sum /var/lib/nq/nq.db").stdout)
        cycle = self.ssh(g, "sudo systemctl stop nqd.service; echo stop-exit=$?; systemctl is-active nqd.service; sudo systemctl start nqd.service; echo start-exit=$?; sleep 3; systemctl is-active nqd.service", timeout=120)
        after_db = text(self.ssh(g, "sudo ls -la /var/lib/nq/; sudo test -s /var/lib/nq/nq.db && echo store-present").stdout)
        admission = self.admit(g, "fs-roomy-n10")
        cls, _, _ = self.execute(g, "fs-roomy-n10", "after-nqd-restart")
        journal = text(self.ssh(g, "sudo journalctl -u nqd.service -b --no-pager -o short-iso | grep -E 'fs-roomy-n10' | tail -5").stdout)
        new_ok = effective(cls) == "explicitly_absent" or "collection admitted and evaluated" in journal
        unchanged = {}
        for key, artifact in list(self.artifacts.items()):
            if not key.startswith("a:") or ":initial" not in key:
                continue
            aid = artifact["artifact_id"]
            e = self.ssh(g, f"{NQ} diagnostics export {aid}")
            canonical = json.dumps(artifact, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
            unchanged[key] = e.returncode == 0 and e.stdout == canonical
        ok = "\nactive\n" in text(cycle.stdout) and "store-present" in after_db and admission["activated"] and new_ok and unchanged and all(unchanged.values())
        self.ssh(g, "sudo systemctl stop nqd.service")
        self.record("PASS" if ok else "FAIL", cycle=text(cycle.stdout), store_before=before_db, store_after=after_db,
                    admission=admission, new_execution=effective(cls), new_execution_artifact=cls,
                    nqd_journal_for_instance=journal, earlier_artifacts_unchanged=unchanged)
    def package_intact(self, g: Guest) -> dict[str, Any]:
        r = self.ssh(g, f"dpkg -s nq-ng | grep -E '^(Status|Version):'; {MANIFEST_CHECK} && echo manifest-ok; /usr/bin/nq --build-info")
        return {"exit": r.returncode, "output": text(r.stdout + r.stderr)}

    def case_n11(self, g: Guest) -> None:
        self.ssh(g, "rm -rf /home/nqacceptor/neg-corrupt && cp -r /home/nqacceptor/candidate /home/nqacceptor/neg-corrupt && python3 - <<'PY'\np='/home/nqacceptor/neg-corrupt/" + PACKAGE + "'\nb=bytearray(open(p,'rb').read())\ni=len(b)//2\nb[i]^=0x01\nopen(p,'wb').write(b)\nprint('flipped byte at offset', i)\nPY", check=True)
        sums = self.ssh(g, "cd /home/nqacceptor/neg-corrupt && sha256sum --check --strict SHA256SUMS; echo sums-exit=$?")
        dpkg = self.ssh(g, f"sudo dpkg -i /home/nqacceptor/neg-corrupt/{PACKAGE}; echo dpkg-exit=$?", timeout=300)
        intact = self.package_intact(g)
        repaired = None
        if "Status: install ok installed" not in intact["output"] or "manifest-ok" not in intact["output"]:
            repaired = self.reinstall(g, "repair after corrupted dpkg -i")
            intact_after = self.package_intact(g)
        else:
            intact_after = intact
        sums_failed = b"sums-exit=0" not in sums.stdout
        dpkg_refused = b"dpkg-exit=0" not in dpkg.stdout
        self.record("PASS" if sums_failed and dpkg_refused else "FAIL", sha256sum=text(sums.stdout + sums.stderr)[-1500:],
                    dpkg=text(dpkg.stdout + dpkg.stderr)[-3000:], installed_after_attempt=intact,
                    repair=repaired, installed_after_repair=intact_after if repaired else None,
                    which="dpkg -i refused" if dpkg_refused else "dpkg -i accepted",
                    installed_intact_after_attempt="Status: install ok installed" in intact["output"] and "manifest-ok" in intact["output"])

    def case_n12(self, g: Guest) -> None:
        r = self.ssh(g, f"rm -rf /home/nqacceptor/neg-missing && cp -r /home/nqacceptor/candidate /home/nqacceptor/neg-missing && rm /home/nqacceptor/neg-missing/{TARBALL} && cd /home/nqacceptor/neg-missing && sha256sum --check --strict SHA256SUMS; echo sums-exit=$?")
        self.record("PASS" if b"sums-exit=0" not in r.stdout else "FAIL", output=text(r.stdout + r.stderr)[-1500:])

    def case_n13(self, g: Guest) -> None:
        self.ssh(g, f"rm -rf /home/nqacceptor/neg-partial && mkdir /home/nqacceptor/neg-partial && head -c $(( $(stat -c %s /home/nqacceptor/candidate/{PACKAGE}) / 2 )) /home/nqacceptor/candidate/{PACKAGE} > /home/nqacceptor/neg-partial/{PACKAGE} && ls -l /home/nqacceptor/neg-partial", check=True)
        dpkg = self.ssh(g, f"sudo dpkg -i /home/nqacceptor/neg-partial/{PACKAGE}; echo dpkg-exit=$?", timeout=300)
        intact = self.package_intact(g)
        repaired = None
        if "Status: install ok installed" not in intact["output"] or "manifest-ok" not in intact["output"]:
            repaired = self.reinstall(g, "repair after truncated dpkg -i")
        refused = b"dpkg-exit=0" not in dpkg.stdout
        still_ok = "Status: install ok installed" in intact["output"] and "manifest-ok" in intact["output"]
        self.record("PASS" if refused and still_ok else "FAIL", dpkg=text(dpkg.stdout + dpkg.stderr)[-3000:],
                    installed_after_attempt=intact, repair=repaired)

    # ------------------------------------------------------------ guest B cases
    def case_b01(self, g: Guest) -> None:
        pre = self.args.predecessor_dir
        self.ssh(g, "mkdir -p /home/nqacceptor/predecessor", check=True)
        self.scp_to(g, [pre / PACKAGE, pre / "SHA256SUMS"], "/home/nqacceptor/predecessor/")
        sums = self.ssh(g, "cd /home/nqacceptor/predecessor && sha256sum --check --ignore-missing --strict SHA256SUMS; echo sums-exit=$?")
        dpkg = self.ssh(g, f"sudo dpkg -i /home/nqacceptor/predecessor/{PACKAGE}; echo dpkg-exit=$?", timeout=300)
        info = self.ssh(g, f"/usr/bin/nq --build-info; {MANIFEST_CHECK} && echo manifest-ok; sudo -u nq /usr/bin/nq profiles list; ls -la {HELPER_DIR}")
        profiles = None
        for line in text(info.stdout).splitlines():
            if line.startswith("["):
                profiles = parse_json(line.encode())
        ok = b"sums-exit=0" in sums.stdout and b"dpkg-exit=0" in dpkg.stdout and b"manifest-ok" in info.stdout
        self.record("PASS" if ok else "FAIL", sha256sum=text(sums.stdout), dpkg=text(dpkg.stdout + dpkg.stderr)[-2500:],
                    build_info_and_layout=text(info.stdout + info.stderr)[-3000:],
                    predecessor_profiles=[(p["id"], p["version"]) for p in profiles] if isinstance(profiles, list) else None)

    def predecessor_config(self, g: Guest) -> str:
        ident = self.identities[g.role]
        body = CONFIG_PREFIX
        for instance in ("host-local", "host-local-2", "host-local-3"):
            body += watcher_block(
                instance, "nq.host", 1, f"host:{ident['hostname']}",
                ["read_procfs", "read_system_info"], "host", {"id": ident["hostname"]}, HOST_HELPER,
            )
        return body
    def case_b02(self, g: Guest) -> None:
        ref = self.install_config(g, self.predecessor_config(g))
        init, init_json = self.nq_json(g, "--json init")
        check, _ = self.nq_json(g, "config check")
        admit, admit_json = self.nq_json(g, "watcher admit host-local", privileged=True)
        cls, artifact, _ = self.execute(g, "host-local", "m3-initial")
        aid = cls.get("artifact_id")
        export = self.ssh(g, f"{NQ} diagnostics export {aid}") if aid else None
        if export is not None and export.returncode == 0:
            self.exports[f"b:{aid}"] = export.stdout
        ok = init.returncode == 0 and check.returncode == 0 and isinstance(admit_json, dict) and admit_json.get("outcome") == "activated" and effective(cls) in ("present", "explicitly_absent")
        self.record("PASS" if ok else "FAIL", config=ref, init=init_json or text(init.stdout + init.stderr)[-800:],
                    config_check_exit=check.returncode, admission=admit_json or text(admit.stdout + admit.stderr)[-1500:],
                    artifact=cls, export_sha256=hashlib.sha256(export.stdout).hexdigest() if export is not None else None)

    def case_b03(self, g: Guest) -> None:
        start = self.ssh(g, "sudo systemctl start nqd.service; echo start-exit=$?; sleep 2; systemctl is-active nqd.service; systemctl is-enabled nqd.service", timeout=120)
        store_before = text(self.ssh(g, "sudo sha256sum /var/lib/nq/nq.db").stdout)
        dpkg = self.ssh(g, f"sudo dpkg -i /home/nqacceptor/candidate/{PACKAGE}; echo dpkg-exit=$?", timeout=300)
        after = self.ssh(g, f"systemctl is-active nqd.service; systemctl is-enabled nqd.service; systemctl show nqd.service -p ActiveState,Result; sudo journalctl -u nqd.service -b --no-pager -o short-iso | tail -12; /usr/bin/nq --build-info; {MANIFEST_CHECK} && echo manifest-ok; sudo stat -c '%n %a %U:%G' /etc/nq /etc/nq/nq.toml /var/lib/nq /var/lib/nq/nq.db /run/nq/helpers; sudo sha256sum /var/lib/nq/nq.db")
        out = text(after.stdout + after.stderr)
        ok = b"dpkg-exit=0" in dpkg.stdout and out.startswith("inactive") and "manifest-ok" in out and store_before.split()[0] in out
        self.record("PASS" if ok else "FAIL", nqd_before=text(start.stdout), dpkg=text(dpkg.stdout + dpkg.stderr)[-4000:],
                    after=out, store_unchanged_by_install=store_before.split()[0] in out,
                    note="prerm upgrade must stop nqd and leave it inactive; postinst must not start or enable it")

    def case_b04(self, g: Guest) -> None:
        steps: dict[str, Any] = {}
        def cmd(label, command, timeout=300):
            r = self.ssh(g, command, timeout=timeout)
            steps[label] = {"exit": r.returncode, "output": text(r.stdout + r.stderr)[-3000:]}
            return r
        cmd("config_check_old_config_new_binary", f"{NQ} config check")
        cmd("doctor_before_upgrade", f"{NQ_RUN} --json doctor")
        cmd("watcher_test_before_upgrade", f"{NQ_RUN} watcher test host-local")
        cls0, _, exe0 = self.execute(g, "host-local-2", "old-store-new-binary")
        steps["execute_fresh_instance_before_upgrade"] = {"exit": exe0.returncode, "effective": effective(cls0), "artifact": cls0}
        old_key = next((k for k in self.exports if k.startswith("b:")), None)
        def export_old(label):
            if old_key:
                aid = old_key[2:]
                e = self.ssh(g, f"{NQ} diagnostics export {aid}")
                steps[label] = {"exit": e.returncode, "identical_to_m3_export": e.stdout == self.exports[old_key],
                                "output_if_not_identical": None if e.stdout == self.exports[old_key] else text(e.stdout + e.stderr)[-1500:]}
        export_old("export_old_artifact_before_upgrade")
        cmd("admin_upgrade_1", f"{NQ} --json admin upgrade --backup-directory /var/lib/nq/backups; echo upgrade-exit=$?; sudo ls -la /var/lib/nq/backups")
        d1 = cmd("doctor_after_upgrade_1", f"{NQ_RUN} --json doctor")
        if d1.returncode != 0:
            cmd("admin_upgrade_2", f"{NQ} --json admin upgrade --backup-directory /var/lib/nq/backups; echo upgrade-exit=$?; sudo ls -la /var/lib/nq/backups")
            cmd("doctor_after_upgrade_2", f"{NQ_RUN} --json doctor")
        export_old("export_old_artifact_after_upgrade")
        test = cmd("watcher_test_host_local_after_upgrade", f"{NQ_RUN} watcher test host-local")
        readmitted = None
        if test.returncode != 0:
            rotate = cmd("watcher_rotate_host_local", f"{NQ_RUN} watcher rotate host-local")
            readmitted = rotate.returncode == 0
        successor = self.acquire(g, "host-local", "after-upgrade-001", "after-upgrade")
        steps["acquire_next_local_host_local_after_upgrade"] = successor
        admission = self.admit(g, "host-local-2")
        steps["admit_fresh_instance_after_upgrade"] = admission
        cls1, _, exe1 = self.execute(g, "host-local-2", "after-upgrade")
        steps["execute_fresh_instance_after_upgrade"] = {"exit": exe1.returncode, "effective": effective(cls1), "artifact": cls1}
        nqd = cmd("nqd_start_after_upgrade", "sudo systemctl start nqd.service; echo start-exit=$?; sleep 3; systemctl is-active nqd.service; sudo journalctl -u nqd.service -b --no-pager -o short-iso | tail -8; sudo systemctl stop nqd.service; sudo systemctl reset-failed nqd.service 2>/dev/null; true", timeout=120)
        final = effective(cls1)
        ok = final in ("present", "explicitly_absent") and "\nactive\n" in text(nqd.stdout)
        self.record("PASS" if ok else "FAIL", steps=steps, re_admission_needed=readmitted is not None,
                    re_admission_succeeded=readmitted, successor_on_original_watcher=successor.get("effective"),
                    final_new_execution=final,
                    note="observed behaviour recorded step by step; refusals of the pre-upgrade store are expected fail-closed behaviour; a reported upgrade that leaves the store unusable is not")
    def case_b05(self, g: Guest) -> None:
        dpkg = self.ssh(g, f"sudo dpkg -i /home/nqacceptor/predecessor/{PACKAGE}; echo dpkg-exit=$?", timeout=300)
        info = self.ssh(g, f"/usr/bin/nq --build-info; {MANIFEST_CHECK} && echo manifest-ok")
        steps: dict[str, Any] = {"dpkg": text(dpkg.stdout + dpkg.stderr)[-3000:], "binary": text(info.stdout + info.stderr)}
        check = self.ssh(g, f"{NQ} config check")
        steps["config_check"] = {"exit": check.returncode, "output": text(check.stdout + check.stderr)[-1500:]}
        old_key = next((k for k in self.exports if k.startswith("b:")), None)
        if old_key:
            aid = old_key[2:]
            e = self.ssh(g, f"{NQ} diagnostics export {aid}")
            steps["export_old_artifact"] = {"exit": e.returncode, "identical": e.stdout == self.exports[old_key], "output": text(e.stdout + e.stderr)[-1500:] if e.stdout != self.exports[old_key] else "(identical bytes)"}
        test = self.ssh(g, f"{NQ_RUN} watcher test host-local")
        steps["watcher_test"] = {"exit": test.returncode, "output": text(test.stdout + test.stderr)[-1500:]}
        admission = self.admit(g, "host-local-3")
        steps["admit_fresh_instance"] = admission
        cls, _, exe = self.execute(g, "host-local-3", "rollback-old-binary")
        steps["execute_fresh_instance"] = {"exit": exe.returncode, "effective": effective(cls), "artifact": cls}
        doctor = self.ssh(g, f"{NQ_RUN} --json doctor")
        steps["doctor"] = {"exit": doctor.returncode, "output": text(doctor.stdout + doctor.stderr)[-3000:]}
        nqd = self.ssh(g, "sudo systemctl start nqd.service; echo start-exit=$?; sleep 3; systemctl is-active nqd.service; systemctl show nqd.service -p ActiveState,Result; sudo journalctl -u nqd.service -b --no-pager -o short-iso | tail -12; sudo systemctl stop nqd.service; sudo systemctl reset-failed nqd.service 2>/dev/null; true", timeout=120)
        steps["nqd"] = text(nqd.stdout + nqd.stderr)
        silently_accepted = admission["activated"] or effective(cls) in ("present", "explicitly_absent") or "\nactive\n" in text(nqd.stdout)
        explicit_refusal = exe.returncode != 0 and not admission["activated"]
        self.record("FAIL" if silently_accepted else ("PASS" if explicit_refusal and b"dpkg-exit=0" in dpkg.stdout else "FAIL"),
                    steps=steps, silently_accepted_unknown_schema=silently_accepted,
                    note="an explicit refusal of the newer store by the old binary is the expected result; silent acceptance is a defect")
    def collect_guest_logs(self, guest: Guest) -> None:
        try:
            self.ssh(guest, "sudo journalctl -b --no-pager -o short-iso > /home/nqacceptor/journal.txt 2>&1; sudo dmesg > /home/nqacceptor/dmesg.txt 2>&1; sudo journalctl -u nqd.service --no-pager -o short-iso > /home/nqacceptor/nqd-journal.txt 2>&1; sudo cp -r /var/lib/nq/admissions /home/nqacceptor/admissions 2>/dev/null; sudo chown -R nqacceptor /home/nqacceptor/admissions 2>/dev/null; sudo ls -laR /var/lib/nq /etc/nq /run/nq > /home/nqacceptor/nq-layout.txt 2>&1; true", timeout=120)
            dest = self.out / "guest-logs" / guest.role
            dest.mkdir(parents=True, exist_ok=True)
            for name in ("journal.txt", "dmesg.txt", "nqd-journal.txt", "nq-layout.txt"):
                self.scp_from(guest, f"/home/nqacceptor/{name}", dest / name)
            run(guest.scp_base() + ["-r", f"{GUEST_USER}@127.0.0.1:/home/nqacceptor/admissions", str(dest / "admissions")], check=False)
        except Exception as error:  # noqa: BLE001
            self.log(f"log collection from {guest.name} failed: {error}")

    def destroy(self) -> None:
        for guest in self.guests.values():
            if guest.process is not None and guest.process.poll() is None:
                if self.args.keep_guests:
                    self.log(f"keeping {guest.name} (pid {guest.process.pid}) as requested")
                    continue
                try:
                    self.ssh(guest, "sudo systemctl poweroff", timeout=20)
                except Exception:  # noqa: BLE001
                    pass
                deadline = time.monotonic() + 60
                while guest.process.poll() is None and time.monotonic() < deadline:
                    time.sleep(1)
                if guest.process.poll() is None:
                    guest.process.kill()
                    guest.process.wait(timeout=30)
                self.log(f"{guest.name} stopped")
            for name in ("serial.log", "qemu.stdout.log", "qemu.stderr.log"):
                src = guest.root / name
                if src.exists():
                    shutil.copy2(src, self.out / "qemu" / f"{guest.role}-{name}")
        if not self.args.keep_guests:
            shutil.rmtree(self.state, ignore_errors=True)
            self.log(f"removed {self.state}")

    def execute_all(self) -> None:
        key = self.state / "id_ed25519"
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "release-closure-20260925", "-f", str(key)])
        a = self.prepare_guest("a", self.args.ssh_port_a, key)
        b = self.prepare_guest("b", self.args.ssh_port_b, key)
        self.boot(a)
        self.boot(b)

        # Guest A: install and verify.
        for case_id, fn in (("A-01", self.case_a01), ("A-02", self.case_a02), ("A-03", self.case_a03),
                            ("A-04", self.case_a04), ("A-05", self.case_a05), ("A-06", self.case_a06),
                            ("A-07", self.case_a07), ("A-08", self.case_a08), ("A-09", self.case_a09),
                            ("A-10", self.case_a10), ("A-11", self.case_a11), ("A-12", self.case_a12)):
            self.run_case(case_id, fn, a)
        if self.results["A-02"]["outcome"] != "PASS":
            for case_id, _ in CASES:
                if case_id.startswith(("A-1", "A-2", "A-3", "N-")) and self.results[case_id]["outcome"] == "NOT_EXERCISED":
                    self.skip(case_id, "candidate did not install (A-02)")
        else:
            self.setup_fixtures(a)
            self.run_case("A-13", self.case_a13, a)
            self.run_case("A-14", self.case_a14, a)
            self.run_case("A-15", self.expect_condition, a, "host-local", "initial", "explicitly_absent")
            self.run_case("A-16", self.case_a16, a)
            self.run_case("A-17", self.expect_condition, a, "fs-full-capacity", "initial", "present",
                          None, fixture=self.fixtures["filesystems"]["full"])
            self.run_case("A-18", self.expect_condition, a, "fs-roomy-capacity", "initial", "explicitly_absent",
                          None, fixture=self.fixtures["filesystems"]["roomy"])
            self.run_case("A-19", self.expect_condition, a, "fs-inodes-full", "initial", "present",
                          None, fixture=self.fixtures["filesystems"]["inodes"])
            self.run_case("A-20", self.expect_condition, a, "fs-inodes-roomy", "initial", "explicitly_absent",
                          None, fixture=self.fixtures["filesystems"]["roomy"])
            self.run_case("A-21", self.case_a21, a)
            self.run_case("A-22", self.case_a22, a)
            self.run_case("A-23", self.expect_condition, a, "unit-fixture", "initial", "explicitly_absent")
            self.run_case("A-24", self.expect_condition, a, "unit-fixture-stopped", "stopped", "present", None,
                          "sudo systemctl stop nq-fixture.service; systemctl show nq-fixture.service -p ActiveState,SubState",
                          admit_first=True,
                          note="fresh instance unit-fixture-stopped (same scope) because diagnostics execute refuses an instance with prior history")
            self.ssh(a, "sudo systemctl start nq-fixture.service")
            self.run_case("A-25", self.expect_condition, a, "unit-fail", "initial", "present",
                          None, unit_state=text(self.ssh(a, "systemctl show nq-fixture-fail.service -p ActiveState,SubState,Result").stdout))
            self.run_case("A-26", self.expect_condition, a, "unit-alias", "initial", "cannot_evaluate", "unit_name_not_canonical",
                          unit_state=text(self.ssh(a, "systemctl show nq-fixture-alias.service -p Id,Names,ActiveState").stdout))
            self.run_case("A-27", self.expect_condition, a, "unit-absent", "initial", "present",
                          None, unit_state=text(self.ssh(a, f"systemctl show {self.fixtures['absent_unit']} -p LoadState,ActiveState").stdout))
            self.run_case("A-28", self.expect_condition, a, "unit-machine", "initial", "cannot_evaluate", "machine_identity_mismatch")
            self.run_case("A-29", self.case_a29, a)
            # nqd runs first against the untouched admissions (before any reinstall
            # replaces helper inodes), then is stopped so its scheduled collections
            # cannot create history on the spare instances the negatives admit lazily.
            self.run_case("A-30", self.case_a30, a)
            self.run_case("A-31", self.case_a31, a)
            self.run_case("N-14", self.case_n14, a)
            for case_id, fn in (("N-01", self.case_n01), ("N-02", self.case_n02), ("N-03", self.case_n03),
                                ("N-04", self.case_n04), ("N-05", self.case_n05), ("N-06", self.case_n06),
                                ("N-07", self.case_n07), ("N-08", self.case_n08), ("N-09", self.case_n09),
                                ("N-10", self.case_n10), ("N-11", self.case_n11), ("N-12", self.case_n12),
                                ("N-13", self.case_n13)):
                self.run_case(case_id, fn, a)
        self.collect_guest_logs(a)

        # Guest B: predecessor continuity and rollback.
        self.run_case("B-01", self.case_b01, b)
        if self.results["B-01"]["outcome"] != "PASS":
            for case_id in ("B-02", "B-03", "B-04", "B-05"):
                self.skip(case_id, "predecessor did not install (B-01)")
        else:
            self.run_case("B-02", self.case_b02, b)
            self.run_case("B-03", self.case_b03, b)
            self.run_case("B-04", self.case_b04, b)
            self.run_case("B-05", self.case_b05, b)
        self.collect_guest_logs(b)

    def main(self) -> int:
        try:
            self.preflight()
        except Refusal as error:
            print(f"refused: {error}", file=sys.stderr)
            return 2
        status = 0
        try:
            self.execute_all()
        except Refusal as error:
            self.log(f"harness refusal: {error}")
            if self.current is not None:
                self.record("FAIL", error=str(error), note="harness refusal")
            for case_id, entry in self.results.items():
                if entry["outcome"] == "NOT_EXERCISED" and entry.get("reason") == "not reached":
                    entry["reason"] = f"harness aborted: {error}"[:500]
            status = 1
        except Exception as error:  # noqa: BLE001
            self.log(f"harness exception: {error}\n{traceback.format_exc()}")
            if self.current is not None:
                self.record("FAIL", error=f"{type(error).__name__}: {error}", note="harness exception")
            for case_id, entry in self.results.items():
                if entry["outcome"] == "NOT_EXERCISED" and entry.get("reason") == "not reached":
                    entry["reason"] = f"harness aborted: {type(error).__name__}: {error}"[:500]
            status = 1
        finally:
            try:
                self.destroy()
            finally:
                self.write_results()
        summary = {o: sum(1 for r in self.results.values() if r["outcome"] == o) for o in ("PASS", "FAIL", "NOT_EXERCISED")}
        self.log(f"done: {summary}")
        return status


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--campaign-dir", type=pathlib.Path, default=DEFAULT_CAMPAIGN)
    p.add_argument("--state-dir", type=pathlib.Path, default=DEFAULT_STATE)
    p.add_argument("--image", type=pathlib.Path, default=DEFAULT_IMAGE_DIR / IMAGE_NAME)
    p.add_argument("--predecessor-dir", type=pathlib.Path, default=DEFAULT_PREDECESSOR)
    p.add_argument("--ssh-port-a", type=int, default=23301)
    p.add_argument("--ssh-port-b", type=int, default=23302)
    p.add_argument("--keep-guests", action="store_true", help="debugging only: leave guests running")
    return p


if __name__ == "__main__":
    sys.exit(Harness(parser().parse_args()).main())
