#!/usr/bin/env python3
"""Minimal stdlib-only specimen for the nq.helper.v1 helper contract.

This is deliberately a single conformance helper, not a supported Python SDK.
It uses one-shot stdio by default. When ``NQ_HELPER_SOCKET`` is set, it binds
one supervised Unix socket connection and serves sequential bounded exchanges.
It never writes logs to a protocol channel.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import signal
import socket
import stat
import sys
import time
from typing import Any


REQUEST_SCHEMA = "nq.helper.request.v1"
RESPONSE_SCHEMA = "nq.helper.response.v1"
REPORT_SCHEMA = "nq.evidence_report.v1"
PROTOCOL_VERSION = "nq.helper.v1"
PROFILE_ID = "nq.conformance"
PROFILE_VERSION = "1"
MAX_REQUEST_BYTES = 1_048_576
MAX_LOG_BYTES = 4_096
MAX_UNIX_PATH_BYTES = 100
TOKEN = re.compile(r"^[A-Za-z0-9._:/@-]{1,255}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

_shutdown_requested = False
_listen_socket: socket.socket | None = None
_connection: socket.socket | None = None


class InvalidRequest(ValueError):
    """The input is not one strict nq.helper.request.v1 document."""


def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidRequest(f"duplicate object key {key!r}")
        result[key] = value
    return result


def exact_keys(
    value: Any,
    required: set[str],
    optional: set[str] = frozenset(),
    *,
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidRequest(f"{field} must be an object")
    keys = set(value)
    if not required <= keys or not keys <= required | optional:
        raise InvalidRequest(
            f"{field} has wrong fields; required={sorted(required)!r}, "
            f"optional={sorted(optional)!r}, actual={sorted(keys)!r}"
        )
    return value


def token(value: Any, field: str) -> str:
    if not isinstance(value, str) or TOKEN.fullmatch(value) is None:
        raise InvalidRequest(f"{field} is not a protocol token")
    return value


def bounded_integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidRequest(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise InvalidRequest(f"{field} is outside [{minimum}, {maximum}]")
    return value


def validate_request(request: Any) -> dict[str, Any]:
    request = exact_keys(
        request,
        {
            "schema",
            "protocol_version",
            "request_id",
            "instance_id",
            "profile",
            "binding",
            "granted_capabilities",
            "deadline",
            "bounds",
        },
        {"checkpoint"},
        field="request",
    )
    if request["schema"] != REQUEST_SCHEMA:
        raise InvalidRequest("unsupported request schema")
    if request["protocol_version"] != PROTOCOL_VERSION:
        raise InvalidRequest("unsupported protocol version")
    token(request["request_id"], "request_id")
    token(request["instance_id"], "instance_id")

    profile = exact_keys(
        request["profile"], {"id", "version", "digest"}, field="profile"
    )
    token(profile["id"], "profile.id")
    token(profile["version"], "profile.version")
    if not isinstance(profile["digest"], str) or DIGEST.fullmatch(profile["digest"]) is None:
        raise InvalidRequest("profile.digest is not a lowercase SHA-256 digest")

    binding = exact_keys(
        request["binding"], {"subject", "scope", "vantage"}, field="binding"
    )
    token(binding["subject"], "binding.subject")
    scope = exact_keys(binding["scope"], {"kind", "value"}, field="binding.scope")
    token(scope["kind"], "binding.scope.kind")
    vantage = exact_keys(
        binding["vantage"], {"kind", "value"}, field="binding.vantage"
    )
    token(vantage["kind"], "binding.vantage.kind")

    capabilities = request["granted_capabilities"]
    if not isinstance(capabilities, list):
        raise InvalidRequest("granted_capabilities must be an array")
    checked_capabilities = [token(item, "granted_capabilities[]") for item in capabilities]
    if len(set(checked_capabilities)) != len(checked_capabilities):
        raise InvalidRequest("granted_capabilities contains a duplicate")

    deadline = exact_keys(
        request["deadline"], {"clock", "expires_at_ns"}, field="deadline"
    )
    if deadline["clock"] != "linux_boottime":
        raise InvalidRequest("unsupported monotonic clock")
    deadline_text = deadline["expires_at_ns"]
    if (
        not isinstance(deadline_text, str)
        or re.fullmatch(r"[1-9][0-9]{0,19}", deadline_text) is None
        or int(deadline_text) > 2**64 - 1
    ):
        raise InvalidRequest("deadline.expires_at_ns must be a canonical decimal u64 string")

    bounds = exact_keys(
        request["bounds"],
        {
            "max_response_bytes",
            "max_observations",
            "max_payload_bytes",
            "max_coverage_entries",
            "max_report_errors",
            "max_checkpoint_bytes",
        },
        field="bounds",
    )
    bounded_integer(bounds["max_response_bytes"], "bounds.max_response_bytes", 256, 16 * 1_048_576)
    bounded_integer(bounds["max_observations"], "bounds.max_observations", 0, 65_535)
    bounded_integer(bounds["max_payload_bytes"], "bounds.max_payload_bytes", 0, 1_048_576)
    bounded_integer(bounds["max_coverage_entries"], "bounds.max_coverage_entries", 0, 4_096)
    bounded_integer(bounds["max_report_errors"], "bounds.max_report_errors", 0, 1_024)
    bounded_integer(bounds["max_checkpoint_bytes"], "bounds.max_checkpoint_bytes", 0, 1_048_576)
    if "checkpoint" in request:
        exact_keys(request["checkpoint"], {"value"}, field="checkpoint")
    return request


def request_echo(request: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "protocol_version",
        "request_id",
        "instance_id",
        "profile",
        "binding",
        "granted_capabilities",
        "checkpoint",
        "deadline",
        "bounds",
    )
    return {field: request[field] for field in fields if field in request}


def refusal(
    request: dict[str, Any],
    boundary: str,
    code: str,
    message: str,
    *,
    retriable: bool = False,
    details: Any = None,
) -> dict[str, Any]:
    return {
        "schema": RESPONSE_SCHEMA,
        "echo": request_echo(request),
        "outcome": {
            "kind": "refusal",
            "refusal": {
                "responsible_instance_id": request["instance_id"],
                "boundary": boundary,
                "code": code,
                "message": message,
                "retriable": retriable,
                "details": {} if details is None else details,
            },
        },
    }


def profile_outcome(request: dict[str, Any]) -> dict[str, Any]:
    profile = request["profile"]
    if profile["id"] != PROFILE_ID or profile["version"] != PROFILE_VERSION:
        return refusal(
            request,
            "profile",
            "unknown_profile",
            "this specimen implements only nq.conformance version 1",
            details={"supported_profile": PROFILE_ID, "supported_version": PROFILE_VERSION},
        )

    binding = request["binding"]
    scope = binding["scope"]
    vantage = binding["vantage"]
    if not binding["subject"].startswith("conformance:"):
        return refusal(
            request, "scope", "unsupported_scope", "subject must start with conformance:"
        )
    if scope["kind"] != "fixture" or not isinstance(scope["value"], dict):
        return refusal(
            request, "scope", "unsupported_scope", "scope must be a fixture object"
        )
    if set(scope["value"]) != {"id", "nonce"}:
        return refusal(
            request,
            "scope",
            "unsupported_scope",
            "fixture scope requires exactly id and nonce",
        )
    fixture_id = scope["value"]["id"]
    nonce = scope["value"]["nonce"]
    if not isinstance(fixture_id, str) or not fixture_id:
        return refusal(request, "scope", "unsupported_scope", "fixture id must be non-empty")
    if not isinstance(nonce, str) or not nonce:
        return refusal(request, "scope", "unsupported_scope", "nonce must be non-empty")
    if vantage["kind"] != "local" or vantage["value"] != {}:
        return refusal(
            request,
            "vantage",
            "unsupported_vantage",
            "conformance requires the empty local vantage",
        )

    bounds = request["bounds"]
    if bounds["max_observations"] < 1 or bounds["max_coverage_entries"] < 1:
        return refusal(
            request,
            "resource",
            "bounds_unsupported",
            "conformance requires one observation and one coverage declaration",
        )

    if hasattr(time, "CLOCK_BOOTTIME"):
        now_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        if now_ns >= int(request["deadline"]["expires_at_ns"]):
            return refusal(
                request,
                "deadline",
                "deadline_expired",
                "request deadline has expired",
                retriable=True,
            )

    observed_at = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    payload = {
        "evidence_basis": {
            "scope": scope,
            "vantage": vantage,
            "access_path": "process",
            "basis": "request_echo",
            "regime": "conformance",
            "capabilities_used": [],
        },
        "nonce": nonce,
    }
    payload_bytes = json.dumps(
        payload, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    if len(payload_bytes) > bounds["max_payload_bytes"]:
        return refusal(
            request,
            "resource",
            "bounds_unsupported",
            "conformance payload exceeds the requested payload bound",
        )

    report = {
        "schema": REPORT_SCHEMA,
        "profile": profile,
        "binding": binding,
        "observed_at": observed_at,
        "status": "complete",
        "coverage": [{"kind": "echo", "state": "complete"}],
        "observations": [
            {
                "ordinal": 0,
                "kind": "echo",
                "subject": binding["subject"],
                "observed_at": observed_at,
                "payload": payload,
            }
        ],
        "errors": [],
        "used_capabilities": [],
        "backend": {
            "implementation": {"name": "python-conformance", "version": "1"},
            "tools": [],
        },
    }
    return {
        "schema": RESPONSE_SCHEMA,
        "echo": request_echo(request),
        "outcome": {"kind": "report", "report": report},
    }


def encode_response(response: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            response,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def parse_request_frame(data: bytes, *, source: str) -> dict[str, Any]:
    """Decode and strictly validate one bounded LF-terminated request."""

    if len(data) > MAX_REQUEST_BYTES:
        raise InvalidRequest("request frame exceeds 1048576 bytes")
    if not data.endswith(b"\n") or not data[:-1] or b"\n" in data[:-1] or b"\r" in data[:-1]:
        raise InvalidRequest(
            f"{source} must contain exactly one LF-terminated JSON document"
        )
    try:
        request_value = json.loads(
            data[:-1].decode("utf-8"), object_pairs_hook=object_without_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidRequest(f"malformed UTF-8 JSON: {error}") from error
    return validate_request(request_value)


def response_for(request: dict[str, Any]) -> bytes | None:
    """Build a response, or ``None`` when the NQ-owned bound cannot fit one."""

    encoded = encode_response(profile_outcome(request))
    if len(encoded) > request["bounds"]["max_response_bytes"]:
        # No valid response can fit the NQ-owned bound. Producing no frame keeps
        # this acquisition failure distinct from a valid inner failed report.
        return None
    return encoded


def run_stdio() -> int:
    """Serve exactly one request on stdin/stdout."""

    data = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    request = parse_request_frame(data, source="stdin")
    encoded = response_for(request)
    if encoded is None:
        return 75
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


def validate_socket_path(raw_path: str) -> str:
    """Require a fresh absolute socket path in a directory owned by this uid."""

    if not raw_path or not os.path.isabs(raw_path):
        raise InvalidRequest("NQ_HELPER_SOCKET must be an absolute path")
    if len(os.fsencode(raw_path)) > MAX_UNIX_PATH_BYTES:
        raise InvalidRequest("NQ_HELPER_SOCKET is too long for a Unix socket")

    parent = os.path.dirname(raw_path)
    try:
        parent_stat = os.lstat(parent)
    except OSError as error:
        raise InvalidRequest(f"socket parent is unavailable: {error}") from error
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise InvalidRequest("socket parent must be a real directory")
    if parent_stat.st_uid != os.geteuid():
        raise InvalidRequest("socket parent must be owned by the helper uid")
    if parent_stat.st_mode & 0o022:
        raise InvalidRequest("socket parent must not be group- or world-writable")
    try:
        os.lstat(raw_path)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise InvalidRequest(f"cannot inspect socket path: {error}") from error
    else:
        raise InvalidRequest("socket path already exists")
    return raw_path


def request_shutdown(_signum: int, _frame: Any) -> None:
    """Interrupt blocking socket operations without emitting protocol output."""

    global _shutdown_requested
    _shutdown_requested = True
    for open_socket in (_connection, _listen_socket):
        if open_socket is not None:
            try:
                open_socket.close()
            except OSError:
                pass


def read_socket_frame(connection: socket.socket) -> bytes | None:
    """Read one bounded frame, returning ``None`` only for clean EOF."""

    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        chunk = connection.recv(min(65_536, MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            if not data:
                return None
            raise InvalidRequest("socket closed within a request frame")
        newline = chunk.find(b"\n")
        if newline >= 0:
            data.extend(chunk[: newline + 1])
            if newline + 1 != len(chunk):
                raise InvalidRequest("socket request contains bytes after its frame")
            return bytes(data)
        data.extend(chunk)
    raise InvalidRequest("request frame exceeds 1048576 bytes")


def run_unix(raw_path: str) -> int:
    """Serve sequential exchanges over exactly one supervised connection."""

    global _connection, _listen_socket
    path = validate_socket_path(raw_path)
    created_identity: tuple[int, int] | None = None
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    _listen_socket = listener
    try:
        listener.bind(path)
        # The validated non-writable parent prevents another uid from replacing
        # the just-bound path before this chmod.
        os.chmod(path, 0o600)
        created = os.lstat(path)
        if not stat.S_ISSOCK(created.st_mode):
            raise InvalidRequest("bound path is not a Unix socket")
        created_identity = (created.st_dev, created.st_ino)
        listener.listen(1)

        try:
            connection, _peer = listener.accept()
        except OSError:
            if _shutdown_requested:
                return 0
            raise
        _connection = connection
        listener.close()
        _listen_socket = None
        with connection:
            while not _shutdown_requested:
                try:
                    frame = read_socket_frame(connection)
                except OSError:
                    if _shutdown_requested:
                        return 0
                    raise
                if frame is None:
                    return 0
                request = parse_request_frame(frame, source="socket")
                encoded = response_for(request)
                if encoded is None:
                    return 75
                connection.sendall(encoded)
        return 0
    finally:
        _connection = None
        _listen_socket = None
        try:
            listener.close()
        except OSError:
            pass
        if created_identity is not None:
            try:
                current = os.lstat(path)
                if (
                    stat.S_ISSOCK(current.st_mode)
                    and (current.st_dev, current.st_ino) == created_identity
                ):
                    os.unlink(path)
            except FileNotFoundError:
                pass


def bounded_error(error: BaseException, *, label: str = "invalid request") -> None:
    """Write one bounded diagnostic to stderr."""

    message = f"{label}: {error}\n".encode("utf-8", errors="replace")
    sys.stderr.buffer.write(message[:MAX_LOG_BYTES])
    sys.stderr.buffer.flush()


def main() -> int:
    """Dispatch to the selected carrier."""

    socket_path = os.environ.get("NQ_HELPER_SOCKET")
    if socket_path is None:
        return run_stdio()
    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    return run_unix(socket_path)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InvalidRequest as error:
        # Bounded stderr is diagnostic only; malformed input has no trustworthy
        # request identity from which to construct a response echo.
        bounded_error(error)
        raise SystemExit(64) from error
    except OSError as error:
        bounded_error(error, label="helper failure")
        raise SystemExit(71) from error
    except Exception as error:  # Keep diagnostics off the protocol and bounded.
        bounded_error(error, label="internal helper failure")
        raise SystemExit(70) from error
