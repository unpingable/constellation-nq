#!/usr/bin/env python3
"""Black-box tests for the Python conformance specimen."""

from __future__ import annotations

import json
import errno
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import unittest


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
HELPER = HERE / "nq_conformance_helper.py"
REQUEST = ROOT / "protocol" / "fixtures" / "valid" / "request.ndjson"


class HelperTest(unittest.TestCase):
    def request(self) -> dict:
        value = json.loads(REQUEST.read_text(encoding="utf-8"))
        if hasattr(time, "CLOCK_BOOTTIME"):
            value["deadline"]["expires_at_ns"] = str(
                time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 30_000_000_000
            )
        return value

    def run_helper(self, request: dict) -> subprocess.CompletedProcess[bytes]:
        frame = (
            json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
        )
        return subprocess.run(
            [str(HELPER)],
            input=frame,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )

    def test_emits_one_exact_echo_report(self) -> None:
        request = self.request()
        result = self.run_helper(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.stdout.count(b"\n"), 1)
        response = json.loads(result.stdout)
        self.assertEqual(response["echo"]["request_id"], request["request_id"])
        report = response["outcome"]["report"]
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["observations"][0]["kind"], "echo")
        self.assertEqual(
            report["observations"][0]["payload"]["nonce"],
            request["binding"]["scope"]["value"]["nonce"],
        )

    def test_unsupported_profile_is_a_typed_refusal(self) -> None:
        request = self.request()
        request["profile"]["id"] = "nq.unknown"
        result = self.run_helper(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        response = json.loads(result.stdout)
        self.assertEqual(response["outcome"]["kind"], "refusal")
        self.assertEqual(
            response["outcome"]["refusal"]["code"], "unknown_profile"
        )

    def test_duplicate_input_key_produces_no_response(self) -> None:
        result = subprocess.run(
            [str(HELPER)],
            input=b'{"schema":"x","schema":"y"}\n',
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        self.assertEqual(result.stdout, b"")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"duplicate object key", result.stderr)


class UnixHelperTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not hasattr(socket, "AF_UNIX"):
            raise unittest.SkipTest("AF_UNIX is unavailable")
        with tempfile.TemporaryDirectory(prefix="nq-unix-probe-") as directory:
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.bind(str(pathlib.Path(directory) / "probe.sock"))
            except OSError as error:
                if error.errno in {errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT}:
                    raise unittest.SkipTest(f"AF_UNIX denied: {error}") from error
                raise
            finally:
                probe.close()

    def request(self) -> dict:
        value = json.loads(REQUEST.read_text(encoding="utf-8"))
        if hasattr(time, "CLOCK_BOOTTIME"):
            value["deadline"]["expires_at_ns"] = str(
                time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 30_000_000_000
            )
        return value

    def frame(self, request: dict) -> bytes:
        return json.dumps(
            request, sort_keys=True, separators=(",", ":")
        ).encode() + b"\n"

    def start(self, path: pathlib.Path) -> subprocess.Popen[bytes]:
        environment = os.environ.copy()
        environment["NQ_HELPER_SOCKET"] = str(path)
        process = subprocess.Popen(
            [str(HELPER)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        deadline = time.monotonic() + 3
        while not path.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate(timeout=1)
                self.fail(
                    f"Unix helper exited before binding: {process.returncode}; "
                    f"stdout={stdout!r}; stderr={stderr!r}"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate(timeout=1)
                self.fail("Unix helper did not bind its socket")
            time.sleep(0.01)
        return process

    def read_frame(self, connection: socket.socket) -> dict:
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = connection.recv(65_536)
            self.assertNotEqual(chunk, b"", "helper closed before its response")
            data.extend(chunk)
        self.assertEqual(data.count(b"\n"), 1)
        return json.loads(data)

    def test_sequential_exchanges_use_one_private_connection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-helper-") as directory:
            path = pathlib.Path(directory) / "helper.sock"
            process = self.start(path)
            mode = path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(str(path))
                first = self.request()
                connection.sendall(self.frame(first))
                first_response = self.read_frame(connection)
                self.assertEqual(
                    first_response["echo"]["request_id"], first["request_id"]
                )

                second = self.request()
                second["request_id"] = "request-python-unix-2"
                second["binding"]["scope"]["value"]["nonce"] = "nonce-2"
                connection.sendall(self.frame(second))
                second_response = self.read_frame(connection)
                self.assertEqual(
                    second_response["echo"]["request_id"], second["request_id"]
                )
                self.assertEqual(
                    second_response["outcome"]["report"]["observations"][0][
                        "payload"
                    ]["nonce"],
                    "nonce-2",
                )
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"")
            self.assertFalse(path.exists())

    def test_malformed_frame_closes_with_bounded_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-helper-") as directory:
            path = pathlib.Path(directory) / "helper.sock"
            process = self.start(path)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(str(path))
                connection.sendall(b'{"schema":"x","schema":"y"}\n')
                self.assertEqual(connection.recv(1), b"")
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 64)
            self.assertEqual(stdout, b"")
            self.assertIn(b"duplicate object key", stderr)
            self.assertLessEqual(len(stderr), 4096)
            self.assertFalse(path.exists())

    def test_termination_while_waiting_is_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="nq-helper-") as directory:
            path = pathlib.Path(directory) / "helper.sock"
            process = self.start(path)
            process.terminate()
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"")
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
