"""Replay the shipped config preflight with a supplied actual NQ executable.

NQ_TEST_BINARY may be the executable itself or the established read-only
public-account overlay wrapper. No database, daemon or helper is started.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


class PackagedPreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        binary = os.environ.get('NQ_TEST_BINARY')
        if not binary:
            raise unittest.SkipTest('set NQ_TEST_BINARY to the actual NQ executable')
        cls.binary = str(Path(binary).resolve())
        unit = Path(__file__).with_name('nqd.service').read_text()
        commands = [shlex.split(line.removeprefix('ExecStartPre='))
                    for line in unit.splitlines() if line.startswith('ExecStartPre=/usr/bin/nq ')]
        if len(commands) != 1:
            raise AssertionError('expected exactly one actual packaged NQ config preflight')
        cls.preflight = commands[0]

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def config(self, *, policy='broken', profile='nq.conformance'):
        binding = ''
        if policy != 'missing':
            data = b'{invalid policy JSON\n'
            document = self.root / 'policy.json'
            document.write_bytes(data)
            digest = 'sha256:' + hashlib.sha256(data).hexdigest()
            binding = ('\n[escalation_policy]\npath = ' + json.dumps(str(document))
                       + '\nsha256 = ' + json.dumps(digest) + '\n')
        text = f'''schema = "nq.config.v1"
database_path = "{self.root}/absent.db"
socket_path = "{self.root}/absent.sock"
admissions_dir = "{self.root}/absent-admissions"
helper_runtime_dir = "{self.root}/absent-helpers"
{binding}
[[watchers]]
instance_id = "conformance.preflight"
subject = "conformance:preflight"
scope = {{ kind = "fixture", value = {{ id = "preflight", nonce = "preflight-nonce" }} }}
vantage = {{ kind = "local", value = {{}} }}
capability_ceiling = []
[watchers.command]
executable = "/usr/bin/true"
execution_account = "nq-helper"
working_directory = "/"
[watchers.profile]
id = "{profile}"
version = 1
[watchers.schedule]
interval_seconds = 60
jitter_seconds = 0
deadline_ms = 5000
retry_backoff_seconds = 1
max_retry_backoff_seconds = 10
[watchers.resources]
max_response_bytes = 1048576
max_stderr_bytes = 65536
max_observations = 4
max_address_space_bytes = 536870912
max_cpu_seconds = 60
max_processes = 32
max_open_files = 128
max_file_bytes = 67108864
'''
        path = self.root / 'nq.toml'
        path.write_text(text)
        return path

    def run_preflight(self, config):
        # Substitute only the actual ELF locator and isolated config path.
        # The option selecting validation scope must come from the unit itself.
        command = [self.binary] + [('--config=' + str(config)) if arg == '--config=/etc/nq/nq.toml'
                                    else arg for arg in self.preflight[1:]]
        return subprocess.run(command, text=True, capture_output=True)

    def test_packaged_preflight_observes_with_missing_or_broken_delivery_policy(self):
        for policy in ('missing', 'broken'):
            with self.subTest(policy=policy):
                result = self.run_preflight(self.config(policy=policy))
                self.assertEqual(result.returncode, 0, json.dumps({'argv': result.args, 'stderr': result.stderr}))
                report = json.loads(result.stdout)
                self.assertEqual(report['scope'], 'observation')
                self.assertIs(report['observation_valid'], True)
                self.assertIs(report['notification_policy_checked'], False)
                self.assertNotIn('valid', report)
                self.assertFalse((self.root / 'absent.db').exists())
                self.assertFalse((self.root / 'absent-admissions').exists())

    def test_packaged_preflight_still_refuses_malformed_observation_config(self):
        config = self.config()
        config.write_text(config.read_text().replace('schema = "nq.config.v1"', 'schema = "invalid"'))
        result = self.run_preflight(config)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected nq.config.v1', result.stderr)

    def test_packaged_preflight_still_refuses_uncompiled_observation_profile(self):
        result = self.run_preflight(self.config(profile='nq.not_compiled'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not compiled', result.stderr)

    def test_strict_default_config_check_still_refuses_broken_policy(self):
        config = self.config()
        result = subprocess.run([self.binary, '--config', str(config), '--json', 'config', 'check'],
                                text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid escalation policy document', result.stderr)


if __name__ == '__main__':
    unittest.main()
