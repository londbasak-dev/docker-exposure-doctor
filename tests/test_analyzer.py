import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from docker_exposure_doctor.analyzer import analyze, load_compose, SafeError
from docker_exposure_doctor.cli import main


def codes(document):
    return {item['rule'] for item in analyze(document)}


class ComposeTests(unittest.TestCase):
    def test_privileged_host_network_and_pid(self):
        found = codes({'services': {'web': {'privileged': True, 'network_mode': 'host', 'pid': 'host', 'user': '1000'}}})
        self.assertTrue({'privileged', 'host-network', 'host-pid'} <= found)

    def test_false_privileged_not_flagged(self):
        self.assertNotIn('privileged', codes({'services': {'web': {'privileged': False}}}))

    def test_docker_socket_in_short_and_long_mounts(self):
        for volume in ('/var/run/docker.sock:/var/run/docker.sock:ro', {'type': 'bind', 'source': '/run/docker.sock', 'target': '/socket'}):
            self.assertIn('docker-socket', codes({'services': {'web': {'volumes': [volume]}}}))

    def test_broad_bind_mount_but_not_named_volume(self):
        self.assertIn('broad-host-mount', codes({'services': {'web': {'volumes': ['/:/host:ro']}}}))
        self.assertIn('broad-host-mount', codes({'services': {'web': {'volumes': [{'type': 'bind', 'source': '/', 'target': '/host'}]}}}))
        self.assertNotIn('broad-host-mount', codes({'services': {'web': {'volumes': ['cache:/cache']}}}))

    def test_short_ports_loopback_and_wildcard(self):
        for port in ('8080:80', '0.0.0.0:8080:80', '[::]:8080:80'):
            self.assertIn('published-port', codes({'services': {'web': {'ports': [port]}}}))
        for port in ('127.0.0.1:8080:80', '[::1]:8080:80'):
            found = codes({'services': {'web': {'ports': [port]}}})
            self.assertNotIn('published-port', found)
            self.assertIn('loopback-port', found)

    def test_long_ports_loopback(self):
        found = codes({'services': {'web': {'ports': [{'target': 80, 'published': '8080', 'host_ip': '127.0.0.1'}]}}})
        self.assertIn('loopback-port', found)
        self.assertNotIn('published-port', found)

    def test_explicit_root_and_unspecified_user(self):
        for user in ('root', '0', '0:1000', 'root:root', '00', '+0', '000:1000'):
            self.assertIn('root-user', codes({'services': {'web': {'user': user}}}))
        self.assertIn('image-user-unknown', codes({'services': {'web': {}}}))
        self.assertNotIn('root-user', codes({'services': {'web': {'user': '1000:1000'}}}))

    def test_normalized_absolute_bind_mounts_and_named_volumes(self):
        for volume in ('/./:/host:ro', '/etc/.:/host:ro', {'type': 'bind', 'source': '/etc/..', 'target': '/host'}):
            self.assertIn('broad-host-mount', codes({'services': {'web': {'user': '1000', 'volumes': [volume]}}}))
        for volume in ('docker.sock:/cache', 'docker_engine:/cache'):
            document = {'services': {'web': {'user': '1000', 'volumes': [volume]}}, 'volumes': {volume.split(':')[0]: {}}}
            self.assertNotIn('docker-socket', codes(document))

    def test_mapped_ipv6_loopback(self):
        found = codes({'services': {'web': {'ports': ['[::ffff:127.0.0.1]:8080:80']}}})
        self.assertIn('loopback-port', found)
        self.assertNotIn('published-port', found)

    def test_unknown_argument_is_not_echoed(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            main(['synthetic-compose', '--SYNTHETIC_PRIVATE_ARG'])
        self.assertNotIn('SYNTHETIC_PRIVATE_ARG', stderr.getvalue())

    def test_inline_secret_never_leaks_values(self):
        for env in ({'API_TOKEN': 'SYNTHETIC_ONLY_VALUE'}, ['PASSWORD=SYNTHETIC_ONLY_VALUE']):
            result = analyze({'services': {'web': {'environment': env}}})
            self.assertIn('inline-secret', {f['rule'] for f in result})
            self.assertNotIn('SYNTHETIC_ONLY_VALUE', json.dumps(result))
        self.assertNotIn('inline-secret', codes({'services': {'web': {'environment': {'TOKEN': '${TOKEN}'}}}}))

    def test_yaml_unsafe_duplicate_and_alias_rejection(self):
        for content in ('!!python/object/apply:os.system [echo synthetic]', 'services: {}\nservices: {}', 'x: &x [*x]\nservices: {}'):
            with self.assertRaises(SafeError):
                load_compose(content)

    def test_schema_and_size_errors(self):
        for content in ('[]', 'services: []', 'services:\n  web: null'):
            with self.assertRaises(SafeError):
                analyze(load_compose(content))
        with self.assertRaises(SafeError):
            load_compose('x'*100, max_bytes=10)

    def test_cli_json_and_safe_error(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'compose.yaml'
            path.write_text('services:\n  web:\n    environment:\n      PASSWORD: SYNTHETIC_ONLY_VALUE\n')
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main([str(path), '--format', 'json']), 0)
            self.assertNotIn('SYNTHETIC_ONLY_VALUE', out.getvalue())
            self.assertIn('findings', json.loads(out.getvalue()))
            path.write_text('services: [SYNTHETIC_ONLY_VALUE')
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(main([str(path)]), 2)
            self.assertNotIn('SYNTHETIC_ONLY_VALUE', err.getvalue())

    def test_fail_on_high_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'compose.yaml'
            path.write_text('services:\n  web:\n    privileged: true\n')
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), '--fail-on', 'high']), 1)


if __name__ == '__main__':
    unittest.main()
