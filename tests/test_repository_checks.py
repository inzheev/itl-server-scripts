import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    'repository_checks', Path(__file__).resolve().parents[1] / 'tools/check_repository.py')
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class SecretChecks(unittest.TestCase):
    def test_synthetic_credentials_are_detected_without_echoing_values(self):
        fixtures = [
            'gh' + 'p_' + 'a' * 36,
            '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----',
            'password=' + '"' + 'synthetic-example' + '"',
            '.'.join(map(str, (10, 2, 3, 4))),
        ]
        for value in fixtures:
            with self.subTest(kind=fixtures.index(value)):
                findings = checks.secret_findings(value)
                self.assertTrue(findings)
                self.assertNotIn(value, repr(findings))

    def test_loopback_and_documentation_address_are_allowed(self):
        self.assertEqual(checks.secret_findings('127.0.0.1 203.0.113.1'), [])


if __name__ == '__main__':
    unittest.main()
