#!/usr/bin/env python3
"""Rootless repository checks; never execute administrative scripts."""

import ast
import ipaddress
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    'private key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    'GitHub token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b'),
    'AWS access key': re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'assigned credential': re.compile(
        r'''(?i)\b(?:password|passwd|api_key|access_token|client_secret)\s*[:=]\s*["'][^"'\s]{8,}["']'''),
}
ADDRESS = re.compile(r'(?<![\w.:])(?:\d{1,3}\.){3}\d{1,3}(?![\w.:])')


def secret_findings(text):
    """Return line/category only; never echo a credential into CI logs."""
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        for label, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append((number, label))
        for match in ADDRESS.finditer(line):
            try:
                address = ipaddress.ip_address(match.group())
            except ValueError:
                continue
            if any(address in network for network in (
                    ipaddress.ip_network((0x0A000000, 8)),
                    ipaddress.ip_network((0xAC100000, 12)),
                    ipaddress.ip_network((0xC0A80000, 16)))):
                findings.append((number, 'internal IPv4 address'))
    return findings


def main():
    # Include ignored files if tracked; do not scan untracked local credentials.
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT,
                            check=True, capture_output=True, timeout=15)
    paths = [ROOT / path.decode('utf-8') for path in result.stdout.split(b'\0') if path]
    if not paths:
        print('ERROR: no tracked files; stage the intended files before checking.')
        return 1
    errors, python_count, bash_count = [], 0, 0
    for path in paths:
        if path.is_symlink() or not path.is_file():
            errors.append(f'{path.relative_to(ROOT)}: expected a regular file')
            continue
        try:
            content = path.read_text(encoding='utf-8')
        except UnicodeError:
            errors.append(f'{path.relative_to(ROOT)}: unexpected binary file; review manually')
            continue
        for number, label in secret_findings(content):
            errors.append(f'{path.relative_to(ROOT)}:{number}: possible {label}')
        if path.suffix == '.py':
            python_count += 1
            try:
                ast.parse(content, filename=str(path))
            except SyntaxError as exc:
                errors.append(f'{path.relative_to(ROOT)}:{exc.lineno}: invalid Python syntax')
        if path.suffix in ('.sh', '.bash') or re.match(r'#![^\n]*\b(?:bash|sh)\b', content):
            bash_count += 1
            check = subprocess.run(['bash', '-n', str(path)], capture_output=True,
                                   text=True, timeout=15)
            if check.returncode:
                errors.append(f'{path.relative_to(ROOT)}: invalid Bash syntax')
    for error in errors:
        print('ERROR:', error)
    print(f'Checked {len(paths)} tracked files; Python: {python_count}; Bash: {bash_count}; '
          f'findings: {len(errors)}.')
    return bool(errors)


if __name__ == '__main__':
    sys.exit(main())
