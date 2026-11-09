# ITL Server Scripts

Repository of standalone Debian/Ubuntu administration scripts. Preserve the
original Python SSH tool; do not add a web stack or server framework.

- Python standard library only; development/CI Python is pinned in `.python-version`.
- Run `python3 tools/check_repository.py` and `python3 -m unittest discover -s tests -v`.
- Administrative code must never run against the build host's SSH configuration.
  Tests use temporary files, simulated ownership and mocked service commands.
- For changes to OpenSSH semantics, consult official OpenSSH documentation and
  test realistic Include/Match, rollback and no-change cases.
- Keep Russian README commands and script exit codes aligned with behavior.
- No secrets, actual server configurations, internal addresses or backup files.
- Release only after CI succeeds for the exact commit. Do not move release tags.
