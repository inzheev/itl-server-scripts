#!/usr/bin/env python3
"""Disable root password authentication in a standard systemd OpenSSH install.

Debian 12/13 and Ubuntu 22.04/24.04; Python 3, no third-party packages.
Run as root:
  python3 disable_root_ssh_password.py --check    # inspect, no changes
  python3 disable_root_ssh_password.py --restart  # apply and restart SSH
  python3 disable_root_ssh_password.py            # apply using reload

Only explicit PermitRootLogin yes values are changed. Includes are traversed
even inside Match blocks. Existing no/forced-commands-only values are retained.
This audits SSH policy, not the account password, PAM, firewall or reachability.
Test a separate root key login before applying. Existing MFA requirements are
not rewritten; detected password-dependent MFA in checked contexts aborts the run.
Before editing, password-dependent AuthenticationMethods anywhere in the Include
graph also cause a conservative refusal, even for an untested Match context.

Backups: /var/backups/ssh-root-password-*/ (original absolute directory tree).
Exit status: 0 = applied / safe policy; 2 = --check found permissive directives;
1 = error. No network downloads, password changes or package installation.
"""

from __future__ import annotations

import argparse
import datetime
import fcntl
import glob
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


CONFIG = Path('/etc/ssh/sshd_config')
INCLUDE_BASE = Path('/etc/ssh')
BACKUP_BASE = Path('/var/backups')
LOCK = Path('/run/lock/disable-root-ssh-password.lock')
SAFE_ROOT_VALUES = {'no', 'prohibit-password', 'without-password', 'forced-commands-only'}
SYSTEMCTL = '/usr/bin/systemctl'
ENV = {**os.environ, 'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}


class Failure(Exception):
    pass


def run(args, *, check=True):
    try:
        result = subprocess.run(args, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', env=ENV, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Failure(f'Не удалось выполнить {args[0]}: {exc}') from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise Failure(f'Команда завершилась с ошибкой: {shlex.join(map(str, args))}\n{detail}')
    return result


def say(message):
    print(message, flush=True)


def service_info(unit):
    result = run([SYSTEMCTL, 'show', unit, '--no-pager',
                  '--property=Id,ActiveState,MainPID,CanReload,KillMode'], check=False)
    if result.returncode:
        return {}
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def select_service():
    active = {}
    for name in ('ssh.service', 'sshd.service'):
        info = service_info(name)
        if info.get('ActiveState') == 'active':
            active[info['Id']] = info
    if len(active) != 1:
        raise Failure('Ожидалась одна работающая служба ssh.service или sshd.service. '
                      'Нестандартный запуск, несколько служб и неактивная служба не поддерживаются.')
    return next(iter(active.values()))


def verify_runtime(info):
    """Reject alternate configs/command-line overrides rather than audit the wrong file."""
    pid = int(info.get('MainPID', '0'))
    if pid <= 0:
        raise Failure('Не удалось определить главный процесс SSH.')
    try:
        binary = Path(os.readlink(f'/proc/{pid}/exe'))
        raw = Path(f'/proc/{pid}/cmdline').read_bytes()
    except OSError as exc:
        raise Failure(f'Не удалось проверить процесс SSH: {exc}') from exc
    if (not binary.is_file() or
            binary.resolve() != Path('/usr/sbin/sshd').resolve()):
        raise Failure('Ожидался стандартный /usr/sbin/sshd из системного пакета OpenSSH.')
    parts = [part.decode('utf-8', 'strict') for part in raw.split(b'\0') if part]
    if not parts:
        raise Failure('Пустая командная строка процесса SSH.')
    if parts[0].startswith('sshd:'):
        title = re.fullmatch(r'sshd:\s+(.+?)\s+\[listener\](?:\s.*)?', parts[0])
        if not title:
            raise Failure('Формат заголовка процесса SSH не распознан; изменений нет.')
        parts = shlex.split(title.group(1))
    if not parts or Path(parts[0]).resolve() != binary.resolve():
        raise Failure('Нестандартная командная строка SSH; изменений нет.')
    if any(not re.fullmatch(r'-[Deq46]+', part) for part in parts[1:]):
        raise Failure('SSH запущен с дополнительными параметрами (например, -f, -o или -p). '
                      'Этот скрипт предназначен для стандартного запуска с /etc/ssh/sshd_config.')
    return str(binary)


def strip_comment(line):
    """OpenSSH keeps # inside a token; a # starting an unquoted token is a comment."""
    quote = None
    escaped = False
    boundary = True
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            boundary = False
            continue
        if char == '\\':
            escaped = True
            boundary = False
            continue
        if quote:
            if char == quote:
                quote = None
            boundary = False
            continue
        if char in ('"', "'"):
            quote = char
            boundary = False
        elif char == '#' and boundary:
            return line[:index]
        else:
            boundary = char.isspace()
    return line


def directive(line, source):
    content = strip_comment(line).strip()
    if not content:
        return '', [], ''
    # sshd -t validates the complete syntax. Only the two relevant directives
    # need interpretation here; shell-like quoting and keyword=value are valid.
    try:
        words = shlex.split(content, comments=False, posix=True)
    except ValueError as exc:
        raise Failure(f'Не удалось разобрать {source}: {exc}') from exc
    first, *args = words
    if '=' in first:
        keyword, value = first.split('=', 1)
        args = ([value] if value else []) + args
    else:
        keyword = first
        if args and args[0].startswith('='):
            value = args.pop(0)[1:]
            if value:
                args.insert(0, value)
    keyword = keyword.lower()
    if keyword in ('include', 'permitrootlogin') and '\\' in content:
        raise Failure(f'Экранирование в {source} не поддерживается; изменений нет.')
    return keyword, args, line[len(strip_comment(line)):].rstrip('\r\n')


def scan_configs(main=CONFIG):
    """Read every reachable Include, independent of whether its Match is active."""
    originals, replacements, locations = {}, {}, []

    def visit(path, stack=()):
        path = path.resolve(strict=True)
        if path in stack or len(stack) >= 16:
            raise Failure(f'Циклический или слишком глубокий Include: {path}')
        if path in originals:
            return
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise Failure(f'Ожидался обычный конфиг root без записи для группы/остальных: {path}')
        data = path.read_bytes()
        originals[path] = data
        lines = data.decode('utf-8', 'surrogateescape').splitlines(keepends=True)
        output = []
        for number, line in enumerate(lines, 1):
            source = f'{path}:{number}'
            keyword, args, comment = directive(line, source)
            if keyword == 'include':
                if not args:
                    raise Failure(f'Пустой Include: {source}')
                for pattern in args:
                    # Fail closed for uncommon libc glob constructs that Python
                    # glob does not implement identically.
                    if (pattern.startswith('~') or '\\' in pattern or
                            any(mark in pattern for mark in ('[', ']', '\n', '\r'))):
                        raise Failure(f'Нестандартный шаблон Include в {source}; изменений нет.')
                    full = Path(pattern) if os.path.isabs(pattern) else INCLUDE_BASE / pattern
                    for included in sorted(glob.glob(str(full))):
                        visit(Path(included), (*stack, path))
            elif keyword == 'permitrootlogin':
                if len(args) != 1 or args[0] not in SAFE_ROOT_VALUES | {'yes'}:
                    raise Failure(f'Не распознано значение PermitRootLogin в {source}.')
                if args[0] == 'yes':
                    indent = line[:len(line) - len(line.lstrip(' \t'))]
                    ending = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
                    line = indent + 'PermitRootLogin prohibit-password'
                    if comment:
                        line += '  ' + comment
                    line += ending
                    locations.append(source)
            output.append(line)
        changed = ''.join(output).encode('utf-8', 'surrogateescape')
        if changed != data:
            if info.st_nlink != 1:
                raise Failure(f'Конфиг имеет несколько жестких ссылок: {path}; изменений нет.')
            replacements[path] = changed

    visit(main)
    return originals, replacements, locations


def effective(binary, connection=None):
    command = [binary, '-T', '-f', str(CONFIG)]
    if connection:
        command += ['-C', connection]
    output = run(command).stdout
    return dict(line.split(None, 1) for line in output.splitlines() if ' ' in line)


def root_contexts():
    contexts = ['user=root,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22',
                'user=root,host=localhost,addr=::1,laddr=::1,lport=22']
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) == 4:
        addr, _, local, port = connection
        # host is an IP here, not a reverse DNS result. All Match branches are
        # covered structurally by scanning the complete Include graph.
        contexts.append(f'user=root,host={addr},addr={addr},laddr={local},lport={port}')
    return list(dict.fromkeys(contexts))


def verify_policy(binary):
    _, pending, _ = scan_configs(CONFIG)
    if pending:
        raise Failure('В подключенных конфигах все еще есть PermitRootLogin yes.')
    policies = [effective(binary)] + [effective(binary, item) for item in root_contexts()]
    for policy in policies:
        if policy.get('permitrootlogin') not in SAFE_ROOT_VALUES:
            raise Failure('Итоговая конфигурация все еще допускает парольную аутентификацию root.')


def check_mfa(binary, originals):
    # Sampled -T contexts cannot cover every Match Address/Host/Group branch.
    # Refuse conservatively when any reachable directive requires a method
    # disabled by prohibit-password, rather than silently breaking key + MFA.
    for path, data in originals.items():
        for number, line in enumerate(data.decode('utf-8', 'surrogateescape').splitlines(), 1):
            keyword, args, _ = directive(line, f'{path}:{number}')
            if keyword != 'authenticationmethods' or args == ['any']:
                continue
            alternatives = [entry.split(',') for entry in args]
            usable = any(not any(method.split(':')[0] in ('password', 'keyboard-interactive')
                                 for method in alternative) for alternative in alternatives)
            key_paths = [alternative for alternative in alternatives if 'publickey' in alternative]
            usable_key = any(not any(method.split(':')[0] in ('password', 'keyboard-interactive')
                                     for method in alternative) for alternative in key_paths)
            if not usable or (key_paths and not usable_key):
                raise Failure(f'Парольная AuthenticationMethods в {path}:{number}. '
                              'Невозможно безопасно исключить влияние на root во всех Match. '
                              'Нужна ручная проверка MFA; изменений нет.')
    for context in root_contexts():
        policy = effective(binary, context)
        methods = policy.get('authenticationmethods', 'any')
        if policy.get('permitrootlogin') != 'yes' or methods == 'any':
            continue
        alternatives = [entry.split(',') for entry in methods.split()]
        usable = any(not any(method == 'password' or method.split(':')[0] == 'keyboard-interactive'
                             for method in alternative) for alternative in alternatives)
        if not usable:
            raise Failure('Для root задана AuthenticationMethods с обязательным паролем или '
                          'keyboard-interactive. После запрета даже вход с ключом перестанет работать '
                          'в одном из проверенных контекстов. Сначала настрой отдельный рабочий '
                          'способ администрирования и скорректируй требование MFA. Изменений нет.')


def atomic_write(path, data, metadata_source):
    fd, name = tempfile.mkstemp(prefix=f'.{path.name}.itl-', dir=path.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        metadata = metadata_source.stat()
        shutil.copy2(metadata_source, temporary)
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
        with temporary.open('wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def apply_service(unit, action):
    run([SYSTEMCTL, action, unit])
    # A successful job is checked again after sshd has had time to re-exec.
    time.sleep(1)
    info = service_info(unit)
    if info.get('ActiveState') != 'active':
        raise Failure(f'После {action} служба {unit} не находится в состоянии active.')
    return verify_runtime(info)


def interrupted(signum, _frame):
    raise Failure(f'Выполнение прервано сигналом {signum}.')


def perform(args):
    info = select_service()
    unit = info['Id']
    binary = verify_runtime(info)
    action = 'restart' if args.restart else 'reload'
    run([binary, '-t', '-f', str(CONFIG)])
    originals, replacements, locations = scan_configs(CONFIG)
    if not args.check and replacements:
        if action == 'reload' and info.get('CanReload') != 'yes':
            raise Failure('Служба не поддерживает reload. Используй --restart после проверки доступа по ключу.')
        if action == 'restart' and info.get('KillMode') != 'process':
            raise Failure('У службы KillMode отличается от process: restart может завершить этот скрипт '
                          'вместе с SSH-сессией. Запусти без --restart для применения через reload.')
    global_policy = effective(binary)
    say(f'[INFO] Служба: {unit}; конфигов проверено: {len(originals)}.')
    say(f'[INFO] Глобальное PermitRootLogin: {global_policy.get("permitrootlogin", "unknown")}.')
    if global_policy.get('permitrootlogin') == 'yes' and not replacements:
        raise Failure('Глобальный запрет отсутствует, но разрешающая строка не найдена. '
                      'Необычная сборка или конфигурация SSH; автоматическое изменение отменено.')
    for location in locations:
        say(f'[FOUND] {location}: PermitRootLogin yes -> prohibit-password')
    if args.check:
        if replacements:
            say('[CHECK] Найдены разрешающие директивы. Ничего не изменено. '
                'Для применения запусти скрипт без --check.')
            return 2
        verify_policy(binary)
        say('[CHECK] В конфигурации вход root по паролю уже запрещен. '
            'Служба не перезапускалась; ее загруженная конфигурация этим режимом не проверяется.')
        return 0

    if not replacements:
        verify_policy(binary)
        say('[OK] В конфигурации вход root по паролю уже запрещен. '
            'Файлы и служба не изменялись; загруженная конфигурация службы не проверялась.')
        return 0

    check_mfa(binary, originals)

    backup_dir = None
    backups = {}
    if replacements:
        BACKUP_BASE.mkdir(mode=0o755, parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-')
        backup_dir = Path(tempfile.mkdtemp(prefix='ssh-root-password-' + stamp, dir=BACKUP_BASE))
        for path in replacements:
            target = backup_dir / str(path).lstrip('/')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copy2(path, target)
            source_stat = path.stat()
            os.chown(target, source_stat.st_uid, source_stat.st_gid)
            os.chmod(target, stat.S_IMODE(source_stat.st_mode))
            backups[path] = target
        say(f'[BACKUP] {backup_dir}')
    # Avoid silently overwriting a concurrent configuration change.
    for path, data in originals.items():
        if path.read_bytes() != data:
            raise Failure(f'Конфиг изменился во время проверки: {path}. Запусти скрипт повторно.')

    modified = []
    service_attempted = False
    try:
        for path, data in replacements.items():
            if path.read_bytes() != originals[path]:
                raise Failure(f'Конфиг дополнительно изменен другим процессом: {path}.')
            # Register before the atomic replacement so signals cannot leave
            # an untracked modification between the rename and bookkeeping.
            modified.append(path)
            atomic_write(path, data, backups[path])
        run([binary, '-t', '-f', str(CONFIG)])
        verify_policy(binary)
        service_attempted = True
        new_binary = apply_service(unit, action)
        verify_policy(new_binary)
    except (Exception, KeyboardInterrupt) as error:
        # A second Ctrl-C/SIGHUP must not interrupt restoration midway.
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        say(f'[ERROR] {error}')
        rollback_errors = []
        for path in reversed(modified):
            try:
                current = path.read_bytes()
                if current == originals[path]:
                    continue
                if current != replacements[path]:
                    raise Failure('файл дополнительно изменен другим процессом; автоматическая перезапись отменена')
                atomic_write(path, originals[path], backups[path])
            except Exception as exc:
                rollback_errors.append(f'{path}: {exc}')
        if not rollback_errors:
            try:
                run([binary, '-t', '-f', str(CONFIG)])
                if service_attempted:
                    current_info = service_info(unit)
                    if current_info.get('ActiveState') != 'active':
                        recovery = 'start'
                    else:
                        recovery = 'reload' if current_info.get('CanReload') == 'yes' else 'restart'
                    apply_service(unit, recovery)
            except Exception as exc:
                rollback_errors.append(str(exc))
        if rollback_errors:
            say('[CRITICAL] Восстановление завершено не полностью:\n' + '\n'.join(rollback_errors))
            if backup_dir:
                say(f'[CRITICAL] Резервные копии: {backup_dir}')
        else:
            say('[ROLLBACK] Исходные настройки восстановлены.' if modified
                else '[INFO] Файлы конфигурации не менялись.')
        return 1

    if replacements:
        say(f'[OK] Вход root по паролю и keyboard-interactive запрещен. '
            f'Изменено файлов: {len(replacements)}.')
    else:
        say('[OK] В конфигурации вход root по паролю уже был запрещен. Настройки повторно применены.')
    say(f'[OK] {unit}: {action} выполнен, служба active, итоговая политика проверена.')
    say('[INFO] Настройки SSH-ключей и запреты no/forced-commands-only сохранены. '
        'Проверь новое подключение по ключу перед закрытием текущего окна.')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='только проверить; код 2 означает найденные разрешения')
    mode.add_argument('--restart', action='store_true', help='применить через restart (по умолчанию reload)')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        say('[ERROR] Запусти скрипт от root.')
        return 1
    os.umask(0o077)
    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, interrupted)
        # A fixed lock also serializes --check with an in-progress application.
        descriptor = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'a') as lock:
            lock_stat = os.fstat(lock.fileno())
            if (not stat.S_ISREG(lock_stat.st_mode) or lock_stat.st_uid != 0 or
                    lock_stat.st_nlink != 1 or lock_stat.st_mode & 0o022):
                raise Failure('Небезопасные параметры файла блокировки; выполнение отменено.')
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Failure('Другой экземпляр скрипта уже работает.')
            return perform(args)
    except (Exception, KeyboardInterrupt) as exc:
        say(f'[ERROR] {exc}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
