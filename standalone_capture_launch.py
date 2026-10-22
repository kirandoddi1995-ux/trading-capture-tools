"""Isolated capture dispatcher. Preview is zero I/O; never grants eligibility."""
from __future__ import annotations

import argparse
from datetime import date
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
from typing import Any


def trusted_gate(root: Path, sha: str) -> Any:
    """Reviewed entrypoint/interpreter/Git/OS are trust base, not hostile-OS defense."""
    import subprocess
    deadline = time.monotonic() + 5.0
    if re.fullmatch('[0-9a-f]{40}', sha) is None:
        raise ValueError('EXTERNAL_FULL_COMMIT_REQUIRED')
    env = {k: v for k, v in os.environ.items() if k.upper() in
           ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull, GIT_GRAFT_FILE=os.devnull)
    def git(*args: str) -> bytes:
        remaining = min(2.0, deadline - time.monotonic())
        if remaining <= 0:
            raise ValueError('BOOTSTRAP_TIME_BOUND')
        result = subprocess.run(['git', '--no-replace-objects', '--no-optional-locks',
            '-c', 'core.fsmonitor=false', '-C', str(root), *args], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining, check=False)
        if result.returncode or len(result.stdout) > 2_000_000:
            raise ValueError('SOURCE_GIT_ADMISSION_UNVERIFIED')
        return result.stdout
    if git('rev-parse', 'HEAD').decode().strip() != sha:
        raise ValueError('EXTERNAL_COMMIT_MISMATCH')
    blobs: dict[str, bytes] = {}
    for name in ('standalone_capture_launch.py', 'standalone_capture_contract.py'):
        path = root / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or getattr(info, 'st_file_attributes', 0) & 0x400 or info.st_size > 1_000_000):
            raise ValueError('SINGLE_LINK_BOOTSTRAP_REQUIRED')
        blob = git('show', sha + ':' + name).replace(b'\r\n', b'\n')
        if path.read_bytes().replace(b'\r\n', b'\n') != blob:
            raise ValueError('COMMITTED_BOOTSTRAP_REQUIRED')
        blobs[name] = blob
    gate = types.ModuleType('standalone_capture_contract')
    gate.__file__ = str(root / 'standalone_capture_contract.py')
    exec(compile(blobs['standalone_capture_contract.py'], gate.__file__, 'exec'), gate.__dict__)
    if time.monotonic() >= deadline:
        raise ValueError('BOOTSTRAP_TIME_BOUND')
    return gate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation', choices=('session', 'schedule', 'versioned', 'diagnostic', 'plan', 'calendar', 'prepared', 'health'), default='session')
    parser.add_argument('--reviewed-source', default='')
    parser.add_argument('--confirm-run', action='store_true')
    args, tail = parser.parse_known_args(argv)
    if tail[:1] == ['--']:
        tail = tail[1:]
    if not args.confirm_run:
        print(json.dumps({'status': 'PREVIEW', 'writes': 0, 'source_reads': 0, 'credential_reads': 0, 'capture_invocations': 0}))
        return 0
    stage = 'ISOLATED_STARTUP'
    started = time.monotonic()
    try:
        if not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and sys.version_info[:3] == (3, 13, 9)):
            raise ValueError('ISOLATED_3139_STARTUP_REQUIRED')
        root = Path(__file__).resolve().parent
        if any(value for key, value in os.environ.items() if key.upper() in {
                'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR',
                'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY'}):
            raise ValueError('CAPTURE_TLS_CONTEXT_REVIEW_REQUIRED')
        stage = 'SOURCE_ADMISSION'
        gate = trusted_gate(root, args.reviewed_source)
        if gate.validate(root, commit=args.reviewed_source):
            raise ValueError('SOURCE_HASH_MISMATCH')
        stage = 'RUNTIME_ADMISSION'
        gate.runtime_check(root)
        if time.monotonic() - started > 15.0:
            raise ValueError('CAPTURE_ADMISSION_TIME_BOUND')
        expected_executable = root / '.venv' / ('Scripts/python.exe' if sys.platform == 'win32' else 'bin/python')
        if Path(sys.executable).absolute() != expected_executable.absolute():
            raise ValueError('BOUND_CAPSULE_INTERPRETER_REQUIRED')
        site = root / '.venv' / ('Lib/site-packages' if sys.platform == 'win32' else 'lib/python3.13/site-packages')
        sys.path[:0] = [str(root), str(site)]  # No site/.pth/customize execution.
        sys.modules['standalone_capture_contract'] = gate
        gate.ADMITTED_COMMIT = args.reviewed_source
        stage = 'GUARDED_PRODUCT_DISPATCH'
        if args.operation == 'calendar':
            calendar = importlib.import_module('nifty_session_calendar')
            close = importlib.import_module('nifty_previous_close')
            day = date.fromisoformat(tail[0])
            previous = close.previous_session(day)
            print(json.dumps({'kind': calendar.cash_session(day)['kind'], 'previous': previous.isoformat(),
                              'filename': 'ind_close_all_' + previous.strftime('%d%m%Y') + '.csv'}))
            return 0
        if args.operation == 'prepared':
            readiness = importlib.import_module('forward_morning_readiness')
            spec = readiness.ReadinessSpec(date.fromisoformat(tail[0]), str(root), str(expected_executable), tail[1], tail[2])
            if readiness._prepared(spec) != 'VERIFIED':
                raise ValueError('PREPARED_BINDING_UNVERIFIED')
            print(json.dumps({'status': 'PREPARED_BINDING_VERIFIED_NOT_CAPTURE'}))
            return 0
        if args.operation == 'health':
            host = importlib.import_module('forward_ops_host')
            daily = importlib.import_module('forward_daily_contract')
            report = host.preflight(date.fromisoformat(tail[0]), tail[1], tail[2], Path(tail[4]),
                                    root=Path(tail[3]), ops=Path(tail[4]))
            accepted = daily.accepted_admission_health(report, tail[1], tail[2], host.MIN_FREE_BYTES)
            if not accepted and report.get('status') == 'PREOPEN_HOST_CHECK_PASSED':
                report.update(status='BLOCKED', code='ADMISSION_HEALTH_NOT_VERIFIED')
            print(json.dumps(report))
            return 0 if accepted else 2
        module = importlib.import_module({'session': 'forward_session_ops', 'schedule': 'forward_nifty_schedule',
            'versioned': 'forward_versioned_capture', 'diagnostic': 'future_ops_diagnostics', 'plan': 'forward_ops_plan'}[args.operation])
        return int(module.main(tail))
    except Exception:
        print(json.dumps({'status': 'BLOCKED', 'code': 'ISOLATED_CAPTURE_ADMISSION_REVIEW_REQUIRED',
                          'stage': stage, 'raw_error_printed': False, 'retry_authorised': False,
                          'approval_authority': False, 'training_eligible': False}))
        return 3  # Distinct admission/unknown-outcome failure reaches wrapper notification.


if __name__ == '__main__':
    raise SystemExit(main())
