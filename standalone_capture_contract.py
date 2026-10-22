"""Standard-library exact-tree admission; never capture, credentials or activation."""
from __future__ import annotations

import argparse
from contextvars import ContextVar
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time
from typing import Any

MANIFEST = 'CAPTURE_DISTRIBUTION.json'
PRODUCER = '1251530731cce5b75fad8601567b9320d07b710d'
CONTROLLER = '563665a32e5454633b0c27256072a7249503c520'
SEED_README = b'# Inactive capture repository\n\nNo capture is commissioned.\n'
DEADLINE: ContextVar[float | None] = ContextVar('capture_source_deadline', default=None)


def normalized_name(name: str) -> str:
    return re.sub('[-_.]+', '-', name).lower()


def check_deadline() -> None:
    deadline = DEADLINE.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise ValueError('SOURCE_ADMISSION_TIME_BOUND')


def public_name(value: object) -> str:
    if not isinstance(value, str) or len(value) > 160 or not value:
        raise ValueError('PUBLIC_PATH_INVALID')
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(p in ('', '.', '..') for p in path.parts):
        raise ValueError('PUBLIC_PATH_INVALID')
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or '\\' in value or ':' in value or any(p.casefold() in {
        'token.json', 'client_secret.json', 'secrets.toml', '.env'} for p in path.parts):
        raise ValueError('PUBLIC_PATH_INVALID')
    return value


def bounded(root: Path, name: str, maximum: int = 2_000_000) -> bytes:
    check_deadline()
    target = root
    for part in PurePosixPath(public_name(name)).parts:
        target = target / part
        if target.is_symlink() or target.is_junction():
            raise ValueError('SOURCE_LINK_REJECTED')
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        raise ValueError('SOURCE_FILE_BOUND')
    with target.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('SOURCE_FILE_BOUND')
    check_deadline()
    return raw.replace(b'\r\n', b'\n')


def git_run(root: Path, args: tuple[str, ...], data: bytes | None = None) -> bytes:
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_GRAFT_FILE=os.devnull,
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    deadline = DEADLINE.get()
    remaining = 5.0 if deadline is None else min(5.0, deadline - time.monotonic())
    if remaining <= 0:
        raise ValueError('SOURCE_ADMISSION_TIME_BOUND')
    result = subprocess.run(['git', '--no-replace-objects', '--no-optional-locks',
                            '-c', 'core.fsmonitor=false', '-C', str(root), *args], env=env,
                            input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=remaining, check=False)
    if result.returncode or len(result.stdout) > 4_000_000:
        raise ValueError('SOURCE_GIT_BOUND_OR_FAILURE')
    return result.stdout


def git(root: Path, *args: str) -> bytes:
    return git_run(root, args)


def git_blobs(root: Path, requests: dict[str, str]) -> dict[str, bytes]:
    """One batched payload read, never one subprocess per source file."""
    if any('\n' in value or '\r' in value for value in requests.values()):
        raise ValueError('BATCH_REQUEST_INVALID')
    raw = git_run(root, ('cat-file', '--batch'), ''.join(value + '\n' for value in requests.values()).encode())
    result: dict[str, bytes] = {}
    cursor = 0
    for name in requests:
        end = raw.find(b'\n', cursor)
        header = raw[cursor:end] if end >= 0 else b''
        if re.fullmatch(rb'[0-9a-f]{40} blob [0-9]{1,7}', header) is None:
            raise ValueError('BATCH_BLOB_HEADER_INVALID')
        size = int(header.rsplit(b' ', 1)[1])
        cursor = end + 1
        if size > 2_000_000 or cursor + size >= len(raw) or raw[cursor + size:cursor + size + 1] != b'\n':
            raise ValueError('BATCH_BLOB_SIZE_INVALID')
        result[name] = raw[cursor:cursor + size].replace(b'\r\n', b'\n')
        cursor += size + 1
    if cursor != len(raw):
        raise ValueError('BATCH_EXTRA_BYTES_REJECTED')
    return result


def validate(root: Path, *, commit: str | None = None, base: str | None = None) -> list[dict[str, str]]:
    token = DEADLINE.set(time.monotonic() + 10.0)
    try:
        result = _validate(root, commit=commit, base=base)
        check_deadline()
        return result
    finally:
        DEADLINE.reset(token)


def _validate(root: Path, *, commit: str | None = None, base: str | None = None) -> list[dict[str, str]]:
    """Hashes are public-source diagnostics only; private names/content never swept."""
    selected = commit if commit is not None else base
    if selected is not None:
        if re.fullmatch('[0-9a-f]{40}', selected) is None:
            raise ValueError('EXTERNAL_FULL_COMMIT_REQUIRED')
        if git(root, 'rev-parse', '--show-toplevel').decode().strip().replace('\\', '/').casefold() != str(root.resolve()).replace('\\', '/').casefold():
            raise ValueError('REPOSITORY_ROOT_REQUIRED')
        if git(root, 'rev-parse', 'HEAD').decode().strip() != selected:
            raise ValueError('EXTERNAL_COMMIT_MISMATCH')
        if base is not None:
            tree = git(root, 'ls-tree', '-r', base)
            if (re.fullmatch(rb'100644 blob [0-9a-f]{40}\tREADME.md\n', tree) is None
                    or git(root, 'show', base + ':README.md') != SEED_README):
                raise ValueError('EXACT_INERT_BOOTSTRAP_BASE_REQUIRED')
    raw = bounded(root, MANIFEST)
    if commit is not None:
        committed_manifest = git(root, 'show', commit + ':' + MANIFEST).replace(b'\r\n', b'\n')
        if raw != committed_manifest:
            raise ValueError('COMMITTED_MANIFEST_MISMATCH')
        raw = committed_manifest
    manifest: Any = json.loads(raw)
    if (not isinstance(manifest, dict) or manifest.get('schema') != 'capture-distribution-v1'
            or manifest.get('producer_origin') != PRODUCER or manifest.get('controller_origin') != CONTROLLER
            or manifest.get('commissioned') is not False or not isinstance(manifest.get('files'), dict)):
        raise ValueError('MANIFEST_CONTRACT_INVALID')
    expected: dict[str, str] = manifest['files']
    if not 40 <= len(expected) <= 160:
        raise ValueError('MANIFEST_COUNT_BOUND')
    # Validate ALL names before opening any payload.
    for name, value in expected.items():
        public_name(name)
        if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
            raise ValueError('MANIFEST_HASH_INVALID')
    failures: list[dict[str, str]] = []
    committed_files = git_blobs(root, {name: commit + ':' + name for name in expected}) if commit is not None else {}
    for name, value in sorted(expected.items()):
        if commit is not None:
            committed = committed_files[name]
            if hashlib.sha256(committed).hexdigest() != value:
                raise ValueError('COMMITTED_PAYLOAD_HASH_MISMATCH')
        actual = hashlib.sha256(bounded(root, name)).hexdigest()
        if actual != value:
            failures.append({'path': name, 'rule': 'HASH_MISMATCH', 'expected': value, 'actual': actual})
    if commit is not None or base is not None:
        entries = git(root, 'ls-files', '--stage', '-z').split(b'\0')
        indexed: set[str] = set()
        objects: dict[str, str] = {}
        for entry in filter(None, entries):
            metadata, name_raw = entry.split(b'\t', 1)
            mode, object_id, stage = metadata.decode('ascii').split(' ')
            name = public_name(name_raw.decode('utf-8'))
            if mode != '100644' or stage != '0':
                raise ValueError('INDEX_MODE_OR_CONFLICT_REJECTED')
            indexed.add(name)
            if re.fullmatch('[0-9a-f]{40}', object_id) is None:
                raise ValueError('INDEX_OBJECT_INVALID')
            objects[name] = object_id
        if indexed != set(expected) | {MANIFEST}:
            raise ValueError('COMPLETE_INDEX_SCOPE_MISMATCH')
        if commit is not None:
            tree = git(root, 'ls-tree', '-r', '--name-only', '-z', commit)
            if set(filter(None, tree.decode('utf-8').split('\0'))) != indexed:
                raise ValueError('COMMITTED_TREE_SCOPE_MISMATCH')
        # An assume-unchanged index bit must not conceal different staged bytes.
        staged_files = git_blobs(root, objects)
        for name in objects:
            staged_raw = staged_files[name]
            if staged_raw != bounded(root, name):
                raise ValueError('INDEX_PHYSICAL_BYTES_MISMATCH')
        if commit is not None and git(root, 'status', '--porcelain').strip():
            raise ValueError('SOURCE_CHECKOUT_NOT_CLEAN')
        # Index and worktree must agree, even for a staged precommit upload.
        if git(root, 'diff', '--name-only').strip():
            raise ValueError('UNSTAGED_SOURCE_REJECTED')
    # Ignored files are not trusted merely because Git status hides them.
    # .venv is the sole declared runtime exception; metadata/hook admission is
    # required separately before the controller starts its interpreter.
    actual_names: set[str] = set()
    directories = 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        check_deadline()
        directories += 1
        if directories > 128:
            raise ValueError('SOURCE_DIRECTORY_BOUND')
        parent = Path(directory)
        dirs[:] = [name for name in dirs if not (parent == root and name in ('.git', '.venv'))]
        for name in dirs:
            path = parent / name
            if path.is_symlink() or path.is_junction():
                raise ValueError('SOURCE_LINK_REJECTED')
        for name in names:
            check_deadline()
            actual_names.add((parent / name).relative_to(root).as_posix())
            if len(actual_names) > 200:
                raise ValueError('SOURCE_TREE_BOUND')
    if actual_names != set(expected) | {MANIFEST}:
        raise ValueError('UNLISTED_SOURCE_FILE_REJECTED')
    return failures


def runtime_check(root: Path) -> int:
    started = time.monotonic()
    lock = bounded(root, 'requirements-capture.lock').decode('utf-8')
    expected = {normalized_name(n): v for n, v in re.findall(r'^([\w.-]+)==([^\s\\]+)', lock, re.M)}
    site = root / '.venv' / ('Lib/site-packages' if os.name == 'nt' else 'lib/python3.13/site-packages')
    for ancestor in (site, *site.parents):
        if ancestor.is_symlink() or ancestor.is_junction():
            raise ValueError('RUNTIME_LINK_REJECTED')
        if ancestor == root:
            break
    if not site.is_dir() or not (root / '.venv/pyvenv.cfg').is_file():
        raise ValueError('RUNTIME_SITE_REQUIRED')
    with os.scandir(site) as entries:
        for index, _ in enumerate(entries):
            if index >= 256 or time.monotonic() - started > 5.0:
                raise ValueError('RUNTIME_DIRECTORY_BOUND')
    cfg = bounded(root, '.venv/pyvenv.cfg', 65536).decode('utf-8')
    system = re.findall(r'^include-system-site-packages\s*=\s*(\S+)\s*$', cfg, re.M | re.I)
    if system != ['false']:
        raise ValueError('RUNTIME_SYSTEM_PACKAGES_REJECTED')
    if list(site.glob('*.pth')) or list(site.glob('sitecustomize*')) or list(site.glob('usercustomize*')):
        raise ValueError('RUNTIME_STARTUP_HOOK_REJECTED')
    observed: dict[str, str] = {}
    for item in metadata.distributions(path=[str(site)]):
        name = normalized_name(item.metadata['Name'])
        if name in observed:
            raise ValueError('DUPLICATE_RUNTIME_DISTRIBUTION')
        observed[name] = item.version
        if len(observed) > 18 or time.monotonic() - started > 5.0:
            raise ValueError('RUNTIME_METADATA_BOUND')
    if len(expected) != 18 or observed != expected or expected.get('certifi') != '2026.10.19':
        raise ValueError('RUNTIME_PROFILE_MISMATCH')
    if time.monotonic() - started > 5.0:
        raise ValueError('RUNTIME_METADATA_BOUND')
    return len(observed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-files', action='store_true')
    mode.add_argument('--verify-commit')
    mode.add_argument('--check-index-base')
    mode.add_argument('--check-tooling', action='store_true')
    mode.add_argument('--check-runtime', action='store_true')
    args = parser.parse_args(argv)
    if not (args.check_files or args.verify_commit or args.check_index_base or args.check_tooling or args.check_runtime):
        print(json.dumps({'status': 'PREVIEW', 'source_reads': 0, 'writes': 0, 'capture_invocations': 0}))
        return 0
    try:
        if args.check_runtime:
            count = runtime_check(Path(__file__).resolve().parent)
            print(json.dumps({'status': 'CAPTURE_RUNTIME_METADATA_MATCH_NOT_CUSTODY', 'distributions': count,
                              'approval_authority': False, 'writes': 0}))
            return 0
        if args.check_tooling:
            lock = bounded(Path(__file__).resolve().parent, 'requirements-test.lock').decode('utf-8')
            pins = dict(re.findall(r'^([A-Za-z0-9_.-]+)==([^\s\\]+)', lock, re.M))
            expected = {normalized_name(name): value for name, value in pins.items()}
            installed = {normalized_name(item.metadata['Name']): item.version for item in metadata.distributions()}
            if installed != expected or expected.get('certifi') != '2026.10.19':
                raise ValueError('CAPTURE_TOOLING_PIN_MISMATCH')
            print(json.dumps({'status': 'CAPTURE_TOOLING_METADATA_MATCH_NOT_AUDIT_PROOF',
                              'distributions': len(expected), 'approval_authority': False, 'writes': 0}))
            return 0
        failures = validate(Path(__file__).resolve().parent, commit=args.verify_commit, base=args.check_index_base)
        print(json.dumps({'status': 'BLOCKED' if failures else 'CAPTURE_SOURCE_VERIFIED_NOT_COMMISSIONED',
                          'failures': failures, 'approval_authority': False, 'capture_invocations': 0,
                          'credential_reads': 0, 'writes': 0}))
        return 2 if failures else 0
    except Exception as error:
        safe = str(error) if isinstance(error, ValueError) and re.fullmatch('[A-Z_]{1,80}', str(error)) else 'SOURCE_ADMISSION_UNVERIFIED'
        print(json.dumps({'status': 'BLOCKED', 'code': safe, 'raw_error_printed': False,
                          'approval_authority': False, 'capture_invocations': 0, 'writes': 0}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
