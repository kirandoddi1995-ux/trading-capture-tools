"""Independent invariants modeled with synthetic Git blobs; no real commits/tasks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import standalone_capture_contract as contract

SHA = 'a' * 40


def image(root: Path) -> dict[str, bytes]:
    files = {f'm{i}.py': b'pass\n' for i in range(40)}
    value = {'schema': 'capture-distribution-v1', 'producer_origin': contract.PRODUCER,
             'controller_origin': contract.CONTROLLER, 'commissioned': False,
             'files': {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
    files[contract.MANIFEST] = json.dumps(value).encode()
    for name, raw in files.items():
        (root / name).write_bytes(raw)
    return files


def fake_git(root: Path, files: dict[str, bytes]):
    def run(actual: Path, *args: str) -> bytes:
        assert actual == root
        if args == ('rev-parse', '--show-toplevel'):
            return str(root).encode()
        if args == ('rev-parse', 'HEAD'):
            return SHA.encode()
        if args[0] == 'show':
            return files[args[1].split(':', 1)[1]]
        if args[0] == 'ls-files':
            return b''.join(b'100644 ' + f'{index:040x}'.encode() + b' 0\t' + name.encode() + b'\0' for index, name in enumerate(files))
        if args[0] == 'cat-file':
            return list(files.values())[int(args[2], 16)]
        if args[0] == 'ls-tree':
            return b'\0'.join(name.encode() for name in files) + b'\0'
        if args[0] in ('status', 'diff'):
            return b''  # Models assume-unchanged hiding physical modifications.
        raise AssertionError(args)
    return run


def test_committed_tree_and_physical_hash_even_with_clean_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    files = image(tmp_path)
    monkeypatch.setattr(contract, 'git', fake_git(tmp_path, files))
    monkeypatch.setattr(contract, 'git_blobs', lambda root, requests: {name: files[name] for name in requests})
    assert contract.validate(tmp_path, commit=SHA) == []
    (tmp_path / 'm0.py').write_bytes(b'altered\n')
    with pytest.raises(ValueError, match='INDEX_PHYSICAL_BYTES_MISMATCH'):
        contract.validate(tmp_path, commit=SHA)


def test_altered_manifest_not_trusted_even_with_clean_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    files = image(tmp_path)
    monkeypatch.setattr(contract, 'git', fake_git(tmp_path, files))
    monkeypatch.setattr(contract, 'git_blobs', lambda root, requests: {name: files[name] for name in requests})
    (tmp_path / contract.MANIFEST).write_bytes(files[contract.MANIFEST] + b' ')
    with pytest.raises(ValueError, match='COMMITTED_MANIFEST_MISMATCH'):
        contract.validate(tmp_path, commit=SHA)


@pytest.mark.parametrize('name', ['token.json', 'client_secret.json', 'ignored.py', '.env', '__pycache__/bad.pyc'])
def test_ignored_extras_still_block_without_reading_them(tmp_path: Path, name: str) -> None:
    image(tmp_path)
    extra = tmp_path / name
    extra.parent.mkdir(exist_ok=True)
    extra.write_bytes(b'SYNTHETIC_DO_NOT_READ')
    with pytest.raises(ValueError, match='UNLISTED_SOURCE_FILE_REJECTED'):
        contract.validate(tmp_path)


def test_only_explicit_runtime_directory_exception(tmp_path: Path) -> None:
    image(tmp_path)
    runtime = tmp_path / '.venv'
    runtime.mkdir()
    (runtime / 'synthetic').write_bytes(b'not admitted by source check')
    assert contract.validate(tmp_path) == []  # Separate exact-runtime gate mandatory.


def test_runtime_hooks_rejected_before_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / 'requirements-capture.lock').write_text('certifi==2026.10.19\n')
    site = tmp_path / '.venv' / ('Lib/site-packages' if contract.os.name == 'nt' else 'lib/python3.13/site-packages')
    site.mkdir(parents=True)
    (tmp_path / '.venv/pyvenv.cfg').write_text('include-system-site-packages = false\n')
    (site / 'injection.pth').write_text('SYNTHETIC_DO_NOT_EXECUTE')
    monkeypatch.setattr(contract.metadata, 'distributions', lambda **kwargs: pytest.fail('hook admission preceded metadata'))
    with pytest.raises(ValueError, match='RUNTIME_STARTUP_HOOK_REJECTED'):
        contract.runtime_check(tmp_path)


def test_runtime_extra_distribution_not_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pins = {'certifi': '2026.10.19', **{f'package{i}': '1.0' for i in range(17)}}
    (tmp_path / 'requirements-capture.lock').write_text(''.join(f'{n}=={v}\n' for n, v in pins.items()))
    site = tmp_path / '.venv' / ('Lib/site-packages' if contract.os.name == 'nt' else 'lib/python3.13/site-packages')
    site.mkdir(parents=True)
    (tmp_path / '.venv/pyvenv.cfg').write_text('include-system-site-packages = false\n')
    class Distribution:
        def __init__(self, name: str, version: str):
            self.metadata = {'Name': name}
            self.version = version
    observed = [Distribution(n, v) for n, v in {**pins, 'extra': '2'}.items()]
    monkeypatch.setattr(contract.metadata, 'distributions', lambda **kwargs: observed)
    with pytest.raises(ValueError, match='RUNTIME_METADATA_BOUND'):
        contract.runtime_check(tmp_path)
