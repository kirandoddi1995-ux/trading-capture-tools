"""Synthetic exact-tree attacks; never installed state or production tasks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import standalone_capture_contract as contract


def fixture(root: Path) -> None:
    files = {f'module{i}.py': hashlib.sha256(b'pass\n').hexdigest() for i in range(40)}
    for name in files:
        (root / name).write_bytes(b'pass\n')
    (root / contract.MANIFEST).write_text(json.dumps({
        'schema': 'capture-distribution-v1', 'producer_origin': contract.PRODUCER,
        'controller_origin': contract.CONTROLLER, 'commissioned': False, 'files': files}), encoding='utf-8')


def test_hashes_and_exact_mutation_diagnostic(tmp_path: Path) -> None:
    fixture(tmp_path)
    assert contract.validate(tmp_path) == []
    (tmp_path / 'module0.py').write_bytes(b'changed\n')
    result = contract.validate(tmp_path)
    assert result == [{'path': 'module0.py', 'rule': 'HASH_MISMATCH',
                       'expected': hashlib.sha256(b'pass\n').hexdigest(),
                       'actual': hashlib.sha256(b'changed\n').hexdigest()}]


@pytest.mark.parametrize('name', ['../private', '/private', 'a/../private', 'C:/private',
                                    'a\\private', 'token.json', 'client_secret.json',
                                    'a/TOKEN.JSON', '.env', 'a//b', './a'])
def test_bad_names_before_payload_read(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture(tmp_path)
    path = tmp_path / contract.MANIFEST
    data = json.loads(path.read_text())
    data['files'][name] = 'a' * 64
    path.write_text(json.dumps(data), encoding='utf-8')
    original = contract.bounded
    reads: list[str] = []

    def bounded(root: Path, value: str, maximum: int = 2_000_000) -> bytes:
        reads.append(value)
        return original(root, value, maximum)

    monkeypatch.setattr(contract, 'bounded', bounded)
    with pytest.raises(ValueError, match='PUBLIC_PATH_INVALID'):
        contract.validate(tmp_path)
    assert reads == [contract.MANIFEST]


def test_preview_no_source_or_git(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> bytes:
        raise AssertionError('PREVIEW_IO')
    monkeypatch.setattr(contract, 'bounded', forbidden)
    monkeypatch.setattr(contract, 'git', forbidden)
    assert contract.main([]) == 0


@pytest.mark.parametrize('key,value', [('producer_origin', '0' * 40), ('controller_origin', '0' * 40),
                                      ('commissioned', True), ('schema', 'other')])
def test_manifest_cannot_commission_or_replace_origins(tmp_path: Path, key: str, value: object) -> None:
    fixture(tmp_path)
    path = tmp_path / contract.MANIFEST
    data = json.loads(path.read_text())
    data[key] = value
    path.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(ValueError, match='MANIFEST_CONTRACT_INVALID'):
        contract.validate(tmp_path)


def test_symlink_rejected_if_platform_allows(tmp_path: Path) -> None:
    fixture(tmp_path)
    path = tmp_path / 'module0.py'
    path.unlink()
    try:
        path.symlink_to(tmp_path / 'module1.py')
    except OSError:
        pytest.skip('native symlink privilege absent; no ACL changes')
    with pytest.raises(ValueError, match='SOURCE_LINK_REJECTED'):
        contract.validate(tmp_path)


def test_profile_is_entire_exact_patched_graph() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / contract.MANIFEST).read_text())
    assert len(manifest['runtime_pins']) == 18
    assert manifest['runtime_pins']['certifi'] == '2026.10.19'
    assert not set(manifest['runtime_pins']) & {'pillow', 'streamlit'}
    for name in ('requirements.txt', 'constraints.txt', 'requirements-archive.txt', 'requirements-forward-operations.txt'):
        assert 'certifi==2026.10.19' in (root / name).read_text()
        assert '2026.7.22' not in (root / name).read_text()
    for name in ('requirements-capture.lock', 'requirements-test.lock'):
        text = (root / name).read_text()
        assert '--require-hashes' in text and '--only-binary=:all:' in text
        assert '2026.7.22' not in text


def test_controller_source_binding_before_install_and_no_fallback() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / 'forward_daily_owner.ps1').read_text()
    assert '$base = $ReviewedCommit' in text
    assert "'reviewed_capture_' + $stamp" in text
    assert 'trading-capture-tools.git' in text
    assert 'Trading-Dashboard.git' not in text
    assert "'-I','-S','-B'" in text
    assert text.index('        Assert-Capsule\n') < text.index("'--require-hashes','--only-binary=:all:'")
    assert "'requirements-capture.lock'" in text
    assert '-Force' not in text[text.index('Register-ScheduledTask'):text.index('Register-ScheduledTask') + 180]
    assert 'Set-Acl' not in '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
