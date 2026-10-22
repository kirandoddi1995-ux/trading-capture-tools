"""No activation, no imports/provider calls before source/runtime admission."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import standalone_capture_launch as launch


def test_preview_never_checks_source_or_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launch, 'trusted_gate', lambda *args: pytest.fail('preview source read'))
    assert launch.main([]) == 0


def test_nonisolated_confirm_never_touches_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launch, 'trusted_gate', lambda *args: pytest.fail('unisolated source read'))
    assert launch.main(['--confirm-run']) == 3


def test_invalid_source_pin_rejected_before_git(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match='EXTERNAL_FULL_COMMIT_REQUIRED'):
        launch.trusted_gate(tmp_path, 'main')


def test_runtime_admission_precedes_product_import(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_sys = SimpleNamespace(flags=SimpleNamespace(isolated=True, no_site=True),
                               dont_write_bytecode=True, version_info=(3, 13, 9))
    monkeypatch.setattr(launch, 'sys', fake_sys)
    events: list[str] = []
    def validate(*args, **kwargs):
        events.append('source')
        return []
    def runtime(*args):
        events.append('runtime')
        raise ValueError('SYNTHETIC_HOOK_REJECTED')
    monkeypatch.setattr(launch, 'trusted_gate', lambda *args: SimpleNamespace(validate=validate, runtime_check=runtime))
    monkeypatch.setattr(launch.os, 'environ', {})
    monkeypatch.setattr(launch.importlib, 'import_module', lambda *args: pytest.fail('premature product import'))
    assert launch.main(['--confirm-run', '--reviewed-source', 'a' * 40]) == 3
    assert events == ['source', 'runtime']


@pytest.mark.parametrize('key', ['REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'https_proxy', 'SSL_CERT_FILE'])
def test_unreviewed_tls_environment_blocks_without_printing_value(key: str, monkeypatch: pytest.MonkeyPatch,
                                                                capsys: pytest.CaptureFixture[str]) -> None:
    fake_sys = SimpleNamespace(flags=SimpleNamespace(isolated=True, no_site=True),
                               dont_write_bytecode=True, version_info=(3, 13, 9))
    monkeypatch.setattr(launch, 'sys', fake_sys)
    monkeypatch.setattr(launch.os, 'environ', {key: 'SYNTHETIC_PRIVATE_VALUE'})
    monkeypatch.setattr(launch, 'trusted_gate', lambda *args: pytest.fail('TLS context should block first'))
    assert launch.main(['--confirm-run']) == 3
    assert 'SYNTHETIC_PRIVATE_VALUE' not in capsys.readouterr().out
