"""Malformed public Git output and expired budgets fail closed."""
from pathlib import Path

import pytest

import standalone_capture_contract as contract


def test_valid_batched_blobs(monkeypatch: pytest.MonkeyPatch) -> None:
    data = b'a' * 40 + b' blob 5\npass\n\n' + b'b' * 40 + b' blob 0\n\n'
    monkeypatch.setattr(contract, 'git_run', lambda *args: data)
    assert contract.git_blobs(Path('.'), {'a.py': 'a' * 40, 'b.py': 'b' * 40}) == {'a.py': b'pass\n', 'b.py': b''}


@pytest.mark.parametrize('data', [b'', b'truncated', b'a' * 40 + b' tree 5\npass\n\n',
    b'a' * 40 + b' blob 9999999\n', b'a' * 40 + b' blob 5\npa',
    b'a' * 40 + b' blob 5\npass\nx', b'a' * 40 + b' blob 5\npass\n\nEXTRA'])
def test_malformed_batch_fails_closed(data: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contract, 'git_run', lambda *args: data)
    with pytest.raises(ValueError):
        contract.git_blobs(Path('.'), {'a.py': 'a' * 40})


def test_newline_batch_injection_blocks_before_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(contract, 'git_run', lambda *args: pytest.fail('malformed batch started Git'))
    with pytest.raises(ValueError, match='BATCH_REQUEST_INVALID'):
        contract.git_blobs(Path('.'), {'a.py': 'bad\nrequest'})


def test_success_after_deadline_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(contract.time, 'monotonic', lambda: clock[0])
    def slow(*args, **kwargs):
        clock[0] = 11.0
        return []
    monkeypatch.setattr(contract, '_validate', slow)
    with pytest.raises(ValueError, match='SOURCE_ADMISSION_TIME_BOUND'):
        contract.validate(tmp_path)


def test_git_deadline_before_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    token = contract.DEADLINE.set(0.0)
    try:
        monkeypatch.setattr(contract.subprocess, 'run', lambda *args, **kwargs: pytest.fail('late process started'))
        with pytest.raises(ValueError, match='SOURCE_ADMISSION_TIME_BOUND'):
            contract.git_run(Path('.'), ('status',))
    finally:
        contract.DEADLINE.reset(token)


def test_git_oversized_output_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace
    monkeypatch.setattr(contract.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b'x' * 4_000_001))
    with pytest.raises(ValueError, match='SOURCE_GIT_BOUND_OR_FAILURE'):
        contract.git_run(Path('.'), ('status',))
