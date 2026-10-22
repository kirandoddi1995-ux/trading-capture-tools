"""Actual capture transports, synthetic sessions only. Not a TLS attack test."""
from unittest.mock import Mock

import requests

import drive_archive
import forward_nifty_job


def test_default_requests_ca_is_certifi() -> None:
    import certifi
    assert requests.certs.where() == certifi.where()
    assert requests.Session().verify is True


def test_drive_uses_authorized_session_default_verification(monkeypatch) -> None:
    session = Mock()
    session.verify = True
    session.request.return_value.status_code = 200
    monkeypatch.setattr(drive_archive, 'AuthorizedSession', lambda creds: session)
    archive = drive_archive.DriveArchive(object(), 'synthetic_folder')
    archive.request('GET', 'https://www.googleapis.com/drive/v3/files')
    args, kwargs = session.request.call_args
    assert args == ('GET', 'https://www.googleapis.com/drive/v3/files')
    assert kwargs['allow_redirects'] is False
    assert kwargs['timeout'] == (10, 90)
    assert 'verify' not in kwargs  # default audited Requests trust, not verify=False
    assert session.verify is True
    assert drive_archive.TOKEN_URI == 'https://oauth2.googleapis.com/token'


def test_upstox_fixed_get_declares_tls_no_order_endpoint() -> None:
    assert forward_nifty_job.URL == 'https://api.upstox.com/v3/historical-candle/intraday/NSE_INDEX%7CNifty%2050/minutes/5'


def test_every_task_plan_executable_resource_is_in_manifest() -> None:
    from datetime import date
    from pathlib import Path
    import json
    import forward_ops_plan
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / 'CAPTURE_DISTRIBUTION.json').read_text())
    plans = forward_ops_plan.plans(date(2022, 1, 3), sid='S-1-5-21-123',
        code=r'C:\Reviewed\capsule', python=r'C:\Reviewed\capsule\.venv\Scripts\python.exe',
        state=r'C:\Private\state', ops=r'C:\Private\ops', reviewed_commit='a' * 40)
    assert len(plans) == 3
    assert all('forward_ops_task.ps1' in xml for xml in plans.values())
    assert 'forward_ops_task.ps1' in manifest['files']
    assert all('-ReviewedCommit ' + 'a' * 40 in xml for xml in plans.values())
    assert (root / 'forward_ops_task.ps1').is_file()


def test_planner_and_host_compare_the_same_commit_bound_actions() -> None:
    from datetime import date
    import xml.etree.ElementTree as ET
    import forward_ops_host
    import forward_ops_plan
    day = date(2022, 1, 3)
    args = {'sid': 'S-1-5-21-123', 'code': r'C:\Reviewed\capsule',
            'python': r'C:\Reviewed\capsule\.venv\Scripts\python.exe',
            'state': r'C:\Private\state', 'ops': r'C:\Private\ops', 'reviewed_commit': 'a' * 40}
    plans = forward_ops_plan.plans(day, **args)
    poll, audit = 'KiranTrading-Versioned-20220103-poll', 'KiranTrading-Versioned-20220103-audit'
    expected = forward_ops_host.expected_task_actions(day, poll, audit, code=args['code'],
        python=args['python'], root=args['state'], ops=args['ops'], system_root=r'C:\Windows', reviewed_commit='a' * 40)
    ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
    for name in (poll, audit):
        xml = ET.fromstring(plans[name])
        action = {field: xml.findtext('t:Actions/t:Exec/t:' + ('Command' if field == 'Execute' else field), namespaces=ns)
                  for field in ('Execute', 'WorkingDirectory', 'Arguments')}
        assert forward_ops_host.exact_action_matches(action, expected[name])
        action['Arguments'] = action['Arguments'].replace('a' * 40, 'b' * 40)
        assert not forward_ops_host.exact_action_matches(action, expected[name])


def test_scheduled_launch_admission_failure_has_independent_signal() -> None:
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    wrapper = (root / 'forward_ops_task.ps1').read_text()
    assert '$process.ExitCode -eq 3' in wrapper
    assert 'ISOLATED_CAPTURE_ADMISSION_REVIEW_REQUIRED' in wrapper
    assert 'MessageBox' in wrapper
    assert '-I -S -B' in wrapper and '--reviewed-source ' in wrapper
    controller = (root / 'forward_daily_owner.ps1').read_text()
    assert '$healthCode' not in controller
    assert "'--operation','health'" in controller
