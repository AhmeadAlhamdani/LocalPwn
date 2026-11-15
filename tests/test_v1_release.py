"""New v1 integration and security regression tests (no real network scan)."""
import json
from pathlib import Path
import pytest
from localpwn.scanner import parse_nmap, ScanError, _command
from localpwn.policy import Policy
from localpwn.engine import Engine
from localpwn.store import Store
from localpwn.validation import propose_safe_checks

XML = '<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'


def test_xml_rejects_dtd():
    with pytest.raises(ScanError):
        parse_nmap('<!DOCTYPE nmaprun [<!ENTITY foo "bar">]><nmaprun/>')


def test_xml_size_limit():
    with pytest.raises(ScanError):
        parse_nmap('x' * 16_000_010)


def test_worker_is_hardened_and_no_shell(monkeypatch):
    monkeypatch.setattr("localpwn.scanner.shutil.which", lambda name: "/usr/bin/" + name)
    cmd = _command('192.0.2.20/32', 'docker', 'localpwn-test')
    assert cmd[:2] == ['docker', 'run']
    assert '--cap-drop' in cmd and '--read-only' in cmd
    assert '--network' in cmd and 'localpwn-scanner:1.0' in cmd
    assert '--name' in cmd and 'localpwn-test' in cmd
    assert cmd[-1] == '192.0.2.20/32'


def test_rejects_unknown_worker():
    with pytest.raises(ScanError):
        _command('127.0.0.1', 'unrestricted')


def test_action_chain_tampering(tmp_path):
    s = Store(tmp_path)
    aid = s.create('127.0.0.1')
    s.action(aid, 'test', 'first', 'success', {'value': 1})
    s.action(aid, 'test', 'second', 'success', {'value': 2})
    assert s.verify_actions(aid)['valid']
    s.db.execute("UPDATE actions SET details='{}' WHERE kind='first'")
    s.db.commit()
    assert not s.verify_actions(aid)['valid']


def test_artifact_hash_tampering(tmp_path):
    s = Store(tmp_path)
    aid = s.create('127.0.0.1')
    item = s.artifact(aid, 'evidence.txt', b'original')
    assert s.verify_artifacts(aid)[0]['valid']
    Path(item['path']).write_bytes(b'changed')
    assert not s.verify_artifacts(aid)[0]['valid']


def test_versioned_artifacts_preserve_previous(tmp_path):
    s = Store(tmp_path)
    aid = s.create('127.0.0.1')
    a = s.artifact(aid, 'report.html', b'first')
    b = s.artifact(aid, 'report.html', b'second')
    assert a['path'] != b['path']
    assert all(i['valid'] for i in s.verify_artifacts(aid))


def test_cancel_then_resume_offline(tmp_path):
    s = Store(tmp_path)
    aid = s.create('127.0.0.1/32')
    s.set_control(aid, ['127.0.0.1/32'], 'none', None, 'native', True)
    s.request_cancel(aid)
    engine = Engine(s, Policy(('127.0.0.1/32',), lab=True))
    cancelled = engine.execute('127.0.0.1', aid=aid, lab_exercise=True, offline_xml=XML)
    assert cancelled == aid
    assert s.snapshot(aid)['assessment']['status'] == 'cancelled'
    engine.execute('127.0.0.1', aid=aid, lab_exercise=True, offline_xml=XML, resume=True)
    assert s.snapshot(aid)['assessment']['status'] == 'complete'
    assert s.verify_actions(aid)['valid']
    assert all(i['valid'] for i in s.verify_artifacts(aid))


def test_planner_suggests_only_scoped_checks():
    hosts = [{'address': '127.0.0.1', 'ports': [{'port': 80, 'protocol': 'tcp'}]},
             {'address': '192.0.2.50', 'ports': [{'port': 80, 'protocol': 'tcp'}]}]
    plan = propose_safe_checks(hosts, Policy(('127.0.0.1/32',)))
    assert len(plan) == 1
    assert plan[0]['target'] == '127.0.0.1'
    assert plan[0]['method'] == 'HEAD'


def test_engine_rejects_scope_changes_on_resume(tmp_path):
    s = Store(tmp_path)
    aid = s.create('127.0.0.1/32')
    s.set_control(aid, ['127.0.0.1/32'])
    with pytest.raises(ValueError):
        Engine(s, Policy(('127.0.0.0/24',))).execute('127.0.0.1', aid=aid, resume=True, offline_xml=XML)


def test_lab_rejects_non_loopback(tmp_path):
    from localpwn.lab import run_container_lab_exercise, LabError
    s = Store(tmp_path)
    aid = s.create('192.0.2.1')
    with pytest.raises(LabError):
        run_container_lab_exercise(Policy(('192.0.2.1/32',), lab=True), s, aid)


def test_ui_contains_controls():
    from importlib.resources import files
    html = files('localpwn').joinpath('static/index.html').read_text()
    for keyword in ['id="cancelRun"', 'id="resumeRun"', 'id="verifyRun"', 'id="labKind"', 'id="worker"']:
        assert keyword in html


def test_ai_restricts_ollama_host(monkeypatch):
    from localpwn.ai import analyze
    monkeypatch.setenv('LOCALPWN_OLLAMA_URL', 'http://192.0.2.10:11434/api/chat')
    with pytest.raises(ValueError):
        analyze([], 'ollama')
