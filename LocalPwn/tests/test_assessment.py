from pathlib import Path
import json
import pytest
from localpwn.engine import Engine
from localpwn.store import Store
from localpwn.policy import Policy
from localpwn.scanner import parse_nmap
from localpwn.lab import run_lab_exercise, LabError

XML='''<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports></host></nmaprun>'''

def test_parse():
    assert parse_nmap(XML)[0]["ports"][0]["port"]==23

def test_offline_assessment(tmp_path):
    store=Store(tmp_path)
    policy=Policy(("127.0.0.1/32",))
    aid=Engine(store,policy).execute("127.0.0.1",offline_xml=XML)
    result=store.snapshot(aid)
    assert result["assessment"]["status"]=="complete"
    assert len(result["findings"])==1
    assert (tmp_path / aid / "report.html").exists()
    assert len(result["actions"])>=4
    assert all(Path(a["path"]).exists() for a in result["artifacts"])

def test_import_scope_mismatch_fails(tmp_path):
    store=Store(tmp_path)
    policy=Policy(("192.168.56.10/32",))
    with pytest.raises(ValueError):
        Engine(store,policy).execute("192.168.56.10",offline_xml=XML)

def test_lab_simulation(tmp_path):
    store=Store(tmp_path)
    p=Policy(("127.0.0.1/32",),lab=True)
    aid=store.create("127.0.0.1")
    result=run_lab_exercise(p,store,aid)
    assert result["cleanup"]=="completed"
    actions=store.snapshot(aid)["actions"]
    assert {a["kind"] for a in actions}=={"fixture_access","reversible_marker"}

def test_lab_without_authorization_fails(tmp_path):
    store=Store(tmp_path)
    aid=store.create("127.0.0.1")
    with pytest.raises(LabError):
        run_lab_exercise(Policy(("127.0.0.1/32",)),store,aid)
