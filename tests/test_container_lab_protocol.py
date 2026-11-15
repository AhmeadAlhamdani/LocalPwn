"""Exercise synthetic training-service protocol locally; Docker itself tested on Kali separately."""
import importlib.util
from http.server import ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
import threading
import pytest
from localpwn.engine import Engine
from localpwn.policy import Policy
from localpwn.store import Store


def test_loopback_lab_validation_and_marker_cleanup(tmp_path):
    lab_file = Path(__file__).parent.parent / 'examples' / 'lab' / 'app.py'
    spec = importlib.util.spec_from_file_location('localpwn_training_fixture', lab_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.MARKER = tmp_path / 'persistence_marker'
    try:
        server = ThreadingHTTPServer(('127.0.0.1', 18181), module.Handler)
    except OSError:
        pytest.skip('Port 18181 already in use; cannot run local training fixture test')
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = Store(tmp_path / 'output')
        xml = files('localpwn').joinpath('static/demo-lab-nmap.xml').read_text()
        policy = Policy(('127.0.0.1/32',), lab=True)
        aid = Engine(store, policy).execute('127.0.0.1', offline_xml=xml,
                  lab_exercise=True, lab_kind='container', lab_persistence=True)
        snap = store.snapshot(aid)
        assert snap['assessment']['status'] == 'complete'
        assert any(a['kind']=='synthetic_object_access' and a['status']=='success' for a in snap['actions'])
        assert any(a['kind']=='synthetic_marker' and a['status']=='success' for a in snap['actions'])
        assert not module.MARKER.exists()
        assert store.verify_actions(aid)['valid']
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
