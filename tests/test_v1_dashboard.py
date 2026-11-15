"""Dashboard lifecycle tests with the actual offline assessment pipeline."""
import time
from fastapi.testclient import TestClient
from localpwn.web import make_app


def test_integrity_endpoint_and_failed_resume(tmp_path):
    with TestClient(make_app(tmp_path), base_url="http://localhost") as client:
        token = client.get('/').text.split("const SESSION='")[1].split("'")[0]
        headers = {'X-Localpwn-Session': token}
        data = {'target': '192.168.56.10', 'allow': '192.168.56.10/32',
                'provider': 'none', 'acknowledged': True, 'demo': True,
                'lab_kind': 'fixture', 'worker': 'native'}
        result = client.post('/api/assessments', json=data, headers=headers)
        assert result.status_code == 202
        aid = result.json()['id']
        for _ in range(150):
            status = client.get(f'/api/assessments/{aid}').json()['assessment']['status']
            if status in ('complete', 'failed'):
                break
            time.sleep(.02)
        assert status == 'complete'
        integrity = client.get(f'/api/assessments/{aid}/integrity')
        assert integrity.status_code == 200
        assert integrity.json()['actions']['valid']
        assert all(x['valid'] for x in integrity.json()['artifacts'])
        assert client.post(f'/api/assessments/{aid}/cancel', headers=headers).status_code == 409
        assert client.post(f'/api/assessments/{aid}/resume', json={'acknowledged': True}, headers=headers).status_code == 409


def test_web_disallows_remote_lab_target(tmp_path):
    with TestClient(make_app(tmp_path), base_url="http://localhost") as client:
        token = client.get('/').text.split("const SESSION='")[1].split("'")[0]
        data = {'target': '192.0.2.42', 'allow': '192.0.2.42/32',
                'acknowledged': True, 'demo': True, 'lab_kind': 'container'}
        res = client.post('/api/assessments', json=data, headers={'X-Localpwn-Session':token})
        assert res.status_code == 422
