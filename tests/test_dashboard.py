"""Dashboard integration tests against the real assessment engine (offline only)."""
import time
from fastapi.testclient import TestClient
from localpwn.web import make_app


def test_dashboard_demo_and_exports(tmp_path):
    with TestClient(make_app(tmp_path), base_url="http://localhost") as client:
        home = client.get("/")
        assert home.status_code == 200
        assert "New assessment" in home.text and "Reports" in home.text
        assert client.get("/api/health").json()["mode"] == "loopback"
        token = home.text.split("const SESSION='")[1].split("'")[0]
        payload = {"target": "192.168.56.10", "allow": "192.168.56.10/32", "provider": "none", "acknowledged": True, "demo": True, "max_hosts": 1}
        assert client.post("/api/assessments", json=payload).status_code == 403
        wrong = dict(payload, target="192.168.56.11")
        assert client.post("/api/assessments", json=wrong, headers={"X-Localpwn-Session": token}).status_code == 422
        response = client.post("/api/assessments", json=payload, headers={"X-Localpwn-Session": token})
        assert response.status_code == 202
        aid = response.json()["id"]
        for _ in range(100):
            snapshot = client.get(f"/api/assessments/{aid}").json()
            if snapshot["assessment"]["status"] in {"complete", "failed"}:
                break
            time.sleep(.05)
        assert snapshot["assessment"]["status"] == "complete"
        assert any(action["kind"] == "reversible_marker" for action in snapshot["actions"])
        for extension, prefix in [("json", b"{"), ("html", b"<!doctype html>"), ("pdf", b"%PDF")]:
            export = client.get(f"/api/assessments/{aid}/export/{extension}")
            assert export.status_code == 200
            assert export.content.startswith(prefix)
        assert client.get(f"/api/assessments/{aid}/inventory").json()[0]["address"] == "192.168.56.10"
        artifact = snapshot["artifacts"][0]
        assert client.get(f"/api/assessments/{aid}/artifacts/{artifact['id']}").status_code == 200


def test_dashboard_rejects_unknown_host_and_out_of_scope(tmp_path):
    with TestClient(make_app(tmp_path), base_url="http://localhost") as client:
        assert client.get("/", headers={"host": "attacker.example"}).status_code == 400
        token = client.get("/").text.split("const SESSION='")[1].split("'")[0]
        headers = {"X-Localpwn-Session": token}
        payload = {"target": "203.0.113.50", "allow": "192.168.56.10/32", "acknowledged": True}
        r = client.post("/api/assessments", json=payload, headers=headers)
        assert r.status_code == 422
        assert "outside authorized scope" in r.text
