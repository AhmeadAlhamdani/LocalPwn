"""Deliberately safe lab demonstration. No remote shells or implants."""
from pathlib import Path
import tempfile
import json

class LabError(Exception): pass

def run_lab_exercise(policy, store, aid, exercise="marker"):
    if not policy.lab or not policy.permits("lab_exploitation"):
        raise LabError("Lab exercises require explicit isolated-lab mode")
    if exercise != "marker": raise LabError("Unknown lab exercise")
    # A deterministic local proof that records a controlled 'access' and ephemeral marker.
    with tempfile.TemporaryDirectory(prefix="localpwn-lab-") as tmp:
        root=Path(tmp)
        proof=root/"vulnerable_fixture.txt"
        proof.write_text("LOCALPWN_DELIBERATE_LAB_FIXTURE\n")
        observed=proof.read_text().strip()=="LOCALPWN_DELIBERATE_LAB_FIXTURE"
        store.action(aid,"lab_validation","fixture_access","success" if observed else "failed",{"sandbox":"temporary-directory","fixture":"deliberately vulnerable", "proof_observed":observed})
        marker=root/"persistence_simulation.marker"
        if policy.permits("lab_persistence"):
            marker.write_text("SIMULATED PERSISTENCE - NOT AN IMPLANT")
            verified=marker.exists()
            marker.unlink()
            store.action(aid,"lab_persistence","reversible_marker","success",{"simulated":True,"marker_created":verified,"marker_removed":not marker.exists()})
        return {"lab_fixture_verified":observed,"persistence_simulated":True,"cleanup":"completed"}


def run_container_lab_exercise(policy, store, aid, port=18181, persistence=False):
    """Test only the deliberately vulnerable, loopback-bound lab fixture.

    Fixed localhost destination, challenge identity, deterministic synthetic
    data, and guaranteed cleanup. Never accepts an attacker-controlled URL.
    """
    import http.client
    if not policy.lab or not policy.allows_ip('127.0.0.1'):
        raise LabError('Container lab requires explicit loopback scope and lab mode')
    if port != 18181:
        raise LabError('Only the documented local lab port is supported')
    def request(method, path):
        conn = http.client.HTTPConnection('127.0.0.1', 18181, timeout=3)
        try:
            conn.request(method, path)
            r = conn.getresponse()
            headers = dict(r.getheaders())
            body = r.read(512).decode('utf-8', 'replace')
            if headers.get('X-LocalPwn-Synthetic-Lab') != 'yes':
                raise LabError('Target is not the designated LocalPwn fixture')
            return r.status, body
        finally:
            conn.close()
    try:
        code, identity = request('GET', '/lab/identity')
        if code != 200 or identity != 'LOCALPWN_SYNTHETIC_LAB_V1':
            raise LabError('Lab identity check failed; refusing to continue')
        code, body = request('GET', '/objects/42')
        proof = code == 200 and body == 'SYNTHETIC_CONFIDENTIAL_RECORD_42'
        store.action(aid, 'lab_validation', 'synthetic_object_access',
                     'success' if proof else 'failed',
                     {'verified': proof, 'fixture': 'synthetic object 42',
                      'impact': 'mock IDOR in local training service; no real data'})
        if not proof:
            raise LabError('Synthetic lab vulnerability not reproduced')
        if not persistence:
            store.action(aid, 'lab_persistence', 'synthetic_marker', 'not_run',
                         {'reason': 'Optional lab marker simulation not enabled'})
            return {'lab_fixture_verified': proof, 'persistence_simulated': False,
                    'cleanup': 'not needed'}
        created = False
        try:
            code, body = request('POST', '/lab/persistence')
            created = code == 200 and body == 'MARKER_CREATED'
            code, body = request('GET', '/lab/persistence')
            observed = created and code == 200 and body == 'MARKER_PRESENT'
        finally:
            code, body = request('DELETE', '/lab/persistence')
            cleaned = code == 200 and body == 'MARKER_REMOVED'
        store.action(aid, 'lab_persistence', 'synthetic_marker',
                     'success' if observed and cleaned else 'failed',
                     {'simulated': True, 'created': created,
                      'observed': observed, 'cleanup_confirmed': cleaned})
        return {'lab_fixture_verified': proof, 'persistence_simulated': observed,
                'cleanup': 'completed' if cleaned else 'failed'}
    except (OSError, TimeoutError) as exc:
        raise LabError('The local synthetic lab is not reachable; start compose.yaml') from exc
