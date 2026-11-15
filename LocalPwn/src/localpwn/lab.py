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
