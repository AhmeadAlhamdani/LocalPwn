"""Durable phases, evidence logging, and bounded automated assessment."""
import json
from .scanner import scan
from .ai import analyze
from .report import render_html
from .lab import run_lab_exercise

class Engine:
    def __init__(self, store, policy):
        self.store=store
        self.policy=policy

    def execute(self, target, provider="none", model=None, lab_exercise=False, aid=None, offline_xml=None):
        normalized=self.policy.validate_target(target)
        if lab_exercise and not self.policy.lab: raise ValueError("Lab exercises need --lab")
        aid=aid or self.store.create(normalized)
        self.store.action(aid,"scope","authorization","accepted",{"scope":self.policy.networks,"target":normalized,"lab":self.policy.lab})
        try:
            self.store.update(aid,"scanning","running")
            if offline_xml is not None:
                from .scanner import parse_nmap
                raw=offline_xml
                hosts=parse_nmap(raw)
                self.store.action(aid,"scanning","nmap_xml_import","success",{"host_count":len(hosts)})
            else:
                hosts,raw=scan(normalized)
                self.store.action(aid,"scanning","nmap_tcp_scan","success",{"host_count":len(hosts),"service_count":sum(len(h['ports']) for h in hosts)})
            # No scan-generated host may escape scope, including imported XML.
            for h in hosts:
                if not self.policy.allows_ip(h["address"]):
                    raise ValueError("Out-of-scope host found in scan output")
            self.store.artifact(aid,"nmap.xml",raw.encode())
            self.store.artifact(aid,"inventory.json",json.dumps(hosts,indent=2).encode())
            self.store.update(aid,"analysis","running")
            self.store.action(aid,"enumeration","service_inventory","success",{"hosts":len(hosts)})
            for host in hosts:
                for port in host["ports"]:
                    if port["port"] in {21,23}:
                        self.store.finding(aid,f"Review exposed service {port['service']} on {host['address']}:{port['port']}","Informational", "Service observed in Nmap inventory; no vulnerability confirmed", "Assess business need and restrict network exposure")
            try:
                result=analyze(hosts,provider,model)
                self.store.action(aid,"analysis","ai_advisory","success",{"provider":provider,"summary":result["summary"],"hypotheses":result["hypotheses"]})
                self.store.artifact(aid,"ai_advisory.json",json.dumps(result,indent=2).encode())
            except Exception as exc:
                self.store.action(aid,"analysis","ai_advisory","failed",{"provider":provider,"error_type":type(exc).__name__})
            if lab_exercise:
                self.store.update(aid,"lab_validation","running")
                run_lab_exercise(self.policy,self.store,aid)
            else:
                self.store.action(aid,"validation","intrusive_tests","not_run",{"reason":"Requires separate approved, constrained validation module; no arbitrary exploitation executed"})
            self.store.update(aid,"report","complete")
            snapshot=self.store.snapshot(aid)
            self.store.artifact(aid,"report.html",render_html(snapshot).encode())
            self.store.artifact(aid,"report.json",json.dumps(snapshot,indent=2).encode())
            return aid
        except Exception as exc:
            self.store.action(aid,"error","assessment_error","failed",{"error_type":type(exc).__name__,"message":str(exc)[:300]})
            self.store.update(aid,"error","failed")
            raise
