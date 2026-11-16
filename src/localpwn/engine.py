"""Resumable, bounded assessment pipeline with persistent audit events."""
from __future__ import annotations
import json
from pathlib import Path
from .scanner import scan, parse_nmap, ScanCancelled
from .ai import analyze
from .report import render_html
from .lab import run_lab_exercise, run_container_lab_exercise
from .validation import propose_safe_checks, run_safe_checks

class AssessmentCancelled(Exception):
    pass


class Engine:
    def __init__(self, store, policy):
        self.store = store
        self.policy = policy

    def _guard(self, aid):
        if self.store.cancelled(aid):
            raise AssessmentCancelled('Assessment cancelled')

    def _cached(self, aid):
        rows = self.store.db.execute(
            'SELECT path, sha256 FROM artifacts WHERE assessment_id=? AND path LIKE ? ORDER BY rowid DESC LIMIT 1',
            (aid, '%/inventory.json')).fetchone()
        if not rows:
            return None
        path = Path(rows['path']).resolve()
        if path.parent != (self.store.root / aid).resolve() or not path.is_file():
            return None
        import hashlib
        if hashlib.sha256(path.read_bytes()).hexdigest() != rows['sha256']:
            return None
        return json.loads(path.read_text())

    def execute(self, target, provider='none', model=None, lab_exercise=False, aid=None,
                offline_xml=None, api_key=None, worker='native', safe_checks=False,
                resume=False, lab_kind="fixture", lab_persistence=False):
        normalized = self.policy.validate_target(target)
        if lab_kind not in {'fixture', 'container'}:
            raise ValueError('Unknown lab kind')
        if lab_exercise and not self.policy.lab:
            raise ValueError('Lab exercises require explicit --lab')
        if worker not in {'native', 'docker'}:
            raise ValueError('Invalid worker mode')
        if provider not in {'none', 'ollama', 'openai', 'anthropic'}:
            raise ValueError('Unsupported provider')
        if aid is None:
            aid = self.store.create(normalized)
        else:
            record = self.store.snapshot(aid)['assessment']
            if record['target'] != normalized:
                raise ValueError('Cannot change target during resume')
            if resume and record['status'] == 'complete':
                raise ValueError('Assessment already completed')
        ctrl = self.store.control(aid)
        if ctrl and (json.loads(ctrl['scope']) != list(self.policy.networks)
                     or ctrl['worker'] != worker or bool(ctrl['demo']) != bool(lab_exercise)
                     or ctrl.get('lab_kind', 'fixture') != lab_kind
                     or bool(ctrl.get('lab_persistence', 0)) != bool(lab_persistence)):
            raise ValueError('Assessment policy differs from its recorded authorization')
        if not ctrl:
            self.store.set_control(aid, self.policy.networks, provider, model, worker, lab_exercise, lab_kind, lab_persistence)
        if resume:
            self.store.reset_cancel(aid)
            self.store.action(aid, 'lifecycle', 'resume', 'accepted', {'worker': worker})
        else:
            self.store.action(aid, 'scope', 'authorization', 'accepted',
                              {'scope': self.policy.networks, 'target': normalized, 'lab': self.policy.lab, 'worker': worker})
        try:
            self._guard(aid)
            hosts = self._cached(aid) if resume else None
            if hosts is not None:
                self.store.action(aid, 'scanning', 'verified_cached_inventory', 'success', {'hosts': len(hosts)})
            else:
                self.store.update(aid, 'scanning', 'running')
                if offline_xml is not None:
                    raw = offline_xml
                    hosts = parse_nmap(raw)
                    self.store.action(aid, 'scanning', 'nmap_xml_import', 'success', {'hosts': len(hosts)})
                else:
                    hosts, raw = scan(normalized, worker=worker, should_cancel=lambda: self.store.cancelled(aid))
                    self.store.action(aid, 'scanning', 'nmap_tcp_scan', 'success',
                                      {'hosts': len(hosts), 'services': sum(len(h['ports']) for h in hosts), 'worker': worker})
                for h in hosts:
                    if not self.policy.allows_ip(h['address']):
                        raise ValueError('Out-of-scope host in imported/scanned XML')
                self.store.artifact(aid, 'nmap.xml', raw.encode())
                self.store.artifact(aid, 'inventory.json', json.dumps(hosts, indent=2).encode())
            self._guard(aid)
            # Enumeration and possible weaknesses are observations, never proofs of exploitation.
            self.store.update(aid, 'enumeration', 'running')
            self.store.action(aid, 'enumeration', 'service_inventory', 'success', {'hosts': len(hosts)})
            previous = {f['title'] for f in self.store.snapshot(aid)['findings']}
            for host in hosts:
                for port in host['ports']:
                    if port['port'] in {21, 23}:
                        title = f"Review exposed service {port['service']} on {host['address']}:{port['port']}"
                        if title not in previous:
                            self.store.finding(aid, title, 'Informational',
                                               'Service observed in Nmap inventory; no vulnerability confirmed',
                                               'Review business need, encrypted alternatives, and access control')
            self._guard(aid)
            self.store.update(aid, 'planning', 'running')
            plan = propose_safe_checks(hosts, self.policy)
            self.store.artifact(aid, 'plan.json', json.dumps(plan, indent=2).encode())
            self.store.action(aid, 'planning', 'deterministic_plan', 'success',
                              {'checks_proposed': len(plan), 'execution': 'safe only'})
            if safe_checks:
                self.store.update(aid, 'safe_validation', 'running')
                run_safe_checks(plan, self.policy, self.store, aid, should_cancel=lambda: self.store.cancelled(aid))
            self._guard(aid)
            self.store.update(aid, 'analysis', 'running')
            try:
                result = analyze(hosts, provider, model, api_key=api_key)
                self.store.action(aid, 'analysis', 'ai_advisory', 'success',
                                  {'provider': provider, 'summary': result['summary'],
                                   'hypotheses': result['hypotheses']})
                self.store.artifact(aid, 'ai_advisory.json', json.dumps(result, indent=2).encode())
            except Exception as exc:
                self.store.action(aid, 'analysis', 'ai_advisory', 'failed',
                                  {'provider': provider, 'error_type': type(exc).__name__})
            self._guard(aid)
            if lab_exercise:
                self.store.update(aid, 'lab_validation', 'running')
                if lab_kind == 'container':
                    run_container_lab_exercise(self.policy, self.store, aid, persistence=lab_persistence)
                else:
                    run_lab_exercise(self.policy, self.store, aid)
            else:
                self.store.action(aid, 'validation', 'intrusive_tests', 'not_run',
                                  {'reason': 'Requires approved, bounded adapter; arbitrary remote exploitation unavailable'})
            self._guard(aid)
            self.store.update(aid, 'report', 'complete')
            snap = self.store.snapshot(aid)
            self.store.artifact(aid, 'report.html', render_html(snap).encode())
            self.store.artifact(aid, 'report.json', json.dumps(snap, indent=2).encode())
            return aid
        except (AssessmentCancelled, ScanCancelled):
            self.store.action(aid, 'lifecycle', 'assessment_cancelled', 'cancelled', {'reason': 'user request'})
            self.store.update(aid, 'cancelled', 'cancelled')
            return aid
        except Exception as exc:
            self.store.action(aid, 'error', 'assessment_error', 'failed',
                              {'type': type(exc).__name__, 'message': str(exc)[:200]})
            self.store.update(aid, 'error', 'failed')
            raise
