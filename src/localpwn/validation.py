"""Registry of bounded, non-destructive HTTP header observation checks."""
from __future__ import annotations
import http.client
import ipaddress
import json

ALLOWED_PORTS = {80, 443, 8080, 8443}


def propose_safe_checks(hosts, policy):
    proposals = []
    for host in hosts:
        if not policy.allows_ip(host['address']):
            continue
        for p in host['ports']:
            if p['port'] in ALLOWED_PORTS and p.get('protocol') == 'tcp':
                proposals.append({
                    'adapter': 'http_headers', 'risk': 'low', 'target': host['address'],
                    'port': p['port'], 'https': p['port'] in {443, 8443},
                    'method': 'HEAD', 'description': 'Observe HTTP response headers; no exploit attempted'})
    return proposals[:64]


def run_safe_checks(plan, policy, store, aid, should_cancel=None):
    for item in plan:
        if should_cancel and should_cancel():
            return
        if item['adapter'] != 'http_headers' or item['port'] not in ALLOWED_PORTS:
            continue
        address = str(ipaddress.ip_address(item['target']))
        if not policy.allows_ip(address):
            raise ValueError('Validation would leave authorized scope')
        connection_class = http.client.HTTPSConnection if item['https'] else http.client.HTTPConnection
        conn = connection_class(address, item['port'], timeout=5)
        try:
            conn.request('HEAD', '/', headers={'User-Agent': 'LocalPwn/1.0'})
            resp = conn.getresponse()
            summary = {'target': address, 'port': item['port'], 'status': resp.status,
                       'headers': {k: v[:180] for k, v in resp.getheaders()
                                   if k.lower() in {'server','content-type','strict-transport-security','x-content-type-options'}}}
            store.action(aid, 'safe_validation', 'http_head', 'observed', summary)
        except (OSError, TimeoutError) as exc:
            store.action(aid, 'safe_validation', 'http_head', 'inconclusive',
                         {'target': address, 'port': item['port'], 'reason': type(exc).__name__})
        finally:
            conn.close()
