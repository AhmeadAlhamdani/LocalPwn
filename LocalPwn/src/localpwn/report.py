"""Offline HTML and JSON reports with HTML escaping."""
import html
import json

def render_html(snapshot):
    a=snapshot["assessment"]
    esc=lambda x: html.escape(str(x),quote=True)
    findings="".join(f"<tr><td>{esc(f['severity'])}</td><td>{esc(f['title'])}</td><td>{esc(f['evidence'])}</td><td>{esc(f['recommendation'])}</td></tr>" for f in snapshot["findings"])
    actions="".join(f"<tr><td>{esc(t['ts'])}</td><td>{esc(t['phase'])}</td><td>{esc(t['kind'])}</td><td>{esc(t['status'])}</td><td><pre>{esc(t['details'])}</pre></td></tr>" for t in snapshot["actions"])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>LocalPwn Report</title><style>body{{font:15px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem;color:#17222b}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border:1px solid #ddd;padding:9px;vertical-align:top;text-align:left}}th{{background:#edf2f6}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;max-width:460px}}.note{{background:#fff5da;padding:1rem;border-radius:6px}}</style></head><body><h1>LocalPwn Security Assessment</h1><p><strong>Target:</strong> {esc(a['target'])} | <strong>Status:</strong> {esc(a['status'])} | <strong>ID:</strong> {esc(a['id'])}</p><p class="note">Automated observations are not a guarantee of complete coverage. Service versions are informational and are not confirmed vulnerabilities. Lab validations are simulations and must not be presented as production compromises.</p><h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Evidence</th><th>Remediation</th></tr>{findings}</table><h2>Action Timeline</h2><table><tr><th>Time (UTC)</th><th>Phase</th><th>Action</th><th>Status</th><th>Details</th></tr>{actions}</table><h2>Artifacts</h2><pre>{esc(json.dumps(snapshot['artifacts'],indent=2))}</pre></body></html>'''
