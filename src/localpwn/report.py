"""Offline HTML and JSON reports with HTML escaping."""
import html
import json

def render_html(snapshot):
    a=snapshot["assessment"]
    esc=lambda x: html.escape(str(x),quote=True)
    findings="".join(f"<tr><td>{esc(f['severity'])}</td><td>{esc(f['title'])}</td><td>{esc(f['evidence'])}</td><td>{esc(f['recommendation'])}</td></tr>" for f in snapshot["findings"])
    actions="".join(f"<tr><td>{esc(t['ts'])}</td><td>{esc(t['phase'])}</td><td>{esc(t['kind'])}</td><td>{esc(t['status'])}</td><td><pre>{esc(t['details'])}</pre></td></tr>" for t in snapshot["actions"])
    integrity = snapshot.get('audit_integrity', {})
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>LocalPwn Report</title><style>body{{font:15px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem;color:#17222b}}table{{border-collapse:collapse;width:100%;margin:1rem 0}}td,th{{border:1px solid #ddd;padding:9px;vertical-align:top;text-align:left}}th{{background:#edf2f6}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;max-width:460px}}.note{{background:#fff5da;padding:1rem;border-radius:6px}}</style></head><body><h1>LocalPwn Security Assessment</h1><p><strong>Target:</strong> {esc(a['target'])} | <strong>Status:</strong> {esc(a['status'])} | <strong>ID:</strong> {esc(a['id'])}</p><p class="note">Automated observations are not a guarantee of complete coverage. Service versions are informational and are not confirmed vulnerabilities. Lab validations are simulations and must not be presented as production compromises.</p><p><strong>Action audit chain:</strong> {esc('verified' if integrity.get('valid') else 'unverified')} (hashes provide tamper indication, not independent authentication)</p><h2>Findings</h2><table><tr><th>Severity</th><th>Title</th><th>Evidence</th><th>Remediation</th></tr>{findings}</table><h2>Action Timeline</h2><table><tr><th>Time (UTC)</th><th>Phase</th><th>Action</th><th>Status</th><th>Details</th></tr>{actions}</table><h2>Artifacts</h2><pre>{esc(json.dumps(snapshot['artifacts'],indent=2))}</pre></body></html>'''


def render_pdf(snapshot):
    """Generate a printable PDF without embedding raw evidence file contents."""
    from io import BytesIO
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from xml.sax.saxutils import escape as xml_escape

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, leftMargin=44, rightMargin=44)
    styles = getSampleStyleSheet()
    story = [Paragraph('LocalPwn Security Assessment', styles['Title']), Spacer(1, 10)]
    assessment = snapshot['assessment']
    for key in ['id', 'target', 'phase', 'status', 'created']:
        story.append(Paragraph(f'<b>{xml_escape(key.title())}:</b> {xml_escape(str(assessment[key]))}', styles['Normal']))
    story.extend([Spacer(1, 15), Paragraph('Scope and limitations', styles['Heading2']),
                  Paragraph('Automated scanning does not guarantee complete coverage. Observed services and AI hypotheses are not independently confirmed vulnerabilities. Synthetic lab demonstrations do not establish access to real hosts.', styles['BodyText']),
                  Spacer(1, 12), Paragraph('Findings & recommendations', styles['Heading2'])])
    if not snapshot['findings']:
        story.append(Paragraph('No findings recorded.', styles['Normal']))
    for finding in snapshot['findings']:
        story.append(Paragraph(xml_escape(str(finding['title'])), styles['Heading3']))
        for field in ['severity', 'evidence', 'recommendation']:
            story.append(Paragraph(f'<b>{field.title()}:</b> {xml_escape(str(finding[field]))}', styles['BodyText']))
        story.append(Spacer(1, 8))
    story.extend([Paragraph('Assessment action history', styles['Heading2'])])
    for action in snapshot['actions']:
        story.append(Paragraph(xml_escape(f"{action['ts']} | {action['phase']} | {action['kind']} | {action['status']}"), styles['BodyText']))
    doc.build(story)
    return buf.getvalue()
