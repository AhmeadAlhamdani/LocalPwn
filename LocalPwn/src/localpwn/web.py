"""Read-only localhost status dashboard; remote access disabled."""
from html import escape
from .store import Store

def make_app(root):
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
    app=FastAPI(title="LocalPwn Dashboard",docs_url=None,redoc_url=None)
    @app.get("/",response_class=HTMLResponse)
    def index():
        s=Store(root)
        entries=s.db.execute("SELECT * FROM assessments ORDER BY created DESC LIMIT 100").fetchall()
        items="".join(f"<li><a href='/assessments/{escape(row['id'])}'>{escape(row['id'])}</a> — {escape(row['target'])} — {escape(row['status'])}</li>" for row in entries)
        return "<html><head><meta charset='utf-8'><title>LocalPwn</title></head><body style='font:16px system-ui;max-width:800px;margin:4rem auto'><h1>LocalPwn assessments</h1><p>Read-only local dashboard. Start scans with the CLI.</p><ul>"+items+"</ul></body></html>"
    @app.get("/assessments/{assessment_id}",response_class=HTMLResponse)
    def detail(assessment_id: str):
        if not assessment_id.isalnum(): raise HTTPException(404)
        from .report import render_html
        try: return render_html(Store(root).snapshot(assessment_id))
        except ValueError: raise HTTPException(404)
    return app
