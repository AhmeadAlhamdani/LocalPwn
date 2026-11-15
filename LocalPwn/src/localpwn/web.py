"""Local-only interactive assessment dashboard with bounded execution.

This service is intended for a single trusted user on loopback. Do not reverse
proxy it or expose port 8000 to another machine; it has no user authentication.
"""
import json
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from importlib.resources import files

from .engine import Engine
from .policy import Policy
from .report import render_html
from .store import Store


def make_app(root):
    from fastapi import FastAPI, HTTPException, Request, Header
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    from fastapi.middleware.trustedhost import TrustedHostMiddleware
    from pydantic import BaseModel, Field

    base = Path(root).resolve()
    store = Store(base)
    store.db.close()
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="localpwn")
    current = set()
    lock = threading.Lock()
    csrf_token = secrets.token_urlsafe(32)
    app = FastAPI(title="LocalPwn", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])

    class AssessmentRequest(BaseModel):
        target: str = Field(min_length=3, max_length=80)
        allow: str = Field(min_length=3, max_length=160)
        provider: str = "none"
        model: str | None = Field(default=None, max_length=120)
        api_key: str | None = Field(default=None, max_length=500)
        max_hosts: int = Field(default=16, ge=1, le=32)
        acknowledged: bool = False
        demo: bool = False

    def check_token(token):
        if not token or not secrets.compare_digest(token, csrf_token):
            raise HTTPException(403, "Invalid session token")

    def connection():
        return Store(base)

    def entry_list():
        s = connection()
        try:
            return [dict(row) for row in s.db.execute("SELECT * FROM assessments ORDER BY created DESC LIMIT 100")]
        finally:
            s.db.close()

    @app.get("/", response_class=HTMLResponse)
    def index():
        html = files("localpwn").joinpath("static/index.html").read_text(encoding="utf-8")
        html = html.replace("__LOCALPWN_SESSION__", csrf_token)
        return HTMLResponse(html, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"})

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.2.0", "mode": "loopback", "sandbox": "not implemented", "live_exploitation": False}

    @app.get("/api/assessments")
    def assessments():
        return entry_list()

    @app.get("/api/assessments/{aid}")
    def assessment(aid: str):
        if not (len(aid) == 12 and aid.isalnum()):
            raise HTTPException(404, "Not found")
        s = connection()
        try:
            return s.snapshot(aid)
        except ValueError:
            raise HTTPException(404, "Not found")
        finally:
            s.db.close()

    def run_assessment(aid, target, policy, provider, model, api_key, offline_xml=None, lab=False):
        s = connection()
        try:
            Engine(s, policy).execute(target, provider=provider, model=model,
                                      lab_exercise=lab, aid=aid, offline_xml=offline_xml,
                                      api_key=api_key)
        except Exception:
            # Engine logs only a bounded error to the local assessment database.
            pass
        finally:
            s.db.close()
            with lock:
                current.discard(aid)

    @app.post("/api/assessments", status_code=202)
    def start(payload: AssessmentRequest, x_localpwn_session: str | None = Header(default=None)):
        check_token(x_localpwn_session)
        if not payload.acknowledged:
            raise HTTPException(422, "Confirm authorization and scope before starting")
        if payload.provider not in {"none", "ollama", "openai", "anthropic"}:
            raise HTTPException(422, "Unsupported provider")
        if payload.api_key and payload.provider not in {"openai", "anthropic"}:
            raise HTTPException(422, "API key only valid for a supported cloud provider")
        try:
            policy = Policy((payload.allow.strip(),), max_hosts=payload.max_hosts,
                            lab=payload.demo)
            target = policy.validate_target(payload.target.strip())
            if payload.demo and (target != "192.168.56.10/32" or payload.allow.strip() != "192.168.56.10/32"):
                raise ValueError("Offline demonstration requires the bundled synthetic target 192.168.56.10/32")
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        with lock:
            if current:
                raise HTTPException(409, "An assessment is already running")
            s = connection()
            try:
                aid = s.create(target)
            finally:
                s.db.close()
            current.add(aid)
        try:
            xml = (files("localpwn").joinpath("static/demo-nmap.xml").read_text(encoding="utf-8")
                   if payload.demo else None)
            executor.submit(run_assessment, aid, target, policy, payload.provider,
                            payload.model, payload.api_key or None, xml, payload.demo)
        except Exception:
            with lock:
                current.discard(aid)
            raise HTTPException(500, "Failed to schedule assessment")
        return {"id": aid, "status": "queued"}

    @app.get("/api/assessments/{aid}/export/{fmt}")
    def export(aid: str, fmt: str):
        if fmt not in {"json", "html", "pdf"}:
            raise HTTPException(404, "Unknown format")
        if not (len(aid) == 12 and aid.isalnum()):
            raise HTTPException(404)
        s = connection()
        try:
            snapshot = s.snapshot(aid)
        except ValueError:
            raise HTTPException(404)
        finally:
            s.db.close()
        if fmt == "json":
            data = json.dumps(snapshot, indent=2)
            mime = "application/json"
        elif fmt == "html":
            data = render_html(snapshot)
            mime = "text/html"
        else:
            from .report import render_pdf
            try:
                data = render_pdf(snapshot)
            except ImportError:
                raise HTTPException(503, "Install optional PDF dependency: pip install reportlab")
            mime = "application/pdf"
        return Response(data, media_type=mime, headers={
            "Content-Disposition": f'attachment; filename="localpwn-{aid}.{fmt}"',
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    @app.get("/api/assessments/{aid}/inventory")
    def inventory(aid: str):
        if not (len(aid) == 12 and aid.isalnum()):
            raise HTTPException(404)
        s = connection()
        try:
            row = s.db.execute("SELECT path FROM artifacts WHERE assessment_id=? AND path LIKE ? ORDER BY rowid DESC LIMIT 1", (aid, "%/inventory.json")).fetchone()
            if row is None:
                return []
            path = Path(row["path"]).resolve()
            if path.parent != (base / aid).resolve() or not path.is_file():
                raise HTTPException(404)
            return json.loads(path.read_text(encoding="utf-8"))
        finally:
            s.db.close()

    @app.get("/api/assessments/{aid}/artifacts/{artifact_id}")
    def artifact(aid: str, artifact_id: str):
        if not (len(aid) == 12 and aid.isalnum() and len(artifact_id) == 32 and artifact_id.isalnum()):
            raise HTTPException(404)
        s = connection()
        try:
            row = s.db.execute("SELECT path FROM artifacts WHERE id=? AND assessment_id=?", (artifact_id, aid)).fetchone()
            if row is None:
                raise HTTPException(404)
            # Only files created under this assessment are accessible.
            path = Path(row["path"]).resolve()
            expected = (base / aid).resolve()
            if path.parent != expected or not path.is_file():
                raise HTTPException(404)
            content = path.read_bytes()
        finally:
            s.db.close()
        return Response(content, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{path.name}"',
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    @app.on_event("shutdown")
    def shutdown():
        executor.shutdown(wait=False, cancel_futures=True)

    return app
