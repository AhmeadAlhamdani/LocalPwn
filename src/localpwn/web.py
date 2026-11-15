"""Single-user, localhost-only assessment console and job controls.

This is not an authenticated multi-user service. Never expose it off-host.
"""
import json
from contextlib import asynccontextmanager
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
    @asynccontextmanager
    async def lifespan(application):
        yield
        executor.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(title="LocalPwn", docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
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
        lab_kind: str = "fixture"
        lab_persistence: bool = False
        worker: str = "native"
        safe_checks: bool = False

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
        return {"status": "ok", "version": "1.0.0-rc1", "mode": "loopback", "sandbox": "optional Docker Nmap worker", "live_exploitation": False, "resume": True, "cancel": True}

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

    def run_assessment(aid, target, policy, provider, model, api_key, offline_xml=None, lab=False, worker="native", safe_checks=False, resume=False, lab_kind="fixture", lab_persistence=False):
        s = connection()
        try:
            Engine(s, policy).execute(target, provider=provider, model=model,
                                      lab_exercise=lab, aid=aid, offline_xml=offline_xml,
                                      api_key=api_key, worker=worker, safe_checks=safe_checks, resume=resume, lab_kind=lab_kind, lab_persistence=lab_persistence)
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
        if payload.worker not in {"native", "docker"}:
            raise HTTPException(422, "Unsupported execution worker")
        if payload.lab_kind not in {"fixture", "container"}:
            raise HTTPException(422, "Unknown lab profile")
        if payload.lab_persistence and not (payload.demo and payload.lab_kind == "container"):
            raise HTTPException(422, "Marker simulation requires the container lab profile")
        if payload.demo and payload.worker != "native":
            raise HTTPException(422, "Offline demo runs only in native fixture mode; it has no network traffic")
        if payload.api_key and payload.provider not in {"openai", "anthropic"}:
            raise HTTPException(422, "API key only valid for a supported cloud provider")
        try:
            policy = Policy((payload.allow.strip(),), max_hosts=payload.max_hosts,
                            lab=payload.demo)
            target = policy.validate_target(payload.target.strip())
            if payload.demo and payload.lab_kind == "fixture" and (target != "192.168.56.10/32" or payload.allow.strip() != "192.168.56.10/32"):
                raise ValueError("Offline demo requires 192.168.56.10/32")
            if payload.demo and payload.lab_kind == "container" and (target != "127.0.0.1/32" or payload.allow.strip() != "127.0.0.1/32"):
                raise ValueError("Container lab requires loopback target 127.0.0.1/32")
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        with lock:
            if current:
                raise HTTPException(409, "An assessment is already running")
            s = connection()
            try:
                aid = s.create(target)
                s.set_control(aid, (payload.allow.strip(),), payload.provider, payload.model, payload.worker, payload.demo, payload.lab_kind, payload.lab_persistence)
            finally:
                s.db.close()
            current.add(aid)
        try:
            xml = (files("localpwn").joinpath("static/demo-nmap.xml").read_text(encoding="utf-8")
                   if payload.demo and payload.lab_kind == 'fixture' else (files('localpwn').joinpath('static/demo-lab-nmap.xml').read_text(encoding='utf-8') if payload.demo and payload.lab_kind == 'container' else None))
            executor.submit(run_assessment, aid, target, policy, payload.provider,
                            payload.model, payload.api_key or None, xml, payload.demo,
                            payload.worker, payload.safe_checks, False, payload.lab_kind, payload.lab_persistence)
        except Exception:
            with lock:
                current.discard(aid)
            raise HTTPException(500, "Failed to schedule assessment")
        return {"id": aid, "status": "queued"}

    @app.post("/api/assessments/{aid}/cancel")
    def cancel(aid: str, x_localpwn_session: str | None = Header(default=None)):
        check_token(x_localpwn_session)
        if not (len(aid) == 12 and aid.isalnum()):
            raise HTTPException(404)
        s = connection()
        try:
            status = s.snapshot(aid)['assessment']['status']
            if status not in {'running', 'pending'}:
                raise HTTPException(409, 'Assessment is not currently running')
            if not s.request_cancel(aid):
                raise HTTPException(409, 'No cancellable job control exists')
            s.action(aid, 'lifecycle', 'cancel_requested', 'accepted', {'source': 'dashboard'})
        except ValueError:
            raise HTTPException(404)
        finally:
            s.close()
        return {'id': aid, 'status': 'cancelling'}

    class ResumeRequest(BaseModel):
        api_key: str | None = Field(default=None, max_length=500)
        safe_checks: bool = False
        acknowledged: bool = False

    @app.post("/api/assessments/{aid}/resume", status_code=202)
    def resume_assessment(aid: str, payload: ResumeRequest,
                          x_localpwn_session: str | None = Header(default=None)):
        check_token(x_localpwn_session)
        if not payload.acknowledged:
            raise HTTPException(422, 'Authorization acknowledgment required')
        if not (len(aid) == 12 and aid.isalnum()):
            raise HTTPException(404)
        with lock:
            if current:
                raise HTTPException(409, 'An assessment is already running')
            s = connection()
            try:
                assessment = s.snapshot(aid)['assessment']
                control = s.control(aid)
                if not control:
                    raise HTTPException(409, 'Legacy assessments cannot be resumed')
                if assessment['status'] == 'complete':
                    raise HTTPException(409, 'Assessment already completed')
                policy = Policy(tuple(json.loads(control['scope'])), lab=bool(control['demo']), max_hosts=32)
                policy.validate_target(assessment['target'])
                provider, model, worker = control['provider'], control['model'], control['worker']
                target, demo = assessment['target'], bool(control['demo'])
                lab_kind = control.get('lab_kind', 'fixture')
                lab_persistence = bool(control.get('lab_persistence', 0))
            except ValueError:
                raise HTTPException(404)
            finally:
                s.close()
            current.add(aid)
        try:
            xml = (files('localpwn').joinpath('static/' + ('demo-lab-nmap.xml' if lab_kind == 'container' else 'demo-nmap.xml')).read_text(encoding='utf-8') if demo else None)
            executor.submit(run_assessment, aid, target, policy, provider, model,
                            payload.api_key, xml, demo, worker, payload.safe_checks, True, lab_kind, lab_persistence)
        except Exception:
            with lock:
                current.discard(aid)
            raise HTTPException(500, 'Resume could not be scheduled')
        return {'id': aid, 'status': 'resuming'}

    @app.get("/api/assessments/{aid}/integrity")
    def integrity(aid: str):
        if not (len(aid) == 12 and aid.isalnum()):
            raise HTTPException(404)
        s = connection()
        try:
            s.snapshot(aid)
            return {'actions': s.verify_actions(aid), 'artifacts': s.verify_artifacts(aid)}
        except ValueError:
            raise HTTPException(404)
        finally:
            s.close()

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

    return app
