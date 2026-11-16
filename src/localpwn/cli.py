"""LocalPwn CLI: local assessments, reporting, cancellation and resume."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
from .policy import Policy
from .store import Store
from .engine import Engine


def build_parser():
    p = argparse.ArgumentParser(prog='localpwn', description='Local-first authorized assessment platform')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor', help='Check installation, Docker, Nmap and AI configuration')
    a = sub.add_parser('assess', help='Run a scoped assessment')
    a.add_argument('target', help='Literal IP address or authorized CIDR')
    a.add_argument('--allow', action='append', required=True, help='Authorized CIDR; repeatable')
    a.add_argument('--lab', action='store_true', help='Enable controlled synthetic lab mode')
    a.add_argument('--lab-exercise', action='store_true', help='Run local synthetic lab exercise')
    a.add_argument('--container-lab', action='store_true', help='Run against local-only Docker lab fixture (requires --lab)')
    a.add_argument('--lab-persistence', action='store_true', help='Opt into creating and removing synthetic Docker lab marker')
    a.add_argument('--provider', choices=['none','ollama','openai','anthropic'], default='none')
    a.add_argument('--model')
    a.add_argument('--worker', choices=['native','docker'], default='native')
    a.add_argument('--safe-checks', action='store_true', help='Bounded HTTP HEAD observations; optional')
    a.add_argument('--max-hosts', type=int, default=32)
    a.add_argument('--import-nmap', help='Use saved Nmap XML instead of sending scan traffic')
    a.add_argument('--root', default='.localpwn')
    r = sub.add_parser('report', help='Print a JSON snapshot')
    r.add_argument('assessment_id'); r.add_argument('--root', default='.localpwn')
    c = sub.add_parser('cancel', help='Request cancellation of an active assessment')
    c.add_argument('assessment_id'); c.add_argument('--root', default='.localpwn')
    v = sub.add_parser('verify', help='Verify the local action hash chain and evidence files')
    v.add_argument('assessment_id'); v.add_argument('--root', default='.localpwn')
    x = sub.add_parser('resume', help='Resume an interrupted assessment using stored scope and worker settings')
    x.add_argument('assessment_id'); x.add_argument('--root', default='.localpwn')
    x.add_argument('--safe-checks', action='store_true')
    w = sub.add_parser('web', help='Run the interactive localhost dashboard')
    w.add_argument('--root', default='.localpwn'); w.add_argument('--port', type=int, default=8000)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == 'doctor':
            print('LocalPwn 1.0.0-rc1')
            print('Python:', sys.version.split()[0])
            print('Nmap:', shutil.which('nmap') or 'NOT INSTALLED')
            print('Docker:', shutil.which('docker') or 'optional / not installed')
            print('Ollama:', shutil.which('ollama') or 'optional / not installed')
            for label, key in [('OpenAI', 'OPENAI_API_KEY'), ('Anthropic','ANTHROPIC_API_KEY')]:
                print(f'{label} key:', 'configured' if os.getenv(key) else 'not configured')
            print('Reports: HTML/JSON; PDF requires reportlab')
        elif args.command == 'assess':
            if not 1 <= args.max_hosts <= 256:
                raise ValueError('Host cap must be between 1 and 256')
            if args.lab_exercise and not args.lab:
                raise ValueError('--lab-exercise requires --lab')
            if args.container_lab and not args.lab:
                raise ValueError('--container-lab requires --lab')
            if args.container_lab and (args.target not in {'127.0.0.1','127.0.0.1/32'}
                                       or args.allow != ['127.0.0.1/32']):
                raise ValueError('Container lab requires exact loopback scope 127.0.0.1/32')
            if args.lab_persistence and not args.container_lab:
                raise ValueError('--lab-persistence requires --container-lab')
            if args.container_lab and args.worker != 'native':
                raise ValueError('The pre-recorded container lab assessment uses the native fixture adapter')
            policy = Policy(tuple(args.allow), lab=args.lab, max_hosts=args.max_hosts)
            store = Store(args.root)
            raw = Path(args.import_nmap).read_text() if args.import_nmap else None
            if args.container_lab and not raw:
                from importlib.resources import files
                raw = files('localpwn').joinpath('static/demo-lab-nmap.xml').read_text()
            aid = Engine(store, policy).execute(
                args.target, args.provider, args.model, args.lab_exercise or args.container_lab,
                offline_xml=raw, worker=args.worker, safe_checks=args.safe_checks,
                lab_kind='container' if args.container_lab else 'fixture',
                lab_persistence=args.lab_persistence)
            print('Assessment:', aid)
            latest = store.db.execute("SELECT path FROM artifacts WHERE assessment_id=? AND path LIKE ? ORDER BY rowid DESC LIMIT 1", (aid, '%report%.html')).fetchone()
            print('HTML report:', latest['path'] if latest else '(not created)')
        elif args.command == 'report':
            print(json.dumps(Store(args.root).snapshot(args.assessment_id), indent=2))
        elif args.command == 'cancel':
            s = Store(args.root)
            if not s.request_cancel(args.assessment_id):
                raise ValueError('Unknown job or legacy assessment')
            print('Cancellation requested:', args.assessment_id)
        elif args.command == 'verify':
            s = Store(args.root)
            s.snapshot(args.assessment_id)
            result = {'actions': s.verify_actions(args.assessment_id),
                      'artifacts': s.verify_artifacts(args.assessment_id)}
            print(json.dumps(result, indent=2))
            if not result['actions']['valid'] or not all(a['valid'] for a in result['artifacts']):
                return 1
        elif args.command == 'resume':
            s = Store(args.root)
            record = s.snapshot(args.assessment_id)['assessment']
            control = s.control(args.assessment_id)
            if not control:
                raise ValueError('This assessment has no recorded scope/worker profile')
            if record['status'] == 'complete':
                raise ValueError('Completed assessments cannot be resumed')
            policy = Policy(tuple(json.loads(control['scope'])), lab=bool(control['demo']), max_hosts=256)
            offline_xml = None
            if control['demo']:
                from importlib.resources import files
                lab_name = 'demo-lab-nmap.xml' if control['lab_kind']=='container' else 'demo-nmap.xml'
                offline_xml = files('localpwn').joinpath('static', lab_name).read_text()
            aid = Engine(s, policy).execute(record['target'], provider=control['provider'],
                    model=control['model'], lab_exercise=bool(control['demo']), aid=args.assessment_id,
                    offline_xml=offline_xml, worker=control['worker'], resume=True,
                    safe_checks=args.safe_checks, lab_kind=control['lab_kind'],
                    lab_persistence=bool(control.get('lab_persistence', 0)))
            print('Resumed:', aid)
        elif args.command == 'web':
            try:
                import uvicorn
            except ImportError as exc:
                raise RuntimeError("Install the web dependencies: pip install -e '.[full]'") from exc
            from .web import make_app
            uvicorn.run(make_app(args.root), host='127.0.0.1', port=args.port)
    except (ValueError, RuntimeError, OSError) as exc:
        print('Error:', exc, file=sys.stderr)
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main())
