"""LocalPwn CLI. Run `localpwn --help`."""
import argparse
import ipaddress
import json
import shutil
import sys
import os
from pathlib import Path
from .policy import Policy
from .store import Store
from .engine import Engine

def build_parser():
    p=argparse.ArgumentParser(prog="localpwn",description="Local-first authorized security assessment")
    sub=p.add_subparsers(dest="command",required=True)
    sub.add_parser("doctor",help="Check optional dependencies and provider configuration")
    a=sub.add_parser("assess",help="Run authorized network discovery and advisory analysis")
    a.add_argument("target",help="Literal IP or CIDR")
    a.add_argument("--allow",action="append",required=True,help="Authorized CIDR (repeatable)")
    a.add_argument("--lab",action="store_true",help="Enable isolated lab exercise policy")
    a.add_argument("--lab-exercise",action="store_true",help="Run synthetic local lab fixture exercise")
    a.add_argument("--provider",choices=["none","ollama","openai","anthropic"],default="none")
    a.add_argument("--model")
    a.add_argument("--root",default=".localpwn")
    a.add_argument("--max-hosts",type=int,default=32)
    a.add_argument("--import-nmap",help="Import saved Nmap XML instead of executing Nmap")
    r=sub.add_parser("report",help="Print assessment snapshot")
    r.add_argument("assessment_id")
    r.add_argument("--root",default=".localpwn")
    w=sub.add_parser("web",help="Start read-only localhost dashboard (install [web] extra)")
    w.add_argument("--root",default=".localpwn")
    w.add_argument("--port",type=int,default=8000)
    return p

def main(argv=None):
    args=build_parser().parse_args(argv)
    try:
        if args.command=="doctor":
            print("Python:",sys.version.split()[0]);print("Nmap:",shutil.which("nmap") or "NOT INSTALLED")
            print("Docker:",shutil.which("docker") or "optional / not detected")
            print("Ollama:",shutil.which("ollama") or "optional / not detected")
            for provider,key in [("OpenAI","OPENAI_API_KEY"),("Anthropic","ANTHROPIC_API_KEY")]:
                print(f"{provider} credential: {'configured' if os.environ.get(key) else 'not configured'}")
        elif args.command=="assess":
            if args.max_hosts < 1 or args.max_hosts > 256: raise ValueError("--max-hosts must be 1..256")
            policy=Policy(tuple(args.allow),lab=args.lab,max_hosts=args.max_hosts)
            root=Store(args.root)
            if args.lab_exercise and not args.lab: raise ValueError("--lab-exercise requires --lab")
            raw=Path(args.import_nmap).read_text() if args.import_nmap else None
            aid=Engine(root,policy).execute(args.target,args.provider,args.model,args.lab_exercise,offline_xml=raw)
            print("Assessment:",aid)
            print("Report:",root.root / aid / "report.html")
        elif args.command=="report":
            print(json.dumps(Store(args.root).snapshot(args.assessment_id),indent=2))
        elif args.command=="web":
            try: import uvicorn
            except ImportError as exc: raise RuntimeError("Install pip install -e '.[web]'") from exc
            from .web import make_app
            uvicorn.run(make_app(args.root),host="127.0.0.1",port=args.port)
    except (ValueError,RuntimeError,OSError) as exc:
        print(f"Error: {exc}",file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
