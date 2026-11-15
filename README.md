# LocalPwn v1.0.0-rc1

**Free, self-hosted, local-first, authorized black-box security assessment console.** This is a **release candidate, not independently production-certified software**. The application assists with scoped service discovery, non-destructive checks, human-readable vulnerability hypotheses, lab-only synthetic validation, local evidence history and reports. It is not a substitute for a professional penetration test.

**Target OS:** Kali Linux (VirtualBox, bare metal or WSL2); Ubuntu may work. **Cost model:** no developer-hosted infrastructure; local Ollama is free of per-token API billing (hardware/electricity still apply); cloud AI uses the user's own OpenAI/Anthropic credentials and bills that user.

## Features

- Interactive localhost dashboard: overview, new assessment, history, discovered assets, findings, audit actions, validation plan, AI analysis, evidence, downloadable HTML/JSON/PDF reports, cancel/resume/verification controls.
- CLI: `assess`, `doctor`, `report`, `cancel`, `resume`, `verify`, `web`.
- Nmap TCP connect scanning and service inventory on explicitly allowlisted literal IP/CIDR targets (maximum 256 IPs from CLI; 32 through the browser). No unrestricted scans or arbitrary generated commands.
- Optional Docker scanner worker with dropped capabilities, memory/CPU/process limits, read-only filesystem and non-root user. **Docker does not provide network-scope firewall enforcement**; configure host network controls separately.
- Deterministic planning of safe HTTP HEAD observations with no redirects and fixed ports, disabled by default. Optional AI analysis through Ollama (local), OpenAI API or Anthropic API (bring-your-own-key); AI never directly executes commands.
- SQLite run states, cancel requests, verified scan-cache resume, redacted advisory logs, a local SHA-256 action chain and per-artifact hashes. Legacy v0.2 records have no hash chain.
- Offline simulated lab exercise; separate optional local Docker lab with an intentionally vulnerable object endpoint, synthetic impact proof and temporary reversible marker exercise. No real-world post-exploitation or persistence.
- Professional HTML/JSON and PDF report exports with findings, evidence and remediation notes. Reports explicitly distinguish observations from confirmed vulnerabilities.

## Installation on Kali Linux

Install Git, clone the repository, then enter its root folder. **These commands assume you have published v1.0 using the included Git guide, which flattens the older nested `LocalPwn/` folder into the repository root.**

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip nmap
cd ~
git clone https://github.com/AhmeadAlhamdani/LocalPwn.git
cd ~/LocalPwn
bash scripts/express-install.sh --test
.venv/bin/localpwn doctor
.venv/bin/localpwn web
```

Open **http://127.0.0.1:8000** in Firefox *inside Kali*. If you already have the repo, stop the old server (`Ctrl+C`), run `cd ~/LocalPwn && git pull --ff-only origin main`, then `bash scripts/upgrade.sh` from the repo root. A newly flattened v1 install uses a **new root-level** `.venv`; the old `~/LocalPwn/LocalPwn/.venv` can be removed only after verifying the new installation.

For a ZIP-only installation (without a Git checkout), extract and open its `LocalPwn/` folder, then run `bash scripts/express-install.sh`.

## Optional Docker scanner

Install Docker Engine through Kali's supported package procedure, start its daemon and confirm `docker version` works for your user. Docker privileges are powerful; evaluate membership in the `docker` group before granting it. Build the worker image:

```bash
cd ~/LocalPwn
docker build -t localpwn-scanner:1.0 -f docker/Dockerfile.scanner docker/
# Then choose Docker in the web UI or --worker docker in the CLI.
```

This worker can still originate network traffic beyond its IP allowlist if an attacker compromises the worker or the container runtime; **do not treat it as a firewall-enforced sandbox**. A segregated VM and external egress filtering are recommended for sensitive use.

## Try the completely offline demo

```bash
cd ~/LocalPwn
.venv/bin/localpwn assess 192.168.56.10 \
  --allow 192.168.56.10/32 --import-nmap examples/nmap.xml \
  --lab --lab-exercise
```

Or use **New assessment → Offline demonstration mode** in the dashboard. The IP is only a fixture label. It is not contacted, exploited or altered.

## Run the optional intentionally vulnerable Docker lab

The only automated exploitation/persistence demonstration is inside the disposable **local synthetic lab**. It neither handles real secrets nor provides access to a remote host.

```bash
cd ~/LocalPwn
docker compose -f examples/lab/compose.yaml up -d --build
# Lab-only assessment: uses a pre-recorded inventory and fixed loopback fixture
.venv/bin/localpwn assess 127.0.0.1 \
  --allow 127.0.0.1/32 --lab --container-lab --lab-persistence
# Stop and delete the local fixture after testing
docker compose -f examples/lab/compose.yaml down
```

In the dashboard: New assessment → Lab exercise type **Local Docker training service**, use target `127.0.0.1` and allow `127.0.0.1/32`, enable demo mode, and start. The lab confirms a mock object-level authorization bug. When the optional persistence marker box is checked, it creates then removes a synthetic file in the disposable container; this is not an implant or persistent access to a real machine.

The lab binds only to `127.0.0.1:18181` on the host. Never rebind or publish this deliberately vulnerable training service to external interfaces. The lab network is configured as internal-only.

## Run discovery against your own test host

```bash
.venv/bin/localpwn assess 192.168.56.101 --allow 192.168.56.101/32
# Optional safe, bounded HTTP HEAD checks
.venv/bin/localpwn assess 192.168.56.101 --allow 192.168.56.101/32 --safe-checks
# Optional Docker Nmap worker
.venv/bin/localpwn assess 192.168.56.101 --allow 192.168.56.101/32 --worker docker
```

No remote exploitation, privilege escalation, lateral movement or persistence will run on external targets. Verify platform rules; for example, a training provider may authorize only one machine rather than a whole subnet.

## AI configuration

From the New Assessment form, choose **No AI**, **Ollama**, **OpenAI API** or **Anthropic API**. Cloud providers require the *user's* API credentials (a ChatGPT subscription is not the same as API access). Keys entered through the UI apply to only that assessment and are not saved intentionally; environment variables are another option. Do not share proprietary inventory with an external provider without authorization.

```bash
# Ollama local server listening at the loopback interface
ollama serve
# If the model is already installed:
.venv/bin/localpwn assess 192.168.56.101 --allow 192.168.56.101/32 \
  --provider ollama --model gpt-oss:20b
# Cloud model use: export OPENAI_API_KEY or ANTHROPIC_API_KEY first.
```

To avoid accidental spending, use `none` or Ollama. Cloud provider responses are bounded to one call per run with short output limits, but **there is no guaranteed hard billing cap**. Model identifiers may need to be supplied as the provider evolves.

## Jobs, evidence and reports

```bash
.venv/bin/localpwn report ASSESSMENT_ID
.venv/bin/localpwn cancel ASSESSMENT_ID
.venv/bin/localpwn resume ASSESSMENT_ID
.venv/bin/localpwn verify ASSESSMENT_ID
.venv/bin/localpwn web --port 8000
```

The working directory's `.localpwn/` stores the SQLite database and evidence folders with restrictive file permissions. Always start CLI and web from the **same directory**, otherwise they will use different databases. Resume reuses a verified cached inventory if available; not every interrupted action can be resumed mid-command. Cancel is cooperative and tries to stop active scan processes.

The dashboard lets you select any assessment and download its current report. Each run has an action history, findings, plan, inventory and evidence list. `verify` detects changed action rows/evidence hashes, but local hashes can be forged by an adversary with filesystem/database write access.

## Project tree

```text
LocalPwn/
├── .github/workflows/ci.yml
├── docker/Dockerfile.scanner
├── docs/
│   ├── ARCHITECTURE.md
│   ├── GITHUB_PUBLISH.md
│   └── RELEASE_ACCEPTANCE.md
├── examples/
│   ├── nmap.xml
│   └── lab/{app.py,Dockerfile,compose.yaml}
├── scripts/{express-install.sh,upgrade.sh,install-wsl.ps1}
├── src/localpwn/
│   ├── {ai,cli,engine,lab,policy,report,scanner,store,validation,web}.py
│   └── static/{index.html,demo-nmap.xml,demo-lab-nmap.xml}
├── tests/
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
├── SECURITY.md
├── README.md
└── pyproject.toml
```

## Tests

```bash
.venv/bin/python -m pip install -e '.[full,test]'
.venv/bin/python -m pytest -q
```

## Publication and maturity

See [GitHub publish instructions](docs/GITHUB_PUBLISH.md), [architecture](docs/ARCHITECTURE.md), [security notes](SECURITY.md) and [acceptance criteria](docs/RELEASE_ACCEPTANCE.md). This candidate is **not production-certified**. Professional external assessments require human judgment, customer authorization, threat modeling, deployment hardening and independent verification.

Apache-2.0 terms apply to original project code. Third-party Nmap/Docker/provider licensing and costs remain the user's responsibility.
