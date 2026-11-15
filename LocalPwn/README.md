# LocalPwn v0.1 — local-first security assessment MVP

A Kali-first, open-source assessment orchestrator. **This is a runnable phase-one implementation, not a complete autonomous pentester.** It supports explicit IP/CIDR authorization boundaries, conservative Nmap scanning or offline XML import, service inventory, optional AI advisory analysis, a durable SQLite action log, hashed evidence artifacts, read-only localhost reports, and a reversible synthetic lab validation demonstration.

## Quick start (Kali / Ubuntu)

```bash
sudo apt update && sudo apt install -y python3 python3-venv nmap
bash scripts/express-install.sh
.venv/bin/localpwn doctor
```

The installer is interactive and does not silently elevate privileges. It installs the app in a project-local virtual environment. Optional `web` dependency is included. To skip the installer, use `python3 -m venv .venv && .venv/bin/pip install -e '.[web,test]'`.

### Run a safe offline demo — no network traffic

```bash
.venv/bin/localpwn assess 192.168.56.10 --allow 192.168.56.10/32 \
  --import-nmap examples/nmap.xml --lab --lab-exercise
.venv/bin/localpwn web
```

Open <http://127.0.0.1:8000>. This exercise uses supplied synthetic Nmap XML and a temporary local fixture. It **does not** exploit `192.168.56.10` or install persistence anywhere.

### Authorized live service inventory

```bash
.venv/bin/localpwn assess 192.168.56.10 --allow 192.168.56.10/32
```

Nmap performs a TCP connect scan with lightweight version detection; no exploitation, remote shells, persistence, or arbitrary agent-generated commands. Network and authorization constraints must be validated by the operator. IPs only in v0.1, not hostnames. The default limit is 32 target addresses; `--max-hosts` can be raised up to 256 with an explicitly allowed range. HTB rules may restrict scanning to a single assigned machine.

## AI providers — user's own credentials or hardware

AI is optional. Without it, all deterministic functionality works. The AI receives sanitized/limited inventory metadata, **not necessarily risk-free**: do not select a cloud provider for confidential environments unless your organization's policies permit data transfer. Providers:

```bash
# Ollama, defaults to local http://127.0.0.1:11434 and model gpt-oss:20b
localpwn assess 192.168.56.10 --allow 192.168.56.10/32 --provider ollama

# OpenAI: first configure OPENAI_API_KEY in the process environment
localpwn assess 192.168.56.10 --allow 192.168.56.10/32 --provider openai

# Anthropic: first configure ANTHROPIC_API_KEY in the process environment
localpwn assess 192.168.56.10 --allow 192.168.56.10/32 --provider anthropic
```

The user pays their own cloud API charges and can supply `--model`. API keys are not saved by LocalPwn. Model availability, versions and pricing may change. No "login with ChatGPT subscription" integration is provided. There is **no cost cap implementation** in v0.1; cloud AI users should control their own spend.

## Output

Data defaults to `.localpwn/`: SQLite database and per-assessment directory containing `nmap.xml`, `inventory.json`, `report.html`, `report.json`, and, when available, `ai_advisory.json`. Each artifact gets a SHA-256 digest in the audit database. Reports distinguish informational observations from confirmed findings. SQLite actions are persistent but are not cryptographically tamper-evident. There is no protected secrets vault in v0.1.

`localpwn report ASSESSMENT_ID` displays full JSON snapshots; `localpwn web` exposes a read-only dashboard on `127.0.0.1:8000`.

## Architecture

- `policy.py`: literal-IP scope checks and allowed action categories
- `scanner.py`: Nmap execution and XML parsing
- `ai.py`: Ollama/OpenAI/Anthropic advisory adapters
- `engine.py`: assessment phase transitions and automatic reports
- `store.py`: SQLite action trail, findings, artifact hashing
- `lab.py`: **simulation only**, local temporary directory marker creation + cleanup
- `web.py`: read-only localhost dashboard

### Security limitations of this MVP

- The *hybrid installation* vision is **not implemented completely**. Docker/VM worker isolation, dependency auto-install, Windows support, and native packaging remain future milestones.
- No automatic exploit-chaining, general target exploitation, post-exploitation, privilege escalation, credential theft, or remote persistence mechanisms are shipped. AI only generates advisory hypotheses.
- No approval UI, policy signing, per-stage workflow retry, or resume command yet. Phase state is saved, but recovery still requires re-running an assessment.
- No independent validation of identified CVEs; product/version matches are not proof of compromise.
- A local temporary directory is not a sandbox. Deploy within a dedicated, appropriately isolated workstation/VM if interacting with untrusted targets.
- Nmap invocation is bounded by `--host-timeout` and a subprocess timeout; a scan can still generate traffic and disruption on fragile services.
- Nmap XML, API responses and stored findings are untrusted inputs. Harden before production use.

## Planned phases

1. **v0.1 (included)**: Kali-first CLI, optional AI, scope, service scanning, import, action records, synthetic lab fixture, reports and tests.
2. **v0.2**: sandbox worker with network egress policy, express dependency setup with rollback, signed policy profiles, persistence/resume, cost budgets and an improved authenticated localhost UI.
3. **v0.3**: audited safe validation plugin SDK with user approvals, bounded non-destructive checks and testing harnesses for intentionally vulnerable Docker labs.
4. **v0.4**: more service adapters, richer AI planning/state, attack-path *hypotheses*, remediation retests, reports in multiple formats, CI-based compatibility testing.
5. **v1.0**: packaging, cross-platform support, mature isolation, extensive security testing and governance controls.

## Tests

```bash
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

## License

Apache-2.0. Bundled third-party tools are not redistributed by this repository. Respect their licenses and the rules of each authorized training platform.

---

## Interactive localhost dashboard (v0.2)

The v0.2 dashboard replaces the former read-only page with a functional assessment console. From a browser you can:

- Enter a **literal IPv4/IPv6 IP or CIDR** and an explicit authorized scope; acknowledge authorization.
- Select deterministic/no-AI, local Ollama, OpenAI API, or Anthropic API. Cloud keys can be entered **for a single run** and are not stored in the local database or browser storage. Existing environment variables are also supported.
- Launch background Nmap discovery or an **offline demo**; see phase and completion status refresh periodically.
- Navigate **Overview**, **New assessment**, **Assessments**, **Findings & evidence** (findings, assets JSON, audit actions, artifacts, AI advisory), **Reports**, and **Settings**.
- Download **HTML**, **JSON**, and **PDF** reports (PDF needs ReportLab), and individual evidence files.

### Install / upgrade on Kali

```bash
sudo apt update
sudo apt install -y git python3 python3-venv nmap
cd ~/LocalPwn
# After obtaining and extracting the new release (or pulling an uploaded GitHub update):
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[full]'
.venv/bin/localpwn doctor
.venv/bin/localpwn web
```

Open **http://127.0.0.1:8000** in the Kali VM. Use **New assessment → Use offline demo preset**, check the authorization box, click **Start assessment**, and view the completed result under **Findings & evidence**. You can also run CLI assessments and inspect their records through the same dashboard if both use the same working directory / `.localpwn` root.

**Security boundaries:** The dashboard is intentionally **single-user, loopback-only**, has no remote user authentication, and must not be exposed via public interfaces, reverse proxies, shared ports, or port-forwarding. The application runs assessments with the OS account's existing permissions. Nmap scans are conservative and bounded; tools are **not yet executed inside Docker/microVM worker sandboxes**. This version does not provide arbitrary AI-driven exploitation, real post-exploitation or persistence, job cancellation, nor true cross-process assessment resume. Its lab demonstration creates and removes a marker inside a temporary local folder; it never accesses a remote host. Do not interpret it as a successful exploit.
