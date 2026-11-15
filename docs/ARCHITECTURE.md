# LocalPwn architecture (v1.0 release candidate)

```text
Kali browser localhost:8000
            |
            v
     FastAPI UI + endpoints  --- session CSRF token / trusted host
            |
            v
  Single background worker pool -----> SQLite job controls & action hashes
            |
            v
         Engine (phase state and checkpoints)
          |         |                  |
          v         v                  v
       Policy    Scanner         AI advisory adapter
       CIDR    native/Docker      none/Ollama/OpenAI/Anthropic
          |         |                  |
          +---------+------------------+
                    |
                    v
       deterministic safe plan + optional HEAD observation
                    |
                    v
     (optional) separate loopback Docker training fixture
                    |
                    v
           SQLite + SHA-256 evidence store
                    |
                    v
           HTML/JSON/PDF reports
```

## Key trust boundaries

1. **The browser and FastAPI share a trusted local OS account.** Not suitable for hostile or multiuser localhost contexts. Must bind to `127.0.0.1`; browser-to-server POSTs require a per-process session token and Host restriction.
2. **The execution worker is not a universal sandbox.** Docker runs Nmap as nonroot with restricted capabilities and filesystem, but can make network connections through the bridge network. The target CIDR is validated by the host controller before invocation. VM/firewall egress confinement must be configured separately.
3. **The AI is not an execution authority.** Nmap output and service names are untrusted text. AI outputs are treated as hypotheses and never turned into unrestricted commands. All actual checks come from deterministic registered code.
4. **Sensitive outputs remain on disk** in `.localpwn/` unless cloud AI explicitly enabled. Evidence is accessible to the OS account and anyone able to access the local dashboard. SHA-256 action chaining detects some local modifications but cannot prove external authenticity.
5. **Container lab is explicitly loopback-only.** The validation module uses a fixed port and an exact synthetic-service identity check before exercising the intentionally vulnerable fixture. It never receives arbitrary target URLs.

## Assessment state

An assessment is created with its target and recorded scope, AI provider/model, worker, and lab profile. Workflow phases are scoped discovery → enumeration → safe plan → optional safe validation → advisory AI → optional isolated lab check → reporting. Cancellation sets a durable flag checked between phases and by the scan process polling loop. Resume requires the same target, scope and worker; a valid stored inventory is reused, otherwise the initial scan runs again. Report artifacts are versioned instead of overwritten.

## Deliberate omissions

There is no LLM shell, remote auto-exploitation, real persistence, general post-exploitation, credential extraction, stealth toolchain, remote multitenant deployment, enterprise identity provider, or cryptographically signed chain of custody. See release acceptance for quality gates before calling a future version production-ready.
