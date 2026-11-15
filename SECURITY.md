# Security Policy — LocalPwn v1.0 release candidate

LocalPwn is **not certified as production-safe**. It has not undergone an external penetration test, threat-model review, independent security audit, or complete compatibility testing on Kali/VirtualBox. Use a disposable Kali VM for trials; do not process regulated or sensitive production evidence before your organization assesses the risks.

## Boundaries

- Written permission and scope are mandatory. Reachable hosts are not automatically in scope. Training platforms such as HTB may authorize only a specific assigned machine.
- Only literal IP/CIDR targets are accepted. DNS redirects/rebinding are therefore not followed by Nmap target resolution. No general mass-scanning defaults.
- Scans use Nmap TCP connect with conservative version detection and rate caps; testing can still disrupt fragile services.
- Non-destructive HTTP checks use HEAD, fixed ports, short timeouts, and no redirect following.
- AI outputs are advisory only. The LLM has no arbitrary process/shell tool, no dynamic plugin installation, and no remote exploit/persistence capability.
- Real exploitation and remote post-exploitation are **not implemented**. The synthetic lab supports a deliberately vulnerable localhost Docker service and reversible marker exercise, with cleanup.
- Docker workers isolate the scanner process and reduce privileges, but **do not enforce network egress allowlists at the hypervisor/firewall layer**. Scope is enforced by the application. Use a VM/firewall and restrict egress appropriately.
- Dashboard is loopback-only and single-user. Session token is anti-CSRF, **not remote authentication**. Never port-forward, reverse-proxy, or expose it to the LAN.
- API credentials supplied through browser are passed to the backend for a single job and are not intentionally stored, but process memory and provider-side logs may contain sensitive material. Do not provide cloud API keys for confidential environments without approval.
- No billing guarantees: one AI request per run, bounded output; user-paid cloud inference and external provider costs are not subject to a guaranteed hard-dollar cap.
- SQLite action chain and SHA-256 hashes show local integrity changes but are not signed or independently trusted chain-of-custody evidence.

## Reporting vulnerabilities

Do not open public issues containing secrets or production targets. Enable GitHub private vulnerability reporting for this repository, or contact its maintainer through a private channel. Rotate any inadvertently shared credentials immediately.

## Planned security gates before production endorsement

- External code review and threat model
- Container/host egress isolation validation
- Kali and Windows/WSL compatibility matrix
- Provider-specific API and billing integration tests
- Load/long-running job, crash/restart and migration tests
- Multi-user or remote deployment security architecture (if ever supported)
- Signed release artifacts, dependency pinning and SBOM generation
