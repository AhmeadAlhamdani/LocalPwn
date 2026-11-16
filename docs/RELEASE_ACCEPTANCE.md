# v1.0 Release Candidate — Acceptance Checklist

The code may carry a v1.0 release-candidate version but it is not production-certified.

## Verified in the provided build environment

- [x] Offline assessment, report and dashboard functional regression suite
- [x] Literal-IP scope validation; imported XML out-of-scope rejection
- [x] Cancellation request and offline resume state handling
- [x] SHA-256 artifact verification and action-chain tamper detection tests
- [x] Bounded Nmap worker command construction tests
- [x] Dashboard form, export and lifecycle API tests
- [x] AI providers supported by existing adapters (code path only)

## Acceptance still required on your Kali VM

- [ ] Clean install on current Kali Linux VirtualBox image
- [ ] Docker Nmap worker build and permitted-scope scan
- [ ] Local synthetic Docker service end-to-end with cleanup
- [ ] Live Nmap checks against a user-owned, nonproduction target
- [ ] Ollama/OpenAI/Anthropic API smoke tests with individual user-owned keys
- [ ] Large scan cancellation and resume under VM resource constraints
- [ ] Rootless Docker/VM network boundaries assessed and configured
- [ ] Secrets, denial-of-service, privilege boundary and report export review
- [ ] Dependency/SBOM and software supply-chain review
- [ ] Independent security audit before any production endorsement

## Explicitly not implemented

- Autonomous remote exploitation or post-exploitation on arbitrary targets
- Real persistent access deployment; lab marker is synthetic only
- General credential discovery, lateral movement, evasion, unbounded agent shell
- Guaranteed hard-dollar provider billing ceiling
- Multi-user authentication, remote/web-hosted deployment, scheduled monitoring

## Release qualification

Use `v1.0.0-rc1` while these gates are open. The naming intentionally avoids asserting that the product is safe for professional penetration tests or use against business-critical systems.
