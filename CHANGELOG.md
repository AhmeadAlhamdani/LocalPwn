# Changelog

## 1.0.0-rc1 (2026-11-15)

- Expanded v0.2 interactive dashboard: execution worker, safe HTTP header observation, loopback lab profile, optional synthetic marker, cancellation, resume, evidence integrity controls.
- Added optional reduced-privilege Docker Nmap worker (image must be built locally).
- Added deterministic validation plan, optional HTTP HEAD check on allowlisted IPs, and local intentionally vulnerable Docker lab fixture with synthetic authorization failure demonstration.
- Added persistent cancellation requests, verified inventory cache recovery, action hash chain, artifact integrity verification and immutable artifact revisions on resume.
- Strengthened XML parser with data/DTD limits and Ollama localhost restriction.
- Added Kali express installer, optional tests, WSL documentation, Git publish guide and GitHub Actions CI.
- Added release acceptance gates and security limitations documentation.

**Known limits:** Not an independent certified production release. No arbitrary live exploitation, post-exploitation, or real persistence against non-lab hosts. Container network egress not firewall-restricted. No multi-user auth or fully robust crash recovery. Cloud model availability and billing not smoke-tested here.

## 0.2.0

- Browser assessment launcher, tabs, provider selection, PDF/JSON/HTML reports.

## 0.1.0

- Authorized Nmap inventory, optional advisory AI, simple local reports and synthetic fixture.
