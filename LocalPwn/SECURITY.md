# Security model

- Assess only systems you own or have explicit written authorization to test.
- CLI requires `--allow` to specify authorized IP/CIDR scope. This is a local policy declaration, not a legal proof of authorization.
- The default scanner is Nmap TCP connect/version-light with no NSE scripts, credentials, or intrusive payloads.
- AI output is never executed as commands. Tool adapters are explicitly coded.
- Scanner XML is untrusted and must be used only from trusted sources. Do not expose the local dashboard beyond loopback.
- Reports and raw scan results may include sensitive information: protect the `.localpwn/` directory and never commit it.
- API keys are read from environment variables; the tool does not collect or persist them.
- Lab 'persistence' is only a temporary marker removed within the same test; there are no implants, remote shells, lateral movement, or privilege escalation modules in v0.1.
- Container/VM isolation is planned but is **not** provided by the current MVP. A temporary directory is not a sandbox.
- For vulnerabilities, please report privately to repository maintainers before public disclosure.
