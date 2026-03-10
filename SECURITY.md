# Security Policy

## Supported Versions

Only the latest tagged release is supported for security fixes.

## Reporting a Vulnerability

Please do not open public issues for vulnerabilities.

1. Send a report with reproduction details and impact to the repository maintainers.
2. Include affected version, component (`backend`, `frontend`, `agent`), and logs if available.
3. If possible, include a minimal proof-of-concept.

We target:
- Initial acknowledgment within 72 hours
- Triage decision within 7 days
- Patch plan as soon as impact is confirmed

## Hardening Baselines

- Use HTTPS/WSS in production.
- Rotate admin credentials and API tokens regularly.
- Enforce strict file permissions for local agent token storage (`600`).
- Keep dependencies up to date (`dependabot` enabled).
- Enable CI and CodeQL scanning before merge.
