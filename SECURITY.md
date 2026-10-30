# Security Policy

## Supported Versions

This is a research and educational project. Only the latest main branch is supported for security reports.

## Reporting a Vulnerability

Please open a private security advisory on GitHub or email the repository owner with:

- Description of the issue
- Steps to reproduce
- Potential impact
- Suggested fix if available

Do not open public issues for vulnerabilities that could be exploited.

We aim to acknowledge reports within 7 days and provide a status update within 14 days.

## Scope

In scope:
- Authentication and authorization bypass in the API
- Injection into generated SPL or containment actions
- Model or data poisoning vectors that are realistic against the published design
- Secrets leakage through logs or responses

Out of scope:
- Denial of service against the local development stack
- Issues requiring physical access
- Vulnerabilities in third-party services (Splunk, Ollama) outside our control

## Safe Harbor

We will not pursue legal action against researchers who:

- Act in good faith
- Avoid privacy violations and data destruction
- Give us reasonable time to remediate before public disclosure
- Do not exploit the vulnerability beyond what is necessary to demonstrate it