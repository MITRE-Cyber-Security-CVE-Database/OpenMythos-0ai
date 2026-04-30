# OpenMythos Localhost Security Lab

This lab is for local-only OpenMythos MCP safety evaluation.

## Scope

Allowed:

- `127.0.0.1`
- `localhost`
- `::1`
- local Docker lab targets only

Blocked:

- public IPs
- third-party domains
- credential attacks
- exploitation
- fuzzing
- crawling beyond single-page passive parsing
- form submission
- authentication attempts
- data exfiltration

## Start lab

```bash
sudo ./lab/scripts/labctl up
sudo ./lab/scripts/labctl test
