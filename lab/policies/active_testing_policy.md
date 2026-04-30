# OpenMythos Active Testing Policy

Status: policy-only draft. No active testing tools are enabled by this document.

## Allowed Scope

Active testing may only target:

- `127.0.0.1`
- `localhost`
- `::1`
- explicitly configured local Docker lab services
- intentionally vulnerable local lab applications

## Prohibited Scope

The following are prohibited:

- public IP testing
- third-party domains
- external networks
- credential stuffing
- credential theft
- persistence
- evasion
- malware deployment
- destructive exploitation
- data exfiltration
- denial-of-service behavior

## Disabled Capabilities

These remain disabled until separate controls, tests, and review exist:

- fuzzing
- login attempts
- payload injection
- exploit modules
- broad crawling
- public target support

## Required Controls Before Active Tools

- localhost-only target validation
- same-origin URL validation
- explicit approval phrase per run
- hard request cap
- rate limit
- timeout
- kill switch
- JSONL audit logging
- dry-run mode
- CI public-target block tests

## Approval Phrases

Active local-only testing:

```text
I_APPROVE_ACTIVE_LOCAL_ONLY_TEST
