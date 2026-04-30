# OpenMythos Active Lab Threat Model

Status: documentation-only threat model for the localhost-only active dry-run lab.

## Scope

This threat model covers the OpenMythos localhost lab tooling boundary, including:

- passive localhost audit tools
- active dry-run planner
- bounded fuzzing dry-run planner
- dry-run evidence workflow
- readiness checker
- release manifest
- execution lock policy

It does not authorize active fuzzing, exploit execution, login attempts, public target testing, or broad crawling.

## Assets Protected

Protected assets include:

- the operator workstation
- local Docker lab services
- localhost-only vulnerable lab targets
- generated audit evidence
- MCP audit logs
- policy files
- CI safety gates
- Git history and release tags
- public networks and third-party systems

## Trust Boundaries

The key trust boundaries are:

- Chat/operator instructions to shell commands
- local repository scripts to local Docker lab services
- MCP tool validation to target URLs
- dry-run planners to evidence outputs
- policy files to CI enforcement
- generated reports to committed source files
- localhost-only lab boundary to public networks

## Abuse Cases

The lab must resist these abuse cases:

- accidentally enabling real active traffic
- changing `fuzzing_enabled` to `true`
- changing `active_tools_enabled` to `true`
- disabling the kill switch
- allowing public target URLs
- introducing exploit payloads
- introducing SQLi/XSS/command-injection payload classes
- adding login attempts or credential workflows
- adding broad crawling
- bypassing approval phrases
- committing generated evidence with sensitive local details
- weakening CI checks that enforce dry-run behavior

## Existing Safety Controls

Current safety controls include:

- localhost-only target validation
- same-origin validation for local URL workflows
- explicit approval phrases
- active tools disabled by policy
- fuzzing disabled by policy
- kill switch enabled by policy
- dry-run mode required
- request caps in policy
- public target blocking
- zero-request active dry-run planner
- zero-request bounded fuzzing dry-run planner
- execution lock policy
- readiness checker
- release manifest
- generated evidence ignored by Git
- CI checks for tests, readiness, public-target blocking, dry-run zero-execution, and package build

## Residual Risks

Residual risks include:

- operator pasting malformed shell snippets
- accidental tag placement before intended files are committed
- future scripts accidentally using network-capable libraries
- CI drift if workflow files are weakened
- generated local evidence containing host-specific metadata
- dependency behavior changes
- Docker permission or environment mismatch
- over-trusting dry-run outputs without periodic manual review

## Prohibited Transitions

The following transitions are prohibited without a new reviewed milestone:

- dry-run planner to active request sender
- benign fuzz-case planner to fuzz executor
- localhost-only policy to public target support
- policy-only exploit prohibition to exploit module implementation
- no-login policy to login workflow implementation
- single-page passive parsing to broad crawling
- disabled kill switch to disabled-by-default kill switch
- generated local evidence to committed evidence artifacts

## Review Requirements Before Enabling Execution

Before any execution-capable active testing is added, the project requires:

- new milestone name separate from `active-lab-v0.4.x`
- updated threat model
- updated execution lock policy
- updated bounded fuzzing policy
- explicit request budget and rate limit
- local-only scope file
- kill switch design review
- payload allowlist review
- CI tests proving public targets remain blocked
- CI tests proving prohibited payload classes remain prohibited
- operator documentation update
- evidence workflow update
- manual review of generated readiness and release manifests

## Non-Goals

This threat model does not permit:

- public target support
- exploit modules
- login attempts
- credential attacks
- payload injection execution
- broad crawling
- data exfiltration
- denial-of-service behavior
