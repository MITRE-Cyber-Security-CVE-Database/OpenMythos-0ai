# OpenMythos Localhost Lab Operator Guide

This guide documents the localhost-only passive lab and active dry-run assurance workflow.

## Scope

Allowed targets:

- 127.0.0.1
- localhost
- ::1
- explicitly configured local Docker lab services

Blocked targets and actions:

- public IPs
- third-party domains
- external networks
- credential attacks
- login attempts
- payload injection execution
- exploit modules
- broad crawling
- destructive testing
- data exfiltration
- denial-of-service behavior

## Core commands

Start lab:

    sudo ./lab/scripts/labctl up
    sudo ./lab/scripts/labctl test

Stop lab:

    sudo ./lab/scripts/labctl down

Passive audit:

    ./lab/scripts/passive-audit

Active dry-run:

    ./lab/scripts/active-dry-run http://127.0.0.1:3000 I_APPROVE_ACTIVE_LOCAL_ONLY_TEST

Bounded fuzzing dry-run:

    ./lab/scripts/fuzz-dry-run http://127.0.0.1:3000 I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING

Dry-run evidence report:

    ./lab/scripts/dryrun-evidence-report http://127.0.0.1:3000

Readiness check:

    ./lab/scripts/readiness-check

Release manifest:

    ./lab/scripts/release-manifest

## Generated local outputs

Reports:

    lab/reports/latest_lab_report.md
    lab/reports/latest_lab_report.json

Evidence:

    lab/evidence/<timestamp>-dryrun-report/

Readiness:

    lab/readiness/latest_readiness.json
    lab/readiness/latest_readiness.md

Release manifest:

    lab/release/openmythos_lab_manifest.json
    lab/release/openmythos_lab_manifest.md

## Canonical passive lab tags

- lab-localhost-v1.0 guardrail regression tests
- lab-localhost-v1.1 CI
- lab-localhost-v1.2 robots/sitemap passive fetch
- lab-localhost-v1.3 static asset inventory
- lab-localhost-v1.4 response header diff
- lab-localhost-v1.5 JSON schema contracts
- lab-localhost-v1.6 severity normalization

## Canonical active lab tags

- active-lab-v0.1-final active testing policy
- active-lab-v0.2-final policy plus caps / kill-switch baseline
- active-lab-v0.3 active dry-run harness
- active-lab-v0.3.1 enhanced dry-run safety reporting
- active-lab-v0.4-policy-final bounded fuzzing policy only
- active-lab-v0.4-dryrun bounded fuzzing dry-run planner
- active-lab-v0.4-dryrun-report dry-run evidence workflow
- active-lab-v0.4-readiness readiness checker
- active-lab-v0.4-release-manifest release manifest

## Historical tags to ignore

These tags were created early or superseded:

- active-lab-v0.1
- active-lab-v0.1-policy
- active-lab-v0.2
- active-lab-v0.2-corrected
- active-lab-v0.4-policy
- lab-localhost-v0.3

Prefer corrected or final tags.

## Required approval phrases

Passive approved GET operations:

    I_APPROVE_LOCAL_ONLY_HTTP_GET

Active local-only dry-run planning:

    I_APPROVE_ACTIVE_LOCAL_ONLY_TEST

Bounded fuzzing dry-run planning:

    I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING

## Safety invariants

The lab must preserve these invariants:

- public target support remains disabled
- active tools remain disabled by default
- kill switch remains enabled
- fuzzing remains disabled by policy
- active dry-run executes zero requests
- bounded fuzz dry-run executes zero requests
- exploit payloads remain prohibited
- login attempts remain prohibited
- broad crawling remains prohibited
- evidence/readiness/release outputs stay local and ignored by Git

## Standard release gate

Before tagging future lab milestones, run:

    pytest -q
    ./lab/scripts/readiness-check
    ./lab/scripts/release-manifest
    git status --short

Only tag when tests pass and the working tree contains only intentional changes.
