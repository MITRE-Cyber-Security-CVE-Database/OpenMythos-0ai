# OpenMythos Bounded Fuzzing Policy

Status: policy-only. No fuzzing execution is enabled.

## Scope

Bounded fuzzing, if later enabled, may only target:

- `127.0.0.1`
- `localhost`
- `::1`
- explicitly configured local Docker lab targets

Public targets are not allowed.

## Default State

Fuzzing is disabled by default.

The default mode must remain:

```text
dry_run
