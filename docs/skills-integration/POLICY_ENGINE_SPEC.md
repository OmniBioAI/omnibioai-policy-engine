# Policy Engine live-interface design (B-04, B-05)

Status: design complete; upstream remediation/approval and implementation are gated.

## Current offline contract

The repository mirrors the current request/decision shape and documents unsafe current behavior (`src/omnibioai_skills/integration/policy_engine.py:86-107`). The proposed v2 decision binds decision ID, policy version/time, enforcement, principal, tenant, action, and resource (`src/omnibioai_skills/integration/policy_engine.py:109-157`). The offline adapter rejects missing approval/mappings, empty claims, malformed/stale/cached decisions, transport failures, and denies (`src/omnibioai_skills/integration/policy_engine.py:164-260`).

## Target interface

Injected port `evaluate(request) -> Decision`.

- Request: `principal_id`, `tenant_id`, exact `action`, canonical resource `skill:<id>@<version>`, verified permission set digest, correlation ID, delegation reference, request time, and `policy-decision/v2`.
- Response: `decision_id`, allowed, bounded reason/error code, `policy_version`, source, evaluated time, cache age, `enforcement=enforced`, and exact echoed binding fields.
- Errors: `DENIED` is authoritative/non-retryable; `UNKNOWN_ACTION`, `UNMAPPED_RESOURCE`, `MALFORMED`, `STALE`, `BINDING_MISMATCH`; availability errors are retryable but never allow.
- Idempotency: evaluation is read-only. Repeated identical request digests may return the same decision ID only within the revocation SLO; changed policy/identity produces a new decision.
- Timeout/retry/backoff: 250 ms connect, 750 ms response, 1 s total; maximum two full-jitter retries for 429/5xx/connection reset. No retry of deny, unknown action, malformed response, or stale decision. Circuit breaker opens after five transient failures for 30 s and fails closed.
- Pagination: none; one complete decision per action/resource. A skill with multiple permissions requires one bound allow per permission.

## Authentication, authorization, and tenancy

The host injects mTLS/workload-identity providers; no endpoint token enters repository config. Scope is `policy.evaluate:skills`, not policy administration. Tenant derives from verified IAM plus route context and must be echoed. Roles, caller-supplied admin flags, wildcard resources, and cross-tenant cache keys are forbidden.

## Audit

For every call emit `skill_authorization`: event/decision IDs, correlation, tenant, principal, action, resource, allow/deny/fail, policy version/source, enforcement, cache age bucket, latency bucket, and error code. Redact reasons through the approved filter. Never include tokens, raw claims/roles, full permissions, request inputs, datasets, PHI/PII, or policy documents.

## Failure and fail-closed rules

No mapping, unknown action, skipped enforcement, absent decision ID/version, mismatched echo, stale/future/cached-beyond-SLO decision, timeout, oversized body, schema drift, circuit-open, or audit failure blocks the protected operation. A policy allow cannot override missing IAM authorization.

## Flags and kill switches

`SKILLS_POLICY_LIVE=false`, owner approval absent, and tenant allowlist empty by default. Enablement needs the v2 contract and exact mapping digest. The global execution kill switch and a policy-specific switch both win. Turning either off invalidates positive caches.

## Test plan

Contract-test the fake for allow/deny, no match, binding mismatch, staleness, malformed/oversized responses, retry bounds, circuit behavior, and tenant-scoped caching. Qualify against the upstream G1-G9 suite, revocation and rolling-upgrade tests, version negotiation, and measured latency; retain immutable owner evidence.

## Owned outside this repo

- [ ] Policy owner closes B-04/G1-G9 and makes unknown/unmapped actions deny.
- [ ] Policy service implements and versions `policy-decision/v2` with decision IDs and bound echoes.
- [ ] Owner approves the exact skill permission-to-action/resource mapping and its digest.
- [ ] Service partitions caches by tenant/principal/action/resource and meets revocation SLO.
- [ ] Service publishes workload identity, size, timeout, availability, and compatibility guarantees.
