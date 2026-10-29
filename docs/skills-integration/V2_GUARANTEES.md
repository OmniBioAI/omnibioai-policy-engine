# Skills policy-decision/v2 guarantees

The v2 capability is inactive unless `SKILLS_POLICY_LIVE=true`. The legacy
`/policy/evaluate` request and response behavior is unchanged while it is off.

Activation additionally requires an owner approval reference, the exact
compiled mapping digest, a non-empty tenant allowlist, trusted OAuth client
IDs, auth-service JWKS/issuer configuration, a transport guarantee, and a
Security Audit durable-receipt endpoint. `SKILLS_POLICY_KILL_SWITCH=true`
always denies, and `skill.execute` has a separate
`SKILLS_EXECUTION_ENABLED=false` default-off switch.

## Contract and limits

- Schema: `policy-decision/v2` only; unknown fields and wrong versions deny.
- Resource: canonical `skill:<id>@<version>` only; wildcard resources deny.
- Mapping: identity mappings for `skill.discover`, `skill.plan`,
  `skill.validate`, and `skill.execute`, with a SHA-256 digest checked at
  activation. The approved canonical mapping digest is
  `4d0ccd4586ce326ca6f1d9eca6216798ef00e8e180c24ae20000fb6c2a8d9e96`.
- Workload identity: RS256 auth-service `client_credentials` token verified
  through JWKS, with audience `policy-engine`, exact scope
  `policy.evaluate:skills`, allowlisted client ID, tenant binding, and a maximum
  lifetime of 60 seconds. No bearer is emitted in decisions or audit.
- Request size: 16 KiB by default, configurable from 1 KiB through 1 MiB.
- Request freshness: 30 seconds by default, configurable through 300 seconds,
  with no more than five seconds of future clock skew.
- Transport: gateway TLS termination; internal TLS or explicit compose network
  isolation, always with a workload token. Anonymous v2 calls deny.
- Audit: Security Audit must return a matching durable receipt. Missing or
  invalid receipts deny and no unaudited allow is returned.
- Availability: any dependency, parsing, revocation, cache, authentication,
  transport, or audit error returns a bound deny. No error path can return
  allow.

## Revocation and caching

The revocation SLO is 60 seconds. Every request checks the tenant/principal authorization epoch synchronously
before evaluation or cache lookup. Missing, unreadable, or mismatched epoch
evidence denies. Positive caching is disabled by default and may be configured
only after Phase 3 qualification; the current implementation rejects any
nonzero cache TTL. The future cache-key contract already partitions
by tenant, principal, action, resource, permission-set digest, authorization
epoch, policy version, and an activation nonce. Denials are never cached.
Feature-flag and kill-switch transitions therefore cannot reuse an earlier
positive decision.

## Compatibility

The service does not initiate network requests, so retry/backoff and circuit
breaking apply to the calling adapter. Evaluation itself is read-only and has
no pagination. Rollout remains disabled by default and requires deployment
qualification of JWKS, transport isolation/TLS, authorization epochs, and
durable Security Audit receipts.

