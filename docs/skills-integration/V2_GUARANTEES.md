# Skills policy-decision/v2 guarantees

The v2 capability is inactive unless `SKILLS_POLICY_LIVE=true`. The legacy
`/policy/evaluate` request and response behavior is unchanged while it is off.

Activation additionally requires an owner approval reference, the exact
compiled mapping digest, a non-empty tenant allowlist, trusted workload IDs,
and a runtime-injected workload secret. `SKILLS_POLICY_KILL_SWITCH=true` always
denies, and `skill.execute` has a separate `SKILLS_EXECUTION_ENABLED=false`
default-off switch.

## Contract and limits

- Schema: `policy-decision/v2` only; unknown fields and wrong versions deny.
- Resource: canonical `skill:<id>@<version>` only; wildcard resources deny.
- Mapping: identity mappings for `skill.discover`, `skill.plan`,
  `skill.validate`, and `skill.execute`, with a SHA-256 digest checked at
  activation. The approved canonical mapping digest is
  `4d0ccd4586ce326ca6f1d9eca6216798ef00e8e180c24ae20000fb6c2a8d9e96`.
- Workload identity: runtime HMAC credential bound to the complete request,
  exact scope `policy.evaluate:skills`, allowlisted workload ID, and a
  timestamp inside the configured freshness window. No credential is stored
  in repository configuration or emitted in decisions/audit.
- Request size: 16 KiB by default, configurable from 1 KiB through 1 MiB.
- Request freshness: 30 seconds by default, configurable through 300 seconds,
  with no more than five seconds of future clock skew.
- Availability: any dependency, parsing, revocation, cache, authentication, or
  audit error returns a bound deny. No error path can return allow.

## Revocation and caching

Every request checks the tenant/principal authorization epoch synchronously
before evaluation or cache lookup. Missing, unreadable, or mismatched epoch
evidence denies. Positive caching is disabled by default and may be configured
only after a numeric revocation SLO is approved; the current implementation
rejects any nonzero cache TTL. The future cache-key contract already partitions
by tenant, principal, action, resource, permission-set digest, authorization
epoch, policy version, and an activation nonce. Denials are never cached.
Feature-flag and kill-switch transitions therefore cannot reuse an earlier
positive decision.

## Compatibility

The service does not initiate network requests, so retry/backoff and circuit
breaking apply to the calling adapter. Evaluation itself is read-only and has
no pagination. Rollout must remain disabled until workload identity, audit
publisher, numeric revocation SLO, and owner evidence are approved.

