# Track B policy integration spec questions

## Resolved by authoritative-spec precedence

1. `docs/production/track-b/iam.md` requires exactly `skill.discover`,
   `skill.plan`, `skill.validate`, and `skill.execute`. Older non-authoritative
   integration documents propose `skill.list`, `skill.read`, `skill.plan`,
   `skill.evaluate`, `skill.execute`, and `skill.admin`. This lane implements
   only the four names in the authoritative IAM spec.

## Owner decisions still required

1. The policy-engine repository has no injected mTLS/workload-identity port.
   The disabled-by-default v2 implementation therefore supplies a narrow HMAC
   workload verifier whose secret is runtime-only. Confirm whether production
   activation must replace it with a platform mTLS verifier before approval.
2. The spec requires a revocation SLO but does not assign a numeric value. The
   implementation rejects every nonzero positive-cache TTL and checks the
   synchronous authorization epoch before every evaluation. Confirm the
   approved maximum cache age before enabling positive caching.
3. The timeout/retry/circuit-breaker guarantees describe a client calling this
   service. The policy engine itself exposes a local FastAPI handler and makes
   no remote policy call. Confirm that those transport guarantees remain the
   caller/adapter owner's responsibility.
4. The spec requires an audit failure to block the operation, but no approved
   Security Audit publisher is present in this repository. The v2 service uses
   an injected audit callable and converts publisher errors to
   `AUDIT_FAILURE`; production activation needs the approved publisher binding.

