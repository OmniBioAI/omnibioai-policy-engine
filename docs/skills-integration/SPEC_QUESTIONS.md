# Track B policy integration spec questions

## Resolved by authoritative-spec precedence

1. `docs/production/track-b/iam.md` requires exactly `skill.discover`,
   `skill.plan`, `skill.validate`, and `skill.execute`. Older non-authoritative
   integration documents propose `skill.list`, `skill.read`, `skill.plan`,
   `skill.evaluate`, `skill.execute`, and `skill.admin`. This lane implements
   only the four names in the authoritative IAM spec.

## Owner answers applied

1. **Workload identity:** v2 accepts only short-lived auth-service
   `client_credentials` access tokens with audience `policy-engine`, scope
   `policy.evaluate:skills`, an allowlisted `client_id`, and the request tenant.
   Tokens are RS256-verified against the configured auth-service JWKS. User
   tokens, anonymous calls, missing `kid`, other algorithms, and tokens lasting
   more than 60 seconds deny.
2. **Revocation:** the approved SLO is 60 seconds. Workload token lifetime and
   JWKS cache lifetime are capped at 60 seconds, and the principal authorization
   epoch is checked synchronously before every decision. Positive decision
   caching remains rejected until separately qualified in Phase 3.
3. **Transport:** the gateway terminates TLS. Internal calls require workload
   tokens and either TLS endpoints or an explicit `network-isolated` compose
   deployment mode. An absent transport guarantee or anonymous v2 request
   denies.
4. **Audit:** v2 publishes `skill_authorization` to Security Audit using a
   runtime-mounted client-credentials token and accepts only a matching receipt
   with `source=security-audit` and `durable=true`. A missing, malformed,
   mismatched, non-durable, or unavailable receipt changes the result to an
   `AUDIT_FAILURE` denial.

No policy-engine spec questions remain open. Phase 3 must qualify positive
caching and the deployed Security Audit receipt endpoint before activation.

