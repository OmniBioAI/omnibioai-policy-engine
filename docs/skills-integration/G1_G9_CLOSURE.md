# B-04 / G1-G9 closure matrix

This closure applies to the feature-flagged Skills v2 path only. The path is
off by default, and the legacy path is intentionally unchanged.

| Gap | v2 closure | Evidence |
|---|---|---|
| G1 unknown/unmapped actions allow | Exact four-entry map; every other action and every non-canonical skill resource denies | `test_gaps_fail_closed` |
| G2 empty permissions bypass | Empty or missing exact permission denies | `test_gaps_fail_closed` |
| G3 caller-supplied claims trusted | Allowlisted workload identity and exact scope sign the entire strict request; permission digest is recomputed; revocation epoch is checked against authority | `test_workload_authentication_binds_complete_request`, `test_revocation_epoch_is_checked_before_every_cache_hit` |
| G4 admin role override | v2 schema forbids roles and extra fields; wildcard permissions do not grant | `test_admin_role_or_wildcard_cannot_be_asserted_or_grant` |
| G5 no decision ID | Every evaluated allow/deny has a 32-hex opaque ID | `test_bound_allow_has_v2_identity_metadata_and_audit` |
| G6 cache lacks version/age | Positive caching is rejected until an SLO is approved; decisions bind policy version/time/cache age; the future key contract includes policy version, identity, epoch and all authorization dimensions | `test_positive_decision_caching_fails_closed_until_slo_is_approved`, `test_cache_key_partitions_every_authorization_binding` |
| G7 skipped enforcement masked | v2 has only `enforcement=enforced`; there is no skipped or admin-override allow | all v2 decision tests |
| G8 tenancy optional | Tenant is mandatory, allowlisted, signed, echoed, epoch-bound, and part of every cache key | bound allow and cache-partition tests |
| G9 invalidation ineffective | Synchronous epoch comparison occurs before every decision; missing/mismatched authority denies, so cache invalidation is not the security boundary | revocation and dependency-failure tests |

Additional guarantees cover mapping-digest activation, independent kill
switches, request freshness and size, audit fail-closed behavior, default-zero
positive-cache TTL, bounded opt-in cache age, and non-caching of denials.

